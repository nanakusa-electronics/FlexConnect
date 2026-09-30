package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"flexconnect/internal/apiserver"
	"flexconnect/internal/appd"
	"flexconnect/internal/buildinfo"
	"flexconnect/internal/ipc"
	"flexconnect/internal/logging"
	"flexconnect/internal/osnet"
	"flexconnect/internal/router"
	storefile "flexconnect/internal/store/file"
	"flexconnect/internal/updater"
	vpnac "flexconnect/internal/vpn/anyconnect"
)

func main() {
	opts, err := parseDaemonOptions(os.Args[1:], os.LookupEnv)
	if errors.Is(err, flagErrHelp) {
		return
	}
	if err != nil {
		logging.Init(os.Stdout, logging.LevelInfo, true)
		logging.WithComponent("flexconnectd").Fatalf("%v", err)
	}

	if isWindowsService() {
		if err := runWindowsService(opts); err != nil {
			logging.Init(os.Stdout, logging.LevelInfo, true)
			logging.WithComponent("flexconnectd").Fatalf("%v", err)
		}
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := runDaemon(ctx, opts); err != nil {
		logging.Init(os.Stdout, logging.LevelInfo, true)
		logging.WithComponent("flexconnectd").Fatalf("%v", err)
	}
}

type daemonOptions struct {
	socket      string
	state       string
	verbose     bool
	secretStore string
	startup     *startupConfig
}

func runDaemon(ctx context.Context, opts daemonOptions) error {
	return runDaemonReady(ctx, opts, nil)
}

func runDaemonReady(ctx context.Context, opts daemonOptions, ready chan<- error) (err error) {
	return runDaemonReadyWithResume(ctx, opts, ready, nil)
}

func runDaemonReadyWithResume(ctx context.Context, opts daemonOptions, ready chan<- error, resume <-chan struct{}) (err error) {
	startedAt := time.Now()
	readySent := false
	sendReady := func(readyErr error) {
		if ready == nil || readySent {
			return
		}
		ready <- readyErr
		close(ready)
		readySent = true
	}
	defer func() {
		if !readySent {
			sendReady(err)
		}
	}()
	appd.SetDebug(opts.verbose)
	logging.Init(os.Stdout, logging.LevelInfo, true)
	logging.SetLevel(condLevel(opts.verbose))
	serverLog := logging.WithComponent("flexconnectd")
	serverLog.Printf("starting pid=%d at=%s", os.Getpid(), startedAt.Format(time.RFC3339Nano))
	if opts.verbose {
		serverLog.Printf("verbose logging enabled")
	}

	if err := ensureElevated(); err != nil {
		return err
	}
	serverLog.Printf("elevation check passed")
	serverLog.Printf("configuration backend=anyconnect custom_socket=%v custom_state=%v", opts.socket != ipc.DefaultSocketPath(), opts.state != defaultStatePath())
	networkJournalPath := filepath.Join(filepath.Dir(opts.state), "network-ownership.json")
	osnet.SetNetworkJournalPath(networkJournalPath)
	if err := osnet.RecoverNetworkJournal(ctx, networkJournalPath); err != nil {
		return err
	}

	service, err := newService(opts.state, opts.secretStore)
	if err != nil {
		return err
	}
	serviceClosed := false
	defer func() {
		if serviceClosed {
			return
		}
		closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if closeErr := service.Close(closeCtx); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	serverLog.Printf("service initialized")
	if err := bootstrapStartup(ctx, service, opts.startup); err != nil {
		return err
	}

	listener, err := ipc.Listen(opts.socket)
	if err != nil {
		sendReady(err)
		return err
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	serverLog.Printf("ipc listener ready custom_socket=%v", opts.socket != ipc.DefaultSocketPath())
	sendReady(nil)

	server := &http.Server{
		Handler: apiserver.New(service).Handler(),
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			identity, ok := ipc.IdentityFromConn(conn)
			if !ok {
				return ctx
			}
			return apiserver.WithActor(ctx, appd.Actor{ID: identity.ID, System: identity.System, Admin: identity.Elevated || identity.System})
		},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 * 1024,
	}
	errCh := make(chan error, 1)
	go func() {
		serverLog.Printf("http server serving")
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	serving := true
	for serving {
		select {
		case err := <-errCh:
			return err
		case fatalErr := <-service.FatalErrors():
			return fatalErr
		case <-resume:
			service.ResumeAutoReconnect()
		case <-ctx.Done():
			serverLog.Printf("shutdown requested after %s", time.Since(startedAt))
			serving = false
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if err := service.Close(shutdownCtx); err != nil {
		return err
	}
	serviceClosed = true

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func condLevel(verbose bool) logging.Level {
	if verbose {
		return logging.LevelDebug
	}
	return logging.LevelInfo
}

func newService(statePath, secretStore string) (*appd.Service, error) {
	store := storefile.New(statePath)
	secrets, err := newSecretStore(statePath, secretStore)
	if err != nil {
		return nil, err
	}
	service, err := appd.New(store, secrets, vpnac.New(), router.DefaultPlanner{})
	if err != nil {
		return nil, err
	}
	configureUpdater(service)
	return service, nil
}

// defaultUpdateInterval is the cadence for online update checks when
// FLEXCONNECT_UPDATE_INTERVAL is not set.
const defaultUpdateInterval = 6 * time.Hour

// configureUpdater wires the GitHub Releases update checker into the service.
// The repository comes from buildinfo.UpdateRepo (overridable at runtime via
// FLEXCONNECT_UPDATE_REPO); the cadence comes from FLEXCONNECT_UPDATE_INTERVAL
// (default 6h, "0" or "disabled" turns checks off). When no repository is
// configured the checker is left unset and the API reports Disabled.
func configureUpdater(service *appd.Service) {
	repo := strings.TrimSpace(buildinfo.UpdateRepo)
	if env := strings.TrimSpace(os.Getenv("FLEXCONNECT_UPDATE_REPO")); env != "" {
		repo = env
	}
	interval := defaultUpdateInterval
	if env := strings.TrimSpace(os.Getenv("FLEXCONNECT_UPDATE_INTERVAL")); env != "" {
		if env == "disabled" || env == "0" {
			interval = 0
		} else if d, err := time.ParseDuration(env); err == nil {
			interval = d
		}
	}
	if repo == "" || interval <= 0 {
		logging.WithComponent("flexconnectd").Printf("update checks disabled repo_configured=%v interval=%s", repo != "", interval)
		return
	}
	service.SetUpdater(updater.New(repo), interval)
	logging.WithComponent("flexconnectd").Printf("update checks enabled repo=%s interval=%s", repo, interval)
}
