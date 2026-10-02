package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"flexconnect/client/local"
	"flexconnect/internal/buildinfo"
	"flexconnect/internal/ipc"
	"flexconnect/internal/logging"
	"flexconnect/internal/loginprobe"
	"flexconnect/internal/netcheck"
	"flexconnect/internal/types"
	"golang.org/x/term"
)

var verbose bool

const (
	defaultCommandTimeout = 15 * time.Second
	connectCommandTimeout = 2 * time.Minute
	maxSecretInputBytes   = 64 * 1024
)

var (
	cliIn  io.Reader = os.Stdin
	cliOut io.Writer = os.Stdout
	cliErr io.Writer = os.Stderr
)

type helpTopic struct {
	Name        string
	Summary     string
	Usage       string
	Description string
	Examples    []string
	Subcommands []helpTopic
}

func main() {
	parsedVerbose := false
	filteredArgs := make([]string, 0, len(os.Args)-1)
	for _, arg := range os.Args[1:] {
		if arg == "-v" || arg == "--verbose" {
			parsedVerbose = true
			continue
		}
		filteredArgs = append(filteredArgs, arg)
	}
	os.Args = append([]string{os.Args[0]}, filteredArgs...)

	socket := flag.String("socket", ipc.DefaultSocketPath(), "daemon socket or named pipe path")
	timeout := flag.Duration("timeout", defaultCommandTimeout, "daemon connectivity and ordinary command timeout")
	connectTimeout := flag.Duration("connect-timeout", connectCommandTimeout, "login and VPN connection timeout")
	showVersion := flag.Bool("version", false, "print version and exit")
	verboseShort := flag.Bool("v", false, "enable verbose debug output")
	verboseLong := flag.Bool("verbose", false, "same as -v")
	flag.Parse()
	if *showVersion {
		_, _ = fmt.Fprintln(cliOut, buildinfo.Version)
		return
	}
	verbose = parsedVerbose || *verboseShort || *verboseLong
	local.SetDebug(verbose)
	logging.Init(cliErr, condLevel(verbose), true)
	args := flag.Args()
	debugf("custom_socket=%t verbose=%t argument_count=%d", *socket != ipc.DefaultSocketPath(), verbose, len(args))
	if len(args) == 0 || isHelpArg(args[0]) {
		_, _ = io.WriteString(cliOut, rootHelp())
		return
	}
	if *timeout <= 0 || *connectTimeout <= 0 {
		fmt.Fprintln(cliErr, "--timeout and --connect-timeout must be positive")
		os.Exit(2)
	}
	client := &local.Client{Socket: *socket}
	if err := runWithTimeouts(context.Background(), client, args, *timeout, *connectTimeout); err != nil {
		fmt.Fprintln(cliErr, err)
		os.Exit(1)
	}
}

func run(parent context.Context, client *local.Client, args []string) error {
	return runWithTimeouts(parent, client, args, defaultCommandTimeout, connectCommandTimeout)
}

func runWithTimeouts(parent context.Context, client *local.Client, args []string, timeout, connectTimeout time.Duration) error {
	if len(args) == 0 {
		_, err := io.WriteString(cliOut, rootHelp())
		return err
	}
	if commandNeedsDaemon(args) {
		if err := checkDaemonConnectivity(parent, client, timeout, commandAllowsUnready(args)); err != nil {
			return err
		}
	}
	if args[0] == "login" && len(args) == 1 {
		return runInteractiveLogin(parent, client, cliIn, cliOut, connectTimeout)
	}

	ctx := parent
	cancel := func() {}
	if args[0] != "watch" {
		commandTimeout := timeout
		if args[0] == "login" || args[0] == "up" || args[0] == "netcheck" {
			commandTimeout = connectTimeout
		}
		ctx, cancel = context.WithTimeout(parent, commandTimeout)
	}
	defer cancel()
	return runCommand(ctx, client, args)
}

func commandNeedsDaemon(args []string) bool {
	if len(args) == 0 || args[0] == "help" || isHelpArg(args[0]) {
		return false
	}
	if len(args) > 1 && wantCommandHelp(args[1:]) {
		return false
	}
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			return false
		}
	}
	switch args[0] {
	case "status", "login", "up", "down", "logs", "diag", "traffic", "watch", "update", "control-mode":
		return true
	case "profile", "route", "proxy":
		return len(args) > 1
	default:
		return false
	}
}

func commandAllowsUnready(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "status", "logs", "diag", "traffic", "watch", "down", "control-mode":
		return true
	case "profile":
		return len(args) > 1 && (args[1] == "list" || args[1] == "current")
	case "route":
		return len(args) > 1 && args[1] == "show"
	case "proxy":
		return len(args) > 1 && args[1] == "status"
	default:
		return false
	}
}

func checkDaemonConnectivity(parent context.Context, client *local.Client, timeout time.Duration, allowUnready bool) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	debugf("checking daemon connectivity")
	live, err := client.Live(ctx)
	if err != nil {
		return daemonConnectivityError(err)
	}
	ready, err := client.Ready(ctx)
	if err != nil {
		return daemonConnectivityError(err)
	}
	if !ready.Ready && !allowUnready {
		return daemonConnectivityError(&local.NotReadyError{Status: *ready})
	}
	debugf("daemon connectivity check passed version=%s api_version=%d ready=%t", live.Version, live.APIMajor, ready.Ready)
	return nil
}

func daemonConnectivityError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("cannot connect to flexconnectd: connectivity check timed out: %w", err)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("cannot connect to flexconnectd: permission denied; on Linux, add this user to the flexconnect group and start a new login session: %w", err)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("cannot connect to flexconnectd: control socket not found; verify that the daemon service is running: %w", err)
	default:
		return fmt.Errorf("cannot connect to flexconnectd: %w", err)
	}
}

func runCommand(ctx context.Context, client *local.Client, args []string) error {
	debugf("run command=%q", args[0])
	if args[0] == "help" {
		return printHelpTopic(args[1:])
	}
	switch args[0] {
	case "status":
		debugf("handling status")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("status")
		}
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		debugf("status result state=%q selected=%q", status.State, status.SelectedProfileID)
		if hasJSONFlag(args[1:]) {
			return printJSON(status)
		}
		profiles, _ := client.Profiles(ctx)
		_, err = io.WriteString(cliOut, formatStatusWithProfiles(status, profiles))
		return err
	case "login":
		debugf("handling login")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("login")
		}
		return runLogin(ctx, client, args[1:])
	case "up":
		debugf("handling up")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("up")
		}
		return runUp(ctx, client, args[1:])
	case "down":
		debugf("handling disconnect")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("down")
		}
		if err := client.Disconnect(ctx); err != nil {
			return err
		}
		debugf("disconnect success")
		return printCurrentStatus(ctx, client)
	case "logs":
		debugf("handling logs")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("logs")
		}
		logs, err := client.Logs(ctx)
		if err != nil {
			return err
		}
		debugf("received %d logs", len(logs))
		return printJSON(logs)
	case "diag":
		debugf("handling diag")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("diag")
		}
		diag, err := client.Diagnostics(ctx)
		if err != nil {
			return err
		}
		if len(args) > 1 {
			path := args[1]
			data, err := json.MarshalIndent(diag, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return err
			}
			debugf("diagnostics wrote to %q bytes=%d", path, len(data))
			_, err = fmt.Fprintf(cliOut, "Wrote diagnostics to %s\n", path)
			return err
		}
		debugf("diagnostics status=%q current=%q connected=%q profiles=%d logs=%d routes=%d",
			diag.Status.State, diag.Status.SelectedProfileID, diag.Status.ConnectedProfileID,
			len(diag.Profiles), len(diag.Logs), len(diag.Status.EffectiveRoutes))
		return printJSON(diag)
	case "traffic":
		debugf("handling traffic")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("traffic")
		}
		traffic, err := client.Traffic(ctx)
		if err != nil {
			return err
		}
		if hasJSONFlag(args[1:]) {
			return printJSON(traffic)
		}
		_, err = io.WriteString(cliOut, formatTrafficSnapshot(*traffic))
		return err
	case "netcheck":
		debugf("handling netcheck")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("netcheck")
		}
		return runNetcheck(ctx, args[1:])
	case "profile":
		debugf("handling profile")
		return runProfile(ctx, client, args[1:])
	case "route":
		debugf("handling route")
		return runRoutes(ctx, client, args[1:])
	case "proxy":
		debugf("handling proxy")
		return runProxy(ctx, client, args[1:])
	case "control-mode":
		debugf("handling control mode")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("control-mode")
		}
		return runControlMode(ctx, client, args[1:])
	case "watch":
		debugf("handling watch")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("watch")
		}
		watcher, err := client.Watch(context.Background())
		if err != nil {
			return err
		}
		defer watcher.Close()
		for {
			notify, err := watcher.Next()
			if err != nil {
				return err
			}
			debugf("watch notify event=%q", notify.Event)
			if err := printJSON(notify); err != nil {
				return err
			}
		}
	case "update":
		debugf("handling update")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("update")
		}
		info, err := client.UpdateCheck(ctx)
		if err != nil {
			return err
		}
		if hasJSONFlag(args[1:]) {
			return printJSON(info)
		}
		_, err = io.WriteString(cliOut, formatUpdateInfo(info))
		return err
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

// loginFetchGroups and loginVerify are package variables so tests can stub
// the network probes that back the interactive login flow.
var (
	loginFetchGroups = loginprobe.FetchGroups
	loginVerify      = loginprobe.VerifyCredentials
)

const loginProbeTimeout = 45 * time.Second

func runInteractiveLogin(parent context.Context, client *local.Client, in io.Reader, out io.Writer, timeout time.Duration) error {
	req, err := promptLoginRequest(parent, in, out)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := client.Login(ctx, req); err != nil {
		return err
	}
	return printCurrentStatus(ctx, client)
}

func runNetcheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("netcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	envFile := fs.String("env-file", netcheck.DefaultEnvFile, "dotenv file containing ENDPOINT, USERNAME, PASSWORD, and optional GROUP")
	endpoint := fs.String("endpoint", "", "optional VPN endpoint override; credentials still come from env-file")
	observeFor := fs.Duration("observe", netcheck.DefaultObserveFor, "how long to keep the user-space TLS tunnel under observation")
	dpdInterval := fs.Duration("dpd-interval", 0, "DPD interval; zero derives it from X-CSTP-DPD")
	noDTLS := fs.Bool("no-dtls", false, "do not open the secondary DTLS channel")
	localIP := fs.String("local-ip", "", "optional local IPv4 source address for the control connection")
	mtu := fs.Int("mtu", 1399, "CSTP MTU used by the user-space traffic probe")
	speedtestURL := fs.String("speedtest-url", netcheck.DefaultSpeedtestURL, "HTTP(S) download URL to probe through the VPN user-space stack")
	speedtestBytes := fs.Int64("speedtest-bytes", netcheck.DefaultSpeedBytes, "maximum bytes to download")
	speedtestTimeout := fs.Duration("speedtest-timeout", netcheck.DefaultSpeedLimit, "maximum duration of the traffic probe")
	noSpeedtest := fs.Bool("no-speedtest", false, "only check connection stability; skip the traffic probe")
	debug := fs.Bool("debug", false, "enable protocol debug logging")
	jsonOutput := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: flexconnect netcheck [--env-file .env] [--speedtest-url URL] [--json]")
	}
	creds, err := netcheck.LoadCredentials(*envFile)
	if err != nil {
		return fmt.Errorf("load netcheck credentials: %w", err)
	}
	if strings.TrimSpace(*endpoint) != "" {
		creds.Endpoint = strings.TrimSpace(*endpoint)
	}
	var speedtest *netcheck.SpeedtestConfig
	if !*noSpeedtest && strings.TrimSpace(*speedtestURL) != "" {
		speedtest, err = netcheck.NewSpeedtestConfig(*speedtestURL, *speedtestBytes, *speedtestTimeout)
		if err != nil {
			return fmt.Errorf("invalid speedtest configuration: %w", err)
		}
	}
	result, err := netcheck.Run(ctx, netcheck.Config{
		Credentials: creds, ObserveFor: *observeFor, DPDInterval: *dpdInterval,
		WithDTLS: !*noDTLS, Debug: verbose || *debug, LocalIP: *localIP,
		Speedtest: speedtest, MTU: *mtu,
	})
	if err != nil {
		if result.Endpoint != "" {
			_, _ = io.WriteString(cliErr, formatNetcheckResult(result))
		}
		return fmt.Errorf("netcheck failed: %w", err)
	}
	if *jsonOutput {
		return printJSON(result)
	}
	_, err = io.WriteString(cliOut, formatNetcheckResult(result))
	return err
}

func runLogin(ctx context.Context, client *local.Client, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "", "server URL")
	user := fs.String("user", "", "username")
	unsafePassword := fs.String("password", "", "unsupported plaintext password")
	passwordFile := fs.String("password-file", "", "read password from a file")
	passwordStdin := fs.Bool("password-stdin", false, "read password from standard input")
	name := fs.String("name", "", "profile name")
	group := fs.String("group", "", "VPN group")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: flexconnect login --server <url> --user <username> (--password-file <path> | --password-stdin) [--name <profile-name> --group <group>]")
	}
	if *unsafePassword != "" {
		return errors.New("--password is not supported because command-line secrets leak through process listings and shell history; use --password-file or --password-stdin")
	}
	if *server == "" || *user == "" {
		return fmt.Errorf("login requires --server and --user")
	}
	password, provided, err := readSecretInput(*passwordFile, *passwordStdin, cliIn)
	if err != nil {
		return err
	}
	if !provided {
		return errors.New("login requires --password-file or --password-stdin; omit all arguments for interactive login")
	}
	if err := client.Login(ctx, types.LoginRequest{
		Name:      *name,
		ServerURL: *server,
		Username:  *user,
		Group:     *group,
		Password:  password,
	}); err != nil {
		return err
	}
	return printCurrentStatus(ctx, client)
}

func readSecretInput(path string, fromStdin bool, in io.Reader) (string, bool, error) {
	if path != "" && fromStdin {
		return "", false, errors.New("--password-file and --password-stdin are mutually exclusive")
	}
	if path == "" && !fromStdin {
		return "", false, nil
	}

	var reader io.Reader = in
	var file *os.File
	if path != "" {
		opened, err := os.Open(path)
		if err != nil {
			return "", false, fmt.Errorf("open password file: %w", err)
		}
		file = opened
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return "", false, fmt.Errorf("inspect password file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return "", false, errors.New("password file must be a regular file")
		}
		if err := validateSecretFile(info); err != nil {
			return "", false, err
		}
		reader = file
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxSecretInputBytes+1))
	if err != nil {
		return "", false, fmt.Errorf("read password input: %w", err)
	}
	if len(data) > maxSecretInputBytes {
		return "", false, fmt.Errorf("password input exceeds %d bytes", maxSecretInputBytes)
	}
	secret := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if secret == "" {
		return "", false, errors.New("password input is empty")
	}
	return secret, true, nil
}

func readKeystore(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open keystore: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect keystore: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("keystore must be a regular file")
	}
	if err := validateSecretFile(info); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read keystore: %w", err)
	}
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, errors.New("keystore size is invalid")
	}
	return data, nil
}

func promptLoginRequest(ctx context.Context, in io.Reader, out io.Writer) (types.LoginRequest, error) {
	reader := bufio.NewReader(in)

	var groups []string
	var server string
	for {
		var err error
		server, err = promptRequiredValue(reader, out, "Server URL")
		if err != nil {
			return types.LoginRequest{}, err
		}
		if _, err := fmt.Fprintf(out, "Testing connection to %s...\n", server); err != nil {
			return types.LoginRequest{}, err
		}
		probeCtx, cancel := context.WithTimeout(ctx, loginProbeTimeout)
		groups, err = loginFetchGroups(probeCtx, server)
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return types.LoginRequest{}, ctx.Err()
		}
		if _, err := fmt.Fprintf(out, "Connection test failed: %v\n", err); err != nil {
			return types.LoginRequest{}, err
		}
	}
	if len(groups) != 0 {
		if _, err := fmt.Fprintf(out, "Connection test succeeded. Available user groups:\n"); err != nil {
			return types.LoginRequest{}, err
		}
		for i, group := range groups {
			if _, err := fmt.Fprintf(out, "  %d. %s\n", i+1, group); err != nil {
				return types.LoginRequest{}, err
			}
		}
	} else if _, err := fmt.Fprintf(out, "Connection test succeeded. The server does not advertise user groups.\n"); err != nil {
		return types.LoginRequest{}, err
	}

	group, user, password, err := promptVerifiedCredentials(ctx, reader, in, out, server, groups)
	if err != nil {
		return types.LoginRequest{}, err
	}
	name, err := promptValue(reader, out, "Profile name", true)
	if err != nil {
		return types.LoginRequest{}, err
	}
	saveMessage := "Login verified; saving profile..."
	if name != "" {
		saveMessage = fmt.Sprintf("Login verified; saving profile %q...", name)
	}
	if _, err := fmt.Fprintf(out, "%s\n", saveMessage); err != nil {
		return types.LoginRequest{}, err
	}
	return types.LoginRequest{
		Name:      name,
		ServerURL: server,
		Username:  user,
		Group:     group,
		Password:  password,
	}, nil
}

// promptVerifiedCredentials loops until the server accepts the group,
// username, and password combination, re-prompting all three fields after
// each failed verification.
func promptVerifiedCredentials(ctx context.Context, reader *bufio.Reader, in io.Reader, out io.Writer, server string, groups []string) (group, user, password string, err error) {
	group, err = promptGroupSelection(reader, out, groups)
	if err != nil {
		return "", "", "", err
	}
	for {
		user, err = promptRequiredValue(reader, out, "Username")
		if err != nil {
			return "", "", "", err
		}
		password, err = promptSecretValue(reader, in, out, "Password")
		if err != nil {
			return "", "", "", err
		}
		if _, err := fmt.Fprintf(out, "Verifying login...\n"); err != nil {
			return "", "", "", err
		}
		probeCtx, cancel := context.WithTimeout(ctx, loginProbeTimeout)
		verifyErr := loginVerify(probeCtx, loginprobe.Options{
			ServerURL: server, Group: group, Username: user, Password: password,
			Timeout: loginProbeTimeout,
		})
		cancel()
		if verifyErr == nil {
			return group, user, password, nil
		}
		if ctx.Err() != nil {
			return "", "", "", ctx.Err()
		}
		if _, err := fmt.Fprintf(out, "Login verification failed: %v\n", verifyErr); err != nil {
			return "", "", "", err
		}
		if _, err := fmt.Fprintf(out, "Re-enter the VPN group, username, and password (Ctrl-C to cancel).\n"); err != nil {
			return "", "", "", err
		}
		group, err = promptGroupSelection(reader, out, groups)
		if err != nil {
			return "", "", "", err
		}
	}
}

// promptGroupSelection asks for one of the advertised groups, accepting either
// the printed index or the exact group name. Without a group list it behaves
// like an optional free-text prompt.
func promptGroupSelection(reader *bufio.Reader, out io.Writer, groups []string) (string, error) {
	if len(groups) == 0 {
		return promptValue(reader, out, "VPN group", true)
	}
	for {
		value, err := promptValue(reader, out, fmt.Sprintf("VPN group [1-%d, default 1]", len(groups)), false)
		if err != nil {
			return "", err
		}
		if value == "" {
			return groups[0], nil
		}
		if index, convErr := strconv.Atoi(value); convErr == nil {
			if index >= 1 && index <= len(groups) {
				return groups[index-1], nil
			}
		}
		for _, group := range groups {
			if value == group {
				return group, nil
			}
		}
		if _, err := fmt.Fprintf(out, "Unknown group %q; choose one of: %s\n", value, strings.Join(groups, ", ")); err != nil {
			return "", err
		}
	}
}

func promptRequiredValue(reader *bufio.Reader, out io.Writer, label string) (string, error) {
	for {
		value, err := promptValue(reader, out, label, false)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
		if _, err := fmt.Fprintf(out, "%s is required.\n", label); err != nil {
			return "", err
		}
	}
}

func promptValue(reader *bufio.Reader, out io.Writer, label string, optional bool) (string, error) {
	suffix := ""
	if optional {
		suffix = " (optional)"
	}
	if _, err := fmt.Fprintf(out, "%s%s: ", label, suffix); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	value := strings.TrimSpace(line)
	if err == io.EOF && value == "" {
		return "", io.ErrUnexpectedEOF
	}
	return value, nil
}

// promptSecretValue reads a secret, echoing one '*' per typed character on
// terminals and falling back to a plain line read when input is piped.
func promptSecretValue(reader *bufio.Reader, in io.Reader, out io.Writer, label string) (string, error) {
	file, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return promptValue(reader, out, label, false)
	}
	if _, err := fmt.Fprintf(out, "%s: ", label); err != nil {
		return "", err
	}
	line, err := readMaskedLine(file, out)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readMaskedLine reads one line from a terminal in raw mode, printing '*' for
// each accepted byte. It supports backspace, Ctrl-U (clear line), Ctrl-C
// (cancel), and Ctrl-D on an empty line (EOF). Escape sequences such as arrow
// keys are discarded instead of being mixed into the secret.
func readMaskedLine(file *os.File, out io.Writer) (string, error) {
	fd := int(file.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	var buf []byte
	single := make([]byte, 1)
	for {
		n, err := file.Read(single)
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				if _, err := fmt.Fprintln(out); err != nil {
					return "", err
				}
				return string(buf), nil
			}
			return "", err
		}
		if n == 0 {
			continue
		}
		switch b := single[0]; b {
		case '\r', '\n':
			if _, err := fmt.Fprintln(out); err != nil {
				return "", err
			}
			return string(buf), nil
		case 0x7f, 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				if _, err := out.Write([]byte("\b \b")); err != nil {
					return "", err
				}
			}
		case 0x03:
			if _, err := fmt.Fprintln(out, "^C"); err != nil {
				return "", err
			}
			return "", errors.New("input interrupted")
		case 0x04:
			if len(buf) == 0 {
				if _, err := fmt.Fprintln(out); err != nil {
					return "", err
				}
				return "", io.EOF
			}
		case 0x15:
			for len(buf) > 0 {
				buf = buf[:len(buf)-1]
				if _, err := out.Write([]byte("\b \b")); err != nil {
					return "", err
				}
			}
		case 0x1b:
			// Swallow CSI/SS3 escape sequences (arrow keys, Home, ...) so
			// their payload bytes never join the secret.
			if n, err := file.Read(single); err != nil || n == 0 {
				if err != nil && err != io.EOF {
					return "", err
				}
				continue
			}
			if single[0] == '[' || single[0] == 'O' {
				if _, err := file.Read(single); err != nil && err != io.EOF {
					return "", err
				}
			}
		case 0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0b, 0x0c, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1c, 0x1d, 0x1e, 0x1f:
			// Ignore other control characters.
		default:
			buf = append(buf, b)
			if _, err := out.Write([]byte("*")); err != nil {
				return "", err
			}
		}
	}
}

func runUp(ctx context.Context, client *local.Client, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profileName := fs.String("p", "", "profile name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: flexconnect up [-p <profile-name>]")
	}
	if *profileName != "" {
		id, err := findProfileIDByName(ctx, client, *profileName)
		if err != nil {
			return err
		}
		if err := client.Connect(ctx, id); err != nil {
			return err
		}
		return printCurrentStatus(ctx, client)
	}
	if _, err := client.CurrentProfile(ctx); err != nil {
		return fmt.Errorf("no profile selected; run `flexconnect login` first")
	}
	if err := client.ConnectCurrent(ctx); err != nil {
		return err
	}
	return printCurrentStatus(ctx, client)
}

func findProfileIDByName(ctx context.Context, client *local.Client, name string) (string, error) {
	profiles, err := client.Profiles(ctx)
	if err != nil {
		return "", err
	}
	match := ""
	for _, profile := range profiles {
		if profile.Name != name {
			continue
		}
		if match != "" {
			return "", fmt.Errorf("multiple profiles named %q; rename one or use `flexconnect profile switch <id>`", name)
		}
		match = profile.ID
	}
	if match == "" {
		return "", fmt.Errorf("profile not found by name: %s", name)
	}
	return match, nil
}

func runControlMode(ctx context.Context, client *local.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: flexconnect control-mode user | flexconnect control-mode machine [-p <profile-name>] [profile-id]")
	}
	mode := strings.ToLower(strings.TrimSpace(args[0]))
	switch mode {
	case "user":
		if len(args) != 1 {
			return errors.New("usage: flexconnect control-mode user")
		}
		operation, err := client.SetControlMode(ctx, "user", "")
		if err != nil {
			return err
		}
		return printJSON(operation)
	case "machine":
		fs := flag.NewFlagSet("control-mode machine", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		profileName := fs.String("p", "", "machine profile name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *profileName != "" && fs.NArg() != 0 || *profileName == "" && fs.NArg() != 1 {
			return errors.New("usage: flexconnect control-mode machine [-p <profile-name>] [profile-id]")
		}
		profileID := ""
		if *profileName != "" {
			id, err := findProfileIDByName(ctx, client, *profileName)
			if err != nil {
				return err
			}
			profileID = id
		} else {
			profileID = fs.Arg(0)
		}
		operation, err := client.SetControlMode(ctx, "machine", profileID)
		if err != nil {
			return err
		}
		return printJSON(operation)
	default:
		return errors.New("control mode must be user or machine")
	}
}

func runProfile(ctx context.Context, client *local.Client, args []string) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printNamedHelp("profile")
	}
	debugf("runProfile subcommand=%q", args[0])
	switch args[0] {
	case "list":
		debugf("profile list")
		profiles, err := client.Profiles(ctx)
		if err != nil {
			return err
		}
		debugf("profile list count=%d", len(profiles))
		return printJSON(profiles)
	case "add":
		debugf("profile add")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("profile add")
		}
		fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		unsafePassword := fs.String("password", "", "unsupported plaintext password")
		passwordFile := fs.String("password-file", "", "read password from a file")
		passwordStdin := fs.Bool("password-stdin", false, "read password from standard input")
		provider := fs.String("provider", string(types.ProviderAnyConnect), "VPN provider: anyconnect or atrust")
		authMethod := fs.String("auth-method", "", "authentication method")
		loginDomain := fs.String("login-domain", "", "aTrust login domain")
		keystore := fs.String("keystore", "", "import passkey keystore from a file")
		compatibilityFile := fs.String("atrust-compatibility-file", "", "load aTrust compatibility settings from JSON")
		scope := fs.String("scope", string(types.ProfileScopeUser), "profile scope: user or machine")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *unsafePassword != "" {
			return errors.New("--password is not supported; use --password-file or --password-stdin")
		}
		positionals := fs.Args()
		if len(positionals) < 2 || len(positionals) > 3 {
			return fmt.Errorf("usage: profile add [--provider anyconnect|atrust] [--auth-method password|ecnu_passkey|shanghaitech_passkey] [--atrust-compatibility-file <json>] [--password-file <path> | --password-stdin | --keystore <path>] <name> <server_url> [username]")
		}
		profile, err := types.NewProfile(positionals[0])
		if err != nil {
			return fmt.Errorf("generate profile ID: %w", err)
		}
		profile.Scope = types.ProfileScope(strings.ToLower(strings.TrimSpace(*scope)))
		if profile.Scope != types.ProfileScopeUser && profile.Scope != types.ProfileScopeMachine {
			return errors.New("--scope must be user or machine")
		}
		profile.ServerURL = positionals[1]
		profile.Provider = types.Provider(*provider)
		if *authMethod != "" {
			profile.AuthMethod = types.AuthMethod(*authMethod)
		} else if profile.Provider == types.ProviderATrust {
			profile.AuthMethod = types.AuthECNUPasskey
		}
		profile.LoginDomain = *loginDomain
		if *compatibilityFile != "" {
			settings, err := readATrustCompatibility(*compatibilityFile)
			if err != nil {
				return err
			}
			profile.ATrustCompatibility = *settings
		}
		if len(positionals) > 2 {
			profile.Username = positionals[2]
		}
		password, _, err := readSecretInput(*passwordFile, *passwordStdin, cliIn)
		if err != nil {
			return err
		}
		var credential []byte
		if *keystore != "" {
			if password != "" {
				return errors.New("--keystore cannot be combined with a password")
			}
			credential, err = readKeystore(*keystore)
			if err != nil {
				return err
			}
		}
		debugf("profile add name=%q username=%q", profile.Name, profile.Username)
		created, err := client.CreateProfileWithCredential(ctx, profile, password, credential)
		if err != nil {
			return err
		}
		if len(credential) != 0 {
			_, _ = fmt.Fprintln(cliErr, "Credential imported. Do not use the source keystore concurrently with FlexConnect; it was not deleted.")
		}
		debugf("profile add created id=%q", created.ID)
		return printJSON(created)
	case "current":
		debugf("profile current")
		profile, err := client.CurrentProfile(ctx)
		if err != nil {
			return err
		}
		debugf("profile current id=%q name=%q", profile.ID, profile.Name)
		return printJSON(profile)
	case "update":
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("profile update")
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: profile update -p <profile-name> [--provider anyconnect|atrust] [--auth-method password|ecnu_passkey|shanghaitech_passkey] [--atrust-compatibility-file <json>] [--password-file <path> | --password-stdin | --keystore <path>] [--login-domain name] [--include a,b] [--exclude c,d]")
		}
		fs := flag.NewFlagSet("profile update", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		profileName := fs.String("p", "", "profile name to update")
		name := fs.String("name", "", "new profile name")
		serverURL := fs.String("server", "", "new server URL")
		user := fs.String("user", "", "new username")
		group := fs.String("group", "", "new VPN group")
		provider := fs.String("provider", "", "new VPN provider")
		authMethod := fs.String("auth-method", "", "new authentication method")
		loginDomain := fs.String("login-domain", "", "new aTrust login domain")
		keystore := fs.String("keystore", "", "import replacement passkey keystore")
		compatibilityFile := fs.String("atrust-compatibility-file", "", "replace aTrust compatibility settings from JSON; {} disables all")
		unsafePassword := fs.String("password", "", "unsupported plaintext password")
		passwordFile := fs.String("password-file", "", "read new password from a file")
		passwordStdin := fs.Bool("password-stdin", false, "read new password from standard input")
		dns := fs.String("dns", "", "comma-separated DNS overrides")
		mtu := fs.String("mtu", "", "MTU override")
		accept := fs.String("accept", "", "accept server routes (true|false)")
		autoReconnect := fs.String("auto-reconnect", "", "reconnect automatically after unexpected disconnect (true|false)")
		applyDNS := fs.String("apply-dns", "", "apply DNS overrides to system DNS configuration (true|false)")
		fs.StringVar(autoReconnect, "auto_reconnect", "", "reconnect automatically after unexpected disconnect (true|false)")
		fs.StringVar(applyDNS, "apply_dns", "", "apply DNS overrides to system DNS configuration (true|false)")
		include := fs.String("include", "", "comma-separated custom include routes")
		exclude := fs.String("exclude", "", "comma-separated custom exclude routes")
		socks5 := fs.String("socks5", "", "enable SOCKS5 proxy (true|false)")
		socks5Listen := fs.String("socks5-listen", "", "SOCKS5 listen address")
		fs.StringVar(socks5Listen, "socks5_listen", "", "SOCKS5 listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(fs.Args()) != 0 {
			return fmt.Errorf("usage: profile update -p <profile-name> [--provider anyconnect|atrust] [--auth-method password|ecnu_passkey|shanghaitech_passkey] [--atrust-compatibility-file <json>] [--password-file <path> | --password-stdin | --keystore <path>] [--login-domain name] [--include a,b] [--exclude c,d]")
		}
		if *unsafePassword != "" {
			return errors.New("--password is not supported; use --password-file or --password-stdin")
		}
		targetID := ""
		if *profileName != "" {
			id, err := findProfileIDByName(ctx, client, *profileName)
			if err != nil {
				return err
			}
			targetID = id
		} else {
			current, err := client.CurrentProfile(ctx)
			if err != nil {
				return fmt.Errorf("no profile selected; run `flexconnect login` first or provide -p <profile-name>")
			}
			targetID = current.ID
		}
		req := types.ProfileUpdateRequest{}
		if *compatibilityFile != "" {
			settings, err := readATrustCompatibility(*compatibilityFile)
			if err != nil {
				return err
			}
			req.ATrustCompatibility = settings
		}
		if *name != "" {
			req.Name = name
		}
		if *serverURL != "" {
			req.ServerURL = serverURL
		}
		if *user != "" {
			req.Username = user
		}
		if *group != "" {
			req.Group = group
		}
		if *provider != "" {
			value := types.Provider(*provider)
			req.Provider = &value
		}
		if *authMethod != "" {
			value := types.AuthMethod(*authMethod)
			req.AuthMethod = &value
		}
		if *loginDomain != "" {
			req.LoginDomain = loginDomain
		}
		password, passwordProvided, err := readSecretInput(*passwordFile, *passwordStdin, cliIn)
		if err != nil {
			return err
		}
		if passwordProvided {
			req.Password = &password
		}
		if *keystore != "" {
			if passwordProvided {
				return errors.New("--keystore cannot be combined with a password")
			}
			req.Credential, err = readKeystore(*keystore)
			if err != nil {
				return err
			}
		}
		if *dns != "" {
			req.DNSOverrides = splitCSV(*dns)
		}
		if *mtu != "" {
			parsedMTU, err := strconv.Atoi(*mtu)
			if err != nil {
				return fmt.Errorf("invalid --mtu value: %w", err)
			}
			req.MTU = &parsedMTU
		}
		if *accept != "" {
			v, err := strconv.ParseBool(*accept)
			if err != nil {
				return fmt.Errorf("invalid --accept value: %w", err)
			}
			req.AcceptServerRoutes = &v
		}
		if *autoReconnect != "" {
			v, err := strconv.ParseBool(*autoReconnect)
			if err != nil {
				return fmt.Errorf("invalid --auto-reconnect value: %w", err)
			}
			req.AutoReconnect = &v
		}
		if *applyDNS != "" {
			v, err := strconv.ParseBool(*applyDNS)
			if err != nil {
				return fmt.Errorf("invalid --apply-dns value: %w", err)
			}
			req.ApplyDNS = &v
		}
		if *include != "" {
			req.CustomInclude = splitCSV(*include)
		}
		if *exclude != "" {
			req.CustomExclude = splitCSV(*exclude)
		}
		if *socks5 != "" {
			v, err := strconv.ParseBool(*socks5)
			if err != nil {
				return fmt.Errorf("invalid --socks5 value: %w", err)
			}
			req.SOCKS5Enabled = &v
		}
		if *socks5Listen != "" {
			req.SOCKS5Listen = socks5Listen
		}
		result, err := client.UpdateProfile(ctx, targetID, req)
		if err != nil {
			return err
		}
		if len(req.Credential) != 0 {
			_, _ = fmt.Fprintln(cliErr, "Credential imported. Do not use the source keystore concurrently with FlexConnect; it was not deleted.")
		}
		return printProfileMutation(result)
	case "switch":
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("profile switch")
		}
		if err := client.SwitchProfile(ctx, mustArg(args, 1, "profile id")); err != nil {
			return err
		}
		debugf("profile switch success id=%q", args[1])
		return nil
	case "remove":
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("profile remove")
		}
		if err := client.DeleteProfile(ctx, mustArg(args, 1, "profile id")); err != nil {
			return err
		}
		debugf("profile remove success id=%q", args[1])
		return nil
	default:
		return fmt.Errorf("unknown profile command: %s", args[0])
	}
}

func runRoutes(ctx context.Context, client *local.Client, args []string) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printNamedHelp("route")
	}
	debugf("runRoute subcommand=%q", args[0])
	switch args[0] {
	case "show":
		debugf("route show")
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		debugf("route show effective=%d", len(status.EffectiveRoutes))
		return printJSON(status.EffectiveRoutes)
	case "set":
		debugf("route set")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("route set")
		}
		fs := flag.NewFlagSet("route set", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		profileName := fs.String("p", "", "profile name to update")
		acceptRaw := ""
		acceptSet := false
		includeRaw := ""
		includeSet := false
		excludeRaw := ""
		excludeSet := false
		fs.Var(&stringFlag{value: &acceptRaw, set: &acceptSet}, "accept", "accept server routes (true|false)")
		fs.Var(&stringFlag{value: &includeRaw, set: &includeSet}, "include", "comma-separated include routes")
		fs.Var(&stringFlag{value: &excludeRaw, set: &excludeSet}, "exclude", "comma-separated exclude routes")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(fs.Args()) != 0 {
			return fmt.Errorf("usage: route set [-p <profile-name>] [--accept true|false] [--include a,b] [--exclude c,d]")
		}
		if !acceptSet && !includeSet && !excludeSet {
			return fmt.Errorf("usage: route set [-p <profile-name>] [--accept true|false] [--include a,b] [--exclude c,d]")
		}
		targetID := *profileName
		if targetID == "" {
			current, err := client.CurrentProfile(ctx)
			if err != nil {
				return err
			}
			targetID = current.ID
		} else {
			id, err := findProfileIDByName(ctx, client, *profileName)
			if err != nil {
				return err
			}
			targetID = id
		}
		req := types.RouteUpdateRequest{}
		if acceptSet {
			v, err := strconv.ParseBool(acceptRaw)
			if err != nil {
				return fmt.Errorf("invalid --accept value: %w", err)
			}
			req.AcceptServerRoutes = &v
		}
		if includeSet {
			req.CustomInclude = splitCSV(includeRaw)
		}
		if excludeSet {
			req.CustomExclude = splitCSV(excludeRaw)
		}
		if includeSet && req.CustomInclude == nil && includeRaw == "" {
			req.CustomInclude = []string{}
		}
		if excludeSet && req.CustomExclude == nil && excludeRaw == "" {
			req.CustomExclude = []string{}
		}
		profile, err := client.UpdateRoutes(ctx, targetID, req)
		if err != nil {
			return err
		}
		debugf("route set updated profile=%q", targetID)
		return printJSON(profile)
	default:
		return fmt.Errorf("unknown route command: %s", args[0])
	}
}

func runProxy(ctx context.Context, client *local.Client, args []string) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printNamedHelp("proxy")
	}
	debugf("runProxy subcommand=%q", args[0])
	switch args[0] {
	case "status":
		debugf("proxy status")
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if status.SOCKS5Enabled {
			_, err = fmt.Fprintf(cliOut, "SOCKS5: enabled on %s\n", status.SOCKS5Listen)
			return err
		}
		_, err = fmt.Fprintln(cliOut, "SOCKS5: disabled")
		return err
	case "enable":
		debugf("proxy enable")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("proxy enable")
		}
		current, err := client.CurrentProfile(ctx)
		if err != nil {
			return err
		}
		req := types.ProfileUpdateRequest{}
		enabled := true
		req.SOCKS5Enabled = &enabled
		if len(args) > 1 {
			listen := args[1]
			req.SOCKS5Listen = &listen
		}
		result, err := client.UpdateProfile(ctx, current.ID, req)
		if err != nil {
			return err
		}
		debugf("proxy enable profile=%q", current.ID)
		return printProfileMutation(result)
	case "disable":
		debugf("proxy disable")
		if wantCommandHelp(args[1:]) {
			return printNamedHelp("proxy disable")
		}
		current, err := client.CurrentProfile(ctx)
		if err != nil {
			return err
		}
		enabled := false
		result, err := client.UpdateProfile(ctx, current.ID, types.ProfileUpdateRequest{SOCKS5Enabled: &enabled})
		if err != nil {
			return err
		}
		debugf("proxy disabled profile=%q", current.ID)
		return printProfileMutation(result)
	default:
		return fmt.Errorf("unknown proxy command: %s", args[0])
	}
}

func printProfileMutation(result types.ProfileMutationResult) error {
	if result.Profile != nil {
		return printJSON(result.Profile)
	}
	if result.Operation != nil {
		return printJSON(types.OperationRef{Operation: *result.Operation})
	}
	return errors.New("local API returned an empty profile mutation result")
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

type stringFlag struct {
	value *string
	set   *bool
}

func (f *stringFlag) Set(v string) error {
	*f.value = v
	if f.set != nil {
		*f.set = true
	}
	return nil
}

func (f *stringFlag) String() string {
	if f.value == nil {
		return ""
	}
	return *f.value
}

func hasJSONFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--json" || arg == "-json" {
			return true
		}
	}
	return false
}

func mustArg(args []string, index int, label string) string {
	if len(args) <= index {
		fmt.Fprintf(cliErr, "missing %s\n", label)
		os.Exit(2)
	}
	return args[index]
}

func printJSON(v any) error {
	enc := json.NewEncoder(cliOut)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printCurrentStatus(ctx context.Context, client *local.Client) error {
	status, err := client.Status(ctx)
	if err != nil {
		return err
	}
	profiles, _ := client.Profiles(ctx)
	_, err = io.WriteString(cliOut, formatStatusWithProfiles(status, profiles))
	return err
}

func formatStatus(status *types.Status) string {
	return formatStatusWithProfiles(status, nil)
}

func formatStatusWithProfiles(status *types.Status, profiles []types.Profile) string {
	if status == nil {
		return "No status available.\n"
	}
	profileName := func(id string) string {
		for _, profile := range profiles {
			if profile.ID == id {
				if profile.Name != "" {
					return profile.Name
				}
				return profile.ServerURL
			}
		}
		return id
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "State: %s\n", status.State)
	if status.SelectedProfileID != "" {
		fmt.Fprintf(&buf, "Selected Profile: %s\n", profileName(status.SelectedProfileID))
	}
	if status.ConnectedProfileID != "" {
		fmt.Fprintf(&buf, "Connected Profile: %s\n", profileName(status.ConnectedProfileID))
	}
	if status.Session != nil {
		fmt.Fprintf(&buf, "Server: %s\n", status.Session.ServerAddress)
		fmt.Fprintf(&buf, "VPN IP: %s\n", status.Session.VPNAddress)
		fmt.Fprintf(&buf, "Tunnel: %s (%s/%s)\n", status.Session.TUNName, status.Session.VPNAddress, status.Session.VPNMask)
		if len(status.Session.DNS) > 0 {
			fmt.Fprintf(&buf, "DNS: %s\n", strings.Join(status.Session.DNS, ", "))
		}
		if len(status.EffectiveRoutes) > 0 {
			fmt.Fprintf(&buf, "Routes: %d effective entries\n", len(status.EffectiveRoutes))
		}
	}
	if status.SOCKS5Enabled {
		fmt.Fprintf(&buf, "SOCKS5: %s\n", status.SOCKS5Listen)
	}
	if status.LastError != "" {
		fmt.Fprintf(&buf, "Last Error: %s\n", status.LastError)
	}
	if status.State == types.StateDisconnected && status.SelectedProfileID == "" {
		buf.WriteString("Next Step: run `flexconnect login` to add a connection.\n")
	} else if status.State == types.StateError {
		buf.WriteString("Next Step: run `flexconnect up` to retry or `flexconnect diag diag.json` for diagnostics.\n")
	}
	if status.UpdatedAt != "" {
		fmt.Fprintf(&buf, "Updated: %s\n", status.UpdatedAt)
	}
	return buf.String()
}

func formatTrafficSnapshot(traffic types.TrafficSnapshot) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Connected: %t\n", traffic.Connected)
	fmt.Fprintf(&buf, "Traffic Sent: %d B\n", traffic.BytesSent)
	fmt.Fprintf(&buf, "Traffic Received: %d B\n", traffic.BytesReceived)
	fmt.Fprintf(&buf, "Speed Sent: %.0f B/s\n", traffic.BytesSentPerSecond)
	fmt.Fprintf(&buf, "Speed Received: %.0f B/s\n", traffic.BytesReceivedPerSecond)
	if traffic.SampledAt != "" {
		fmt.Fprintf(&buf, "Sampled: %s\n", traffic.SampledAt)
	}
	return buf.String()
}

func formatNetcheckResult(result netcheck.Result) string {
	var buf bytes.Buffer
	status := result.Status
	if status == "" {
		status = "unknown"
	}
	fmt.Fprintf(&buf, "Netcheck: %s\n", status)
	fmt.Fprintf(&buf, "Mode: %s (user-space stack, no OS TUN)\n", result.Mode)
	fmt.Fprintf(&buf, "Endpoint: %s\n", result.Endpoint)
	fmt.Fprintf(&buf, "Underlay: %s local=%s gateway=%s\n", result.LocalInterface, result.LocalIPv4, result.Gateway)
	if result.RequestedLocalIP != "" {
		fmt.Fprintf(&buf, "Requested Source IP: %s\n", result.RequestedLocalIP)
	}
	fmt.Fprintf(&buf, "Auth Socket: %s -> %s\n", result.AuthLocalAddress, result.AuthRemoteAddress)
	fmt.Fprintf(&buf, "CSTP: %s vpn_ip=%s mtu=%d\n", result.CSTPStatus, result.VPNAddress, result.MTU)
	fmt.Fprintf(&buf, "TLS: dpd=%s keepalive=%s transport=%s\n", result.TLSDPD, result.TLSKeepalive, result.Transport)
	if result.DTLSEnabled {
		fmt.Fprintf(&buf, "DTLS: enabled port=%s peer=%s\n", result.DTLSPort, result.DTLSPeer)
	} else {
		buf.WriteString("DTLS: disabled or unavailable\n")
	}
	fmt.Fprintf(&buf, "Observation: %s dpd_sent=%d tls_frames=%d dtls_frames=%d\n",
		result.ObservationDuration.Round(time.Millisecond), result.DPDSent, result.TLSFrames, result.DTLSFrames)
	if result.Speedtest == nil {
		buf.WriteString("Speedtest: skipped\n")
	} else {
		test := result.Speedtest
		fmt.Fprintf(&buf, "Speedtest: target=%s transport=%s\n", test.TargetHost, test.Transport)
		fmt.Fprintf(&buf, "  Result: %d bytes in %s (%.2f MiB/s)\n", test.Bytes, test.Duration.Round(time.Millisecond), test.MiBPS)
		fmt.Fprintf(&buf, "  Frames: outbound=%d B/%d packets inbound=%d B/%d packets\n",
			test.OutboundFrameBytes, test.OutboundPackets, test.InboundFrameBytes, test.InboundPackets)
	}
	return buf.String()
}

func formatUpdateInfo(info *types.UpdateInfo) string {
	if info == nil {
		return "No update information available.\n"
	}
	var buf bytes.Buffer
	if info.Disabled {
		fmt.Fprintf(&buf, "Current: %s\n", info.CurrentVersion)
		buf.WriteString("Update checks are disabled (no update repository configured).\n")
		return buf.String()
	}
	if info.Error != "" {
		fmt.Fprintf(&buf, "Current: %s\n", info.CurrentVersion)
		fmt.Fprintf(&buf, "Update check failed: %s\n", info.Error)
		return buf.String()
	}
	fmt.Fprintf(&buf, "Current: %s\n", info.CurrentVersion)
	fmt.Fprintf(&buf, "Latest: %s\n", info.LatestVersion)
	if info.UpdateAvailable {
		buf.WriteString("Update available: yes\n")
	} else {
		buf.WriteString("Update available: no\n")
	}
	if info.ReleaseURL != "" {
		fmt.Fprintf(&buf, "Release: %s\n", info.ReleaseURL)
	}
	return buf.String()
}

func usage() {
	_, _ = io.WriteString(cliOut, rootHelp())
}

func isHelpArg(arg string) bool {
	return arg == "help" || arg == "--help" || arg == "-h"
}

func wantCommandHelp(args []string) bool {
	return len(args) > 0 && isHelpArg(args[0])
}

func printHelpTopic(path []string) error {
	if len(path) == 0 {
		_, err := io.WriteString(cliOut, rootHelp())
		return err
	}
	return printNamedHelp(strings.Join(path, " "))
}

func printNamedHelp(name string) error {
	topic, ok := lookupHelpTopic(name)
	if !ok {
		return fmt.Errorf("unknown help topic: %s", name)
	}
	_, err := io.WriteString(cliOut, renderHelpTopic(topic))
	return err
}

func rootHelp() string {
	return renderHelpTopic(rootHelpTopic())
}

func debugf(format string, args ...any) {
	if !verbose {
		return
	}
	logging.WithComponent("flexconnect").Debugf(format, args...)
}

func condLevel(verbose bool) logging.Level {
	if verbose {
		return logging.LevelDebug
	}
	return logging.LevelInfo
}

func renderHelpTopic(topic helpTopic) string {
	var buf bytes.Buffer
	if topic.Usage != "" {
		fmt.Fprintf(&buf, "USAGE\n  %s\n", topic.Usage)
	}
	if topic.Description != "" {
		fmt.Fprintf(&buf, "\n%s\n", topic.Description)
	}
	if len(topic.Subcommands) > 0 {
		buf.WriteString("\nSUBCOMMANDS\n")
		width := 0
		for _, sub := range topic.Subcommands {
			if len(sub.Name) > width {
				width = len(sub.Name)
			}
		}
		for _, sub := range topic.Subcommands {
			fmt.Fprintf(&buf, "  %-*s  %s\n", width, sub.Name, sub.Summary)
		}
	}
	if len(topic.Examples) > 0 {
		buf.WriteString("\nEXAMPLES\n")
		for _, ex := range topic.Examples {
			fmt.Fprintf(&buf, "  %s\n", ex)
		}
	}
	buf.WriteString("\nGLOBAL FLAGS\n")
	buf.WriteString("  --socket <path>               path to daemon socket or named pipe\n")
	buf.WriteString("  --timeout <duration>          connectivity and ordinary command timeout (default 15s)\n")
	buf.WriteString("  --connect-timeout <duration>  login and VPN connection timeout (default 2m)\n")
	buf.WriteString("  -v, --verbose                 enable verbose debug output\n")
	buf.WriteString("  --version                     print version and exit\n")
	if topic.Name == "flexconnect" {
		buf.WriteString("\nFor command-specific help, run `flexconnect help <command>` or add `--help` after a command.\n")
	}
	return buf.String()
}

func rootHelpTopic() helpTopic {
	return helpTopic{
		Name:    "flexconnect",
		Summary: "CLI for the FlexConnect daemon",
		Usage:   "flexconnect [--socket <path>] [--timeout <duration>] [--connect-timeout <duration>] [-v|--verbose] <command> [command flags]",
		Description: "FlexConnect controls the local FlexConnect daemon, manages VPN profiles,\n" +
			"starts AnyConnect or aTrust sessions, and exposes local tools like diagnostics and VPN-only SOCKS5 proxying.",
		Subcommands: []helpTopic{
			{Name: "status", Summary: "Show current daemon and VPN status"},
			{Name: "login", Summary: "Create a profile and log in"},
			{Name: "up", Summary: "Connect the current or named profile"},
			{Name: "down", Summary: "Disconnect the current VPN session"},
			{Name: "profile", Summary: "List, edit, and switch profiles"},
			{Name: "route", Summary: "Show or update per-profile route rules"},
			{Name: "proxy", Summary: "Control the built-in local SOCKS5 proxy"},
			{Name: "control-mode", Summary: "Enter or exit administrator-owned machine mode"},
			{Name: "logs", Summary: "Show recent daemon logs"},
			{Name: "diag", Summary: "Export diagnostics as JSON"},
			{Name: "traffic", Summary: "Show traffic totals and speeds"},
			{Name: "netcheck", Summary: "Connect, inspect the underlay, and measure VPN traffic"},
			{Name: "watch", Summary: "Stream daemon events as NDJSON"},
			{Name: "update", Summary: "Check for a new FlexConnect release"},
		},
		Examples: []string{
			"flexconnect status",
			"flexconnect login",
			"flexconnect login --server https://vpn.example.com --user alice --password-file ./secrets/flexconnect_password --name corp",
			"flexconnect up",
			"flexconnect up -p corp",
			"flexconnect down",
			"flexconnect traffic",
			"flexconnect netcheck --env-file .env",
			"flexconnect profile update -p corp --user alice --server vpn.example.com --password-file ./secrets/flexconnect_password --auto-reconnect true --apply-dns true --socks5-listen 127.0.0.1:1080",
			"flexconnect proxy enable 127.0.0.1:1080",
			"flexconnect control-mode user",
		},
	}
}

func lookupHelpTopic(name string) (helpTopic, bool) {
	topics := map[string]helpTopic{
		"status": {
			Name:        "status",
			Usage:       "flexconnect status [--json]",
			Description: "Show the current daemon state, active profile, session details, routes, and local SOCKS5 proxy status.",
			Examples:    []string{"flexconnect status", "flexconnect status --json"},
		},
		"login": {
			Name:        "login",
			Usage:       "flexconnect login [--server <url> --user <username> (--password-file <path> | --password-stdin) --name <profile-name> --group <group>]",
			Description: "Create or update a profile, log in, and keep it as the last used profile. With no flags, prompts interactively: the server URL is connection-tested to list the available user groups, then group, username, and password are verified against the server (password input echoes '*') before the profile is saved.",
			Examples: []string{
				"flexconnect login",
				"flexconnect login --server https://vpn.example.com --user alice --password-file ./secrets/flexconnect_password --name corp",
			},
		},
		"up": {
			Name:        "up",
			Usage:       "flexconnect up [-p <profile-name>]",
			Description: "Connect the last used profile, or the named profile when -p is provided.",
			Examples:    []string{"flexconnect up", "flexconnect up -p corp"},
		},
		"down": {
			Name:        "down",
			Usage:       "flexconnect down",
			Description: "Disconnect the active VPN session and stop any per-profile local proxy.",
			Examples:    []string{"flexconnect down"},
		},
		"logs": {
			Name:        "logs",
			Usage:       "flexconnect logs",
			Description: "Print recent daemon logs as JSON.",
		},
		"diag": {
			Name:        "diag",
			Usage:       "flexconnect diag [file]",
			Description: "Print diagnostics as JSON or write them to a file.",
			Examples:    []string{"flexconnect diag", "flexconnect diag diag.json"},
		},
		"traffic": {
			Name:        "traffic",
			Usage:       "flexconnect traffic [--json]",
			Description: "Show VPN traffic totals and sampled upload/download speeds.",
			Examples:    []string{"flexconnect traffic", "flexconnect traffic --json"},
		},
		"netcheck": {
			Name:        "netcheck",
			Usage:       "flexconnect netcheck [--env-file <path>] [--speedtest-url <url>] [--json]",
			Description: "Run a connection-level CSTP/DTLS probe without an OS TUN, keep it under observation, and download a bounded payload through the user-space VPN stack.",
			Examples: []string{
				"flexconnect netcheck --env-file .env",
				"flexconnect netcheck --env-file .env --speedtest-url https://speed.example/download?bytes=4194304",
				"flexconnect netcheck --env-file .env --no-speedtest --json",
			},
		},
		"watch": {
			Name:        "watch",
			Usage:       "flexconnect watch",
			Description: "Stream daemon notifications as newline-delimited JSON.",
		},
		"update": {
			Name:        "update",
			Usage:       "flexconnect update [--json]",
			Description: "Check GitHub Releases for a newer FlexConnect version and report whether an update is available. This only checks and reports; it never downloads or installs anything.",
			Examples:    []string{"flexconnect update", "flexconnect update --json"},
		},
		"profile": {
			Name:        "profile",
			Usage:       "flexconnect profile <subcommand>",
			Description: "Manage stored VPN profiles.",
			Subcommands: []helpTopic{
				{Name: "list", Summary: "List all profiles"},
				{Name: "current", Summary: "Show the current profile"},
				{Name: "add", Summary: "Create a profile"},
				{Name: "update", Summary: "Update profile fields"},
				{Name: "switch", Summary: "Switch current profile"},
				{Name: "remove", Summary: "Delete a profile"},
			},
			Examples: []string{
				"flexconnect profile list",
				"flexconnect profile add --password-file ./secrets/flexconnect_password corp https://vpn.example.com alice",
				"flexconnect profile update -p corp --socks5 true --socks5-listen 127.0.0.1:1080",
			},
		},
		"profile add": {
			Name:        "profile add",
			Usage:       "flexconnect profile add [--provider anyconnect|atrust] [--auth-method password|ecnu_passkey|shanghaitech_passkey] [--atrust-compatibility-file <json>] [--password-file <path> | --password-stdin | --keystore <path>] <name> <server_url> [username]",
			Description: "Create a user profile by default. Elevated administrators may create machine profiles with --scope machine.",
		},
		"profile switch": {
			Name:        "profile switch",
			Usage:       "flexconnect profile switch <profile-id>",
			Description: "Switch the daemon's current profile. If another profile is connected, it reconnects using the new profile.",
		},
		"profile remove": {
			Name:        "profile remove",
			Usage:       "flexconnect profile remove <profile-id>",
			Description: "Delete a profile and its stored secret reference.",
		},
		"profile update": {
			Name:  "profile update",
			Usage: "flexconnect profile update -p <profile-name> [--provider anyconnect|atrust] [--auth-method password|ecnu_passkey|shanghaitech_passkey] [--atrust-compatibility-file <json>] [--password-file <path> | --password-stdin | --keystore <path>] [--login-domain name] [--include a,b] [--exclude c,d]",
			Description: "Update profile fields in place. Runtime-relevant changes reconnect an active profile automatically.\n" +
				"Use `socks5=true` to enable the built-in VPN-only SOCKS5 proxy for that profile.",
		},
		"route": {
			Name:        "route",
			Usage:       "flexconnect route <subcommand>",
			Description: "Inspect or change per-profile route behavior.",
			Subcommands: []helpTopic{
				{Name: "show", Summary: "Show effective routes from current status"},
				{Name: "set", Summary: "Update include/exclude route rules"},
			},
			Examples: []string{
				"flexconnect route show",
				"flexconnect route set --accept true --include 10.0.0.0/8 --exclude 1.1.1.1/32",
				"flexconnect route set -p corp --accept false --include 10.0.0.0/8 --exclude 1.1.1.1/32",
			},
		},
		"route set": {
			Name:        "route set",
			Usage:       "flexconnect route set [-p <profile-name>] [--accept true|false] [--include a,b] [--exclude c,d]",
			Description: "Update route preferences for a profile. If that profile is connected, FlexConnect reapplies the connection.",
		},
		"proxy": {
			Name:        "proxy",
			Usage:       "flexconnect proxy <subcommand>",
			Description: "Control the built-in local SOCKS5 proxy. Proxy TCP connections and DNS resolution go through the connected VPN session only; FlexConnect does not fall back to the local network.",
			Subcommands: []helpTopic{
				{Name: "status", Summary: "Show current SOCKS5 status"},
				{Name: "enable", Summary: "Enable SOCKS5 for current profile"},
				{Name: "disable", Summary: "Disable SOCKS5 for current profile"},
			},
			Examples: []string{
				"flexconnect proxy status",
				"flexconnect proxy enable 127.0.0.1:1080",
				"flexconnect proxy disable",
			},
		},
		"proxy enable": {
			Name:        "proxy enable",
			Usage:       "flexconnect proxy enable [listen-address]",
			Description: "Enable the built-in VPN-only SOCKS5 proxy on the current profile. The listener starts automatically when that profile connects and fails closed if VPN tunnel dialing is unavailable.",
		},
		"proxy disable": {
			Name:        "proxy disable",
			Usage:       "flexconnect proxy disable",
			Description: "Disable the built-in SOCKS5 proxy on the current profile.",
		},
		"control-mode": {
			Name:        "control-mode",
			Usage:       "flexconnect control-mode user | flexconnect control-mode machine [-p <profile-name>] [profile-id]",
			Description: "Elevated administrators enter unattended machine mode with a machine profile or explicitly exit it. Machine mode remains locked after connection failure until this command exits it.",
			Examples: []string{
				"flexconnect profile add --scope machine --password-file ./secrets/flexconnect_password unattended https://vpn.example.com machine-user",
				"flexconnect control-mode machine -p unattended",
				"flexconnect control-mode user",
			},
		},
	}
	topic, ok := topics[name]
	return topic, ok
}
