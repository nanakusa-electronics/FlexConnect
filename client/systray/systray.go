package systray

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	systraylib "fyne.io/systray"
	"github.com/gen2brain/beeep"

	"flexconnect/client/local"
	"flexconnect/internal/logging"
	"flexconnect/internal/types"
)

var systrayLog = logging.WithComponent("flexconnect-systray")

// timeNow is overridable in tests for deterministic time-based behavior.
var timeNow = time.Now

// jitterFraction returns a float in [0,1); overridable in tests to make
// retryDelay deterministic.
var jitterFraction = func() float64 { return rand.Float64() }

const (
	// Backoff tuning for watch reconnects.
	backoffBase = 1 * time.Second
	backoffMax  = 30 * time.Second
	// notified dedup table: keep recent lifecycle notifications and reclaim memory.
	notifiedTTL = 5 * time.Minute
	notifiedMax = 64
	// opTimeout bounds individual tray-initiated daemon operations.
	opTimeout = 15 * time.Second
	// rebuildDebounce coalesces bursts of state changes into one menu rebuild.
	rebuildDebounce = 60 * time.Millisecond
)

// daemonClient is the subset of *local.Client methods used by the tray. It is
// an interface so tests can inject a fake client without depending on a live
// daemon socket.
type daemonClient interface {
	Status(context.Context) (*types.Status, error)
	Profiles(context.Context) ([]types.Profile, error)
	Traffic(context.Context) (*types.TrafficSnapshot, error)
	UpdateCheck(context.Context) (*types.UpdateInfo, error)
	Disconnect(context.Context) error
	SwitchProfile(context.Context, string) error
	Connect(context.Context, string) error
	ConnectCurrent(context.Context) error
	UpdateProfile(context.Context, string, types.ProfileUpdateRequest) (types.ProfileMutationResult, error)
	DiagnosticsText(context.Context) (string, error)
	Watch(context.Context) (*local.Watcher, error)
}

type notificationSender interface {
	Send(title, body string) error
	Alert(title, body string) error
}

type beeepNotificationSender struct{}

func (beeepNotificationSender) Send(title, body string) error {
	return beeep.Notify(title, body, "")
}

func (beeepNotificationSender) Alert(title, body string) error {
	return beeep.Alert(title, body, "")
}

type toggleAction int

const (
	toggleNone toggleAction = iota
	toggleConnect
	toggleDisconnect
)

type toggleState struct {
	Title   string
	Enabled bool
	Action  toggleAction
}

type Menu struct {
	Client daemonClient

	rebuildMu              sync.Mutex
	mu                     sync.Mutex
	status                 *types.Status
	traffic                types.TrafficSnapshot
	profiles               []types.Profile
	updateInfo             *types.UpdateInfo
	updateNotified         bool
	rebuildCh              chan struct{}
	runCtx                 context.Context
	runCancel              context.CancelFunc
	menuCancel             context.CancelFunc
	notifier               notificationSender
	notified               map[string]time.Time
	authenticationNotified string
	errorSeen              map[string]time.Time
	render                 func(context.Context, menuModel)
}

func (m *Menu) Run() {
	if m.Client == nil {
		m.Client = &local.Client{}
	}
	systraylib.SetTitle("FlexConnect")
	systraylib.Run(m.onReady, m.onExit)
}

func (m *Menu) onReady() {
	setTrayIconColor(trayIconBlue)
	setTooltip("FlexConnect")
	m.init()
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.runCtx = ctx
	m.runCancel = cancel
	m.mu.Unlock()
	m.refresh(ctx)
	m.rebuild()
	go m.rebuildLoop(ctx)
	go m.openLoop(ctx)
	go m.watch(ctx)
	go m.updateCheckLoop(ctx)
}

func (m *Menu) onExit() {
	m.mu.Lock()
	if m.runCancel != nil {
		m.runCancel()
	}
	if m.menuCancel != nil {
		m.menuCancel()
	}
	m.mu.Unlock()
}

func (m *Menu) init() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rebuildCh == nil {
		m.rebuildCh = make(chan struct{}, 1)
	}
	if m.notifier == nil {
		m.notifier = beeepNotificationSender{}
	}
	if m.notified == nil {
		m.notified = map[string]time.Time{}
	}
	if m.errorSeen == nil {
		m.errorSeen = map[string]time.Time{}
	}
	if m.render == nil {
		m.render = m.renderMenu
	}
}

// reportError records every tray error and presents a bounded, deduplicated
// alert. Reconnect/watch loops can encounter the same IPC error repeatedly;
// suppressing only identical errors for a short interval keeps the desktop
// usable while retaining the full error in the component log.
func (m *Menu) reportError(operation string, err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	m.init()
	message := strings.Join(strings.Fields(err.Error()), " ")
	if len(message) > 320 {
		message = message[:320] + "..."
	}
	key := operation + ":" + message
	now := timeNow()
	const errTTL = 30 * time.Second
	m.mu.Lock()
	last, seen := m.errorSeen[key]
	if seen && now.Sub(last) < errTTL {
		m.mu.Unlock()
		return
	}
	m.errorSeen[key] = now
	// Proactively sweep expired entries on every report so the table drains
	// shortly after the daemon recovers, not only once it exceeds 64 entries.
	for k, at := range m.errorSeen {
		if now.Sub(at) >= errTTL {
			delete(m.errorSeen, k)
		}
	}
	notifier := m.notifier
	m.mu.Unlock()

	wrapped := fmt.Errorf("%s: %w", operation, err)
	systrayLog.Error(wrapped)
	if notifier != nil {
		if notifyErr := notifier.Alert("FlexConnect tray error", operation+"\n\n"+message); notifyErr != nil {
			systrayLog.Error(fmt.Errorf("desktop error alert failed operation=%s: %w", operation, notifyErr))
		}
	}
}

func (m *Menu) requestRebuild() {
	m.init()
	select {
	case m.rebuildCh <- struct{}{}:
	default:
	}
}

func (m *Menu) refresh(ctx context.Context) {
	var (
		status           *types.Status
		profiles         []types.Profile
		traffic          *types.TrafficSnapshot
		update           *types.UpdateInfo
		sErr, pErr, tErr error
	)
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); status, sErr = m.Client.Status(ctx) }()
	go func() { defer wg.Done(); profiles, pErr = m.Client.Profiles(ctx) }()
	go func() { defer wg.Done(); traffic, tErr = m.Client.Traffic(ctx) }()
	// Update info is best-effort: the daemon caches the result, and a failure
	// here should not surface as a "daemon unavailable" alert.
	go func() { defer wg.Done(); update, _ = m.Client.UpdateCheck(ctx) }()
	wg.Wait()

	m.mu.Lock()
	if status != nil {
		m.status = status
	}
	if profiles != nil {
		m.profiles = profiles
	}
	if traffic != nil {
		m.traffic = *traffic
	}
	if update != nil {
		m.updateInfo = update
	}
	m.mu.Unlock()

	// Report at most one consolidated error per refresh cycle instead of one
	// per failed call, so a daemon outage produces a single desktop alert.
	if sErr != nil || pErr != nil || tErr != nil {
		first := sErr
		if first == nil {
			first = pErr
		}
		if first == nil {
			first = tErr
		}
		m.reportError("daemon unavailable", first)
	}
}

func (m *Menu) rebuild() {
	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()

	m.mu.Lock()
	status := copyStatus(m.status)
	traffic := m.traffic
	profiles := append([]types.Profile(nil), m.profiles...)
	update := m.updateInfo
	if m.menuCancel != nil {
		m.menuCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.menuCancel = cancel
	m.mu.Unlock()

	m.render(ctx, buildMenuModel(status, traffic, profiles, update))
}

func (m *Menu) handleProfileSelection(ctx context.Context, profileID string) {
	m.mu.Lock()
	status := copyStatus(m.status)
	m.mu.Unlock()
	if status != nil && status.SelectedProfileID == profileID {
		return
	}

	if status != nil && status.State == types.StateConnected {
		if err := m.Client.Disconnect(ctx); err != nil {
			m.reportError("disconnect failed", err)
			return
		}
	}

	if err := m.Client.SwitchProfile(ctx, profileID); err != nil {
		m.reportError("switch profile failed", err)
		return
	}
	if status != nil && status.State == types.StateConnected {
		if err := m.Client.Connect(ctx, profileID); err != nil {
			m.reportError("reconnect after profile switch failed", err)
			return
		}
	}
	m.refresh(ctx)
	m.requestRebuild()
}

func statusCurrentID(status *types.Status) string {
	if status == nil {
		return ""
	}
	return status.SelectedProfileID
}

func currentProfileByID(profiles []types.Profile, id string) *types.Profile {
	for _, profile := range profiles {
		if profile.ID == id {
			current := profile
			return &current
		}
	}
	return nil
}

func (m *Menu) handleSocks5Toggle(enabled bool) {
	m.mu.Lock()
	status := copyStatus(m.status)
	m.mu.Unlock()
	req := types.ProfileUpdateRequest{SOCKS5Enabled: &enabled}
	if status == nil || status.SelectedProfileID == "" {
		m.reportError("update SOCKS5 setting failed", fmt.Errorf("no profile selected"))
		return
	}
	ctx, cancel := m.opCtx()
	defer cancel()
	if _, err := m.Client.UpdateProfile(ctx, status.SelectedProfileID, req); err != nil {
		m.reportError("update SOCKS5 setting failed", err)
		return
	}
	m.refresh(ctx)
	m.requestRebuild()
}

func (m *Menu) handleAutoReconnectToggle(enabled bool) {
	m.mu.Lock()
	status := copyStatus(m.status)
	m.mu.Unlock()
	if status == nil || status.SelectedProfileID == "" {
		m.reportError("update auto-reconnect setting failed", fmt.Errorf("no profile selected"))
		return
	}
	req := types.ProfileUpdateRequest{AutoReconnect: &enabled}
	ctx, cancel := m.opCtx()
	defer cancel()
	if _, err := m.Client.UpdateProfile(ctx, status.SelectedProfileID, req); err != nil {
		m.reportError("update auto-reconnect setting failed", err)
		return
	}
	m.refresh(ctx)
	m.requestRebuild()
}

func (m *Menu) handleApplyDNSToggle(enabled bool) {
	m.mu.Lock()
	status := copyStatus(m.status)
	m.mu.Unlock()
	if status == nil || status.SelectedProfileID == "" {
		m.reportError("update DNS setting failed", fmt.Errorf("no profile selected"))
		return
	}
	req := types.ProfileUpdateRequest{ApplyDNS: &enabled}
	ctx, cancel := m.opCtx()
	defer cancel()
	if _, err := m.Client.UpdateProfile(ctx, status.SelectedProfileID, req); err != nil {
		m.reportError("update DNS setting failed", err)
		return
	}
	m.refresh(ctx)
	m.requestRebuild()
}

// opCtx returns a context derived from the tray lifecycle so in-flight
// operations are cancelled on exit instead of outliving the process.
func (m *Menu) opCtx() (context.Context, context.CancelFunc) {
	m.mu.Lock()
	parent := m.runCtx
	m.mu.Unlock()
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, opTimeout)
}

func (m *Menu) handleToggle(action toggleAction) {
	ctx, cancel := m.opCtx()
	defer cancel()
	switch action {
	case toggleConnect:
		if err := m.Client.ConnectCurrent(ctx); err != nil {
			m.reportError("connect failed", err)
		}
	case toggleDisconnect:
		if err := m.Client.Disconnect(ctx); err != nil {
			m.reportError("disconnect failed", err)
		}
	}
	m.refresh(ctx)
	m.requestRebuild()
}

func (m *Menu) copyDiagnostics() {
	ctx, cancel := m.opCtx()
	defer cancel()
	text, err := m.Client.DiagnosticsText(ctx)
	if err != nil {
		m.reportError("read diagnostics failed", err)
		return
	}
	if err := writeClipboard(text); err != nil {
		m.reportError("copy diagnostics failed", err)
	}
}

func (m *Menu) renderMenu(ctx context.Context, model menuModel) {
	systraylib.ResetMenu()
	setTrayIconColor(model.Icon)
	setTooltip(model.Tooltip)
	for _, item := range model.Items {
		m.renderMenuItem(ctx, nil, item)
	}
}

func (m *Menu) renderMenuItem(ctx context.Context, parent *systraylib.MenuItem, item menuItemModel) {
	if item.Separator {
		if parent == nil {
			systraylib.AddSeparator()
		} else {
			parent.AddSeparator()
		}
		return
	}

	menuItem := addMenuItem(parent, item)
	if item.Checked {
		menuItem.Check()
	}
	if item.Disabled {
		menuItem.Disable()
	} else {
		m.bindMenuAction(ctx, menuItem, item)
	}
	for _, child := range item.Children {
		m.renderMenuItem(ctx, menuItem, child)
	}
}

func addMenuItem(parent *systraylib.MenuItem, item menuItemModel) *systraylib.MenuItem {
	if parent == nil {
		if item.Checkbox {
			return systraylib.AddMenuItemCheckbox(item.Title, item.Tooltip, item.Checked)
		}
		return systraylib.AddMenuItem(item.Title, item.Tooltip)
	}
	if item.Checkbox {
		return parent.AddSubMenuItemCheckbox(item.Title, item.Tooltip, item.Checked)
	}
	return parent.AddSubMenuItem(item.Title, item.Tooltip)
}

func (m *Menu) bindMenuAction(ctx context.Context, item *systraylib.MenuItem, model menuItemModel) {
	switch model.Action {
	case menuActionToggle:
		onClick(ctx, item, func(context.Context) { m.handleToggle(model.Toggle) })
	case menuActionProfile:
		onClick(ctx, item, func(ctx context.Context) { m.handleProfileSelection(ctx, model.ProfileID) })
	case menuActionSocks5:
		onClick(ctx, item, func(context.Context) { m.handleSocks5Toggle(model.Value) })
	case menuActionAutoReconnect:
		onClick(ctx, item, func(context.Context) { m.handleAutoReconnectToggle(model.Value) })
	case menuActionApplyDNS:
		onClick(ctx, item, func(context.Context) { m.handleApplyDNSToggle(model.Value) })
	case menuActionCopyDiagnostics:
		onClick(ctx, item, func(context.Context) { m.copyDiagnostics() })
	case menuActionQuit:
		onClick(ctx, item, func(context.Context) { systraylib.Quit() })
	}
}

// updateTrayTooltip sets the tray hover tooltip from current state without
// resetting the menu. Safe to call on every traffic tick.
func (m *Menu) updateTrayTooltip() {
	m.mu.Lock()
	status := copyStatus(m.status)
	traffic := m.traffic
	profiles := append([]types.Profile(nil), m.profiles...)
	m.mu.Unlock()
	setTooltip(tooltipText(status, traffic, profiles))
}

// defaultUpdateCheckInterval is the fallback cadence for polling the daemon's
// update-check endpoint when FLEXCONNECT_UPDATE_INTERVAL is unset.
const defaultUpdateCheckInterval = 6 * time.Hour

// updateCheckInterval resolves the tray's update polling cadence from
// FLEXCONNECT_UPDATE_INTERVAL (a Go duration string). A zero or "disabled"
// value turns the periodic check off.
func updateCheckInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("FLEXCONNECT_UPDATE_INTERVAL"))
	if raw == "" {
		return defaultUpdateCheckInterval
	}
	if strings.EqualFold(raw, "disabled") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// updateCheckLoop periodically asks the daemon for the latest release info and
// surfaces a one-time desktop notification plus a menu row when a newer
// version is available. The daemon performs (and caches) the actual GitHub
// query; the tray only polls the local API.
func (m *Menu) updateCheckLoop(ctx context.Context) {
	interval := updateCheckInterval()
	if interval <= 0 {
		return
	}
	m.init()
	// Check once shortly after startup so a fresh session sees pending
	// updates, then settle into the configured cadence.
	m.fetchUpdateInfo(ctx)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.fetchUpdateInfo(ctx)
			timer.Reset(interval)
		}
	}
}

// fetchUpdateInfo pulls the daemon's cached update-check result, stores it for
// the next menu rebuild, and emits a single desktop notification per newly
// detected release.
func (m *Menu) fetchUpdateInfo(ctx context.Context) {
	update, err := m.Client.UpdateCheck(ctx)
	if err != nil || update == nil {
		return
	}
	m.mu.Lock()
	changed := !updateInfoEqual(m.updateInfo, update)
	// Reset the notified flag when a different release is detected so each new
	// version produces one notification.
	if m.updateInfo != nil && m.updateInfo.LatestVersion != update.LatestVersion {
		m.updateNotified = false
	}
	m.updateInfo = update
	shouldNotify := update.UpdateAvailable && !m.updateNotified
	if shouldNotify {
		m.updateNotified = true
	}
	notifier := m.notifier
	m.mu.Unlock()

	if changed {
		m.requestRebuild()
	}
	if shouldNotify && notifier != nil {
		title := "FlexConnect update available"
		body := "Version " + update.LatestVersion + " is available."
		if update.ReleaseURL != "" {
			body += "\n" + update.ReleaseURL
		}
		if err := notifier.Send(title, body); err != nil {
			systrayLog.Error(fmt.Errorf("update notification failed: %w", err))
		}
	}
}

// updateInfoEqual reports whether two update-check results are equivalent for
// the purposes of deciding whether the menu needs a rebuild.
func updateInfoEqual(a, b *types.UpdateInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.UpdateAvailable == b.UpdateAvailable &&
		a.LatestVersion == b.LatestVersion &&
		a.ReleaseURL == b.ReleaseURL &&
		a.Disabled == b.Disabled &&
		a.Error == b.Error
}

func (m *Menu) rebuildLoop(ctx context.Context) {
	m.init()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.rebuildCh:
			// Drain any burst queued by rapid state changes, then wait a short
			// debounce window so a flurry of notifications collapses into a
			// single ResetMenu instead of flickering the menu.
			m.drainRebuilds()
			timer := time.NewTimer(rebuildDebounce)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			m.drainRebuilds()
			m.rebuild()
		}
	}
}

func (m *Menu) drainRebuilds() {
	for {
		select {
		case <-m.rebuildCh:
		default:
			return
		}
	}
}

func (m *Menu) openLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-systraylib.TrayOpenedCh:
			m.refresh(ctx)
			m.requestRebuild()
		}
	}
}

func (m *Menu) watch(ctx context.Context) {
	m.init()
	attempt := 0
	for {
		watcher, err := m.Client.Watch(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.reportError("watch connection failed", err)
			if !m.waitForBackoff(ctx, attempt) {
				return
			}
			attempt++
			continue
		}
		// Connection re-established: reset backoff so the next failure starts
		// from the base delay instead of a previously escalated value.
		attempt = 0
		for {
			notify, err := watcher.Next()
			if err != nil {
				_ = watcher.Close()
				if ctx.Err() != nil {
					return
				}
				m.reportError("watch stream failed", err)
				break
			}
			m.handleNotify(notify, m.updateTrayTooltip)
		}
		if !m.waitForBackoff(ctx, attempt) {
			return
		}
		attempt++
	}
}

// waitForBackoff sleeps for the backoff delay computed for attempt before
// returning true. It returns false if ctx is cancelled while waiting.
func (m *Menu) waitForBackoff(ctx context.Context, attempt int) bool {
	timer := time.NewTimer(retryDelay(attempt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *Menu) handleNotify(notify types.Notify, updateTooltip func()) {
	stateChanged := false
	trafficChanged := false
	m.mu.Lock()
	if notify.Status != nil {
		m.status = notify.Status
		stateChanged = true
	}
	if notify.Profiles != nil {
		m.profiles = append([]types.Profile(nil), notify.Profiles...)
		stateChanged = true
	}
	if notify.Traffic != nil {
		m.traffic = *notify.Traffic
		trafficChanged = true
	}
	m.mu.Unlock()
	if notify.Authentication != nil {
		m.notifyAuthentication(*notify.Authentication)
	}
	if notify.Connection != nil {
		m.notifyConnection(*notify.Connection)
	}
	if trafficChanged && !stateChanged {
		updateTooltip()
	}
	if stateChanged {
		m.requestRebuild()
	}
}

func (m *Menu) notifyConnection(event types.ConnectionEvent) {
	if event.Kind != "connection_lost" && event.Kind != "reconnect_scheduled" && event.Kind != "reconnected" && event.Kind != "reconnect_failed" && event.Kind != "reconnect_exhausted" {
		return
	}
	m.init()
	key := event.ID
	if event.ConnectionID != "" {
		key = event.ConnectionID + ":" + event.Kind
	}
	now := timeNow()
	m.mu.Lock()
	if last, ok := m.notified[key]; ok && now.Sub(last) < notifiedTTL {
		m.mu.Unlock()
		return
	}
	m.notified[key] = now
	// Bound memory: sweep TTL-expired entries, and if a burst of distinct
	// fresh keys pushes past the cap, evict the oldest until back under cap.
	for k, at := range m.notified {
		if now.Sub(at) >= notifiedTTL {
			delete(m.notified, k)
		}
	}
	for len(m.notified) > notifiedMax {
		var oldestKey string
		var oldestAt time.Time
		first := true
		for k, at := range m.notified {
			if first || at.Before(oldestAt) {
				oldestKey, oldestAt, first = k, at, false
			}
		}
		delete(m.notified, oldestKey)
	}
	notifier := m.notifier
	m.mu.Unlock()

	title := "FlexConnect"
	body := event.Kind
	switch event.Kind {
	case "connection_lost":
		title = "VPN connection lost"
		body = event.ReasonCode
		if event.Error != "" {
			body += ": " + event.Error
		}
	case "reconnect_scheduled":
		title = "VPN reconnecting"
		body = fmt.Sprintf("Attempt %d scheduled", event.Attempt)
	case "reconnected":
		title = "VPN reconnected"
		body = "The VPN session was restored."
	case "reconnect_failed":
		title = "VPN reconnect failed"
	case "reconnect_exhausted":
		title = "VPN reconnect stopped"
		body = fmt.Sprintf("Attempt %d", event.Attempt)
		if event.Error != "" {
			body += ": " + event.Error
		}
	}
	if err := notifier.Send(title, body); err != nil {
		systrayLog.Error(fmt.Errorf("desktop notification failed event=%s: %w", event.Kind, err))
	}
}

// retryDelay returns an exponentially growing delay with a ±20% jitter,
// capped at backoffMax. attempt 0 starts at backoffBase (~1s); each
// subsequent failure doubles the base until the cap is reached.
func retryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := backoffBase
	for i := 0; i < attempt && d < backoffMax; i++ {
		d *= 2
	}
	if d > backoffMax {
		d = backoffMax
	}
	// ±20% jitter to avoid synchronized reconnect storms.
	spread := float64(d) * 0.2
	delta := time.Duration(jitterFraction()*2*spread - spread)
	d += delta
	if d < backoffBase {
		d = backoffBase
	}
	if d > backoffMax {
		d = backoffMax
	}
	return d
}

func writeClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "-Command", "Set-Clipboard")
	case "darwin":
		cmd = exec.Command("pbcopy")
	default:
		cmd = exec.Command("sh", "-c", "command -v wl-copy >/dev/null 2>&1 && wl-copy || xclip -selection clipboard")
	}
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func onClick(ctx context.Context, item *systraylib.MenuItem, fn func(context.Context)) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-item.ClickedCh:
				if !ok || ctx.Err() != nil {
					return
				}
				fn(ctx)
			}
		}
	}()
}

func setTooltip(text string) {
	if runtime.GOOS == "linux" {
		systraylib.SetTitle(text)
		return
	}
	systraylib.SetTooltip(text)
}

func setTrayIconColor(color trayIconColor) {
	systraylib.SetIcon(trayIconForColor(color))
	if runtime.GOOS == "linux" {
		time.Sleep(10 * time.Millisecond)
	}
}

func toggleForStatus(status *types.Status) toggleState {
	if status == nil {
		return toggleState{Title: "Connect", Enabled: true, Action: toggleConnect}
	}
	switch status.State {
	case types.StateConnected:
		return toggleState{Title: "Disconnect", Enabled: true, Action: toggleDisconnect}
	case types.StateConnecting, types.StateReconnecting:
		return toggleState{Title: string(status.State), Enabled: false, Action: toggleNone}
	default:
		return toggleState{Title: "Connect", Enabled: true, Action: toggleConnect}
	}
}

// maxTooltipLen is the Windows NOTIFYICONDATA szTip limit (128 WCHARs,
// minus one for the null terminator). We count runes, not bytes, because
// each BMP character (including ↑↓…) occupies one WCHAR.
const maxTooltipLen = 127

func tooltipText(status *types.Status, traffic types.TrafficSnapshot, profiles []types.Profile) string {
	state := stateText(status)

	// Line 1: state – always shown in full (short).
	line1 := fmt.Sprintf("%s", state)

	// Line 3: traffic & speed – always shown (use "0" when idle, never hide).
	speed := fmt.Sprintf("\u2191%s/s \u2193%s/s",
		formatByteSizeCompact(uint64(traffic.BytesSentPerSecond)),
		formatByteSizeCompact(uint64(traffic.BytesReceivedPerSecond)))
	line3 := speed

	// Line 2: identity – may be truncated when total exceeds maxTooltipLen.
	identity := trafficIdentity(status, profiles)

	// Calculate how many characters remain for the identity line using
	// rune count (matching Windows WCHAR semantics).
	budget := maxTooltipLen - len([]rune(line1)) - 1 - len([]rune(line3)) - 1
	if budget < 0 {
		budget = 0
	}
	line2 := truncateTo(identity, budget)

	return line1 + "\n" + line2 + "\n" + line3
}

// truncateTo returns s if it fits within max, otherwise shortens it with "…".
func truncateTo(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(runes[:max-1]) + "…"
}

// formatByteSizeCompact produces short labels with B/KB/MB/GB suffixes
// (e.g. "512B", "1.5KB", "2.3MB").
func formatByteSizeCompact(bytes uint64) string {
	const (
		kibi = 1024
		mebi = 1024 * 1024
		gibi = 1024 * 1024 * 1024
	)
	switch {
	case bytes >= gibi:
		return fmt.Sprintf("%.1fGB", float64(bytes)/float64(gibi))
	case bytes >= mebi:
		return fmt.Sprintf("%.1fMB", float64(bytes)/float64(mebi))
	case bytes >= kibi:
		return fmt.Sprintf("%.1fKB", float64(bytes)/float64(kibi))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

func trafficSummaryRows(status *types.Status, traffic types.TrafficSnapshot, profiles []types.Profile) []string {
	rows := []string{"Status: " + stateText(status)}

	// Profile name.
	profileName := profileNameForStatus(status, profiles)
	if profileName != "" {
		rows = append(rows, "Profile: "+profileName)
	}

	// VPN IP from session.
	if status != nil && status.Session != nil {
		if ip := strings.TrimSpace(status.Session.VPNAddress); ip != "" {
			rows = append(rows, "IP: "+ip)
		}
	}

	rows = append(rows,
		fmt.Sprintf("Traffic: ↑%s ↓%s", formatByteSizeCompact(traffic.BytesSent), formatByteSizeCompact(traffic.BytesReceived)),
	)
	return rows
}

// profileNameForStatus returns the display name of the current profile, or empty.
func profileNameForStatus(status *types.Status, profiles []types.Profile) string {
	if status == nil || status.SelectedProfileID == "" {
		return ""
	}
	return profileNameByID(profiles, status.SelectedProfileID)
}

func trafficIdentity(status *types.Status, profiles []types.Profile) string {
	if status == nil {
		return ""
	}
	parts := []string{}
	if status.SelectedProfileID != "" {
		parts = append(parts, profileNameByID(profiles, status.SelectedProfileID))
	}
	if status.Session != nil && strings.TrimSpace(status.Session.VPNAddress) != "" {
		parts = append(parts, status.Session.VPNAddress)
	}
	return strings.Join(parts, " · ")
}

func profileTitle(profile types.Profile) string {
	if strings.TrimSpace(profile.Name) != "" {
		return profile.Name
	}
	if strings.TrimSpace(profile.ServerURL) != "" {
		return profile.ServerURL
	}
	if strings.TrimSpace(profile.ID) != "" {
		return profile.ID
	}
	return "Profile"
}

func profileNameByID(profiles []types.Profile, id string) string {
	for _, profile := range profiles {
		if profile.ID == id {
			return profileTitle(profile)
		}
	}
	return id
}

func stateText(status *types.Status) string {
	if status == nil || status.State == "" {
		return "Unavailable"
	}
	return string(status.State)
}

func copyStatus(status *types.Status) *types.Status {
	if status == nil {
		return nil
	}
	copy := *status
	if status.Session != nil {
		session := *status.Session
		copy.Session = &session
	}
	copy.EffectiveRoutes = append([]types.RouteSpec(nil), status.EffectiveRoutes...)
	return &copy
}

func formatByteSize(bytes uint64) string {
	const (
		kibi = 1024
		mebi = 1024 * 1024
		gibi = 1024 * 1024 * 1024
	)
	switch {
	case bytes >= gibi:
		return fmt.Sprintf("%.2f GiB", float64(bytes)/float64(gibi))
	case bytes >= mebi:
		return fmt.Sprintf("%.2f MiB", float64(bytes)/float64(mebi))
	case bytes >= kibi:
		return fmt.Sprintf("%.2f KiB", float64(bytes)/float64(kibi))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func formatByteRate(bytesPerSecond float64) string {
	return formatByteFloat(bytesPerSecond) + "/s"
}

func formatByteFloat(bytes float64) string {
	const (
		kibi = 1024
		mebi = 1024 * 1024
		gibi = 1024 * 1024 * 1024
	)
	switch {
	case bytes >= gibi:
		return fmt.Sprintf("%.2f GiB", bytes/float64(gibi))
	case bytes >= mebi:
		return fmt.Sprintf("%.2f MiB", bytes/float64(mebi))
	case bytes >= kibi:
		return fmt.Sprintf("%.2f KiB", bytes/float64(kibi))
	default:
		return fmt.Sprintf("%.0f B", bytes)
	}
}

func (m *Menu) notifyAuthentication(challenge types.AuthenticationChallenge) {
	if challenge.ID == "" || challenge.Method != "sms" || !timeNow().Before(challenge.ExpiresAt) {
		return
	}
	m.init()
	m.mu.Lock()
	if m.authenticationNotified == challenge.ID {
		m.mu.Unlock()
		return
	}
	m.authenticationNotified = challenge.ID
	notifier := m.notifier
	m.mu.Unlock()
	if err := notifier.Send("VPN verification required", "Run flexconnect auth respond in a terminal to enter your SMS verification code."); err != nil {
		systrayLog.Error(fmt.Errorf("authentication notification failed: %w", err))
	}
}
