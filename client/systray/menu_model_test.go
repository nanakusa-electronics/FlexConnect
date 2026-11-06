package systray

import (
	"strings"
	"testing"

	"flexconnect/internal/types"
)

func TestUnattendedModeMenu(t *testing.T) {
	for _, enabled := range []*bool{nil, types.BoolPtr(false), types.BoolPtr(true)} {
		profile := types.Profile{ID: "p1", UnattendedMode: enabled}
		settings := settingsMenuItem(&types.Status{SelectedProfileID: "p1"}, []types.Profile{profile})
		item := assertHasItem(t, settings.Children, "Connect on Daemon Start")
		want := types.BoolValue(enabled, false)
		if item.Disabled || !item.Checkbox || item.Checked != want || item.Value != !want || item.Action != menuActionUnattendedMode {
			t.Fatalf("menu item = %+v", item)
		}
	}
	item := assertHasItem(t, settingsMenuItem(nil, nil).Children, "Connect on Daemon Start")
	if !item.Disabled {
		t.Fatal("startup toggle enabled without a selected profile")
	}
}

func TestMenuModelUnavailableHasCoreItems(t *testing.T) {
	model := buildMenuModel(nil, types.TrafficSnapshot{}, nil, nil)

	assertHasItem(t, model.Items, "Status: Unavailable")
	connect := assertHasItem(t, model.Items, "Connect")
	if connect.Disabled || connect.Action != menuActionToggle || connect.Toggle != toggleConnect {
		t.Fatalf("Connect item = %+v", connect)
	}
	profile := assertHasItem(t, model.Items, "Profiles")
	assertHasItem(t, profile.Children, "No profiles")
	assertHasItem(t, model.Items, "Settings")
	assertHasItem(t, model.Items, "Quit")
}

func TestMenuModelConnectingDisablesMainAction(t *testing.T) {
	model := buildMenuModel(&types.Status{State: types.StateConnecting, SelectedProfileID: "p1"}, types.TrafficSnapshot{}, []types.Profile{
		{ID: "p1", Name: "Work"},
	}, nil)

	item := assertHasItem(t, model.Items, "Connecting")
	if !item.Disabled || item.Action != menuActionNone {
		t.Fatalf("Connecting item = %+v", item)
	}
	assertHasItem(t, model.Items, "Profiles")
	assertHasItem(t, model.Items, "Settings")
	assertHasItem(t, model.Items, "Quit")
}

func TestMenuModelConnectedShowsDisconnectAndVPNIP(t *testing.T) {
	status := &types.Status{
		State:              types.StateConnected,
		SelectedProfileID:  "p1",
		ConnectedProfileID: "p1",
		Session:            &types.SessionInfo{VPNAddress: "10.0.0.8"},
	}
	traffic := types.TrafficSnapshot{
		Connected:              true,
		BytesSent:              1024,
		BytesReceived:          2048,
		BytesSentPerSecond:     512,
		BytesReceivedPerSecond: 1536,
	}
	model := buildMenuModel(status, traffic, []types.Profile{{ID: "p1", Name: "Work"}}, nil)

	disconnect := assertHasItem(t, model.Items, "Disconnect")
	if disconnect.Disabled || disconnect.Action != menuActionToggle || disconnect.Toggle != toggleDisconnect {
		t.Fatalf("Disconnect item = %+v", disconnect)
	}
	wantTooltip := "Connected\nWork · 10.0.0.8\n↑512B/s ↓1.5KB/s"
	if model.Tooltip != wantTooltip {
		t.Fatalf("tooltip = %q, want %q", model.Tooltip, wantTooltip)
	}
	info := assertHasItem(t, model.Items, "Information: 10.0.0.8")
	assertHasItem(t, info.Children, "Status: Connected")
	assertHasItem(t, info.Children, "Profile: Work")
	assertHasItem(t, info.Children, "IP: 10.0.0.8")
	assertHasItem(t, info.Children, "Traffic: ↑1.0KB ↓2.0KB")
	profile := assertHasItem(t, model.Items, "Profiles")
	child := assertHasItem(t, profile.Children, "Work")
	if !child.Checked {
		t.Fatalf("current profile not checked: %+v", child)
	}
	if countItemsWithPrefix(model.Items, "Selected Profile: Work")+countItemsWithPrefix(model.Items, "Connected Profile: Work") != 1 {
		t.Fatalf("duplicate current/connected profile rows: %+v", itemTitles(model.Items))
	}
}

func TestMenuModelErrorShowsLastError(t *testing.T) {
	model := buildMenuModel(&types.Status{State: types.StateError, LastError: "bad password"}, types.TrafficSnapshot{}, nil, nil)

	assertHasItem(t, model.Items, "Last Error: bad password")
	if trayIconColorForStatus(&types.Status{State: types.StateError}) != trayIconRed {
		t.Fatal("error state should use red tray icon")
	}
}

func TestTrayIconColorForStatus(t *testing.T) {
	tests := []struct {
		name   string
		status *types.Status
		want   trayIconColor
	}{
		{name: "nil", status: nil, want: trayIconBlue},
		{name: "disconnected", status: &types.Status{State: types.StateDisconnected}, want: trayIconBlue},
		{name: "connecting", status: &types.Status{State: types.StateConnecting}, want: trayIconRed},
		{name: "reconnecting", status: &types.Status{State: types.StateReconnecting}, want: trayIconRed},
		{name: "error", status: &types.Status{State: types.StateError}, want: trayIconRed},
		{name: "connected", status: &types.Status{State: types.StateConnected}, want: trayIconGreen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trayIconColorForStatus(tt.status); got != tt.want {
				t.Fatalf("color = %s, want %s", got, tt.want)
			}
		})
	}
}

func assertHasItem(t *testing.T, items []menuItemModel, title string) menuItemModel {
	t.Helper()
	for _, item := range items {
		if item.Title == title {
			return item
		}
	}
	t.Fatalf("missing item %q in %v", title, itemTitles(items))
	return menuItemModel{}
}

func itemTitles(items []menuItemModel) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item.Separator {
			out = append(out, "-")
			continue
		}
		out = append(out, item.Title)
	}
	return out
}

func countItemsWithPrefix(items []menuItemModel, prefix string) int {
	count := 0
	for _, item := range items {
		if strings.HasPrefix(item.Title, prefix) {
			count++
		}
	}
	return count
}

func TestMenuModelInformationRichSession(t *testing.T) {
	status := &types.Status{
		State:             types.StateConnected,
		SelectedProfileID: "p1",
		Session: &types.SessionInfo{
			ServerAddress: "vpn.example.com",
			Hostname:      "myhost",
			TUNName:       "utun3",
			VPNAddress:    "10.0.0.8",
			VPNMask:       "255.255.255.0",
			DNS:           []string{"8.8.8.8", "8.8.4.4"},
			MTU:           1400,
			TLSCipher:     "ECDHE-RSA-AES256-GCM-SHA384",
			DTLSCipher:    "ECDHE-RSA-AES256-GCM-SHA384",
		},
		EffectiveRoutes: []types.RouteSpec{
			{Destination: "10.0.0.0/8", Action: "include", Source: "server"},
			{Destination: "192.168.0.0/16", Action: "include", Source: "custom"},
			{Destination: "0.0.0.0/0", Action: "exclude", Source: "server"},
		},
	}
	traffic := types.TrafficSnapshot{
		BytesSent:     1024,
		BytesReceived: 2048,
	}
	model := buildMenuModel(status, traffic, []types.Profile{{ID: "p1", Name: "Work"}}, nil)

	info := assertHasItem(t, model.Items, "Information: 10.0.0.8")
	assertHasItem(t, info.Children, "Server: vpn.example.com")
	assertHasItem(t, info.Children, "Hostname: myhost")
	assertHasItem(t, info.Children, "TUN: utun3")
	assertHasItem(t, info.Children, "VPN IP: 10.0.0.8/24")
	assertHasItem(t, info.Children, "MTU: 1400")
	assertHasItem(t, info.Children, "DNS: 8.8.8.8, 8.8.4.4")
	assertHasItem(t, info.Children, "TLS: ECDHE-RSA-AES256-GCM-SHA384")
	assertHasItem(t, info.Children, "DTLS: ECDHE-RSA-AES256-GCM-SHA384")

	routes := assertHasItem(t, info.Children, "Routes (3)")
	assertHasItem(t, routes.Children, "2 included, 1 excluded")
	assertHasItem(t, routes.Children, "10.0.0.0/8 [server]")
	assertHasItem(t, routes.Children, "192.168.0.0/16 [custom]")
	assertHasItem(t, routes.Children, "0.0.0.0/0 (excluded) [server]")
}

func TestMenuModelInformationNoSession(t *testing.T) {
	status := &types.Status{
		State:             types.StateDisconnected,
		SelectedProfileID: "p1",
		EffectiveRoutes:   []types.RouteSpec{},
	}
	model := buildMenuModel(status, types.TrafficSnapshot{}, []types.Profile{{ID: "p1", Name: "Work"}}, nil)

	info := assertHasItem(t, model.Items, "Information")
	// No session → no session detail items, only basic rows.
	routes := assertHasItem(t, info.Children, "Routes (0)")
	assertHasItem(t, routes.Children, "No routes")
}

func TestMenuModelUpdateAvailableItem(t *testing.T) {
	update := &types.UpdateInfo{
		LatestVersion:   "9.9.9",
		UpdateAvailable: true,
		ReleaseURL:      "https://github.com/owner/repo/releases/tag/v9.9.9",
	}
	model := buildMenuModel(&types.Status{State: types.StateDisconnected}, types.TrafficSnapshot{}, nil, update)

	item := assertHasItem(t, model.Items, "Update available: v9.9.9")
	if !item.Disabled {
		t.Fatal("update item should be disabled (check-only)")
	}
	if item.Tooltip != update.ReleaseURL {
		t.Fatalf("tooltip = %q, want release URL", item.Tooltip)
	}
}

func TestMenuModelNoUpdateItemWhenUpToDate(t *testing.T) {
	update := &types.UpdateInfo{LatestVersion: "1.0.6", UpdateAvailable: false}
	model := buildMenuModel(&types.Status{State: types.StateDisconnected}, types.TrafficSnapshot{}, nil, update)

	for _, item := range model.Items {
		if strings.HasPrefix(item.Title, "Update available") {
			t.Fatalf("unexpected update item: %+v", item)
		}
	}
}

func TestTruncateTo(t *testing.T) {
	tests := []struct {
		name string
		s    string
		max  int
		want string
	}{
		{name: "fits", s: "abc", max: 5, want: "abc"},
		{name: "exact", s: "abc", max: 3, want: "abc"},
		{name: "truncated", s: "abcdef", max: 3, want: "ab…"},
		{name: "single rune left", s: "abc", max: 1, want: "…"},
		{name: "zero max", s: "abc", max: 0, want: ""},
		{name: "negative max", s: "abc", max: -1, want: ""},
		{name: "unicode", s: "你好世界!", max: 4, want: "你好世…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateTo(tt.s, tt.max); got != tt.want {
				t.Fatalf("truncateTo(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
			}
		})
	}
}

func TestTooltipTextFitsWithinLimit(t *testing.T) {
	tests := []struct {
		name     string
		status   *types.Status
		traffic  types.TrafficSnapshot
		profiles []types.Profile
	}{
		{
			name: "short identity",
			status: &types.Status{
				State:             types.StateConnected,
				SelectedProfileID: "p1",
				Session:           &types.SessionInfo{VPNAddress: "10.0.0.8"},
			},
			traffic: types.TrafficSnapshot{
				BytesSent:              1024,
				BytesReceived:          2048,
				BytesSentPerSecond:     512,
				BytesReceivedPerSecond: 1536,
			},
			profiles: []types.Profile{{ID: "p1", Name: "Work"}},
		},
		{
			name: "long identity gets truncated",
			status: &types.Status{
				State:             types.StateConnected,
				SelectedProfileID: "p1",
				Session:           &types.SessionInfo{VPNAddress: "192.168.100.200"},
			},
			traffic: types.TrafficSnapshot{
				BytesSent:              1024,
				BytesReceived:          2048,
				BytesSentPerSecond:     512,
				BytesReceivedPerSecond: 1536,
			},
			profiles: []types.Profile{{ID: "p1", Name: "Very Long Corporate VPN Profile Name That Exceeds Normal Length"}},
		},
		{
			name: "zero traffic shows 0",
			status: &types.Status{
				State:             types.StateConnected,
				SelectedProfileID: "p1",
				Session:           &types.SessionInfo{VPNAddress: "10.0.0.1"},
			},
			traffic:  types.TrafficSnapshot{},
			profiles: []types.Profile{{ID: "p1", Name: "Work"}},
		},
		{
			name:   "unavailable",
			status: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tooltipText(tt.status, tt.traffic, tt.profiles)
			if len([]rune(got)) > maxTooltipLen {
				t.Fatalf("tooltip rune length %d exceeds max %d: %q", len([]rune(got)), maxTooltipLen, got)
			}
			// Every tooltip must include state in line 1 and traffic markers.
			if got == "" || !strings.Contains(got, "\n") {
				t.Fatalf("tooltip too short: %q", got)
			}
			if !strings.Contains(got, "\u2191") || !strings.Contains(got, "\u2193") {
				t.Fatalf("missing traffic markers: %q", got)
			}
			// Must be at most 3 lines.
			lines := strings.Split(got, "\n")
			if len(lines) > 3 || len(lines) < 3 {
				t.Fatalf("expected 3 lines, got %d: %q", len(lines), got)
			}
		})
	}
}
