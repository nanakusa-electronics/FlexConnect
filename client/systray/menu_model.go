package systray

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"

	brandicons "flexconnect/assets/icons"
	"flexconnect/internal/types"
)

type menuAction int

const (
	menuActionNone menuAction = iota
	menuActionToggle
	menuActionProfile
	menuActionSocks5
	menuActionUnattendedMode
	menuActionAutoReconnect
	menuActionApplyDNS
	menuActionCopyDiagnostics
	menuActionQuit
)

type trayIconColor string

const (
	trayIconBlue  trayIconColor = "blue"
	trayIconRed   trayIconColor = "red"
	trayIconGreen trayIconColor = "green"
)

type menuModel struct {
	Icon    trayIconColor
	Tooltip string
	Items   []menuItemModel
}

type menuItemModel struct {
	Title     string
	Tooltip   string
	Disabled  bool
	Checked   bool
	Checkbox  bool
	Separator bool
	Action    menuAction
	Toggle    toggleAction
	ProfileID string
	Value     bool
	Children  []menuItemModel
}

func buildMenuModel(status *types.Status, traffic types.TrafficSnapshot, profiles []types.Profile, update *types.UpdateInfo) menuModel {
	profiles = append([]types.Profile(nil), profiles...)
	sort.Slice(profiles, func(i, j int) bool {
		return strings.ToLower(profileTitle(profiles[i])) < strings.ToLower(profileTitle(profiles[j]))
	})

	model := menuModel{Icon: trayIconColorForStatus(status), Tooltip: tooltipText(status, traffic, profiles)}
	model.Items = append(model.Items, statusItems(status, profiles)...)
	if item := updateMenuItem(update); item != nil {
		model.Items = append(model.Items, *item)
	}
	model.Items = append(model.Items, separatorItem())
	model.Items = append(model.Items, toggleItemForStatus(status))
	if info := informationItem(status, traffic, profiles); len(info.Children) > 0 {
		model.Items = append(model.Items, info)
	}
	model.Items = append(model.Items, separatorItem(), profileMenuItem(status, profiles), separatorItem(), settingsMenuItem(status, profiles), separatorItem(), menuItemModel{
		Title:   "Quit",
		Tooltip: "Quit the app",
		Action:  menuActionQuit,
	})
	return model
}

func statusItems(status *types.Status, profiles []types.Profile) []menuItemModel {
	items := []menuItemModel{disabledItem("Status: " + stateText(status))}
	if status == nil {
		return items
	}
	if status.SelectedProfileID != "" {
		items = append(items, disabledItem("Selected Profile: "+profileNameByID(profiles, status.SelectedProfileID)))
	}
	if status.ConnectedProfileID != "" && status.ConnectedProfileID != status.SelectedProfileID {
		items = append(items, disabledItem("Connected Profile: "+profileNameByID(profiles, status.ConnectedProfileID)))
	}
	if status.LastError != "" {
		items = append(items, disabledItem("Last Error: "+status.LastError))
	}
	return items
}

func toggleItemForStatus(status *types.Status) menuItemModel {
	toggle := toggleForStatus(status)
	item := menuItemModel{Title: toggle.Title, Disabled: !toggle.Enabled}
	if toggle.Enabled {
		item.Action = menuActionToggle
		item.Toggle = toggle.Action
	}
	return item
}

func informationItem(status *types.Status, traffic types.TrafficSnapshot, profiles []types.Profile) menuItemModel {
	title := "Information"
	if status != nil && status.Session != nil && status.Session.VPNAddress != "" {
		title = "Information: " + status.Session.VPNAddress
	}
	item := menuItemModel{Title: title}

	// Basic rows (status, identity, traffic).
	basicRows := trafficSummaryRows(status, traffic, profiles)
	for _, row := range basicRows {
		if strings.TrimSpace(row) != "" {
			item.Children = append(item.Children, disabledItem(row))
		}
	}

	if status != nil && status.Session != nil {
		s := status.Session

		// Separator before session details.
		item.Children = append(item.Children, separatorItem())

		// Session details.
		if s.ServerAddress != "" {
			item.Children = append(item.Children, disabledItem("Server: "+s.ServerAddress))
		}
		if s.Hostname != "" {
			item.Children = append(item.Children, disabledItem("Hostname: "+s.Hostname))
		}
		if s.TUNName != "" {
			item.Children = append(item.Children, disabledItem("TUN: "+s.TUNName))
		}
		if s.VPNAddress != "" && s.VPNMask != "" {
			label := "VPN IP: " + s.VPNAddress + "/" + maskToCIDR(s.VPNMask)
			item.Children = append(item.Children, disabledItem(label))
		}
		if s.MTU > 0 {
			item.Children = append(item.Children, disabledItem(fmt.Sprintf("MTU: %d", s.MTU)))
		}

		// DNS servers.
		if len(s.DNS) > 0 {
			item.Children = append(item.Children, disabledItem("DNS: "+strings.Join(s.DNS, ", ")))
		}

		// Cipher info.
		if s.TLSCipher != "" {
			item.Children = append(item.Children, disabledItem("TLS: "+s.TLSCipher))
		}
		if s.DTLSCipher != "" {
			item.Children = append(item.Children, disabledItem("DTLS: "+s.DTLSCipher))
		}
	}

	// Routes submenu (shown even without an active session).
	if status != nil {
		routesItem := routesMenuItem(status)
		if len(routesItem.Children) > 0 {
			item.Children = append(item.Children, separatorItem(), routesItem)
		}
	}

	return item
}

func routesMenuItem(status *types.Status) menuItemModel {
	routes := status.EffectiveRoutes
	includeCount := 0
	excludeCount := 0
	for _, r := range routes {
		if r.Action == "exclude" {
			excludeCount++
		} else {
			includeCount++
		}
	}
	title := fmt.Sprintf("Routes (%d)", len(routes))
	item := menuItemModel{Title: title}
	if len(routes) == 0 {
		item.Children = append(item.Children, disabledItem("No routes"))
		return item
	}
	// Show summary line.
	summary := fmt.Sprintf("%d included", includeCount)
	if excludeCount > 0 {
		summary += fmt.Sprintf(", %d excluded", excludeCount)
	}
	item.Children = append(item.Children, disabledItem(summary), separatorItem())

	// List individual routes.
	for _, r := range routes {
		label := r.Destination
		if r.Action == "exclude" {
			label += " (excluded)"
		}
		source := ""
		if r.Source != "" {
			source = " [" + r.Source + "]"
		}
		item.Children = append(item.Children, disabledItem(label+source))
	}
	return item
}

// maskToCIDR converts an IPv4 netmask like "255.255.255.0" to a CIDR prefix
// length like "24". Returns the input unchanged if parsing fails.
func maskToCIDR(mask string) string {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return mask
	}
	ones, _ := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3]).Size()
	return strconv.Itoa(ones)
}

func profileMenuItem(status *types.Status, profiles []types.Profile) menuItemModel {
	currentID := statusCurrentID(status)
	title := "Profiles"
	item := menuItemModel{Title: title}
	if len(profiles) == 0 {
		item.Children = append(item.Children, disabledItem("No profiles"))
		return item
	}
	for _, profile := range profiles {
		item.Children = append(item.Children, menuItemModel{
			Title:     profileTitle(profile),
			Tooltip:   profile.ServerURL,
			Checked:   profile.ID == currentID,
			Checkbox:  true,
			Action:    menuActionProfile,
			ProfileID: profile.ID,
		})
	}
	return item
}

func settingsMenuItem(status *types.Status, profiles []types.Profile) menuItemModel {
	currentProfile := currentProfileByID(profiles, statusCurrentID(status))
	socks5Enabled := status != nil && status.SOCKS5Enabled
	unattendedEnabled := false
	autoReconnectEnabled := false
	applyDNSEnabled := true
	if currentProfile != nil {
		unattendedEnabled = types.BoolValue(currentProfile.UnattendedMode, false)
		autoReconnectEnabled = types.BoolValue(currentProfile.AutoReconnect, false)
		applyDNSEnabled = types.BoolValue(currentProfile.ApplyDNS, true)
	}
	disabled := currentProfile == nil
	return menuItemModel{
		Title: "Settings",
		Children: []menuItemModel{
			{Title: "Enable SOCKS5 Proxy", Disabled: disabled, Checked: socks5Enabled, Checkbox: true, Action: menuActionSocks5, Value: !socks5Enabled},
			{Title: "Connect on Daemon Start", Disabled: disabled, Checked: unattendedEnabled, Checkbox: true, Action: menuActionUnattendedMode, Value: !unattendedEnabled},
			{Title: "Auto Reconnect", Disabled: disabled, Checked: autoReconnectEnabled, Checkbox: true, Action: menuActionAutoReconnect, Value: !autoReconnectEnabled},
			{Title: "Apply DNS", Disabled: disabled, Checked: applyDNSEnabled, Checkbox: true, Action: menuActionApplyDNS, Value: !applyDNSEnabled},
			{Title: "Copy Diagnostics", Action: menuActionCopyDiagnostics},
		},
	}
}

func disabledItem(title string) menuItemModel {
	return menuItemModel{Title: title, Disabled: true}
}

// updateMenuItem renders a disabled "Update available" row when a newer
// release exists. It is informational only (check-only): clicking it does
// nothing, and the tooltip points at the release page.
func updateMenuItem(update *types.UpdateInfo) *menuItemModel {
	if update == nil || !update.UpdateAvailable || update.LatestVersion == "" {
		return nil
	}
	return &menuItemModel{
		Title:    "Update available: v" + update.LatestVersion,
		Tooltip:  update.ReleaseURL,
		Disabled: true,
	}
}

func separatorItem() menuItemModel {
	return menuItemModel{Separator: true}
}

func trayIconColorForStatus(status *types.Status) trayIconColor {
	if status == nil {
		return trayIconBlue
	}
	switch status.State {
	case types.StateConnected:
		return trayIconGreen
	case types.StateConnecting, types.StateReconnecting, types.StateError:
		return trayIconRed
	default:
		return trayIconBlue
	}
}

func trayIconForColor(color trayIconColor) []byte {
	if runtime.GOOS == "linux" {
		switch color {
		case trayIconRed:
			return brandicons.TrayRedPNG()
		case trayIconGreen:
			return brandicons.TrayGreenPNG()
		default:
			return brandicons.TrayBluePNG()
		}
	}
	switch color {
	case trayIconRed:
		return brandicons.TrayRedICO()
	case trayIconGreen:
		return brandicons.TrayGreenICO()
	default:
		return brandicons.TrayBlueICO()
	}
}
