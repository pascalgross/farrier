package collect

import (
	"context"
	"fmt"
	"sort"

	"github.com/coreos/go-systemd/v22/dbus"
)

// unitPatterns are the unit types HostSeal reports on.
//
// Only the three types the intent catalogue can act on are listed. Reporting mounts, devices and slices
// would triple the size of every heartbeat with rows nobody can do anything about.
var unitPatterns = []string{"*.service", "*.socket", "*.timer"}

// ListUnits reads systemd unit state over D-Bus.
//
// It uses the D-Bus interface rather than parsing systemctl output, and that is not a stylistic
// preference. systemctl has no machine-readable output mode: `systemctl list-units --output=json` looks
// like it should work and does not, because -o/--output selects a *journal* output mode and list-units
// ignores it entirely. `systemctl --help` lists no --json flag, while busctl, networkctl and
// systemd-analyze all do. Verified on systemd 255 / Ubuntu 24.04.
//
// The D-Bus route returns typed structs with no parsing, and reading unit state needs no polkit
// authorisation, so the unprivileged agent can do it with no capabilities at all.
func ListUnits(ctx context.Context) ([]Unit, bool, error) {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("collect: connecting to systemd over D-Bus: %w", err)
	}
	defer conn.Close()

	statuses, err := conn.ListUnitsByPatternsContext(ctx, nil, unitPatterns)
	if err != nil {
		return nil, false, fmt.Errorf("collect: listing units: %w", err)
	}

	units := make([]Unit, 0, len(statuses))
	for _, s := range statuses {
		units = append(units, Unit{
			Name:        s.Name,
			Description: s.Description,
			LoadState:   s.LoadState,
			ActiveState: s.ActiveState,
			SubState:    s.SubState,
		})
	}

	// A stable order means the facts digest does not change simply because systemd enumerated units
	// differently, which would otherwise make every heartbeat look like a change and defeat the
	// digest-first design entirely.
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })

	truncated := false
	if len(units) > MaxServices {
		units = units[:MaxServices]
		truncated = true
	}
	return units, truncated, nil
}
