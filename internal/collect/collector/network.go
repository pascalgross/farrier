package collector

import (
	"context"
	"net"
	"sort"

	"github.com/pegasusnetworks/farrier/internal/collect"
)

// maxAddresses caps the addresses reported for one interface.
//
// A host with a large number of virtual addresses — a load balancer, a container host — would otherwise
// send hundreds of lines every time its facts changed. Ten is enough to recognise a machine.
const maxAddresses = 10

// networkInterface is one interface as reported to the control plane.
type networkInterface struct {
	// Name is the kernel's name for the interface, such as "eth0".
	Name string `json:"name"`

	// MTU is the interface's maximum transmission unit.
	MTU int `json:"mtu"`

	// Up reports whether the interface is administratively up.
	Up bool `json:"up"`

	// Addresses are the assigned addresses in CIDR form, capped at maxAddresses.
	Addresses []string `json:"addresses,omitempty"`

	// AddressesTruncated reports that the list was cut short.
	AddressesTruncated bool `json:"addressesTruncated,omitempty"`
}

// init registers the network collector.
func init() {
	Register(collect.NewCollectorFunc("network", collectNetwork))
}

// collectNetwork reports the host's network interfaces and addresses.
//
// It is the collector that justifies AF_NETLINK in the systemd unit's RestrictAddressFamilies:
// net.Interfaces uses a netlink socket on Linux, and without that family it returns nothing — and does
// so without an error, which is the class of failure this project tries hardest not to ship. Hardware
// addresses are deliberately not reported: they identify a machine no better than the host id already
// does and they are the sort of thing that ends up in a support ticket.
func collectNetwork(context.Context) (any, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	out := make([]networkInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		// The loopback interface is the same on every host and tells an operator nothing.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		reported := networkInterface{
			Name: iface.Name,
			MTU:  iface.MTU,
			Up:   iface.Flags&net.FlagUp != 0,
		}

		addrs, addrErr := iface.Addrs()
		if addrErr == nil {
			for _, addr := range addrs {
				reported.Addresses = append(reported.Addresses, addr.String())
			}
			sort.Strings(reported.Addresses)
			if len(reported.Addresses) > maxAddresses {
				reported.Addresses = reported.Addresses[:maxAddresses]
				reported.AddressesTruncated = true
			}
		}
		out = append(out, reported)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		// Reported as an explicit note rather than an empty list. A host with no interfaces at all is
		// either a container with a very unusual configuration or an agent whose netlink access has
		// been taken away, and the two want different responses.
		return map[string]any{
			"interfaces": out,
			"note":       "no non-loopback interfaces were visible; check RestrictAddressFamilies includes AF_NETLINK",
		}, nil
	}
	return map[string]any{"interfaces": out}, nil
}
