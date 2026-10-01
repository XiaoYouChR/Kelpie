// Derived from goed2k upnp.go.

// Package nat opens Kelpie's listening ports on the local UPnP Internet
// Gateway Device so peers outside the NAT can connect in.
package nat

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

type mapping struct {
	service  service
	protocol string
	port     int
}

// Open asks every UPnP gateway found on the LAN to forward tcpPort (TCP) and
// udpPort (UDP) to this host, external port equal to internal port. A zero
// port is skipped. Mappings are permanent (lease 0) until the returned
// function closes them. The external address is the first one a gateway
// reports, or the zero Addr when none does. Open succeeds when at least one
// mapping was added.
func Open(ctx context.Context, tcpPort, udpPort int, description string) (func(context.Context) error, netip.Addr, error) {
	locations := probeLocations(ctx)
	if len(locations) == 0 {
		return nil, netip.Addr{}, errors.New("nat: no UPnP gateway found")
	}
	return openAt(ctx, locations, tcpPort, udpPort, description)
}

func openAt(ctx context.Context, locations []string, tcpPort, udpPort int, description string) (func(context.Context) error, netip.Addr, error) {
	var wanted []mapping
	if tcpPort > 0 {
		wanted = append(wanted, mapping{protocol: "TCP", port: tcpPort})
	}
	if udpPort > 0 {
		wanted = append(wanted, mapping{protocol: "UDP", port: udpPort})
	}
	if len(wanted) == 0 {
		return nil, netip.Addr{}, errors.New("nat: no port to open")
	}

	var errs []error
	var services []service
	for _, location := range locations {
		found, err := fetchServices(ctx, location)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		services = append(services, found...)
	}

	var added []mapping
	var external netip.Addr
	for _, s := range services {
		hasAdded := false
		for _, m := range wanted {
			if err := s.addMapping(ctx, m.protocol, m.port, description); err != nil {
				errs = append(errs, err)
				continue
			}
			added = append(added, mapping{service: s, protocol: m.protocol, port: m.port})
			hasAdded = true
		}
		if hasAdded && !external.IsValid() {
			if ip, err := s.fetchExternalIP(ctx); err == nil {
				external = ip
			}
		}
	}
	if len(added) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("nat: no port mapping added on %d gateway(s): %w", len(locations), errors.Join(errs...))
	}

	closeMappings := func(ctx context.Context) error {
		var errs []error
		for _, m := range added {
			if err := m.service.deleteMapping(ctx, m.protocol, m.port); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	return closeMappings, external, nil
}
