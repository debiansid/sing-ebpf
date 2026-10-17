//go:build with_ebpf && (linux || android)

package core

import (
	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// tcEndpointFlowCapacity bounds the TCP endpoint flows whose READY gate
	// decision is pinned. Only flows matching the endpoint policy use it.
	tcEndpointFlowCapacity = 8192

	// Use top bits of uint32 to avoid colliding with upstream flag allocations.
	tcFlagEndpointEnabled = 1 << 31
	tcFlagEndpointReady   = 1 << 30
)

func endpointPolicyEnabled(config TCConfig, policy CompiledPolicy) bool {
	return config.EnableLocal && len(policy.endpointPortEntries) > 0
}

func endpointFlowCapacity(config TCConfig, policy CompiledPolicy) uint32 {
	if endpointPolicyEnabled(config, policy) {
		return tcEndpointFlowCapacity
	}
	return 1
}

func endpointReadyFlags(flags uint32, ready bool) uint32 {
	if ready {
		return flags | tcFlagEndpointReady
	}
	return flags &^ tcFlagEndpointReady
}

func applyEndpointFlags(flags uint32, config TCConfig, policy CompiledPolicy) uint32 {
	if endpointPolicyEnabled(config, policy) {
		flags |= tcFlagEndpointEnabled
	}
	return flags
}

// SetEndpointVPNReady changes only the endpoint gate. Matching local traffic
// is intercepted until the endpoint is ready, then natively bypassed. UDP
// follows the gate per packet; a TCP flow keeps the decision taken for its SYN.
func (b *TCBackend) SetEndpointVPNReady(ready bool) error {
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	if b.control.Flags&tcFlagEndpointEnabled == 0 {
		return nil
	}
	previous := b.control.Flags
	b.control.Flags = endpointReadyFlags(previous, ready)
	if b.control.Flags == previous {
		return nil
	}
	if err := b.updateControlLocked(); err != nil {
		b.control.Flags = previous
		return err
	}
	return nil
}

func compileEndpointPolicy(config ActionPolicy) (dualStackCIDRPrefixes, []tcPortKey, error) {
	if len(config.EndpointCIDR) == 0 && len(config.EndpointPort) == 0 {
		return dualStackCIDRPrefixes{}, nil, nil
	}
	if len(config.EndpointCIDR) == 0 || len(config.EndpointPort) == 0 {
		return dualStackCIDRPrefixes{}, nil, E.New("TC eBPF endpoint policy requires CIDR and port decisions")
	}
	endpoint, err := compileDestinationPassDecisions(config.EndpointCIDR)
	if err != nil {
		return dualStackCIDRPrefixes{}, nil, E.Cause(err, "compile TC eBPF endpoint CIDR policy")
	}
	if len(endpoint.ipv4) > maxDestinationCIDRPolicyEntries || len(endpoint.ipv6) > maxDestinationCIDRPolicyEntries {
		return dualStackCIDRPrefixes{}, nil, E.New("TC eBPF endpoint CIDR policy exceeds map capacity")
	}
	if len(config.EndpointPort) > TCPolicyPortCapacity {
		return dualStackCIDRPrefixes{}, nil, E.New("TC eBPF endpoint port policy exceeds map capacity")
	}
	ports := make([]tcPortKey, 0, len(config.EndpointPort))
	for _, decision := range config.EndpointPort {
		if decision.Port == 0 || decision.Action != DecisionPass ||
			(decision.Protocol != ProtocolTCP && decision.Protocol != ProtocolUDP) {
			return dualStackCIDRPrefixes{}, nil, E.New("invalid TC eBPF endpoint port decision")
		}
		ports = append(ports, tcPortKey{Protocol: decision.Protocol, Port: decision.Port})
	}
	return endpoint, ports, nil
}

func populateEndpointPortPolicyMap(mapInstance *CiliumEBPF.Map, entries []tcPortKey) error {
	if mapInstance == nil {
		return errBackendClosed
	}
	value := uint8(1)
	for _, entry := range entries {
		if err := mapInstance.Update(&entry, &value, CiliumEBPF.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}
