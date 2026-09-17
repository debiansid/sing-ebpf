//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
)

type PolicyConfig struct {
	EnableTCP           bool
	EnableUDP           bool
	Local               LocalPolicy
	SharedDNSMode       DNSMode
	SharedBypassPrivate bool
	ForceInterceptIPv4  netip.Prefix
	ForceInterceptIPv6  netip.Prefix
	IncludeSourceCIDR   []netip.Prefix
	ExcludeSourceCIDR   []netip.Prefix
	IncludeSourceMAC    []MACAddress
	ExcludeSourceMAC    []MACAddress
	LocalBypassPort     []PortRange
	SharedBypassPort    []PortRange
	EndpointEnabled     bool
	EndpointEnableTCP   bool
	EndpointEnableUDP   bool
	EndpointCIDR        []netip.Prefix
	EndpointPort        []PortRange
}

// CompiledPolicy is an immutable policy snapshot shared by all eBPF data
// planes created for one consumer. ForceInterceptIPv4 and ForceInterceptIPv6
// are opaque application-supplied destination prefixes: the library neither
// assigns their meaning nor resolves addresses within them.
type CompiledPolicy struct {
	local                   LocalPolicy
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	sharedDNSMode           DNSMode
	sharedBypassPrivate     bool
	forceInterceptIPv4      netip.Prefix
	forceInterceptIPv6      netip.Prefix
	includeSource           dualStackCIDRPrefixes
	excludeSource           dualStackCIDRPrefixes
	includeSourceMAC        []MACAddress
	excludeSourceMAC        []MACAddress
	localBypassPortEntries  []tcPortKey
	sharedBypassPortEntries []tcPortKey
	endpointEnabled         bool
	endpoint                dualStackCIDRPrefixes
	endpointPortEntries     []tcPortKey
}

func CompilePolicy(config PolicyConfig) (CompiledPolicy, error) {
	uidEntries, uidDefaultBypass, err := compileUIDPolicy(config.Local)
	if err != nil {
		return CompiledPolicy{}, err
	}
	forceInterceptIPv4, err := normalizeAddressPrefix("IPv4 force-intercept range", config.ForceInterceptIPv4, true)
	if err != nil {
		return CompiledPolicy{}, err
	}
	forceInterceptIPv6, err := normalizeAddressPrefix("IPv6 force-intercept range", config.ForceInterceptIPv6, false)
	if err != nil {
		return CompiledPolicy{}, err
	}
	includeIPv4, includeIPv6, err := compileBypassCIDRPolicy(config.IncludeSourceCIDR)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile eBPF include source CIDR policy")
	}
	excludeIPv4, excludeIPv6, err := compileBypassCIDRPolicy(config.ExcludeSourceCIDR)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile eBPF exclude source CIDR policy")
	}
	if len(includeIPv4) > maxSharedSourceCIDRPolicyEntries || len(includeIPv6) > maxSharedSourceCIDRPolicyEntries ||
		len(excludeIPv4) > maxSharedSourceCIDRPolicyEntries || len(excludeIPv6) > maxSharedSourceCIDRPolicyEntries {
		return CompiledPolicy{}, E.New("eBPF source CIDR policy exceeds map capacity")
	}
	if len(config.IncludeSourceMAC) > maxSharedSourceMACPolicyEntries ||
		len(config.ExcludeSourceMAC) > maxSharedSourceMACPolicyEntries {
		return CompiledPolicy{}, E.New("eBPF source MAC policy exceeds map capacity")
	}
	localBypassPortEntries, err := compilePortPolicy(config.LocalBypassPort, config.EnableTCP, config.EnableUDP)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile local eBPF port bypass policy")
	}
	sharedBypassPortEntries, err := compilePortPolicy(config.SharedBypassPort, config.EnableTCP, config.EnableUDP)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile shared eBPF port bypass policy")
	}
	var endpointIPv4, endpointIPv6 []netip.Prefix
	var endpointPortEntries []tcPortKey
	if config.EndpointEnabled {
		if len(config.EndpointCIDR) == 0 || len(config.EndpointPort) == 0 {
			return CompiledPolicy{}, E.New("TC eBPF endpoint policy requires CIDR and port entries")
		}
		endpointIPv4, endpointIPv6, err = compileBypassCIDRPolicy(config.EndpointCIDR)
		if err != nil {
			return CompiledPolicy{}, E.Cause(err, "compile TC eBPF endpoint CIDR policy")
		}
		if len(endpointIPv4) > maxBypassCIDRPolicyEntries || len(endpointIPv6) > maxBypassCIDRPolicyEntries {
			return CompiledPolicy{}, E.New("TC eBPF endpoint CIDR policy exceeds map capacity")
		}
		endpointEnableTCP := config.EndpointEnableTCP
		endpointEnableUDP := config.EndpointEnableUDP
		if !endpointEnableTCP && !endpointEnableUDP {
			endpointEnableTCP = true
			endpointEnableUDP = true
		}
		endpointEnableTCP = endpointEnableTCP && config.EnableTCP
		endpointEnableUDP = endpointEnableUDP && config.EnableUDP
		if !endpointEnableTCP && !endpointEnableUDP {
			return CompiledPolicy{}, E.New("TC eBPF endpoint network does not overlap enabled inbound network")
		}
		endpointPortEntries, err = compilePortPolicy(config.EndpointPort, endpointEnableTCP, endpointEnableUDP)
		if err != nil {
			return CompiledPolicy{}, E.Cause(err, "compile TC eBPF endpoint port policy")
		}
	}
	local := config.Local
	local.IncludeUID = slices.Clone(local.IncludeUID)
	local.ExcludeUID = slices.Clone(local.ExcludeUID)
	return CompiledPolicy{
		local:                   local,
		uidEntries:              uidEntries,
		uidDefaultBypass:        uidDefaultBypass,
		sharedDNSMode:           config.SharedDNSMode,
		sharedBypassPrivate:     config.SharedBypassPrivate,
		forceInterceptIPv4:      forceInterceptIPv4,
		forceInterceptIPv6:      forceInterceptIPv6,
		includeSource:           dualStackCIDRPrefixes{ipv4: includeIPv4, ipv6: includeIPv6},
		excludeSource:           dualStackCIDRPrefixes{ipv4: excludeIPv4, ipv6: excludeIPv6},
		includeSourceMAC:        slices.Clone(config.IncludeSourceMAC),
		excludeSourceMAC:        slices.Clone(config.ExcludeSourceMAC),
		localBypassPortEntries:  localBypassPortEntries,
		sharedBypassPortEntries: sharedBypassPortEntries,
		endpointEnabled:         config.EndpointEnabled,
		endpoint:                dualStackCIDRPrefixes{ipv4: endpointIPv4, ipv6: endpointIPv6},
		endpointPortEntries:     endpointPortEntries,
	}, nil
}

func compilePortPolicy(ranges []PortRange, enableTCP, enableUDP bool) ([]tcPortKey, error) {
	var entries []tcPortKey
	for _, portRange := range ranges {
		if portRange.Start == 0 || portRange.Start > portRange.End {
			return nil, E.New("invalid eBPF port bypass range")
		}
		for port := uint32(portRange.Start); port <= uint32(portRange.End); port++ {
			if enableTCP {
				entries = append(entries, tcPortKey{Protocol: ProtocolTCP, Port: uint16(port)})
			}
			if enableUDP {
				entries = append(entries, tcPortKey{Protocol: ProtocolUDP, Port: uint16(port)})
			}
			if len(entries) > tcPortPolicyCapacity {
				return nil, E.New("eBPF port bypass policy exceeds map capacity")
			}
		}
	}
	return entries, nil
}
