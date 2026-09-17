//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// CompiledPolicy is an immutable policy snapshot shared by all eBPF data
// planes created for one consumer. ForceInterceptIPv4 and ForceInterceptIPv6
// are opaque application-supplied destination prefixes: the library neither
// assigns their meaning nor resolves addresses within them.
type CompiledPolicy struct {
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	localDNSMode            DNSMode
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
	localInitialBypass      dualStackCIDRPrefixes
	sharedInitialBypass     dualStackCIDRPrefixes
	endpoint                dualStackCIDRPrefixes
	endpointPortEntries     []tcPortKey
}

// CompileActionPolicy translates the caller's final pass/intercept rules into
// the internal map layout. The translation intentionally contains no
// sing-box concepts: a pass action becomes a bypass map entry and an
// intercept action becomes an include/force entry where the selected data
// plane supports it.
func CompileActionPolicy(config ActionPolicy) (CompiledPolicy, error) {
	if err := validateActionScope(config.Local, "local"); err != nil {
		return CompiledPolicy{}, err
	}
	if err := validateActionScope(config.Shared, "shared"); err != nil {
		return CompiledPolicy{}, err
	}
	local, localBypass, localForceIPv4, localForceIPv6, err := compileActionScope(config.Local, "local")
	if err != nil {
		return CompiledPolicy{}, err
	}
	shared, sharedBypass, sharedForceIPv4, sharedForceIPv6, err := compileActionScope(config.Shared, "shared")
	if err != nil {
		return CompiledPolicy{}, err
	}
	endpoint, endpointPorts, err := compileEndpointPolicy(config)
	if err != nil {
		return CompiledPolicy{}, err
	}
	if localForceIPv4.IsValid() && sharedForceIPv4.IsValid() && localForceIPv4 != sharedForceIPv4 {
		return CompiledPolicy{}, E.New("local and shared IPv4 intercept prefixes differ")
	}
	if localForceIPv6.IsValid() && sharedForceIPv6.IsValid() && localForceIPv6 != sharedForceIPv6 {
		return CompiledPolicy{}, E.New("local and shared IPv6 intercept prefixes differ")
	}
	forceIPv4 := localForceIPv4
	if !forceIPv4.IsValid() {
		forceIPv4 = sharedForceIPv4
	}
	forceIPv6 := localForceIPv6
	if !forceIPv6.IsValid() {
		forceIPv6 = sharedForceIPv6
	}
	return CompiledPolicy{
		uidEntries:              local.uidEntries,
		uidDefaultBypass:        local.uidDefaultBypass,
		localDNSMode:            actionDNSMode(config.Local),
		includeSource:           shared.includeSource,
		excludeSource:           shared.excludeSource,
		includeSourceMAC:        shared.includeSourceMAC,
		excludeSourceMAC:        shared.excludeSourceMAC,
		localBypassPortEntries:  local.localBypassPortEntries,
		sharedBypassPortEntries: shared.sharedBypassPortEntries,
		forceInterceptIPv4:      forceIPv4,
		forceInterceptIPv6:      forceIPv6,
		localInitialBypass:      localBypass,
		sharedInitialBypass:     sharedBypass,
		sharedDNSMode:           actionDNSMode(config.Shared),
		sharedBypassPrivate:     false,
		endpoint:                endpoint,
		endpointPortEntries:     endpointPorts,
	}, nil
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
	if len(config.EndpointPort) > tcPortPolicyCapacity {
		return dualStackCIDRPrefixes{}, nil, E.New("TC eBPF endpoint port policy exceeds map capacity")
	}
	ports := make([]tcPortKey, 0, len(config.EndpointPort))
	for _, decision := range config.EndpointPort {
		if decision.Port == 0 || decision.Action != DecisionPass ||
			(decision.Protocol != ProtocolTCP && decision.Protocol != ProtocolUDP) {
			return dualStackCIDRPrefixes{}, nil, E.New("invalid TC eBPF endpoint port decision")
		}
		if decision.Protocol == ProtocolTCP && !config.EnableTCP || decision.Protocol == ProtocolUDP && !config.EnableUDP {
			return dualStackCIDRPrefixes{}, nil, E.New("TC eBPF endpoint port decision uses a disabled protocol")
		}
		ports = append(ports, tcPortKey{Protocol: decision.Protocol, Port: decision.Port})
	}
	return endpoint, ports, nil
}

type compiledActionScope struct {
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	includeSource           dualStackCIDRPrefixes
	excludeSource           dualStackCIDRPrefixes
	includeSourceMAC        []MACAddress
	excludeSourceMAC        []MACAddress
	localBypassPortEntries  []tcPortKey
	sharedBypassPortEntries []tcPortKey
}

func actionDNSMode(scope ActionScope) DNSMode {
	for _, rule := range scope.DestinationPort {
		if rule.Port == 53 && rule.Action == DecisionIntercept {
			return DNSModeHijack
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Port == 53 && rule.Action == DecisionPass {
			return DNSModeOff
		}
	}
	return DNSModeRespectPolicy
}

func validateActionScope(scope ActionScope, name string) error {
	if !scope.Default.Valid() {
		return E.New("invalid ", name, " eBPF default decision: ", scope.Default)
	}
	for _, rule := range scope.UID {
		if rule.Start > rule.End || !rule.Action.Valid() {
			return E.New("invalid ", name, " UID decision")
		}
	}
	for _, rule := range scope.SourceCIDR {
		if !rule.Prefix.IsValid() || !rule.Action.Valid() {
			return E.New("invalid ", name, " source CIDR decision")
		}
	}
	for _, rule := range scope.DestinationCIDR {
		if !rule.Prefix.IsValid() || !rule.Action.Valid() {
			return E.New("invalid ", name, " destination CIDR decision")
		}
	}
	for _, rule := range scope.SourceMAC {
		if !rule.Action.Valid() {
			return E.New("invalid ", name, " source MAC decision")
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Port == 0 || !rule.Action.Valid() {
			return E.New("invalid ", name, " destination port decision")
		}
	}
	return nil
}

func compileActionScope(scope ActionScope, name string) (compiledActionScope, dualStackCIDRPrefixes, netip.Prefix, netip.Prefix, error) {
	result := compiledActionScope{}
	var err error
	var bypass dualStackCIDRPrefixes
	var forceIPv4, forceIPv6 netip.Prefix
	result.uidEntries, result.uidDefaultBypass, err = compileUIDActionPolicy(scope.UID, scope.Default)
	if err != nil {
		return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.Cause(err, name, " UID policy")
	}
	var sourceInclude, sourceExclude []netip.Prefix
	for _, rule := range scope.SourceCIDR {
		if rule.Action == DecisionPass {
			sourceExclude = append(sourceExclude, rule.Prefix)
		} else {
			sourceInclude = append(sourceInclude, rule.Prefix)
		}
	}
	result.includeSource.ipv4, result.includeSource.ipv6, err = compileCIDRPrefixes(sourceInclude)
	if err != nil {
		return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.Cause(err, name, " include source CIDR policy")
	}
	result.excludeSource.ipv4, result.excludeSource.ipv6, err = compileCIDRPrefixes(sourceExclude)
	if err != nil {
		return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.Cause(err, name, " exclude source CIDR policy")
	}
	for _, rule := range scope.SourceMAC {
		if rule.Action == DecisionPass {
			result.excludeSourceMAC = append(result.excludeSourceMAC, rule.Address)
		} else {
			result.includeSourceMAC = append(result.includeSourceMAC, rule.Address)
		}
	}
	for _, rule := range scope.DestinationCIDR {
		prefix := rule.Prefix.Masked()
		if rule.Action == DecisionPass {
			if prefix.Addr().Is4() {
				bypass.ipv4 = append(bypass.ipv4, prefix)
			} else {
				bypass.ipv6 = append(bypass.ipv6, prefix)
			}
			continue
		}
		if prefix.Addr().Is4() {
			if forceIPv4.IsValid() && forceIPv4 != prefix {
				return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.New(name, " has multiple IPv4 intercept prefixes")
			}
			forceIPv4 = prefix
		} else {
			if forceIPv6.IsValid() && forceIPv6 != prefix {
				return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.New(name, " has multiple IPv6 intercept prefixes")
			}
			forceIPv6 = prefix
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Action != DecisionPass {
			// DNS interception is enforced before UID/source selection by the data plane.
			if scope.Default == DecisionPass && rule.Port != 53 {
				return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.New(name, " cannot override a pass default with port intercept")
			}
			continue
		}
		entry := tcPortKey{Protocol: rule.Protocol, Port: rule.Port}
		if name == "shared" {
			result.sharedBypassPortEntries = append(result.sharedBypassPortEntries, entry)
		} else {
			result.localBypassPortEntries = append(result.localBypassPortEntries, entry)
		}
	}
	return result, bypass, forceIPv4, forceIPv6, nil
}
