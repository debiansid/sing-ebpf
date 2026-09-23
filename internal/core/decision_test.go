//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"testing"
)

func TestDecisionValues(t *testing.T) {
	if !DecisionPass.Valid() || !DecisionIntercept.Valid() {
		t.Fatal("supported eBPF decisions must be valid")
	}
	if Decision(2).Valid() {
		t.Fatal("unknown eBPF decision was accepted")
	}
}

func TestCompileActionPolicyUsesFinalActions(t *testing.T) {
	policy, err := CompileActionPolicy(ActionPolicy{
		EnableTCP: true,
		EnableUDP: true,
		Local: ActionScope{
			Default: DecisionIntercept,
			UID:     []UIDDecision{{Start: 10000, End: 10010, Action: DecisionPass}},
			DestinationCIDR: []CIDRDecision{{
				Prefix: netip.MustParsePrefix("192.168.0.0/16"),
				Action: DecisionPass,
			}},
		},
		Shared: ActionScope{
			Default: DecisionIntercept,
			SourceCIDR: []CIDRDecision{{
				Prefix: netip.MustParsePrefix("192.0.2.0/24"),
				Action: DecisionIntercept,
			}},
			SourceMAC: []MACDecision{{
				Address: MACAddress{2, 0, 0, 0, 0, 1},
				Action:  DecisionPass,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.uidEntries) == 0 || policy.uidDefaultBypass {
		t.Fatalf("UID pass action was not compiled into the local decision: entries=%d defaultBypass=%v", len(policy.uidEntries), policy.uidDefaultBypass)
	}
	if len(policy.localInitialBypass.ipv4) != 1 || !policy.localInitialBypass.ipv4[0].Addr().Is4() {
		t.Fatalf("destination pass action was not compiled into the local bypass map: %+v", policy.localInitialBypass)
	}
	if len(policy.includeSource.ipv4) != 1 || len(policy.excludeSourceMAC) != 1 {
		t.Fatalf("shared source actions were not compiled: include=%+v exclude_mac=%+v", policy.includeSource, policy.excludeSourceMAC)
	}
}

func TestCompileActionPolicyDerivesDNSAction(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		action     Decision
		wantLocal  DNSMode
		wantShared DNSMode
	}{
		{"hijack", DecisionIntercept, DNSModeHijack, DNSModeHijack},
		{"off", DecisionPass, DNSModeOff, DNSModeOff},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			policy, err := CompileActionPolicy(ActionPolicy{
				Local: ActionScope{
					Default:         DecisionIntercept,
					DestinationPort: []PortDecision{{Protocol: ProtocolUDP, Port: 53, Action: testCase.action}},
				},
				Shared: ActionScope{
					Default:         DecisionIntercept,
					DestinationPort: []PortDecision{{Protocol: ProtocolUDP, Port: 53, Action: testCase.action}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if policy.localDNSMode != testCase.wantLocal || policy.sharedDNSMode != testCase.wantShared {
				t.Fatalf("DNS modes = %v/%v, want %v/%v", policy.localDNSMode, policy.sharedDNSMode, testCase.wantLocal, testCase.wantShared)
			}
		})
	}
	policy, err := CompileActionPolicy(ActionPolicy{
		Local:  ActionScope{Default: DecisionIntercept},
		Shared: ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.localDNSMode != DNSModeRespectPolicy || policy.sharedDNSMode != DNSModeRespectPolicy {
		t.Fatalf("empty DNS action policy = %v/%v, want respect-policy", policy.localDNSMode, policy.sharedDNSMode)
	}
}

func TestDNSHijackWithUIDDefaultPass(t *testing.T) {
	for _, protocol := range []uint8{ProtocolTCP, ProtocolUDP} {
		config := ActionPolicy{
			EnableTCP: true, EnableUDP: true,
			Local: ActionScope{Default: DecisionPass,
				UID:             []UIDDecision{{Start: 1000, End: 1000, Action: DecisionIntercept}},
				DestinationPort: []PortDecision{{Protocol: protocol, Port: 53, Action: DecisionIntercept}},
			},
			Shared: ActionScope{Default: DecisionIntercept},
		}
		policy, err := CompileActionPolicy(config)
		if err != nil {
			t.Fatal(err)
		}
		if policy.localDNSMode != DNSModeHijack || !policy.uidDefaultBypass || len(policy.uidEntries) == 0 {
			t.Fatalf("lost DNS hijack or UID selection: %+v", policy)
		}
		config.Local.DestinationPort[0].Port = 443
		if _, err = CompileActionPolicy(config); err == nil {
			t.Fatal("unsupported non-DNS override accepted")
		}
	}
}
