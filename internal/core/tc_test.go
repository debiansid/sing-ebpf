//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestTCABI(t *testing.T) {
	if size := unsafe.Sizeof(tcControl{}); size != 72 {
		t.Fatalf("unexpected TC control size: %d", size)
	}
	if offset := unsafe.Offsetof(tcControl{}.RoutingMark); offset != 12 {
		t.Fatalf("unexpected TC routing mark offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.DeliveryInterface); offset != 8 {
		t.Fatalf("unexpected TC delivery interface offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.ListenerPort); offset != 16 {
		t.Fatalf("unexpected TC listener port offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.ForceInterceptIPv6Mask); offset != 54 {
		t.Fatalf("unexpected TC IPv6 ForceIntercept mask offset: %d", offset)
	}
	if size := unsafe.Sizeof(tcAssignKey{}); size != 44 {
		t.Fatalf("unexpected TC assignment key size: %d", size)
	}
	if size := unsafe.Sizeof(TCAssignment{}); size != 24 {
		t.Fatalf("unexpected TC assignment value size: %d", size)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.SocketCookie); offset != 0 {
		t.Fatalf("unexpected TC assignment socket cookie offset: %d", offset)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.InterfaceIndex); offset != 8 {
		t.Fatalf("unexpected TC assignment interface index offset: %d", offset)
	}
}

func TestTCIPv6PathFlags(t *testing.T) {
	localFlags := tcFlags(TCConfig{EnableLocalIPv6: true}, CompiledPolicy{})
	if localFlags&tcFlagLocalIPv6 == 0 || localFlags&tcFlagSharedIPv6 != 0 {
		t.Fatalf("unexpected local IPv6 flags: %#x", localFlags)
	}
	sharedFlags := tcFlags(TCConfig{EnableSharedIPv6: true}, CompiledPolicy{})
	if sharedFlags&tcFlagLocalIPv6 != 0 || sharedFlags&tcFlagSharedIPv6 == 0 {
		t.Fatalf("unexpected shared IPv6 flags: %#x", sharedFlags)
	}
	hybridFlags := tcFlags(TCConfig{EnableLocalIPv6: true, EnableSharedIPv6: true}, CompiledPolicy{})
	if hybridFlags&(tcFlagLocalIPv6|tcFlagSharedIPv6) != tcFlagLocalIPv6|tcFlagSharedIPv6 {
		t.Fatalf("unexpected hybrid IPv6 flags: %#x", hybridFlags)
	}
}

func TestTCEndpointFlags(t *testing.T) {
	policy := CompiledPolicy{
		endpoint:            dualStackCIDRPrefixes{ipv4: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		endpointPortEntries: []tcPortKey{{Protocol: ProtocolTCP, Port: 4500}},
	}
	flags := tcFlags(TCConfig{EnableLocal: true}, policy)
	if flags&tcFlagEndpointEnabled == 0 || flags&tcFlagEndpointReady != 0 {
		t.Fatalf("unexpected endpoint flags: %#x", flags)
	}
	const existingTCFlagNamespace = 1<<24 - 1
	if tcFlagEndpointEnabled&existingTCFlagNamespace != 0 ||
		tcFlagEndpointReady&(existingTCFlagNamespace|tcFlagEndpointEnabled) != 0 {
		t.Fatal("endpoint flag collides with the TC flag namespace")
	}
	ready := endpointReadyFlags(flags, true)
	if ready&tcFlagEndpointReady == 0 || endpointReadyFlags(ready, false) != flags {
		t.Fatalf("endpoint READY transition failed: %#x", ready)
	}
	if tcFlags(TCConfig{EnableShared: true}, policy)&tcFlagEndpointEnabled != 0 {
		t.Fatal("shared-only backend enabled endpoint policy")
	}
}

func TestEndpointReadyControlFailure(t *testing.T) {
	b := &TCBackend{runtime: &tcRuntime{}, controlMapFD: -1}
	b.control.Flags = tcFlagEndpointEnabled | tcFlagTCP
	if err := b.SetEndpointVPNReady(false); err != nil {
		t.Fatalf("unchanged state wrote the control map: %v", err)
	}
	if err := b.SetEndpointVPNReady(true); err == nil || b.control.Flags != tcFlagEndpointEnabled|tcFlagTCP {
		t.Fatal("failed control write committed READY")
	}
}

func TestMakeTCAssignKey(t *testing.T) {
	for _, test := range []struct {
		source      string
		destination string
		family      uint8
	}{
		{"192.0.2.10:12345", "1.1.1.1:443", addressFamilyIPv4},
		{"[2001:db8::10]:12345", "[2606:4700:4700::1111]:443", addressFamilyIPv6},
	} {
		source := netip.MustParseAddrPort(test.source)
		destination := netip.MustParseAddrPort(test.destination)
		key, err := makeTCAssignKey(ProtocolTCP, source, destination, 17)
		if err != nil {
			t.Fatal(err)
		}
		if key.Family != test.family || key.Protocol != ProtocolTCP ||
			key.SourcePort != source.Port() || key.DestinationPort != destination.Port() || key.InterfaceIndex != 17 {
			t.Fatalf("unexpected TC assignment key: %+v", key)
		}
		if got := tcKeyAddress(key.Family, key.SourceAddress); got != source.Addr() {
			t.Fatalf("unexpected source address: %s", got)
		}
		if got := tcKeyAddress(key.Family, key.DestinationAddress); got != destination.Addr() {
			t.Fatalf("unexpected destination address: %s", got)
		}
	}
	if _, err := makeTCAssignKey(
		ProtocolUDP,
		netip.MustParseAddrPort("192.0.2.1:1"),
		netip.MustParseAddrPort("[2001:db8::1]:2"),
		0,
	); err == nil {
		t.Fatal("mixed address families were accepted")
	}
}

func tcKeyAddress(family uint8, address [16]byte) netip.Addr {
	if family == addressFamilyIPv4 {
		return netip.AddrFrom4([4]byte(address[:4]))
	}
	return netip.AddrFrom16(address)
}
