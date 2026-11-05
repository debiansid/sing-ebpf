//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// The retiring bit is shared with native/tc_isolation.h; a mismatch makes
// userspace treat live routes of odd network generations as retiring.
func TestTCReturnRetiringMatchesNative(t *testing.T) {
	// Kernel-guest runs execute prebuilt binaries outside the module; inside
	// the source tree a missing header is a failure, not a skip.
	if _, err := os.Stat("../../go.mod"); errors.Is(err, fs.ErrNotExist) {
		t.Skip("not running inside the sing-ebpf source tree")
	}
	header, err := os.ReadFile("../../native/tc_isolation.h")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("#define SB_TC_RETURN_RETIRING 0x%08XU", tcReturnRetiring)
	if !strings.Contains(string(header), want) {
		t.Fatalf("native/tc_isolation.h lacks %q", want)
	}
	if generation := uint32(1); generation&tcReturnRetiring != 0 {
		t.Fatal("an odd network generation is treated as retiring")
	}
}
