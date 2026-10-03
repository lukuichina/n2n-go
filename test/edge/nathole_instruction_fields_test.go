package edge_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"n2n-go/pkg/p2p"
)

// handleNatHoleInstruction does not hand the decoded protobuf to the p2p
// package directly. It reads every field it cares about off the protobuf and
// rebuilds a fresh p2p.NatHoleInstruction literal, because it has to
// normalise SenderMac to "us" along the way. Anything not named in that
// literal is silently dropped, and the symptom is deceptive: the
// NatHoleInstruction log line is printed from the protobuf a few lines
// earlier, so the field looks present right up until the receiver punches a
// single useless candidate.
//
// That already happened once: SenderAssistedEndpoints was logged, arrived
// over the wire, and never made it into the literal, so every receiver fell
// back to the STUN-reflexive pubSocket -- the one address a carrier NAT
// will not hairpin. The pair then had a working sender, a receiver that
// could never be reached, and no direct traffic at all.
//
// Comparing the literal against the struct is the only way to notice the
// next field someone adds to the proto and forgets here.
// edgeSource resolves a filename in pkg/edge without assuming the working
// directory is the package under test. This file lives in test/edge, not in
// pkg/edge, so a bare relative path would read the wrong directory.
func edgeSource(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "pkg", "edge", name)
}

func TestHandleNatHoleInstructionCopiesEveryField(t *testing.T) {
	src, err := os.ReadFile(edgeSource(t, "handlers_missing.go"))
	if err != nil {
		t.Fatalf("read handlers_missing.go: %v", err)
	}

	// Isolate the struct literal passed to SetNatHoleInstruction.
	const anchor = "SetNatHoleInstruction(macStrToBytes("
	start := strings.Index(string(src), anchor)
	if start < 0 {
		t.Fatalf("no %s call in handlers_missing.go", anchor)
	}
	rest := string(src)[start:]
	end := strings.Index(rest, "})")
	if end < 0 {
		t.Fatal("SetNatHoleInstruction literal is not terminated by \"})\"")
	}
	literal := rest[:end]

	msgType := reflect.TypeOf(p2p.NatHoleInstruction{})
	for i := 0; i < msgType.NumField(); i++ {
		field := msgType.Field(i)
		// state / unknownFields / sizeCache are protoc-gen-go's own bookkeeping.
		// They are unexported, nothing outside the p2p package can set them,
		// and no caller in this package should try.
		if !field.IsExported() {
			continue
		}
		// The zero value is not evidence of presence -- "Role:" must not
		// be satisfied by "RegularPortsChange:".
		re := regexp.MustCompile(`(?m)^\s+` + field.Name + `:`)
		if !re.MatchString(literal) {
			t.Errorf("p2p.NatHoleInstruction.%s is never set in the literal rebuilt "+
				"by handleNatHoleInstruction; it will be dropped on the floor. "+
				"Either copy it here or add it to the skip list in this test with "+
				"a comment saying why it is intentionally omitted.", field.Name)
		}
	}
}
