package edge_test

import (
	. "n2n-go/pkg/edge"
	"net"
	"testing"
)

// A single STUN response used to abort classification outright, leaving
// NatFeature nil and the edge advertising natType="unknown". The Worker's
// isCoordEligible accepts only HardNAT/EasyNAT, so such a peer was dropped
// from hole-punch coordination entirely -- not merely treated as the hard
// case. Observed 2026-10-02 on E1 (100.64.0.1) and log3 (100.64.0.4): both
// online, both reported "unknown".
func TestClassifyNATFeatureWithSinglePublicAddress(t *testing.T) {
	// Mapped IP is one of ours -> no NAT in the path at all, which a single
	// sample can settle.
	nf, err := ClassifyNATFeature([]string{"203.0.113.10:40000"}, []string{"203.0.113.10"})
	if err != nil {
		t.Fatalf("a single public address must classify, not error: %v", err)
	}
	if nf.NatType != EasyNAT {
		t.Fatalf("public host should be %s, got %s", EasyNAT, nf.NatType)
	}
	if !nf.PublicNetwork {
		t.Fatal("mapped address is a local address; PublicNetwork should be set")
	}
}

// A single mapped address that is NOT ours proves nothing about cone vs
// symmetric. The point of this test is that we must still answer: HardNAT is
// a usable, conservative answer, "unknown" is not -- it disqualifies the peer
// from coordination altogether.
func TestClassifyNATFeatureWithSingleNATAddressStaysEligible(t *testing.T) {
	nf, err := ClassifyNATFeature([]string{"111.101.5.1:54523"}, []string{"192.168.1.11"})
	if err != nil {
		t.Fatalf("a single mapped address must classify, not error: %v", err)
	}
	if nf.NatType != HardNAT {
		t.Fatalf("cannot prove cone from one sample; want the conservative %s, got %s",
			HardNAT, nf.NatType)
	}
	if nf.PublicNetwork {
		t.Fatal("mapped address is not local; PublicNetwork must not be set")
	}
}

// The new single-sample path must not disturb the ordinary multi-sample
// classification it shares a function with.
func TestClassifyNATFeatureStillDetectsSymmetricWithTwoSamples(t *testing.T) {
	cases := []struct {
		name     string
		addrs    []string
		local    []string
		want     string
		behavior string
	}{
		{
			name:     "cone keeps ip and port",
			addrs:    []string{"111.101.5.1:40000", "111.101.5.1:40000"},
			local:    []string{"192.168.1.11"},
			want:     EasyNAT,
			behavior: BehaviorNoChange,
		},
		{
			name:     "symmetric changes port",
			addrs:    []string{"111.101.5.1:40000", "111.101.5.1:41234"},
			local:    []string{"192.168.1.11"},
			want:     HardNAT,
			behavior: BehaviorPortChanged,
		},
		{
			name:     "symmetric changes address",
			addrs:    []string{"111.101.5.1:40000", "77.72.169.212:40000"},
			local:    []string{"192.168.1.11"},
			want:     HardNAT,
			behavior: BehaviorIPChanged,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nf, err := ClassifyNATFeature(tc.addrs, tc.local)
			if err != nil {
				t.Fatalf("ClassifyNATFeature: %v", err)
			}
			if nf.NatType != tc.want {
				t.Fatalf("NatType = %s, want %s", nf.NatType, tc.want)
			}
			if nf.Behavior != tc.behavior {
				t.Fatalf("Behavior = %s, want %s", nf.Behavior, tc.behavior)
			}
		})
	}
}

// Zero addresses is still an error -- there is nothing to classify, and
// inventing a type here would be exactly the fabrication the caller checks
// for by testing the error.
func TestClassifyNATFeatureRejectsNoAddresses(t *testing.T) {
	if _, err := ClassifyNATFeature(nil, []string{"192.168.1.11"}); err == nil {
		t.Fatal("no addresses must remain an error")
	}
	if _, err := ClassifyNATFeature([]string{}, []string{"192.168.1.11"}); err == nil {
		t.Fatal("empty address list must remain an error")
	}
}

// A malformed single address must still be reported rather than silently
// classified.
func TestClassifyNATFeatureRejectsMalformedSingleAddress(t *testing.T) {
	if _, err := ClassifyNATFeature([]string{"not-a-host-port"}, []string{"192.168.1.11"}); err == nil {
		t.Fatal("a malformed address must be an error")
	}
	if _, err := ClassifyNATFeature([]string{"1.2.3.4:notaport"}, nil); err == nil {
		t.Fatal("a non-numeric port must be an error")
	}
}

// Guard the actual consequence: whatever the edge advertises must be one the
// Worker will coordinate. This mirrors handler.js:386.
func TestAdvertisedNatTypeIsAlwaysWorkerEligible(t *testing.T) {
	workerAccepts := []string{HardNAT, EasyNAT}
	accepted := func(s string) bool {
		for _, w := range workerAccepts {
			if s == w {
				return true
			}
		}
		return false
	}

	inputs := [][]string{
		{"203.0.113.10:40000"},                       // public, one sample
		{"111.101.5.1:54523"},                        // NAT, one sample
		{"111.101.5.1:40000", "111.101.5.1:40000"},   // cone
		{"111.101.5.1:40000", "111.101.5.1:41234"},   // symmetric port
		{"111.101.5.1:40000", "77.72.169.212:40000"}, // symmetric addr
	}
	for _, in := range inputs {
		nf, err := ClassifyNATFeature(in, []string{"192.168.1.11"})
		if err != nil {
			t.Fatalf("%v: %v", in, err)
		}
		if !accepted(nf.NatType) {
			t.Fatalf("%v classified as %q, which isCoordEligible would reject", in, nf.NatType)
		}
	}
	_ = net.IP{}
}
