package codec

import (
	"testing"

	netstructpb "n2n-go/pkg/protocol/netstruct"
	p2p "n2n-go/pkg/p2p/pb"

	"google.golang.org/protobuf/proto"
)

// TestEncodeDecode verifies that proto.Marshal/Unmarshal round-trips correctly
// for the generated protobuf types used in n2n protocol.
func TestEncodeDecode(t *testing.T) {
	original := &netstructpb.RegisterRequest{
		EdgeMacAddr:        "aa:bb:cc:dd:ee:ff",
		EdgeDesc:           "test-edge",
		CommunityName:      "default",
		EncryptedMachineId: []byte{1, 2, 3},
		ClearMachineId:     []byte{4, 5, 6},
	}

	data, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Encode returned empty data")
	}

	decoded, err := Decode[*netstructpb.RegisterRequest](data)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	// decoded is **netstructpb.RegisterRequest; dereference to get the message
	d := *decoded

	if d.EdgeMacAddr != original.EdgeMacAddr {
		t.Errorf("EdgeMacAddr mismatch: got %q, want %q", d.EdgeMacAddr, original.EdgeMacAddr)
	}
	if d.EdgeDesc != original.EdgeDesc {
		t.Errorf("EdgeDesc mismatch: got %q, want %q", d.EdgeDesc, original.EdgeDesc)
	}
	if d.CommunityName != original.CommunityName {
		t.Errorf("CommunityName mismatch: got %q, want %q", d.CommunityName, original.CommunityName)
	}
	if string(d.EncryptedMachineId) != string(original.EncryptedMachineId) {
		t.Errorf("EncryptedMachineId mismatch: got %q, want %q", d.EncryptedMachineId, original.EncryptedMachineId)
	}
	if string(d.ClearMachineId) != string(original.ClearMachineId) {
		t.Errorf("ClearMachineId mismatch: got %q, want %q", d.ClearMachineId, original.ClearMachineId)
	}
}

// TestCodecRoundTrip verifies the Codec type round-trips for p2p types.
func TestCodecRoundTrip(t *testing.T) {
	original := &p2p.PeerInfo{
		VirtualIp: "100.64.0.1",
		PubSocket: "192.168.1.1:1234",
		Community: "default",
		Desc:      "test-peer",
	}

	c := NewCodec[*p2p.PeerInfo]()

	data, err := c.Encode(original)
	if err != nil {
		t.Fatalf("Codec.Encode failed: %v", err)
	}

	decoded, err := c.Decode(data)
	if err != nil {
		t.Fatalf("Codec.Decode failed: %v", err)
	}
	d := *decoded

	if d.Community != original.Community {
		t.Errorf("Community mismatch: got %q, want %q", d.Community, original.Community)
	}
	if d.Desc != original.Desc {
		t.Errorf("Desc mismatch: got %q, want %q", d.Desc, original.Desc)
	}
	if d.PubSocket != original.PubSocket {
		t.Errorf("PubSocket mismatch: got %q, want %q", d.PubSocket, original.PubSocket)
	}
}

// TestProtoDirectMarshalUnmarshal verifies proto.Marshal/Unmarshal directly.
func TestProtoDirectMarshalUnmarshal(t *testing.T) {
	original := &netstructpb.RegisterResponse{
		IsRegisterOk: true,
		VirtualIp:    "100.64.0.1",
		Masklen:      16,
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}

	decoded := &netstructpb.RegisterResponse{}
	err = proto.Unmarshal(data, decoded)
	if err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}

	if decoded.IsRegisterOk != original.IsRegisterOk {
		t.Errorf("IsRegisterOk mismatch: got %v, want %v", decoded.IsRegisterOk, original.IsRegisterOk)
	}
	if decoded.VirtualIp != original.VirtualIp {
		t.Errorf("VirtualIp mismatch: got %q, want %q", decoded.VirtualIp, original.VirtualIp)
	}
	if decoded.Masklen != original.Masklen {
		t.Errorf("Masklen mismatch: got %d, want %d", decoded.Masklen, original.Masklen)
	}
}

// TestIppoolLeaseRoundTrip verifies ippool.Lease protobuf round-trip.
func TestIppoolLeaseRoundTrip(t *testing.T) {
	original := &netstructpb.IppoolLease{
		Ip:     []byte{10, 0, 0, 1},
		Mac:    "aa:bb:cc:dd:ee:ff",
		Sticky: true,
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}

	decoded := &netstructpb.IppoolLease{}
	err = proto.Unmarshal(data, decoded)
	if err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}

	if decoded.Mac != original.Mac {
		t.Errorf("Mac mismatch: got %q, want %q", decoded.Mac, original.Mac)
	}
	if decoded.Sticky != original.Sticky {
		t.Errorf("Sticky mismatch: got %v, want %v", decoded.Sticky, original.Sticky)
	}
}