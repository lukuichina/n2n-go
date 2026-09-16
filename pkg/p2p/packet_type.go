package p2p

import "n2n-go/pkg/protocol/spec"

// PacketTyped is the interface implemented by all protocol message types.
type PacketTyped interface {
	PacketType() spec.PacketType
}

func (*PeerInfoList) PacketType() spec.PacketType { return spec.TypePeerInfo }
func (*PeerP2PInfos) PacketType() spec.PacketType   { return spec.TypeP2PStateInfo }
func (*P2PFullState) PacketType() spec.PacketType   { return spec.TypeP2PFullState }