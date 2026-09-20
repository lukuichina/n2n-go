package netstruct

import "n2n-go/pkg/protocol/spec"

// PacketTyped is the interface implemented by all protocol message types.
// Types implementing this interface can be used with protocol.Message[T] and
// SendStruct/BroadcastStruct helpers.
type PacketTyped interface {
	PacketType() spec.PacketType
}

// LeasesInfos messages
func (*LeasesInfos) PacketType() spec.PacketType { return spec.TypeLeasesInfos }
func (*OnlineCheck) PacketType() spec.PacketType   { return spec.TypeOnlineCheck }

// Register messages
func (*SnPublicSecret) PacketType() spec.PacketType       { return spec.TypeSNPublicSecret }
func (*RegisterRequest) PacketType() spec.PacketType      { return spec.TypeRegisterRequest }
func (*RetryRegisterRequest) PacketType() spec.PacketType { return spec.TypeRetryRegisterRequest }
func (*RegisterResponse) PacketType() spec.PacketType     { return spec.TypeRegisterResponse }
func (*HeartbeatPulse) PacketType() spec.PacketType       { return spec.TypeHeartbeat }
func (*UnregisterRequest) PacketType() spec.PacketType    { return spec.TypeUnregisterRequest }

// Peer messages
func (*PeerListRequest) PacketType() spec.PacketType { return spec.TypePeerListRequest }
func (*PeerToPing) PacketType() spec.PacketType      { return spec.TypePing }

// ice_turn messages
func (*ICECandidate) PacketType() spec.PacketType   { return spec.TypeICECandidate }
func (*TURNCredentials) PacketType() spec.PacketType { return spec.TypeTURNCredentials }