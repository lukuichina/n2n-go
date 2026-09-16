package p2p

type PeerInfoEventType uint8

const (
	TypeList       PeerInfoEventType = 1
	TypeRegister   PeerInfoEventType = 2
	TypeUnregister PeerInfoEventType = 3
)