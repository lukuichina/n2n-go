package netstruct

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"

	"n2n-go/pkg/protocol/spec"
)

// Ack is a simple acknowledgment message (TypeAck = 5).
type Ack struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Ack) Reset()                        { *x = Ack{} }
func (x *Ack) String() string                { return protoimpl.X.MessageStringOf(x) }
func (*Ack) ProtoMessage()                   {}
func (x *Ack) ProtoReflect() protoreflect.Message {
	return protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
}

func (*Ack) PacketType() spec.PacketType { return spec.TypeAck }