package codec

import (
	"fmt"
	"reflect"

	"google.golang.org/protobuf/proto"
)

// Codec provides protobuf-based serialization for protocol messages.
// T must be a pointer to a type implementing proto.Message
// (e.g., *netstruct.RegisterRequest, *p2p.pb.PeerInfo).
type Codec[T any] struct {
	encodable *T
}

func NewCodec[T any]() *Codec[T] {
	var x T
	return &Codec[T]{
		encodable: &x,
	}
}

func (c *Codec[T]) Encode(x T) ([]byte, error) {
	return Encode(x)
}

func (c *Codec[T]) Decode(data []byte) (*T, error) {
	return Decode[T](data)
}

// Encode serializes a protobuf message using proto.Marshal.
// T must be a pointer to a type implementing proto.Message.
func Encode[T any](x T) ([]byte, error) {
	msg, ok := any(x).(proto.Message)
	if !ok {
		return nil, fmt.Errorf("type %T does not implement proto.Message", x)
	}
	return proto.Marshal(msg)
}

// Decode deserializes a protobuf message using proto.Unmarshal.
// T must be a pointer to a type implementing proto.Message.
// If T is a nil pointer, the underlying struct is allocated automatically.
// Returns a pointer to T (which may be **T if T is already a pointer).
func Decode[T any](data []byte) (*T, error) {
	var x T

	// If x is a nil pointer, allocate the underlying struct
	rv := reflect.ValueOf(&x).Elem()
	if rv.Kind() == reflect.Ptr && rv.IsNil() {
		rv.Set(reflect.New(rv.Type().Elem()))
	}

	msg, ok := any(x).(proto.Message)
	if !ok {
		return nil, fmt.Errorf("type %T does not implement proto.Message", x)
	}

	err := proto.Unmarshal(data, msg)
	if err != nil {
		return nil, fmt.Errorf("error while decoding: %w", err)
	}
	return &x, nil
}