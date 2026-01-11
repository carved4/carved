package tasks

import (
	"sync"

	"github.com/carved4/carved/shared/proto"
)

var (
	registry	= make(Registry)
	registryLock	sync.RWMutex
)

func Register(taskType proto.TaskType, handler Handler) {
	registryLock.Lock()
	defer registryLock.Unlock()
	registry[taskType] = handler
}

func Get(taskType proto.TaskType) (Handler, bool) {
	registryLock.RLock()
	defer registryLock.RUnlock()
	h, ok := registry[taskType]
	return h, ok
}

func Execute(task *proto.Task) *proto.TaskResult {
	handler, ok := Get(task.Type)
	if !ok {
		return &proto.TaskResult{
			TaskID:		task.ID,
			ImplantID:	task.ImplantID,
			Status:		proto.StatusError,
			Error:		"unknown task type: " + string(task.Type),
		}
	}
	return handler(task)
}

