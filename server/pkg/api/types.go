package api

import "github.com/carved4/carved/shared/proto"

type CreateListenerRequest struct {
	Name	string			`json:"name"`
	Type	proto.ListenerType	`json:"type"`
	Host	string			`json:"host"`
	Port	uint16			`json:"port"`
}

type CreateTaskRequest struct {
	Type	proto.TaskType	`json:"type"`
	Args	[]string	`json:"args,omitempty"`
	Data	[]byte		`json:"data,omitempty"`
}

type BuildImplantRequest struct {
	ListenerID	string	`json:"listener_id"`
	Sleep		uint32	`json:"sleep"`
	Jitter		uint8	`json:"jitter"`
	Format		string	`json:"format"`
	Algorithm	string	`json:"algorithm"`
}

type Response struct {
	Success	bool		`json:"success"`
	Data	interface{}	`json:"data,omitempty"`
	Error	string		`json:"error,omitempty"`
}

type ImplantsResponse struct {
	Implants []ImplantInfo `json:"implants"`
}

type ImplantInfo struct {
	ID		string	`json:"id"`
	Hostname	string	`json:"hostname"`
	Username	string	`json:"username"`
	Domain		string	`json:"domain"`
	OS		string	`json:"os"`
	Arch		string	`json:"arch"`
	PID		uint32	`json:"pid"`
	Process		string	`json:"process"`
	Elevated	bool	`json:"elevated"`
	FirstSeen	string	`json:"first_seen"`
	LastSeen	string	`json:"last_seen"`
	Sleep		uint32	`json:"sleep"`
	Jitter		uint8	`json:"jitter"`
	Alive		bool	`json:"alive"`
}

type TasksResponse struct {
	Tasks []TaskInfo `json:"tasks"`
}

type TaskInfo struct {
	ID		string			`json:"id"`
	ImplantID	string			`json:"implant_id"`
	Type		proto.TaskType		`json:"type"`
	Args		[]string		`json:"args"`
	Status		proto.TaskStatus	`json:"status"`
	Output		string			`json:"output"`
	Error		string			`json:"error"`
	Created		string			`json:"created"`
	Completed	string			`json:"completed,omitempty"`
}

type ListenersResponse struct {
	Listeners []ListenerInfo `json:"listeners"`
}

type ListenerInfo struct {
	ID	string			`json:"id"`
	Name	string			`json:"name"`
	Type	proto.ListenerType	`json:"type"`
	Host	string			`json:"host"`
	Port	uint16			`json:"port"`
	Active	bool			`json:"active"`
	Created	string			`json:"created"`
}

type CredentialsResponse struct {
	Credentials []CredentialInfo `json:"credentials"`
}

type CredentialInfo struct {
	ID		string	`json:"id"`
	ImplantID	string	`json:"implant_id"`
	Source		string	`json:"source"`
	Domain		string	`json:"domain"`
	Username	string	`json:"username"`
	Secret		string	`json:"secret"`
	Type		string	`json:"type"`
	Created		string	`json:"created"`
}

