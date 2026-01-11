package db

import (
	"time"

	"github.com/carved4/carved/shared/proto"
)

type Implant struct {
	ID		string		`json:"id"`
	Hostname	string		`json:"hostname"`
	Username	string		`json:"username"`
	Domain		string		`json:"domain"`
	OS		string		`json:"os"`
	Arch		string		`json:"arch"`
	PID		uint32		`json:"pid"`
	Process		string		`json:"process"`
	Elevated	bool		`json:"elevated"`
	FirstSeen	time.Time	`json:"first_seen"`
	LastSeen	time.Time	`json:"last_seen"`
	Sleep		uint32		`json:"sleep"`
	Jitter		uint8		`json:"jitter"`
	Alive		bool		`json:"alive"`
}

type Task struct {
	ID		string			`json:"id"`
	ImplantID	string			`json:"implant_id"`
	Type		proto.TaskType		`json:"type"`
	Args		string			`json:"args"`
	Data		[]byte			`json:"data"`
	Status		proto.TaskStatus	`json:"status"`
	Output		[]byte			`json:"output"`
	Error		string			`json:"error"`
	Created		time.Time		`json:"created"`
	Completed	*time.Time		`json:"completed,omitempty"`
}

type Listener struct {
	ID	string			`json:"id"`
	Name	string			`json:"name"`
	Type	proto.ListenerType	`json:"type"`
	Host	string			`json:"host"`
	Port	uint16			`json:"port"`
	Active	bool			`json:"active"`
	Created	time.Time		`json:"created"`
}

type Loot struct {
	ID		string		`json:"id"`
	ImplantID	string		`json:"implant_id"`
	Type		LootType	`json:"type"`
	Name		string		`json:"name"`
	Data		[]byte		`json:"data"`
	Created		time.Time	`json:"created"`
}

type LootType string

const (
	LootCredential	LootType	= "credential"
	LootFile	LootType	= "file"
	LootScreenshot	LootType	= "screenshot"
)

type Credential struct {
	ID		string		`json:"id"`
	ImplantID	string		`json:"implant_id"`
	Source		string		`json:"source"`
	Domain		string		`json:"domain"`
	Username	string		`json:"username"`
	Secret		string		`json:"secret"`
	Type		string		`json:"type"`
	Created		time.Time	`json:"created"`
}

