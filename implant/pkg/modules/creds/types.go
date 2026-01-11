package creds

type Credential struct {
	Username	string
	Password	string
	NTHash		string
	RID		uint32
	Status		string
}

type LSASecret struct {
	Name		string
	Type		string
	Data		[]byte
	NTHash		[]byte
	MachineKey	[]byte
	UserKey		[]byte
	Password	string
	MatchedUser	string
}

type DumpResult struct {
	BootKey		[]byte
	ComputerName	string
	DomainName	string
	IsDomainJoined	bool
	Credentials	map[string]*Credential
	LSASecrets	[]*LSASecret
	NTDSHashes	[]string
}

var ExtractedCredentials map[string]*Credential

