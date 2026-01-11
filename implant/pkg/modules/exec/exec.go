package exec

import (
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

type WIN32_FIND_DATAW struct {
	DwFileAttributes	uint32
	FtCreationTime		[8]byte
	FtLastAccessTime	[8]byte
	FtLastWriteTime		[8]byte
	NFileSizeHigh		uint32
	NFileSizeLow		uint32
	DwReserved0		uint32
	DwReserved1		uint32
	CFileName		[260]uint16
	CAlternateFileName	[14]uint16
}

type STARTUPINFO struct {
	cb		uint32
	lpReserved	*uint16
	lpDesktop	*uint16
	lpTitle		*uint16
	dwX		uint32
	dwY		uint32
	dwXSize		uint32
	dwYSize		uint32
	dwXCountChars	uint32
	dwYCountChars	uint32
	dwFillAttribute	uint32
	dwFlags		uint32
	wShowWindow	uint16
	cbReserved2	uint16
	lpReserved2	*byte
	hStdInput	uintptr
	hStdOutput	uintptr
	hStdError	uintptr
}

type PROCESS_INFORMATION struct {
	hProcess	uintptr
	hThread		uintptr
	dwProcessId	uint32
	dwThreadId	uint32
}

type SECURITY_ATTRIBUTES struct {
	nLength			uint32
	lpSecurityDescriptor	uintptr
	bInheritHandle		uint32
}

type TOKEN_ELEVATION struct {
	TokenIsElevated uint32
}

func ExecCmd(cmd string) string {
	return ExecCmdTimeout(cmd, 60000)
}

func ExecCmdTimeout(cmd string, timeoutMs uint32) string {
	kernel32base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	createProcessW := wc.GetFunctionAddress(kernel32base, wc.GetHash("CreateProcessW"))
	closeHandle := wc.GetFunctionAddress(kernel32base, wc.GetHash("CloseHandle"))
	createPipe := wc.GetFunctionAddress(kernel32base, wc.GetHash("CreatePipe"))
	readFile := wc.GetFunctionAddress(kernel32base, wc.GetHash("ReadFile"))
	waitForSingleObject := wc.GetFunctionAddress(kernel32base, wc.GetHash("WaitForSingleObject"))
	terminateProcess := wc.GetFunctionAddress(kernel32base, wc.GetHash("TerminateProcess"))
	setHandleInformation := wc.GetFunctionAddress(kernel32base, wc.GetHash("SetHandleInformation"))

	var hRead, hWrite uintptr

	sa := SECURITY_ATTRIBUTES{
		nLength:		uint32(unsafe.Sizeof(SECURITY_ATTRIBUTES{})),
		lpSecurityDescriptor:	0,
		bInheritHandle:		1,
	}

	ret, _, _ := wc.CallG0(createPipe, uintptr(unsafe.Pointer(&hRead)), uintptr(unsafe.Pointer(&hWrite)), uintptr(unsafe.Pointer(&sa)), 0)
	if ret == 0 {
		return "[error] failed to create pipe"
	}

	const HANDLE_FLAG_INHERIT = 0x00000001
	wc.CallG0(setHandleInformation, hRead, HANDLE_FLAG_INHERIT, 0)

	var si STARTUPINFO
	si.cb = uint32(unsafe.Sizeof(si))
	const STARTF_USESTDHANDLES = 0x00000100
	si.dwFlags = STARTF_USESTDHANDLES
	si.hStdOutput = hWrite
	si.hStdError = hWrite

	var pi PROCESS_INFORMATION

	cmdPtr, _ := wc.UTF16ptr(cmd)

	const CREATE_NO_WINDOW = 0x08000000

	ret, _, _ = wc.CallG0(
		createProcessW,
		0,
		uintptr(unsafe.Pointer(cmdPtr)),
		0,
		0,
		1,
		CREATE_NO_WINDOW,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		wc.CallG0(closeHandle, hRead)
		wc.CallG0(closeHandle, hWrite)
		return "[error] failed to create process"
	}

	wc.CallG0(closeHandle, hWrite)
	hWrite = 0

	outputChan := make(chan []byte, 1)
	go func() {
		var output []byte
		buffer := make([]byte, 4096)
		var bytesRead uint32

		for {
			ret, _, _ := wc.CallG0(
				readFile,
				hRead,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				uintptr(unsafe.Pointer(&bytesRead)),
				0,
			)

			if ret == 0 || bytesRead == 0 {
				break
			}
			output = append(output, buffer[:bytesRead]...)
		}
		outputChan <- output
	}()

	const WAIT_TIMEOUT = 0x00000102
	waitRet, _, _ := wc.CallG0(waitForSingleObject, pi.hProcess, uintptr(timeoutMs))

	timedOut := waitRet == WAIT_TIMEOUT
	if timedOut {

		wc.CallG0(terminateProcess, pi.hProcess, 1)
	}

	if pi.hProcess != 0 {
		wc.CallG0(closeHandle, pi.hProcess)
	}
	if pi.hThread != 0 {
		wc.CallG0(closeHandle, pi.hThread)
	}

	var output []byte
	select {
	case output = <-outputChan:
	default:

		if hRead != 0 {
			wc.CallG0(closeHandle, hRead)
			hRead = 0
		}
		output = <-outputChan
	}

	if hRead != 0 {
		wc.CallG0(closeHandle, hRead)
	}

	result := string(output)
	if timedOut {
		result += "\n[timeout] command exceeded timeout"
	}

	return result
}

