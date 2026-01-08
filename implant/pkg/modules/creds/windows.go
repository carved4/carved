package creds

import (
	"fmt"
	"unsafe"

	"github.com/carved4/go-wincall"
)

const (
	GENERIC_READ			= 0x80000000
	FILE_SHARE_READ			= 0x00000001
	FILE_SHARE_WRITE		= 0x00000002
	FILE_SHARE_DELETE		= 0x00000004
	OPEN_EXISTING			= 3
	FILE_FLAG_BACKUP_SEMANTICS	= 0x02000000
	FILE_READ_ATTRIBUTES		= 0x80
	INVALID_HANDLE_VALUE		= ^uintptr(0)
)

type FILETIME struct {
	LowDateTime	uint32
	HighDateTime	uint32
}

type FileInformation struct {
	FileAttributes		uint32
	CreationTime		FILETIME
	LastAccessTime		FILETIME
	LastWriteTime		FILETIME
	VolumeSerialNumber	uint32
	FileSizeHigh		uint32
	FileSizeLow		uint32
	NumberOfLinks		uint32
	FileIndexHigh		uint32
	FileIndexLow		uint32
}

func OpenVolume(volumePath string) (uintptr, error) {
	utf16Path, err := wincall.UTF16ptr(volumePath)
	if err != nil {
		return 0, fmt.Errorf("UTF16ptr failed: %v", err)
	}

	handle, _, lastErr := wincall.Call("kernel32.dll", "CreateFileW",
		uintptr(unsafe.Pointer(utf16Path)),
		GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		0,
		0,
	)

	if handle == INVALID_HANDLE_VALUE || handle == 0 {
		errCode, _, _ := wincall.Call("kernel32.dll", "GetLastError")
		return 0, fmt.Errorf("CreateFileW failed with error code %d: %v", errCode, lastErr)
	}

	return handle, nil
}

func openFileForAttributes(filePath string) (uintptr, error) {
	longPath := `\\?\` + filePath
	utf16Path, err := wincall.UTF16ptr(longPath)
	if err != nil {
		return 0, err
	}

	handle, _, err := wincall.Call("kernel32.dll", "CreateFileW",
		uintptr(unsafe.Pointer(utf16Path)),
		FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		0,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)

	if handle == INVALID_HANDLE_VALUE || handle == 0 {
		return 0, fmt.Errorf("CreateFileW failed: %v", err)
	}

	return handle, nil
}

func CloseHandle(handle uintptr) {
	wincall.Call("kernel32.dll", "CloseHandle", handle)
}

func getFileInformation(fileHandle uintptr) (*FileInformation, error) {
	info := &FileInformation{}

	success, _, err := wincall.Call("kernel32.dll", "GetFileInformationByHandle",
		fileHandle,
		uintptr(unsafe.Pointer(info)),
	)

	if success == 0 {
		return nil, fmt.Errorf("GetFileInformationByHandle failed: %v", err)
	}

	return info, nil
}

func getMftRecordNumber(info *FileInformation) uint64 {
	frn := (uint64(info.FileIndexHigh) << 32) | uint64(info.FileIndexLow)
	return frn & 0x0000FFFFFFFFFFFF
}

func getFileSize(info *FileInformation) uint64 {
	return (uint64(info.FileSizeHigh) << 32) | uint64(info.FileSizeLow)
}

