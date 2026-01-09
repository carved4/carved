package loader

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
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
)

type datap struct {
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
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '+', ' ', '#':
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
				// Unknown specifier, skip it but consume an arg
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

	if size == 0 || buffer == 0 {
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

func copyMemory(dst, src uintptr, size uint32) {
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), size)
	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(src)), size)
	copy(dstSlice, srcSlice)
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
