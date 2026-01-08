package loader

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"unicode/utf16"
)

type DataParser struct {
	original	uintptr
	buffer		uintptr
	length		uint32
	size		uint32
}

func PackArgs(data []string) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
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
			packed, err = packBinary(value)
		case 'i':
			packed, err = packIntString(value)
		case 's':
			packed, err = packShortString(value)
		case 'z':
			packed, err = packString(value)
		case 'Z':
			packed, err = packWideString(value)
		default:

			packed, err = packString(arg)
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

func packBinary(data string) ([]byte, error) {
	hexData, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(hexData)))
	buff = append(buff, hexData...)
	return buff, nil
}

func packInt(i uint32) []byte {
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, i)
	return buff
}

func packIntString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	return packInt(uint32(i)), nil
}

func packShort(i uint16) []byte {
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, i)
	return buff
}

func packShortString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, err
	}
	return packShort(uint16(i)), nil
}

func packString(s string) ([]byte, error) {

	strBytes := append([]byte(s), 0)
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(strBytes)))
	buff = append(buff, strBytes...)
	return buff, nil
}

func packWideString(s string) ([]byte, error) {

	runes := []rune(s)
	utf16Chars := utf16.Encode(runes)
	utf16Chars = append(utf16Chars, 0)

	buf := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}

	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(len(buf)))
	result = append(result, buf...)
	return result, nil
}

