package creds

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	HIVE_SIGNATURE	= 0x66676572
	NK_SIGNATURE	= 0x6B6E
	VK_SIGNATURE	= 0x6B76
	LF_SIGNATURE	= 0x666C
	LH_SIGNATURE	= 0x686C
	RI_SIGNATURE	= 0x6972
)

type RegistryHive struct {
	Data		[]byte
	RootCellIndex	int32
}

type NKRecord struct {
	Signature		uint16
	Flags			uint16
	SubkeyCount		uint32
	SubkeyListOffset	int32
	ValueCount		uint32
	ValueListOffset		int32
	NameLength		uint16
	ClassNameOffset		int32
	ClassNameLength		uint16
	Name			string
	ClassName		string
}

type VKRecord struct {
	Signature	uint16
	NameLength	uint16
	DataLength	uint32
	DataOffset	int32
	DataType	uint32
	Name		string
	Data		[]byte
}

func ParseHive(data []byte) (*RegistryHive, error) {
	if len(data) < 0x1000 {
		return nil, fmt.Errorf("file too small")
	}

	signature := binary.LittleEndian.Uint32(data[0:4])
	if signature != HIVE_SIGNATURE {
		return nil, fmt.Errorf("invalid hive signature")
	}

	rootCellOffset := binary.LittleEndian.Uint32(data[0x24:0x28])

	return &RegistryHive{
		Data:		data,
		RootCellIndex:	int32(rootCellOffset),
	}, nil
}

func (h *RegistryHive) GetCell(offset int32) []byte {
	if offset == -1 || offset == 0 {
		return nil
	}

	realOffset := 0x1000 + int(offset)
	if realOffset < 0 || realOffset+4 > len(h.Data) {
		return nil
	}

	cellSize := int32(binary.LittleEndian.Uint32(h.Data[realOffset : realOffset+4]))
	if cellSize < 0 {
		cellSize = -cellSize
	}

	if realOffset+int(cellSize) > len(h.Data) {
		return nil
	}

	return h.Data[realOffset+4 : realOffset+int(cellSize)]
}

func (h *RegistryHive) ReadNKRecord(offset int32) (*NKRecord, error) {
	cell := h.GetCell(offset)
	if cell == nil || len(cell) < 0x50 {
		return nil, fmt.Errorf("invalid cell (size: %d)", len(cell))
	}

	signature := binary.LittleEndian.Uint16(cell[0:2])
	if signature != NK_SIGNATURE {
		return nil, fmt.Errorf("invalid NK signature: 0x%04X", signature)
	}

	flags := binary.LittleEndian.Uint16(cell[2:4])
	stableSubkeyCount := binary.LittleEndian.Uint32(cell[0x14:0x18])
	volatileSubkeyCount := binary.LittleEndian.Uint32(cell[0x18:0x1C])
	subkeyListOffset := int32(binary.LittleEndian.Uint32(cell[0x1C:0x20]))
	valueCount := binary.LittleEndian.Uint32(cell[0x24:0x28])
	valueListOffset := int32(binary.LittleEndian.Uint32(cell[0x28:0x2C]))
	classNameOffset := int32(binary.LittleEndian.Uint32(cell[0x30:0x34]))
	nameLength := binary.LittleEndian.Uint16(cell[0x48:0x4A])
	classNameLength := binary.LittleEndian.Uint16(cell[0x4A:0x4C])
	totalSubkeys := stableSubkeyCount + volatileSubkeyCount

	nk := &NKRecord{
		Signature:		signature,
		Flags:			flags,
		SubkeyCount:		totalSubkeys,
		SubkeyListOffset:	subkeyListOffset,
		ValueCount:		valueCount,
		ValueListOffset:	valueListOffset,
		NameLength:		nameLength,
		ClassNameOffset:	classNameOffset,
		ClassNameLength:	classNameLength,
	}

	nameStart := 0x4C
	if nameStart+int(nk.NameLength) <= len(cell) {
		nk.Name = string(cell[nameStart : nameStart+int(nk.NameLength)])
	}

	if classNameOffset > 0 && classNameLength > 0 {
		classCell := h.GetCell(classNameOffset)
		if classCell != nil {
			maxLen := int(classNameLength)
			if maxLen > len(classCell) {
				maxLen = len(classCell)
			}
			className := ""
			for i := 0; i < maxLen; i++ {
				className += fmt.Sprintf("%02x", classCell[i])
			}
			nk.ClassName = className
		}
	}

	return nk, nil
}

func (h *RegistryHive) ReadVKRecord(offset int32) (*VKRecord, error) {
	cell := h.GetCell(offset)
	if cell == nil {
		return nil, fmt.Errorf("invalid cell (GetCell returned nil)")
	}
	if len(cell) < 0x14 {
		return nil, fmt.Errorf("invalid cell (size: %d, need at least 0x14)", len(cell))
	}

	signature := binary.LittleEndian.Uint16(cell[0:2])
	if signature != VK_SIGNATURE {
		return nil, fmt.Errorf("invalid VK signature: 0x%04x (expected 0x%04x)", signature, VK_SIGNATURE)
	}

	nameLen := binary.LittleEndian.Uint16(cell[2:4])
	var flags uint16
	if len(cell) >= 18 {
		flags = binary.LittleEndian.Uint16(cell[16:18])
	}

	vk := &VKRecord{
		Signature:	signature,
		NameLength:	nameLen,
		DataLength:	binary.LittleEndian.Uint32(cell[4:8]),
		DataOffset:	int32(binary.LittleEndian.Uint32(cell[8:12])),
		DataType:	binary.LittleEndian.Uint32(cell[12:16]),
	}

	nameStart := 0x14
	if nameLen > 0 {
		nameEnd := nameStart + int(nameLen)
		if nameEnd > len(cell) {
			nameEnd = len(cell)
		}
		nameBytes := cell[nameStart:nameEnd]
		if flags&0x0001 != 0 {
			vk.Name = string(nameBytes)
		} else {
			vk.Name = string(nameBytes)
		}
	} else {
		vk.Name = "(Default)"
	}

	if vk.DataLength > 0 {
		dataLen := vk.DataLength & 0x7FFFFFFF
		if vk.DataLength&0x80000000 != 0 {
			vk.Data = cell[8:12][:dataLen]
		} else if dataLen > 0 {
			dataCell := h.GetCell(vk.DataOffset)
			if dataCell != nil && len(dataCell) >= int(dataLen) {
				vk.Data = dataCell[:dataLen]
			}
		}
	}

	return vk, nil
}

func (h *RegistryHive) GetSubkeys(nk *NKRecord) []*NKRecord {
	if nk.SubkeyCount == 0 || nk.SubkeyListOffset == -1 {
		return nil
	}

	cell := h.GetCell(nk.SubkeyListOffset)
	if cell == nil || len(cell) < 2 {
		return nil
	}

	signature := binary.LittleEndian.Uint16(cell[0:2])
	var subkeys []*NKRecord

	switch signature {
	case LF_SIGNATURE, LH_SIGNATURE:
		count := binary.LittleEndian.Uint16(cell[2:4])
		for i := uint16(0); i < count; i++ {
			offset := 4 + int(i)*8
			if offset+4 > len(cell) {
				break
			}
			subkeyOffset := int32(binary.LittleEndian.Uint32(cell[offset : offset+4]))
			subkey, err := h.ReadNKRecord(subkeyOffset)
			if err == nil {
				subkeys = append(subkeys, subkey)
			}
		}
	case RI_SIGNATURE:
		count := binary.LittleEndian.Uint16(cell[2:4])
		for i := uint16(0); i < count; i++ {
			offset := 4 + int(i)*4
			if offset+4 > len(cell) {
				break
			}
			listOffset := int32(binary.LittleEndian.Uint32(cell[offset : offset+4]))
			listCell := h.GetCell(listOffset)
			if listCell == nil || len(listCell) < 4 {
				continue
			}
			listCount := binary.LittleEndian.Uint16(listCell[2:4])
			for j := uint16(0); j < listCount; j++ {
				subOffset := 4 + int(j)*8
				if subOffset+4 > len(listCell) {
					break
				}
				subkeyOffset := int32(binary.LittleEndian.Uint32(listCell[subOffset : subOffset+4]))
				subkey, err := h.ReadNKRecord(subkeyOffset)
				if err == nil {
					subkeys = append(subkeys, subkey)
				}
			}
		}
	}

	return subkeys
}

func (h *RegistryHive) GetValues(nk *NKRecord) []*VKRecord {
	if nk.ValueCount == 0 || nk.ValueListOffset == -1 {
		return nil
	}

	cell := h.GetCell(nk.ValueListOffset)
	if cell == nil {
		return nil
	}

	var values []*VKRecord
	for i := uint32(0); i < nk.ValueCount; i++ {
		offset := int(i) * 4
		if offset+4 > len(cell) {
			break
		}
		valueOffset := int32(binary.LittleEndian.Uint32(cell[offset : offset+4]))
		value, err := h.ReadVKRecord(valueOffset)
		if err == nil {
			values = append(values, value)
		}
	}

	return values
}

func (h *RegistryHive) FindKey(path string) (*NKRecord, error) {
	parts := strings.Split(path, "\\")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid path")
	}

	currentNK, err := h.ReadNKRecord(h.RootCellIndex)
	if err != nil {
		return nil, err
	}

	for _, part := range parts {
		if part == "" {
			continue
		}

		subkeys := h.GetSubkeys(currentNK)
		found := false
		for _, subkey := range subkeys {
			if strings.EqualFold(subkey.Name, part) {
				currentNK = subkey
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("key not found: %s", part)
		}
	}

	return currentNK, nil
}

func utf16ToString(data []byte) string {
	str := ""
	for i := 0; i < len(data)-1; i += 2 {
		if i+1 < len(data) {
			ch := binary.LittleEndian.Uint16(data[i : i+2])
			if ch == 0 {
				break
			}
			str += string(rune(ch))
		}
	}
	return str
}

func hexStringToBytes(hexStr string) []byte {
	bytes := make([]byte, 0)
	for i := 0; i < len(hexStr); i += 2 {
		if i+1 >= len(hexStr) {
			break
		}
		var b byte
		fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		bytes = append(bytes, b)
	}
	return bytes
}

