package creds

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/carved4/go-wincall"
)

const (
	MFT_RECORD_SIZE	= 1024
	ATTR_FILE_NAME	= 0x30
	ATTR_DATA	= 0x80
)

type NTFSBootSector struct {
	BytesPerSector		uint16
	SectorsPerCluster	uint8
	ClusterSize		uint64
	MftCluster		uint64
}

type DataRun struct {
	Length	uint64
	LCN	int64
}

type FileInfo struct {
	FileName	string
	ParentRef	uint64
	FileSize	uint64
	Runs		[]DataRun
}

func ReadNTFSBoot(volumeHandle uintptr) (*NTFSBootSector, error) {
	buffer := make([]byte, 512)
	var bytesRead uint32

	success, _, err := wincall.Call("kernel32.dll", "ReadFile",
		volumeHandle,
		uintptr(unsafe.Pointer(&buffer[0])),
		512,
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)

	if success == 0 {
		return nil, fmt.Errorf("ReadFile failed: %v", err)
	}

	ntfs := &NTFSBootSector{
		BytesPerSector:		binary.LittleEndian.Uint16(buffer[11:13]),
		SectorsPerCluster:	buffer[13],
	}

	ntfs.ClusterSize = uint64(ntfs.BytesPerSector) * uint64(ntfs.SectorsPerCluster)
	ntfs.MftCluster = binary.LittleEndian.Uint64(buffer[48:56])

	return ntfs, nil
}

func readMftRecord(volumeHandle uintptr, ntfs *NTFSBootSector, recNum uint64) ([]byte, error) {
	mftOffset := ntfs.MftCluster * ntfs.ClusterSize
	recOffset := int64(mftOffset + (recNum * MFT_RECORD_SIZE))

	offsetLow := uint32(recOffset & 0xFFFFFFFF)
	offsetHigh := int32(recOffset >> 32)

	newPosLow, _, err := wincall.Call("kernel32.dll", "SetFilePointer",
		volumeHandle,
		uintptr(offsetLow),
		uintptr(unsafe.Pointer(&offsetHigh)),
		0,
	)

	if newPosLow == 0xFFFFFFFF && err != nil {
		return nil, fmt.Errorf("SetFilePointer failed: %v", err)
	}

	buffer := make([]byte, MFT_RECORD_SIZE)
	var bytesRead uint32

	success, _, err := wincall.Call("kernel32.dll", "ReadFile",
		volumeHandle,
		uintptr(unsafe.Pointer(&buffer[0])),
		MFT_RECORD_SIZE,
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)

	if success == 0 {
		return nil, fmt.Errorf("ReadFile failed: %v", err)
	}

	return buffer, nil
}

func parseFileInfoFromRecord(record []byte) *FileInfo {
	info := &FileInfo{
		FileName:	"<unknown>",
		ParentRef:	5,
		FileSize:	0,
		Runs:		nil,
	}

	if len(record) < 22 {
		return info
	}

	attrOffset := int(binary.LittleEndian.Uint16(record[20:22]))

	for attrOffset < len(record)-4 {
		attrType := binary.LittleEndian.Uint32(record[attrOffset : attrOffset+4])

		if attrType == 0xFFFFFFFF {
			break
		}

		if attrOffset+8 >= len(record) {
			break
		}

		attrLen := int(binary.LittleEndian.Uint32(record[attrOffset+4 : attrOffset+8]))
		if attrLen == 0 || attrOffset+attrLen > len(record) {
			break
		}

		nonResident := record[attrOffset+8]

		if attrType == ATTR_FILE_NAME && attrOffset+90 < len(record) {
			if attrOffset+32 <= len(record) {
				parentRef := binary.LittleEndian.Uint64(record[attrOffset+24 : attrOffset+32])
				info.ParentRef = parentRef & 0xFFFFFFFFFFFF
			}

			if attrOffset+88 < len(record) {
				nameLen := int(record[attrOffset+88])
				nameStart := attrOffset + 90
				nameEnd := nameStart + nameLen*2

				if nameEnd <= len(record) {
					nameBytes := record[nameStart:nameEnd]
					name := ""
					for i := 0; i < len(nameBytes); i += 2 {
						if i+1 < len(nameBytes) {
							ch := binary.LittleEndian.Uint16(nameBytes[i : i+2])
							if ch != 0 {
								name += string(rune(ch))
							}
						}
					}
					info.FileName = name
				}
			}
		}

		if attrType == ATTR_DATA {
			if nonResident == 0 {
				if attrOffset+24 <= len(record) {
					info.FileSize = binary.LittleEndian.Uint64(record[attrOffset+16 : attrOffset+24])
				}
			} else {
				if attrOffset+56 <= len(record) {
					info.FileSize = binary.LittleEndian.Uint64(record[attrOffset+48 : attrOffset+56])
					dataRunOffset := int(binary.LittleEndian.Uint16(record[attrOffset+32 : attrOffset+34]))
					dataRunStart := attrOffset + dataRunOffset
					dataRunEnd := attrOffset + attrLen

					if dataRunStart < dataRunEnd && dataRunEnd <= len(record) {
						info.Runs = parseDataRuns(record[dataRunStart:dataRunEnd])
					}
				}
			}
		}

		attrOffset += attrLen
	}

	return info
}

func parseDataRuns(attr []byte) []DataRun {
	runs := []DataRun{}
	pos := 0
	var curLCN int64 = 0

	for pos < len(attr) && attr[pos] != 0x00 {
		header := attr[pos]
		lenSize := int(header & 0x0F)
		offSize := int((header >> 4) & 0x0F)
		pos++

		if lenSize == 0 {
			break
		}

		if pos+lenSize > len(attr) {
			break
		}

		length := uint64(0)
		for i := 0; i < lenSize; i++ {
			length |= uint64(attr[pos]) << (8 * uint(i))
			pos++
		}

		offset := int64(0)
		if offSize > 0 {
			if pos+offSize > len(attr) {
				break
			}

			for i := 0; i < offSize; i++ {
				offset |= int64(attr[pos]) << (8 * uint(i))
				pos++
			}

			if (attr[pos-1] & 0x80) != 0 {
				for i := offSize; i < 8; i++ {
					offset |= int64(0xFF) << (8 * uint(i))
				}
			}
		}

		curLCN += offset
		runs = append(runs, DataRun{Length: length, LCN: curLCN})
	}

	return runs
}

func ExtractFile(volumeHandle uintptr, ntfs *NTFSBootSector, filePath string) []byte {
	fileHandle, err := openFileForAttributes(filePath)
	if err != nil {
		return nil
	}

	fileInfo, err := getFileInformation(fileHandle)
	CloseHandle(fileHandle)

	if err != nil {
		return nil
	}

	mftRecordNumber := getMftRecordNumber(fileInfo)

	mftRecord, err := readMftRecord(volumeHandle, ntfs, mftRecordNumber)
	if err != nil {
		return nil
	}

	info := parseFileInfoFromRecord(mftRecord)

	var data []byte

	if info.Runs != nil && len(info.Runs) > 0 {
		data = make([]byte, 0, info.FileSize)
		bytesWritten := uint64(0)

		for _, run := range info.Runs {
			toRead := run.Length * ntfs.ClusterSize
			if bytesWritten+toRead > info.FileSize {
				toRead = info.FileSize - bytesWritten
			}

			if run.LCN == 0 {
				data = append(data, make([]byte, toRead)...)
				bytesWritten += toRead
				continue
			}

			diskOffset := int64(run.LCN) * int64(ntfs.ClusterSize)
			offsetLow := uint32(diskOffset & 0xFFFFFFFF)
			offsetHigh := int32(diskOffset >> 32)

			wincall.Call("kernel32.dll", "SetFilePointer",
				volumeHandle,
				uintptr(offsetLow),
				uintptr(unsafe.Pointer(&offsetHigh)),
				0,
			)

			buffer := make([]byte, toRead)
			var bytesRead uint32

			wincall.Call("kernel32.dll", "ReadFile",
				volumeHandle,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(toRead),
				uintptr(unsafe.Pointer(&bytesRead)),
				0,
			)

			data = append(data, buffer[:bytesRead]...)
			bytesWritten += uint64(bytesRead)

			if bytesWritten >= info.FileSize {
				break
			}
		}
	} else {
		attrOffset := int(binary.LittleEndian.Uint16(mftRecord[20:22]))

		for attrOffset < len(mftRecord)-4 {
			attrType := binary.LittleEndian.Uint32(mftRecord[attrOffset : attrOffset+4])
			if attrType == 0xFFFFFFFF {
				break
			}

			attrLen := int(binary.LittleEndian.Uint32(mftRecord[attrOffset+4 : attrOffset+8]))
			if attrLen == 0 || attrOffset+attrLen > len(mftRecord) {
				break
			}

			if attrType == ATTR_DATA {
				nonResident := mftRecord[attrOffset+8]
				if nonResident == 0 && attrOffset+24 <= len(mftRecord) {
					valLen := int(binary.LittleEndian.Uint32(mftRecord[attrOffset+16 : attrOffset+20]))
					valOff := int(binary.LittleEndian.Uint16(mftRecord[attrOffset+20 : attrOffset+22]))
					dataStart := attrOffset + valOff
					dataEnd := dataStart + valLen
					if dataEnd <= len(mftRecord) {
						data = mftRecord[dataStart:dataEnd]
					}
				}
			}

			attrOffset += attrLen
		}
	}

	return data
}

func extractDomainInfo(volumeHandle uintptr, ntfs *NTFSBootSector) (string, bool) {
	softwareData := ExtractFile(volumeHandle, ntfs, "C:\\Windows\\System32\\config\\SOFTWARE")
	if softwareData == nil {
		return "", false
	}

	hive, err := ParseHive(softwareData)
	if err != nil {
		return "", false
	}

	winlogonKey, err := hive.FindKey("Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
	if err != nil {
		return "", false
	}

	values := hive.GetValues(winlogonKey)
	var defaultDomainName string

	for _, vk := range values {
		if vk.Name == "DefaultDomainName" && len(vk.Data) > 0 {
			defaultDomainName = utf16ToString(vk.Data)
		}
	}

	tcpipKey, err := hive.FindKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
	if err == nil {
		tcpipValues := hive.GetValues(tcpipKey)
		for _, vk := range tcpipValues {
			if vk.Name == "Domain" && len(vk.Data) > 0 {
				domain := utf16ToString(vk.Data)
				if domain != "" && domain != "WORKGROUP" {
					return domain, true
				}
			}
		}
	}

	computerNameKey, err := hive.FindKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName")
	if err == nil {
		computerValues := hive.GetValues(computerNameKey)
		for _, vk := range computerValues {
			if vk.Name == "ComputerName" && len(vk.Data) > 0 {
			}
		}
	}

	if defaultDomainName != "" && defaultDomainName != "." && defaultDomainName != "WORKGROUP" {
		return defaultDomainName, true
	}

	return "", false
}

