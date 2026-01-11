package loader

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	coffMachineAMD64 = 0x8664
	coffMachineI386  = 0x14c

	coffSectionExecute = 0x20000000
	coffSectionRead    = 0x40000000
	coffSectionWrite   = 0x80000000

	imageSymClassExternal = 2
	imageSymClassStatic   = 3

	imageRelAMD64Addr64   = 0x0001
	imageRelAMD64Addr32   = 0x0002
	imageRelAMD64Addr32NB = 0x0003
	imageRelAMD64Rel32    = 0x0004
	imageRelAMD64Rel32_1  = 0x0005
	imageRelAMD64Rel32_2  = 0x0006
	imageRelAMD64Rel32_3  = 0x0007
	imageRelAMD64Rel32_4  = 0x0008
	imageRelAMD64Rel32_5  = 0x0009
)

type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type coffSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type coffSymbol struct {
	Name               [8]byte
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type coffRelocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

type loadedSection struct {
	name    string
	addr    uintptr
	size    uint32
	chars   uint32
	rawData []byte
}

const bofOutputBufSize = 64 * 1024

var bofOutputBuf = make([]byte, bofOutputBufSize)

var (
	cppRuntimeInit   sync.Once
	cppRuntimeDLLs   []uintptr
	cppSymbolCache   = make(map[string]uintptr)
	cppSymbolCacheMu sync.RWMutex
)

func initCppRuntime() {
	cppRuntimeInit.Do(func() {
		mingwRuntimes := []string{
			"libstdc++-6.dll",
			"libgcc_s_seh-1.dll",
			"libgcc_s_dw2-1.dll",
			"libwinpthread-1.dll",
		}

		for _, dll := range mingwRuntimes {
			hModule := wc.LoadLibraryLdr(dll)
			if hModule != 0 {
				cppRuntimeDLLs = append(cppRuntimeDLLs, hModule)
			}
		}

		msvcRuntimes := []string{
			"vcruntime140.dll",
			"vcruntime140_1.dll",
			"msvcp140.dll",
			"ucrtbase.dll",
			"msvcrt.dll",
		}

		for _, dll := range msvcRuntimes {
			hModule := wc.LoadLibraryLdr(dll)
			if hModule != 0 {
				cppRuntimeDLLs = append(cppRuntimeDLLs, hModule)
			}
		}
	})
}

func resolveCppSymbol(name string) uintptr {
	cppSymbolCacheMu.RLock()
	if addr, ok := cppSymbolCache[name]; ok {
		cppSymbolCacheMu.RUnlock()
		return addr
	}
	cppSymbolCacheMu.RUnlock()
	initCppRuntime()

	namesToTry := []string{name, "_" + name}

	for _, hModule := range cppRuntimeDLLs {
		for _, tryName := range namesToTry {
			addr := wc.GetFunctionAddress(hModule, wc.GetHash(tryName))
			if addr != 0 {
				cppSymbolCacheMu.Lock()
				cppSymbolCache[name] = addr
				cppSymbolCacheMu.Unlock()
				return addr
			}
		}
	}

	return 0
}

const useSyscallCallbacks = true

func LoadBOF(coffBytes []byte, args []byte) (string, error) {
	return LoadBOFWithEntry(coffBytes, args, "go")
}

func LoadBOFWithEntry(coffBytes []byte, args []byte, entryName string) (string, error) {
	if len(coffBytes) < int(unsafe.Sizeof(coffHeader{})) {
		return "", fmt.Errorf("invalid COFF: too small")
	}

	if useSyscallCallbacks {
		SetupBofOutput(bofOutputBuf)
		ResetBofOutputLen()
		ClearKeyStore()
	} else {
		wc.ResetBofOutput()
		wc.SetBofOutputBuffer(bofOutputBuf)
	}

	header := (*coffHeader)(unsafe.Pointer(&coffBytes[0]))
	if header.Machine != coffMachineAMD64 {
		return "", fmt.Errorf("unsupported architecture: 0x%x (only x64 supported)", header.Machine)
	}

	sectionOffset := unsafe.Sizeof(coffHeader{}) + uintptr(header.SizeOfOptionalHeader)
	sections := make([]loadedSection, header.NumberOfSections)

	gotSize := uint32(0)
	bssSize := uint32(0)

	symbolTableOffset := header.PointerToSymbolTable
	stringTableOffset := symbolTableOffset + uint32(header.NumberOfSymbols)*18

	for i := uint32(0); i < uint32(header.NumberOfSymbols); i++ {
		symOffset := symbolTableOffset + i*18
		if symOffset+18 > uint32(len(coffBytes)) {
			break
		}
		sym := (*coffSymbol)(unsafe.Pointer(&coffBytes[symOffset]))

		if sym.StorageClass == imageSymClassExternal && sym.SectionNumber == 0 {
			symName := getSymbolName(coffBytes, sym, stringTableOffset)
			if strings.HasPrefix(symName, "__imp_") {
				gotSize += 8
			} else if sym.Value > 0 {
				bssSize += sym.Value + 8
			}
		}
		i += uint32(sym.NumberOfAuxSymbols)
	}

	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")

	for i := uint16(0); i < header.NumberOfSections; i++ {
		secHdrOffset := sectionOffset + uintptr(i)*40
		secHdr := (*coffSectionHeader)(unsafe.Pointer(&coffBytes[secHdrOffset]))

		secName := getSectionName(secHdr.Name)
		allocSize := uintptr(secHdr.SizeOfRawData)

		if strings.HasPrefix(secName, ".bss") {
			allocSize = uintptr(bssSize)
			if allocSize == 0 {
				allocSize = 0x1000
			}
		}

		if allocSize == 0 {
			sections[i] = loadedSection{name: secName, chars: secHdr.Characteristics}
			continue
		}

		var baseAddr uintptr
		var regionSize uintptr = allocSize
		ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
			currProc, uintptr(unsafe.Pointer(&baseAddr)), 0,
			uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageRW)
		if ret != 0 {
			return "", fmt.Errorf("failed to allocate section %s: 0x%x", secName, ret)
		}

		if secHdr.SizeOfRawData > 0 && secHdr.PointerToRawData > 0 {
			rawData := coffBytes[secHdr.PointerToRawData : secHdr.PointerToRawData+secHdr.SizeOfRawData]
			dst := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), secHdr.SizeOfRawData)
			copy(dst, rawData)
		}

		sections[i] = loadedSection{
			name:  secName,
			addr:  baseAddr,
			size:  uint32(allocSize),
			chars: secHdr.Characteristics,
		}
	}

	var gotBase uintptr
	if gotSize > 0 {
		var regionSize uintptr = uintptr(gotSize)
		ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
			currProc, uintptr(unsafe.Pointer(&gotBase)), 0,
			uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageRW)
		if ret != 0 {
			return "", fmt.Errorf("failed to allocate GOT: 0x%x", ret)
		}
	}

	var bssBase uintptr
	if bssSize > 0 {
		var regionSize uintptr = uintptr(bssSize)
		ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
			currProc, uintptr(unsafe.Pointer(&bssBase)), 0,
			uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageRW)
		if ret != 0 {
			return "", fmt.Errorf("failed to allocate BSS: 0x%x", ret)
		}
	}

	gotOffset := uintptr(0)
	bssOffset := uintptr(0)
	gotMap := make(map[string]uintptr)

	// Ensure cleanup happens even if we return early
	defer func() {
		ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
		for i := range sections {
			if sections[i].addr != 0 {
				baseAddr := sections[i].addr
				regionSize := uintptr(0)
				wc.IndirectSyscall(ntFree.SSN, ntFree.Address,
					currProc, uintptr(unsafe.Pointer(&baseAddr)),
					uintptr(unsafe.Pointer(&regionSize)), memRelease)
			}
		}
		if gotBase != 0 {
			regionSize := uintptr(0)
			wc.IndirectSyscall(ntFree.SSN, ntFree.Address,
				currProc, uintptr(unsafe.Pointer(&gotBase)),
				uintptr(unsafe.Pointer(&regionSize)), memRelease)
		}
		if bssBase != 0 {
			regionSize := uintptr(0)
			wc.IndirectSyscall(ntFree.SSN, ntFree.Address,
				currProc, uintptr(unsafe.Pointer(&bssBase)),
				uintptr(unsafe.Pointer(&regionSize)), memRelease)
		}
	}()

	for i := uint16(0); i < header.NumberOfSections; i++ {
		secHdrOffset := sectionOffset + uintptr(i)*40
		secHdr := (*coffSectionHeader)(unsafe.Pointer(&coffBytes[secHdrOffset]))

		if secHdr.NumberOfRelocations == 0 || sections[i].addr == 0 {
			continue
		}

		for r := uint16(0); r < secHdr.NumberOfRelocations; r++ {
			relocOffset := secHdr.PointerToRelocations + uint32(r)*10
			if relocOffset+10 > uint32(len(coffBytes)) {
				break
			}
			reloc := (*coffRelocation)(unsafe.Pointer(&coffBytes[relocOffset]))

			symOffset := symbolTableOffset + reloc.SymbolTableIndex*18
			if symOffset+18 > uint32(len(coffBytes)) {
				continue
			}
			sym := (*coffSymbol)(unsafe.Pointer(&coffBytes[symOffset]))
			symName := getSymbolName(coffBytes, sym, stringTableOffset)

			var symbolAddr uintptr
			isGotEntry := false

			if sym.StorageClass == imageSymClassExternal && sym.SectionNumber == 0 {
				if strings.HasPrefix(symName, "__imp_") {

					isGotEntry = true
					if existing, ok := gotMap[symName]; ok {
						symbolAddr = existing
					} else {
						resolvedAddr := resolveImport(symName[6:])
						if resolvedAddr == 0 {
							return "", fmt.Errorf("failed to resolve symbol: %s", symName)
						}
						symbolAddr = gotBase + gotOffset
						*(*uintptr)(unsafe.Pointer(symbolAddr)) = resolvedAddr
						gotMap[symName] = symbolAddr
						gotOffset += 8
					}
				} else if sym.Value > 0 {

					symbolAddr = bssBase + bssOffset
					bssOffset += uintptr(sym.Value) + 8
				} else {

					isGotEntry = true
					resolvedAddr := resolveImport(symName)
					if resolvedAddr == 0 {
						return "", fmt.Errorf("failed to resolve external symbol: %s", symName)
					}

					symbolAddr = gotBase + gotOffset
					*(*uintptr)(unsafe.Pointer(symbolAddr)) = resolvedAddr
					gotMap[symName] = symbolAddr
					gotOffset += 8
				}
			} else if sym.SectionNumber > 0 && int(sym.SectionNumber) <= len(sections) {

				targetSection := &sections[sym.SectionNumber-1]
				symbolAddr = targetSection.addr + uintptr(sym.Value)
			} else {
				continue
			}

			applyRelocation(sections[i].addr, reloc, sym, symbolAddr, isGotEntry)
		}
	}

	ntProt := wc.GetSyscall(wc.GetHash("NtProtectVirtualMemory"))
	for i := range sections {
		if sections[i].addr == 0 || sections[i].size == 0 {
			continue
		}
		if sections[i].chars&coffSectionExecute != 0 {
			var oldProt uint32
			baseAddr := sections[i].addr
			regionSize := uintptr(sections[i].size)
			wc.IndirectSyscall(ntProt.SSN, ntProt.Address,
				currProc, uintptr(unsafe.Pointer(&baseAddr)),
				uintptr(unsafe.Pointer(&regionSize)),
				uintptr(pageRX), uintptr(unsafe.Pointer(&oldProt)))
		}
	}

	entryPoint := uintptr(0)
	for i := uint32(0); i < uint32(header.NumberOfSymbols); i++ {
		symOffset := symbolTableOffset + i*18
		if symOffset+18 > uint32(len(coffBytes)) {
			break
		}
		sym := (*coffSymbol)(unsafe.Pointer(&coffBytes[symOffset]))
		symName := getSymbolName(coffBytes, sym, stringTableOffset)

		if symName == entryName && sym.SectionNumber > 0 {
			targetSection := &sections[sym.SectionNumber-1]
			entryPoint = targetSection.addr + uintptr(sym.Value)
			break
		}
		i += uint32(sym.NumberOfAuxSymbols)
	}

	if entryPoint == 0 {
		return "", fmt.Errorf("entry point '%s' not found", entryName)
	}

	argPtr := uintptr(0)
	argLen := uintptr(0)
	if len(args) > 0 {
		argPtr = uintptr(unsafe.Pointer(&args[0]))
		argLen = uintptr(len(args))
	}

	if useSyscallCallbacks {

		syscall.SyscallN(entryPoint, argPtr, argLen)
	} else {

		wc.CallG0(entryPoint, argPtr, argLen)
	}

	// Cleanup is handled by defer

	var outputLen int
	if useSyscallCallbacks {
		_, outputLen = GetBofOutput()
	} else {
		outputLen = wc.GetBofOutputLen()
	}
	if outputLen > 0 && outputLen <= len(bofOutputBuf) {
		return string(bofOutputBuf[:outputLen]), nil
	}
	return "", nil
}

func getSectionName(name [8]byte) string {
	n := 0
	for n < 8 && name[n] != 0 {
		n++
	}
	return string(name[:n])
}

func getSymbolName(coffBytes []byte, sym *coffSymbol, stringTableOffset uint32) string {

	if sym.Name[0] == 0 && sym.Name[1] == 0 && sym.Name[2] == 0 && sym.Name[3] == 0 {
		offset := binary.LittleEndian.Uint32(sym.Name[4:8])
		strOffset := stringTableOffset + offset
		if strOffset < uint32(len(coffBytes)) {
			end := strOffset
			for end < uint32(len(coffBytes)) && coffBytes[end] != 0 {
				end++
			}
			return string(coffBytes[strOffset:end])
		}
		return ""
	}

	n := 0
	for n < 8 && sym.Name[n] != 0 {
		n++
	}
	return string(sym.Name[:n])
}

func applyRelocation(sectionAddr uintptr, reloc *coffRelocation, sym *coffSymbol, symbolAddr uintptr, isGotEntry bool) {
	patchAddr := sectionAddr + uintptr(reloc.VirtualAddress)

	existingValue := *(*uint32)(unsafe.Pointer(patchAddr))

	adjustedSymbolAddr := symbolAddr
	// symbolOffset was previously calculated here but is unused.
	// We keep the logic below to preserve the addend behavior (skipping addend for static symbols).

	if (sym.StorageClass == imageSymClassStatic && sym.Value != 0) ||
		(sym.StorageClass == imageSymClassExternal && sym.SectionNumber != 0) {
		// no-op, just skip addend
	} else if !isGotEntry {

		adjustedSymbolAddr += uintptr(existingValue)
	}

	switch reloc.Type {
	case imageRelAMD64Addr64:
		*(*uint64)(unsafe.Pointer(patchAddr)) = uint64(adjustedSymbolAddr)

	case imageRelAMD64Addr32NB:

		// ADDR32NB is a 32-bit RVA (Relative Virtual Address).
		// Since we don't have a single image base for the whole BOF,
		// we treat the current section's base address as the image base
		// for relocations within it.
		valueToWrite := adjustedSymbolAddr - sectionAddr
		*(*uint32)(unsafe.Pointer(patchAddr)) = uint32(valueToWrite)

	case imageRelAMD64Rel32, imageRelAMD64Rel32_1, imageRelAMD64Rel32_2,
		imageRelAMD64Rel32_3, imageRelAMD64Rel32_4, imageRelAMD64Rel32_5:

		extraOffset := uintptr(reloc.Type - 4)
		delta := adjustedSymbolAddr - extraOffset - (patchAddr + 4)
		*(*int32)(unsafe.Pointer(patchAddr)) = int32(delta)
	}
}

func resolveImport(name string) uintptr {

	if parts := strings.SplitN(name, "$", 2); len(parts) == 2 {
		dllName := strings.ToLower(parts[0]) + ".dll"
		funcName := parts[1]
		hModule := wc.LoadLibraryLdr(dllName)
		if hModule != 0 {
			return wc.GetFunctionAddress(hModule, wc.GetHash(funcName))
		}
		return 0
	}

	if strings.HasPrefix(name, "_") {
		name = name[1:]
	}

	if name == "__chkstk" || name == "__chkstk_ms" {
		hModule := wc.LoadLibraryLdr("ntdll.dll")
		if hModule != 0 {

			addr := wc.GetFunctionAddress(hModule, wc.GetHash("_chkstk"))
			if addr != 0 {
				return addr
			}

			addr = wc.GetFunctionAddress(hModule, wc.GetHash("__chkstk"))
			if addr != 0 {
				return addr
			}
		}
	}

	switch name {
	case "BeaconOutput", "BeaconPrintf",
		"BeaconDataParse", "BeaconDataInt", "BeaconDataShort",
		"BeaconDataLength", "BeaconDataExtract",
		"BeaconAddValue", "BeaconGetValue", "BeaconRemoveValue",
		"toWideChar",
		"BeaconFormatAlloc", "BeaconFormatReset", "BeaconFormatFree",
		"BeaconFormatAppend", "BeaconFormatPrintf", "BeaconFormatToString",
		"BeaconFormatInt", "BeaconUseToken", "BeaconRevertToken",
		"BeaconIsAdmin", "BeaconGetSpawnTo", "BeaconSpawnTemporaryProcess",
		"BeaconInjectProcess", "BeaconInjectTemporaryProcess",
		"BeaconCleanupProcess", "BeaconGetOutputData", "BeaconInformation":
		return GetBeaconCallback(name)
	}

	// GCC/MinGW C++ runtime symbols mapping (names are already stripped of leading _)
	if name == "ZdlPvy" || name == "ZdlPv" {
		name = "free"
	} else if name == "Znwy" || name == "Znwm" || name == "Znam" {
		name = "malloc"
	} else if name == "ZdaPv" || name == "ZdaPvy" {
		name = "free"
	} else if name == "Unwind_Resume" || name == "_Unwind_Resume" {
		name = "SetLastError"
	} else if name == "cxa_call_unexpected" || name == "_cxa_call_unexpected" {
		name = "SetLastError"
	} else if name == "gxx_personality_seh0" || name == "_gxx_personality_seh0" {
		name = "SetLastError"
	}

	if strings.HasPrefix(name, "ZTVN") || strings.HasPrefix(name, "ZTV") ||
		strings.HasPrefix(name, "ZTIN") || strings.HasPrefix(name, "ZTI") ||
		strings.HasPrefix(name, "ZTSN") || strings.HasPrefix(name, "ZTS") {
		return resolveCppSymbol(name)
	}
	if strings.Contains(name, "cxa_") || strings.Contains(name, "Unwind") ||
		strings.Contains(name, "gxx_personality") || strings.Contains(name, "cxx_") {
		return resolveCppSymbol(name)
	}

	funcHash := wc.GetHash(name)

	alwaysLoadedDLLs := []string{
		"kernel32.dll",
		"ntdll.dll",
		"kernelbase.dll",
	}

	for _, dll := range alwaysLoadedDLLs {
		hModule := wc.GetModuleBase(wc.GetHash(dll))
		if hModule != 0 {
			addr := wc.GetFunctionAddress(hModule, funcHash)
			if addr != 0 {
				return addr
			}
		}
	}

	optionalDLLs := []string{
		"advapi32.dll",
		"user32.dll",
		"ws2_32.dll",
		"ole32.dll",
		"oleaut32.dll",
		"shell32.dll",
		"shlwapi.dll",
		"netapi32.dll",
		"iphlpapi.dll",
		"secur32.dll",
		"crypt32.dll",
		"dnsapi.dll",
		"rpcrt4.dll",
		"version.dll",
		"winhttp.dll",
		"wininet.dll",
		"psapi.dll",
		"dbghelp.dll",
		"msvcrt.dll",
		"ucrtbase.dll",
		"samlib.dll",
		"wtsapi32.dll",
		"mpr.dll",
	}

	for _, dll := range optionalDLLs {
		hModule := wc.GetModuleBase(wc.GetHash(dll))
		if hModule != 0 {
			addr := wc.GetFunctionAddress(hModule, funcHash)
			if addr != 0 {
				return addr
			}
		}
	}

	for _, dll := range optionalDLLs {
		hModule := wc.LoadLibraryLdr(dll)
		if hModule != 0 {
			addr := wc.GetFunctionAddress(hModule, funcHash)
			if addr != 0 {
				return addr
			}
		}
	}

	return 0
}
