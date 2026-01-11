# carved

a command & control framework written in go. featuring full BOF loader support that will work with any Cobalt Strike compatible BOF, full pe + dll + shellcode injection support with various methods, run shell commands, take screenshots, dump chrome cookies/passwords/cards, dump hashes with raw disk parsing, manage multiple implants, stagers in rust/nim/zig/c, and a lot more :3
 
## architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            SERVER (linux/windows)                               │
│                                                                                 │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐  ┌─────────────────┐   │
│  │   Web Panel   │  │   REST API   │  │  HTTP Listener │  │ Payload Server  │   │
│  │  (panel.go)   │  │  (router.go) │  │   (http.go)    │  │  /implant       │   │
│  │               │  │              │  │                │  │  /payloads/*    │   │
│  │ - Random auth │  │ - Tasks      │  │ - Checkins     │  │                 │   │
│  │ - BOF browser │  │ - Implants   │  │ - Task results │  │ - Serves        │   │
│  │ - Shellcode   │  │ - Creds      │  │ - Registration │  │   implant.exe   │   │
│  │ - Credentials │  │ - Listeners  │  │ (AES-256-GCM)  │  │   gobound.dll   │   │
│  └───────────────┘  └──────────────┘  └────────────────┘  └─────────────────┘   │
│          │                 │                  │                   │             │
│          └─────────────────┴──────────────────┴───────────────────┘             │
│                                       │                                         │
│                                ┌──────┴──────┐                                  │
│                                │   SQLite    │                                  │
│                                │   (db.go)   │                                  │
│                                └─────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           │                            │                            │
           ▼                            ▼                            ▼
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────────┐
│      STAGERS        │    │                     │    │      BOFs/ Directory    │
│                     │    │                     │    │                         │
│ stager_c.exe   10KB │    │                     │    │  - Cobalt Strike        │
│ stager_zig.exe 10KB │    │                     │    │    compatible BOFs      │
│ stager_nim.exe 137KB│    │                     │    │  - TrustedSec SA-BOF    │
│ stager_rust.exe 21KB│    │                     │    │  - Custom BOFs          │
│                     │    │                     │    │                         │
│ - WinHTTP download  │    │                     │    │                         │
│ - In-memory PE map  │    │                     │    │                         │
│ - NT API execution  │    │                     │    │                         │
│ - No console window │    │                     │    │                         │
└─────────────────────┘    │                     │    └─────────────────────────┘
           │               │                     │                  │
           │ Downloads     │                     │                  │
           │ /implant      │                     │                  │
           ▼               │                     │                  │
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           IMPLANT (windows x64)                                  │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │                          Transport Layer                                   │  │
│  │  - AES-256-GCM encrypted communications (all C2 traffic)                   │  │
│  │  - WinHTTP via manual API resolution (no static imports)                   │  │
│  │  - Registration & beacon loop with configurable sleep/jitter               │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
│                                      │                                           │
│  ┌───────────────────────────────────┴────────────────────────────────────────┐  │
│  │                          Task Registry                                     │  │
│  │  - Handler registration pattern                                            │  │
│  │  - JSON task serialization                                                 │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
│                                      │                                           │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │                             Modules                                        │  │
│  │                                                                            │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │    Loader    │  │  Shellcode   │  │    Creds     │  │    Chrome    │    │  │
│  │  │              │  │              │  │              │  │              │    │  │
│  │  │ - BOF/COFF   │  │ - Enclave    │  │ - SAM dump   │  │ - Cookies    │    │  │
│  │  │ - PE loader  │  │ - Indirect   │  │ - LSA secrets│  │ - Passwords  │    │  │
│  │  │ - DLL inject │  │ - RunOnce    │  │ - NTDS.dit   │  │ - Credit cards│   │  │
│  │  │ - Reflective │  │              │  │              │  │ - App-bound  │    │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │  │
│  │                                                                            │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                      │  │
│  │  │     Exec     │  │   Evasion    │  │  Filesystem  │                      │  │
│  │  │              │  │              │  │              │                      │  │
│  │  │ - cmd.exe    │  │ - Unhook     │  │ - ls/cd/pwd  │                      │  │
│  │  │ - PowerShell │  │   ntdll.dll  │  │ - cat/mkdir  │                      │  │
│  │  │ - Process    │  │ - Indirect   │  │ - upload     │                      │  │
│  │  │   listing    │  │   syscalls   │  │ - download   │                      │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘                      │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ DLL Injection (reflective)
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               gobound.dll                                        │
│                                                                                  │
│  - Reflectively injected into Chrome process                                     │
│  - Decrypts app-bound encryption key via IElevator COM interface                 │
│  - Communicates master key back to implant via named pipe                        │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### components

- **server**: linux/windows binary hosting web panel, REST API, and C2 listener on configurable ports
- **implant**: windows x64 executable that beacons to the server, executes tasks, returns results. all communications are AES-256-GCM encrypted
- **stagers**: tiny windows loaders that download and execute the implant in-memory using NT APIs (available in C, Zig, Nim, and Rust)
- **gobound.dll**: helper dll for chrome credential extraction (reflectively injected into chrome process to decrypt the app-bound encryption master key)

## building

requires:
- go 1.24+ and mingw-w64 for cgo (gobound.dll and C stager)
- zig 0.15+ for Zig stager
- nim 2.0+ with winim package for Nim stager (`nimble install winim`)
- rust with x86_64-pc-windows-gnu target for Rust stager (`rustup target add x86_64-pc-windows-gnu`)

```bash
./build.sh
```

the build script will prompt for stager configuration:
- **C2 server IP** - where the stager will download the implant from (default: 127.0.0.1)
- **C2 listener port** - the listener port (default: 8443)
- **Enable TLS?** - generates self-signed certificates for HTTPS (default: no)

outputs:
- `build/server` - linux team server
- `build/server.exe` - windows team server
- `build/implant.exe` - windows implant  
- `build/stager_c.exe` - C stager (~10KB)
- `build/stager_zig.exe` - Zig stager (~10KB)
- `build/stager_nim.exe` - Nim stager (~137KB)
- `build/stager_rust.exe` - Rust stager (~21KB)
- `build/payloads/gobound.dll` - chrome extraction dll
- `build/payloads/implant.exe` - implant served by the `/implant` endpoint

## configuration

edit `implant/cmd/main.go` before building to set:
- server url (default: `http://127.0.0.1:8443/`)
- sleep interval (default: 5 seconds)
- jitter percentage (default: 10%)

web panel credentials are **randomly generated** on each server start and printed to the console.

## deployment

### quick setup with vultr

1. spin up a vps on [vultr](https://www.vultr.com/) (or any vps provider) - ubuntu/debian works great
2. note your public ip address
3. **Option A: Build Remotely (Recommended)**
   - SSH into your VPS
   - Clone or upload the repository
   - Run the setup script to install all build dependencies (Go, Rust, Zig, Nim):
     ```bash
     chmod +x setup.sh
     ./setup.sh
     ```
   - Build the framework:
     ```bash
     ./build.sh
     ```
     - Enter your VPS IP when prompted
     - Enable TLS to generate self-signed certificates
   - Start the server:
     ```bash
     cd build
     ./server -port 9000 -listener 8443
     ```

4. **Option B: Build Locally**
   - Edit `implant/cmd/main.go` and set `ServerURL` to your VPS IP/URL (e.g. `https://YOUR_VPS_IP:8443/` if using TLS)
   - Build using `./build.sh` (enable TLS if desired)
   - SCP the `build/` directory and `BOFs/` directory to your VPS
   - SSH in and start the server

5. Access the web panel at `http://YOUR_VPS_IP:9000`
6. Run a stager on target x64 windows machine

### running locally

start the server:
```bash
./build/server -port 9000 -listener 8443 -db carved.db
```

flags:
- `-port` - API/web panel port (default: 9000)
- `-listener` - C2 listener port (default: 8443)
- `-db` - sqlite database path (default: carved.db)

the server provides:
- web panel on the API port (http://0.0.0.0:9000)
- C2 listener on the listener port for implant communications
- CLI interface for direct interaction

## commands

### filesystem
- `shell <command>` - execute cmd.exe command
- `powershell <command>` - execute powershell command
- `cd <path>` - change directory
- `pwd` - print working directory
- `ls [path]` - list directory contents
- `cat <file>` - read file contents
- `upload <path>` - upload file to implant (select file in ui)
- `download <path>` - download file from implant
- `mkdir <path>` - create directory
- `rm <path>` - remove file or directory

### process
- `ps` - list processes
- `kill <pid>` - kill process by pid

### info
- `whoami` - current user info
- `env` - environment variables

### credentials
- `hashdump` - dump sam hashes and lsa secrets (requires admin)
- `chrome` - extract chrome passwords, cookies, credit cards

### evasion
- `unhook` - unhook ntdll.dll (removes edr hooks by remapping clean ntdll from disk)

### shellcode execution
- `execute` - run shellcode with method selection:
  - `enclave` - uses LdrCallEnclave via mscoree.dll RWX heap + vdsutil.dll allocation
  - `indirect` - indirect syscalls with NtAllocateVirtualMemory + RtlCreateUserThread
  - `once` - uses RtlRunOnceExecuteOnce (synchronous, do NOT use shellcode that calls ExitProcess)

shellcode should not call ExitProcess or the implant will die.

### module loading
- `load_dll <url>` - reflectively load dll into current process (supports URL or embedded data)
- `load_pe <url>` - load and execute pe in memory (supports URL or embedded data, wipes PE headers, clears command line, hooks exit functions to ExitThread)
- `inject_dll <pid|process> [url]` - reflectively inject dll into remote process by PID or process name

### bof execution
- `bof` - execute beacon object file

bof files go in `BOFs/` directory on the server. the loader supports cobalt strike compatible bofs with dynamic function resolution (DLL$Function syntax).

## technical details

### api resolution

the implant uses manual api resolution via PEB walking and djb2 hash lookups. no static imports to suspicious apis. syscalls are resolved at runtime and called indirectly through ntdll gadgets using the go-wincall library.

### transport

**encryption:**

all C2 communications are encrypted using AES-256-GCM authenticated encryption:
- 32-byte (256-bit) pre-shared key configured at build time
- random 12-byte nonce generated per message and prepended to ciphertext
- authenticated encryption prevents tampering and ensures integrity
- encryption covers: registration, beacons, task results, and server responses

the encryption key is set via the build.sh script and generated with openssl

**http layer:**

WinHTTP apis resolved manually (no static imports):
- `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`
- `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpReadData`
- supports http and https (via WINHTTP_FLAG_SECURE)
- random user agent generated at compile time (unique per build)

### bof loader

the coff loader implements:
- x64 COFF parsing and section mapping
- relocation processing (IMAGE_REL_AMD64_ADDR64, REL32, ADDR32NB)
- dynamic import resolution via `DLL$Function` syntax
- GOT/BSS allocation for external symbols
- memory protection adjustment per section characteristics

**beacon api implementation:**

the bof loader uses `syscall.NewCallback` from Go's standard library to create Windows-callable function pointers for beacon apis. this was necessary because calling BOF code requires proper ABI translation between Go's calling convention and the Windows x64 ABI. rather than reimplementing the complex Go ABI -> OS ABI translation that `syscall.NewCallback` handles internally, we leverage it to create proper callback trampolines. all CS compatible BOFs should work, open an issue if you find something I missed!

### stagers

the stagers are tiny stage1 loaders available in multiple languages (C, Zig, Nim, Rust) that all:
1. download `implant.exe` from the `/implant` endpoint using WinHTTP
2. map the PE into memory manually (parse headers, copy sections, process relocations, resolve imports)
3. set proper memory protections per section
4. execute the entry point via `NtCreateThreadEx`

all memory operations use NT APIs (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`) for evasion. the stagers have no console window and minimal imports.

| stager | size | notes |
|--------|------|-------|
| stager_c.exe | ~10KB | smallest, mingw-w64 compiled |
| stager_zig.exe | ~10KB | comparable to C, no runtime |
| stager_nim.exe | ~137KB | larger due to nim runtime |
| stager_rust.exe | ~247KB | includes rust std library |

all stagers are functionally identical - choose based on your opsec requirements or toolchain preferences.

### pe/dll loader

reflective loader features:
- section mapping with proper alignment
- base relocation processing (type 3 and 10)
- import resolution with api-set schema support
- TLS callback execution
- remote process injection via NtWriteVirtualMemory
- DllMain invocation via shellcode stub

pe loader additionally:
- wipes PE headers after loading
- clears command line from PEB
- hooks exit functions (ExitProcess, exit, _exit, etc.) to ExitThread to prevent implant termination

### credential extraction

**sam/lsa dumping:**
- admin only, will fail gracefully if not admin :3
- direct NTFS parsing to read locked registry hives (SAM, SYSTEM, SECURITY)
- bootkey extraction from SYSTEM hive
- sam hash decryption (RC4/AES depending on version)
- lsa secret decryption including cached domain credentials, service account passwords, DPAPI keys

**chrome extraction:**
- scans chrome processes for open file handles to Cookies, Login Data, Web Data
- duplicates handles to read locked sqlite databases
- injects gobound.dll into chrome process
- gobound.dll uses Chrome's IElevator COM interface to decrypt the app-bound encryption key
- master key returned via named pipe
- decrypts v20 encrypted values using AES-GCM

### shellcode execution methods

**enclave method:**
1. load mscoree.dll and vdsutil.dll
2. get RWX heap from GetProcessExecutableHeap
3. allocate via VdsHeapAlloc
4. copy shellcode
5. execute via LdrCallEnclave

**indirect syscall method:**
1. NtAllocateVirtualMemory (PAGE_READWRITE)
2. copy shellcode
3. NtProtectVirtualMemory (PAGE_EXECUTE_READ)
4. RtlCreateUserThread

**runonce method:**
1. allocate and copy shellcode
2. execute via RtlRunOnceExecuteOnce
3. synchronous,blocks until completion

## database schema

sqlite database stores:
- `implants` - registered implants with metadata
- `tasks` - queued and completed tasks
- `listeners` - configured listeners
- `credentials` - extracted credentials

## web panel

single-page application with:
- implant management (list, interact, clear)
- task execution and output viewing
- listener management
- bof browser and execution
- shellcode upload and execution with method selection
- credential viewer
- results filtering by type (hashdump, chrome, shell, bof)

## credits

- [TrustedSec](https://github.com/trustedsec) - the BOFs in the `BOFs/` directory are from their [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) and [CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF) repos. huge thanks for the awesome open source tooling!

## dependencies

- [go-wincall](https://github.com/carved4/go-wincall) - windows api calls via indirect syscalls and manual resolution
- [go-chi/chi](https://github.com/go-chi/chi) - http router
- [modernc.org/sqlite](https://modernc.org/sqlite) - pure go sqlite driver
- [go-ese](https://github.com/Velocidex/go-ese) - ESE database parsing for NTDS.dit

## limitations

- C2 traffic is encrypted (AES-256-GCM) and supports HTTPS (via self-signed certs generated during build)
- implant is windows x64 only
- server is linux only (or windows with go1.24.11 for cross-compilation)
- no persistence mechanisms built in
- chrome extraction requires chrome to be running with the target databases open
- hashdump/lsasecrets requires running as admin/system
- bofs that crash usually have unhandled edge cases in argument parsing

## notes

- the web panel uses session cookies with 24 hour expiry
- web panel credentials are randomly generated on each server start (check console output)
- task results are base64 encoded in the API responses
- the server CLI and web panel can be used simultaneously
- implant generates a new UUID on each execution (no persistence)
- BOFs are served from the `BOFs/` directory relative to server working directory
- payloads (like gobound.dll and implant.exe) are served from the `payloads/` directory
- the `/implant` endpoint serves `payloads/implant.exe` for the stager

## contributing

contributions are welcome :3

feel free to open issues, submit pull requests, or just fork and do whatever you want with it. this project is meant for educational purposes and security research. if you add something cool, share it back!

some areas that could use love:
- https listener support (TLS termination on server side)
- additional evasion techniques
- more beacon api implementations
- persistence modules
- alternative transport protocols (DNS, SMB, etc.)

## project structure

```
carved/
├── build.sh                    # linux/mac build script
├── build.bat                   # windows build script
├── stager/
│   ├── stager.c                # C stager source
│   ├── stager.zig              # Zig stager source
│   ├── stager.nim              # Nim stager source
│   ├── stager.rs               # Rust stager source
│   ├── build.zig               # Zig build configuration
│   ├── Cargo.toml              # Rust build configuration
│   └── build.sh                # standalone stager build script (C only)
├── go.mod
├── utils/
│   └── genua/              # random user agent generator
├── shared/
│   ├── crypto/
│   │   └── crypto.go           # AES-256-GCM encryption/decryption
│   └── proto/
│       └── types.go            # shared types between server and implant
├── server/
│   ├── cmd/
│   │   └── main.go             # server entrypoint + CLI
│   └── pkg/
│       ├── api/
│       │   ├── router.go       # REST API routes
│       │   └── types.go        # API request/response types
│       ├── db/
│       │   ├── db.go           # sqlite operations
│       │   └── models.go       # database models
│       ├── listeners/
│       │   └── http.go         # C2 listener implementation
│       └── web/
│           └── panel.go        # embedded web panel HTML/JS/CSS
├── implant/
│   ├── cmd/
│   │   ├── main.go             # implant entrypoint
│   │   └── bof_test/
│   │       └── main.go         # standalone BOF tester
│   └── pkg/
│       ├── tasks/
│       │   ├── handlers.go     # task handler implementations
│       │   ├── registry.go     # handler registration
│       │   └── types.go        # task types
│       ├── transport/
│       │   ├── http.go         # WinHTTP transport
│       │   └── types.go        # transport interfaces
│       └── modules/
│           ├── loader/
│           │   ├── coff.go         # BOF/COFF loader
│           │   ├── coff_args.go    # BOF argument packing
│           │   ├── beacon_api.go   # beacon API callbacks (uses syscall.NewCallback)
│           │   ├── loader.go       # remote DLL injection
│           │   ├── pe-loader.go    # local PE/DLL loading
│           │   └── meltloader.go   # PE loading with cleanup
│           ├── shellcode/
│           │   └── shellcode.go    # shellcode execution methods
│           ├── exec/
│           │   └── exec.go         # command execution
│           ├── chrome/
│           │   └── chrome.go       # chrome credential extraction
│           └── creds/
│               ├── creds.go        # main dump functions
│               ├── sam.go          # SAM parsing
│               ├── lsa.go          # LSA secret parsing
│               ├── ntds.go         # NTDS.dit parsing
│               ├── ntfs.go         # raw NTFS reading
│               ├── registry.go     # registry hive parsing
│               ├── crypto.go       # decryption routines
│               ├── token.go        # token operations
│               ├── windows.go      # windows API wrappers
│               └── types.go        # credential types
└── gobound/
    └── dll/
        ├── main.go             # chrome key decryption DLL
        └── types.go            # COM/Windows types
```
