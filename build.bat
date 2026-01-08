@echo off
echo [*] Building carved C2 framework...

REM Use go1.24.11 for cross-compilation (default go only does win x64)
if "%GO_CMD%"=="" set GO_CMD=go1.24.11

if not exist build\payloads mkdir build\payloads

echo [*] Building gobound.dll...
cd payloads\gobound
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=1
go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o ..\..\build\payloads\gobound.dll
cd ..\..

echo [*] Building server (using %GO_CMD%)...
cd server\cmd
set GOOS=windows
%GO_CMD% build -ldflags="-s -w" -trimpath -o ..\..\build\server.exe
cd ..\..

echo [*] Building implant...
cd implant\cmd
go build -ldflags="-s -w -H windowsgui" -trimpath -o ..\..\build\implant.exe
cd ..\..

echo [+] Build complete!
echo     build\server.exe       - Team server
echo     build\implant.exe      - Windows implant
echo     build\payloads\        - DLLs for injection

