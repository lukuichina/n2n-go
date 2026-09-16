#!/bin/bash
# 静态编译脚本 — 无 CGO 依赖，产出纯静态二进制
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="/usr/local/go/bin:$PATH"
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

echo "=== Building for Linux (static, amd64) ==="
mkdir -p build_linux
go build -ldflags="-s -w" -o build_linux/ ./cmd/edge/ ./cmd/supernode/ ./cmd/benchmark/

echo ""
echo "=== Building for Windows (static, amd64) ==="
mkdir -p build_win
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o build_win/ ./cmd/edge/ ./cmd/supernode/ ./cmd/benchmark/

echo ""
echo "=== Done ==="
ls -lh build_linux/
echo ""
ls -lh build_win/