#!/usr/bin/env bash
# 运行全部测试：单元测试 + 集成测试（TCP/UDP 真实收发）。
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

echo "==> go vet"
go vet ./...

echo "==> 单元测试 (netutil / config / engine)"
go test ./internal/... -count=1

echo "==> 集成测试 (真实 TCP/UDP 收发)"
go test ./internal/engine/ -count=1 -run 'TestTCP|TestUDP|TestListener' -v

echo "==> 全部测试通过"
