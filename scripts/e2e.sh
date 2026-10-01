#!/usr/bin/env bash
# 端到端测试：启动真实的 l4fwd.exe，用真实报文验证 TCP/UDP/RAW 转发与网页面板。
#
# RAW 测试需要在某个网卡上额外配置两个别名地址（客户端与目标各一个），
# 比如网卡 external 当前是 172.16.0.32/12，就加 172.16.0.40 与 172.16.0.41：
#
#   powershell -ExecutionPolicy Bypass -File scripts/e2e-aliases.ps1 -Add
#
# 运行结束后可用 -Remove 清理别名地址。
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

# 从当前网卡地址推断一个可用的 /24 网段用于别名（默认沿用 172.16.0.0/24）。
export L4FWD_E2E_CLIENT="${L4FWD_E2E_CLIENT:-172.16.0.40}"
export L4FWD_E2E_LISTEN="${L4FWD_E2E_LISTEN:-172.16.0.32}"
export L4FWD_E2E_TARGET="${L4FWD_E2E_TARGET:-172.16.0.41}"
export L4FWD_BIN="${L4FWD_BIN:-$(pwd)/bin/l4fwd.exe}"

if [ ! -x "$L4FWD_BIN" ]; then
  echo "找不到 $L4FWD_BIN，先执行 scripts/build.sh" >&2
  exit 1
fi

echo "==> 端到端测试 (client=$L4FWD_E2E_CLIENT listen=$L4FWD_E2E_LISTEN target=$L4FWD_E2E_TARGET)"
go test ./test/e2e/ -count=1 -timeout 300s -v "$@"
