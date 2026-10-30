#!/usr/bin/env bash
# 端到端测试：启动真实的 l4fwd 二进制，用真实报文验证 TCP/UDP/RAW 转发与网页面板。
#
# Windows 的 RAW 用例需要两个别名地址（客户端 / 目标，SIO_RCVALL 不抓回环流量）：
#
#   powershell -ExecutionPolicy Bypass -File scripts/e2e-aliases.ps1 -Add
#
# Linux / OpenBSD 直接把 127.0.0.0/8 当本机地址，默认用 127.0.0.2 与 127.0.0.3，
# 不需要额外配置；原始套接字需要 root（CI 用 sudo 运行本脚本）。
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

HOST_OS="$(go env GOOS)"
if [ "$HOST_OS" = "windows" ]; then
  export L4FWD_E2E_CLIENT="${L4FWD_E2E_CLIENT:-172.16.0.40}"
  export L4FWD_E2E_LISTEN="${L4FWD_E2E_LISTEN:-172.16.0.32}"
  export L4FWD_E2E_TARGET="${L4FWD_E2E_TARGET:-172.16.0.41}"
  default_bin="$(pwd)/bin/l4fwd.exe"
else
  export L4FWD_E2E_CLIENT="${L4FWD_E2E_CLIENT:-127.0.0.2}"
  export L4FWD_E2E_LISTEN="${L4FWD_E2E_LISTEN:-127.0.0.1}"
  export L4FWD_E2E_TARGET="${L4FWD_E2E_TARGET:-127.0.0.3}"
  default_bin="$(pwd)/bin/l4fwd"
fi
export L4FWD_BIN="${L4FWD_BIN:-$default_bin}"

if [ ! -x "$L4FWD_BIN" ]; then
  echo "找不到 $L4FWD_BIN，先执行 scripts/build.sh" >&2
  exit 1
fi

echo "==> 端到端测试 (client=$L4FWD_E2E_CLIENT listen=$L4FWD_E2E_LISTEN target=$L4FWD_E2E_TARGET)"
go test ./test/e2e/ -count=1 -timeout 600s -v "$@"
