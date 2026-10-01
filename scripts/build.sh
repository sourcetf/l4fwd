#!/usr/bin/env bash
# 构建 l4fwd。
#
# 产物：
#   bin/l4fwd.exe        普通版（asInvoker，不弹 UAC）：TCP/UDP 转发开箱可用
#   bin/l4fwd-admin.exe  全功能版（requireAdministrator，弹 UAC）：额外支持 RAW 原始套接字
#                        与混杂捕获；也可直接对 bin/l4fwd.exe 使用 -firewall 前手动提权
#   bin/rawtest.exe      原始套接字抓包/发包测试工具（WITH_TOOLS=1 时构建）
set -euo pipefail

cd "$(dirname "$0")/.."
source ./env.sh

VERSION="${VERSION:-1.0.0}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
BUILDTIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X l4fwd/internal/version.Version=${VERSION} -X l4fwd/internal/version.Commit=${COMMIT} -X l4fwd/internal/version.BuildTime=${BUILDTIME}"

# Windows 的版本资源必须是纯数字四段（a.b.c.d），而发布用的版本串可能带前缀或
# 后缀（v1.2.3、1.2.3-rc1、0.0.0-latest）。这里只给资源用归一化后的四段，
# 二进制里 -ldflags 写入的仍是完整版本串（面板上显示的那个）。
RESOURCE_VERSION="$(
  printf '%s' "${VERSION#v}" |
    awk -F'[.-]' '{ printf "%d.%d.%d.%d", ($1+0), ($2+0), ($3+0), ($4+0) }'
)"
if ! printf '%s' "$RESOURCE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  RESOURCE_VERSION="0.0.0.0"
fi

mkdir -p bin
echo "==> 构建 l4fwd.exe / l4fwd-admin.exe (version=${VERSION} commit=${COMMIT} 资源版本=${RESOURCE_VERSION})"
go build -trimpath -ldflags "${LDFLAGS}" -o bin/l4fwd.exe ./cmd/l4fwd
go build -trimpath -ldflags "${LDFLAGS}" -o bin/l4fwd-admin.exe ./cmd/l4fwd

echo "==> 嵌入清单与版本资源"
go run ./build/embed -exe bin/l4fwd.exe       -manifest build/l4fwd.manifest       -version "${RESOURCE_VERSION}"
go run ./build/embed -exe bin/l4fwd-admin.exe -manifest build/l4fwd-admin.manifest -version "${RESOURCE_VERSION}"

if [ "${WITH_TOOLS:-1}" = "1" ]; then
  echo "==> 构建 rawtest.exe（原始套接字抓包/发包测试工具）"
  go build -trimpath -o bin/rawtest.exe ./tools/rawtest
fi

echo "==> 完成："
ls -la bin/
