#!/usr/bin/env bash
# 构建 l4fwd。
#
# 默认构建当前系统；交叉编译时设置 TARGET_OS / TARGET_ARCH：
#
#   TARGET_OS=linux  bash scripts/build.sh
#   TARGET_OS=openbsd bash scripts/build.sh
#
# 产物：
#   Windows:
#     bin/l4fwd.exe        普通版（asInvoker，不弹 UAC）：TCP/UDP 转发开箱可用
#     bin/l4fwd-admin.exe  全功能版（requireAdministrator，弹 UAC）：额外支持 RAW
#                          原始套接字与混杂捕获
#     bin/rawtest.exe      原始套接字抓包/发包测试工具（WITH_TOOLS=1 时构建）
#   Linux / OpenBSD:
#     bin/l4fwd            单文件，无 UAC 概念；RAW 需要 root 或 CAP_NET_RAW
#     bin/rawtest
#   交叉编译时产物带 -<os>-<arch> 后缀，避免覆盖本机构建。
set -euo pipefail

cd "$(dirname "$0")/.."
source ./env.sh

HOST_OS="$(go env GOOS)"
HOST_ARCH="$(go env GOARCH)"
TARGET_OS="${TARGET_OS:-$HOST_OS}"
TARGET_ARCH="${TARGET_ARCH:-$HOST_ARCH}"

VERSION="${VERSION:-1.0.0}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
BUILDTIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X l4fwd/internal/version.Version=${VERSION} -X l4fwd/internal/version.Commit=${COMMIT} -X l4fwd/internal/version.BuildTime=${BUILDTIME}"

SUFFIX=""
if [ "$TARGET_OS" != "$HOST_OS" ] || [ "$TARGET_ARCH" != "$HOST_ARCH" ]; then
  SUFFIX="-${TARGET_OS}-${TARGET_ARCH}"
fi

export GOOS="$TARGET_OS"
export GOARCH="$TARGET_ARCH"
export CGO_ENABLED=0

mkdir -p bin

build() {
  # build <output> <package>
  echo "==> go build -o $1 $2"
  go build -trimpath -ldflags "${LDFLAGS}" -o "$1" "$2"
}

if [ "$TARGET_OS" = "windows" ]; then
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

  echo "==> 构建 l4fwd${SUFFIX}.exe / l4fwd-admin${SUFFIX}.exe (version=${VERSION} commit=${COMMIT} 资源版本=${RESOURCE_VERSION})"
  build "bin/l4fwd${SUFFIX}.exe" ./cmd/l4fwd
  build "bin/l4fwd-admin${SUFFIX}.exe" ./cmd/l4fwd

  # 清单与版本资源只能在本机（Windows）写入；交叉编译时跳过，产物仍可运行，
  # 只是不会弹 UAC。
  if [ "$HOST_OS" = "windows" ]; then
    echo "==> 嵌入清单与版本资源"
    go run ./build/embed -exe "bin/l4fwd${SUFFIX}.exe"       -manifest build/l4fwd.manifest       -version "${RESOURCE_VERSION}"
    go run ./build/embed -exe "bin/l4fwd-admin${SUFFIX}.exe" -manifest build/l4fwd-admin.manifest -version "${RESOURCE_VERSION}"
  else
    echo "==> 跳过清单嵌入（交叉编译）"
  fi

  if [ "${WITH_TOOLS:-1}" = "1" ]; then
    echo "==> 构建 rawtest${SUFFIX}.exe（原始套接字抓包/发包测试工具）"
    go build -trimpath -o "bin/rawtest${SUFFIX}.exe" ./tools/rawtest
  fi
else
  echo "==> 构建 l4fwd${SUFFIX} (${TARGET_OS}/${TARGET_ARCH}, version=${VERSION} commit=${COMMIT})"
  build "bin/l4fwd${SUFFIX}" ./cmd/l4fwd
  if [ "${WITH_TOOLS:-1}" = "1" ]; then
    echo "==> 构建 rawtest${SUFFIX}"
    go build -trimpath -o "bin/rawtest${SUFFIX}" ./tools/rawtest
  fi
fi

echo "==> 完成："
ls -la bin/
