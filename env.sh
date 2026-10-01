#!/usr/bin/env bash
# 设置 Go 工具链环境。
#
# 本机开发时优先使用项目自带的工具链（_tools/go，不污染系统 PATH）；
# CI 或已经装好 Go 的机器上直接用系统 Go。两条路径都不需要手工改脚本。
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -x "$_here/_tools/go/bin/go" ] || [ -x "$_here/_tools/go/bin/go.exe" ]; then
  export GOROOT="$_here/_tools/go"
  export GOPATH="$_here/_tools/gopath"
  export GOCACHE="$_here/_tools/gocache"
  export GOMODCACHE="$GOPATH/pkg/mod"
  export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
fi

# 国内镜像优先，然后是官方代理（CI 上 goproxy.cn 不通时会自动回退）。
export GOPROXY="${GOPROXY:-https://goproxy.cn,https://proxy.golang.org,direct}"
export GOFLAGS="${GOFLAGS:--mod=mod}"

unset _here
