// Command l4fwd is a layer 4 and raw IP port forwarder for Windows, Linux and
// OpenBSD: it listens on local ports and relays traffic at layer 4 (TCP/UDP),
// and can also relay arbitrary IP protocols through raw sockets so that custom,
// non-TCP/UDP protocols work.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"l4fwd/internal/cli"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	cfgPath := flag.String("c", "", "配置文件路径 (默认: 程序目录/config.json)")
	flag.StringVar(cfgPath, "config", "", "配置文件路径 (同 -c)")
	listen := flag.String("listen", "", "临时添加一条 TCP/UDP 转发：<本地端口> 或 <监听地址:端口>")
	target := flag.String("target", "", "临时规则的目标：<目标地址:端口> 或 <ip>")
	kind := flag.String("type", "tcp", "临时规则类型：tcp | udp | raw")
	proto := flag.String("proto", "", "-type=raw 时的协议：47 / gre / 200，或 all = 全部协议（TCP+UDP+其余所有 IP 协议）")
	web := flag.String("web", "", "覆盖面板监听地址，例如 127.0.0.1:8686 或关闭：off")
	noBrowser := flag.Bool("no-browser", false, "不自动打开浏览器面板")
	level := flag.String("log-level", "", "日志级别：debug | info | warn | error")
	logFile := flag.String("log-file", "", "日志文件路径（留空则只输出到控制台）")
	showVersion := flag.Bool("version", false, "显示版本并退出")
	fw := flag.Bool("firewall", false, "为当前规则创建 Windows 防火墙入站放行规则（仅 Windows，需管理员）")
	readOnly := flag.Bool("read-only", false, "面板只读模式：禁止通过网页修改规则")
	check := flag.Bool("check", false, "只校验配置文件的合法性并退出")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println(cli.VersionString())
		return
	}

	opts := cli.Options{
		ConfigPath:  resolveConfigPath(*cfgPath),
		ListenSpec:  *listen,
		TargetSpec:  *target,
		Kind:        *kind,
		Protocol:    *proto,
		WebOverride: *web,
		NoBrowser:   *noBrowser,
		LogLevel:    *level,
		LogFile:     *logFile,
		Firewall:    *fw,
		ReadOnly:    *readOnly,
		CheckOnly:   *check,
	}
	if err := cli.Run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "错误: "+err.Error())
		os.Exit(1)
	}
}

// resolveConfigPath picks the config file: explicit flag wins, otherwise a
// config.json next to the executable (falling back to the working directory).
func resolveConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, "config.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		// Keep data next to the binary when the directory is writable.
		if writable(dir) {
			return candidate
		}
	}
	if wd, err := os.Getwd(); err == nil && writable(wd) {
		return filepath.Join(wd, "config.json")
	}
	fallback := os.TempDir()
	return filepath.Join(fallback, "config.json")
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".l4fwd-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func usage() {
	exe := filepath.Base(os.Args[0])
	var b strings.Builder
	fmt.Fprintf(&b, "%s - 四层端口转发 / 原始套接字任意协议转发（Windows / Linux / OpenBSD）\n\n", exe)
	fmt.Fprintf(&b, "用法:\n")
	fmt.Fprintf(&b, "  %s [选项]\n\n", exe)
	fmt.Fprintf(&b, "常用示例:\n")
	fmt.Fprintf(&b, "  %s                                    启动并打开网页面板，在面板里管理规则\n", exe)
	fmt.Fprintf(&b, "  %s -listen 8080 -target 192.168.1.10:80       把本机 8080 转发到 192.168.1.10:80 (TCP)\n", exe)
	fmt.Fprintf(&b, "  %s -type udp -listen 5353 -target 10.0.0.5:5353   转发 UDP 5353\n", exe)
	fmt.Fprintf(&b, "  %s -type raw -proto 47 -target 10.0.0.9       转发 GRE(47) 协议到 10.0.0.9\n", exe)
	fmt.Fprintf(&b, "  %s -type raw -proto 200 -listen 0.0.0.0 -target 10.0.0.9   转发自定义协议 200\n", exe)
	fmt.Fprintf(&b, "  %s -type raw -proto all -listen 19001 -target 10.0.0.9:19001  一个端口收 TCP/UDP/任意协议\n", exe)
	fmt.Fprintf(&b, "  %s -firewall                          为配置里所有端口添加 Windows 防火墙放行规则（仅 Windows）\n\n", exe)
	fmt.Fprintf(&b, "选项:\n")
	flag.PrintDefaults()
}
