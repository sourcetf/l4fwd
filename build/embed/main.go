//go:build windows

// Command l4fwd-embed writes a Win32 application manifest and version resource
// into an already built l4fwd.exe.
//
// A manifest is what tells Windows to show the UAC prompt (requireAdministrator)
// and to treat the binary as DPI aware. Raw sockets, SIO_RCVALL capture and
// firewall rules all need administrator rights, so two manifests are shipped:
//
//	build/l4fwd.manifest       asInvoker      - TCP/UDP forwarding works, no UAC
//	build/l4fwd-admin.manifest requireAdmin   - everything works, UAC prompt
//
// Usage:
//
//	go run ./build/embed -exe bin/l4fwd.exe \
//	    -manifest build/l4fwd-admin.manifest \
//	    -version 1.0.0 -desc "l4fwd 四层端口转发工具"
//
// The executable must not be running while its resources are rewritten.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	beginUpdateResourceW = kernel32.NewProc("BeginUpdateResourceW")
	updateResourceW      = kernel32.NewProc("UpdateResourceW")
	endUpdateResourceW   = kernel32.NewProc("EndUpdateResourceW")
)

const (
	manifestResourceType = 24 // RT_MANIFEST
	versionResourceType  = 16 // RT_VERSION
	manifestResourceID   = 1  // CREATEPROCESS_MANIFEST_RESOURCE_ID
	versionResourceID    = 1  // VS_VERSION_INFO
	langUSEnglish        = 0x0409
	codepageUnicode      = 1200
)

func main() {
	exe := flag.String("exe", "bin/l4fwd.exe", "target executable")
	manifest := flag.String("manifest", "build/l4fwd.manifest", "manifest file to embed")
	version := flag.String("version", "1.0.0", "version, e.g. 1.0.0")
	desc := flag.String("desc", "l4fwd 四层端口转发工具", "FileDescription value")
	product := flag.String("product", "l4fwd", "ProductName value")
	flag.Parse()

	if _, err := os.Stat(*exe); err != nil {
		fatal("target not found: %v", err)
	}
	manifestData, err := os.ReadFile(*manifest)
	if err != nil {
		fatal("read manifest: %v", err)
	}
	versionData, err := buildVersionResource(*version, *desc, *product, filepath.Base(*exe))
	if err != nil {
		fatal("build version resource: %v", err)
	}

	pathPtr, err := windows.UTF16PtrFromString(*exe)
	if err != nil {
		fatal("path: %v", err)
	}
	handle, _, callErr := beginUpdateResourceW.Call(uintptr(unsafe.Pointer(pathPtr)), 0)
	if handle == 0 {
		fatal("BeginUpdateResource failed (is the exe running?): %v", callErr)
	}

	ok := updateResource(handle, manifestResourceType, manifestResourceID, manifestData)
	ok = updateResource(handle, versionResourceType, versionResourceID, versionData) && ok

	discard := uintptr(0)
	if !ok {
		discard = 1
	}
	if ret, _, err := endUpdateResourceW.Call(handle, discard); ret == 0 {
		fatal("EndUpdateResource failed: %v", err)
	}
	if !ok {
		fatal("resource update failed")
	}
	fmt.Printf("embedded manifest (%s) and version %s into %s\n",
		filepath.Base(*manifest), *version, *exe)
}

func updateResource(handle uintptr, resType, resID int, data []byte) bool {
	var ptr *byte
	if len(data) > 0 {
		ptr = &data[0]
	}
	ret, _, err := updateResourceW.Call(
		handle,
		uintptr(uint32(resType)),
		uintptr(uint32(resID)),
		uintptr(uint32(langUSEnglish)),
		uintptr(unsafe.Pointer(ptr)),
		uintptr(len(data)),
	)
	if ret == 0 {
		fmt.Fprintf(os.Stderr, "embed: UpdateResource(type=%d, id=%d) failed: %v\n", resType, resID, err)
		return false
	}
	return true
}

// ---------- VS_VERSIONINFO construction ----------

// block is a version resource node: a header, an optional fixed value and
// children. Lengths are patched once the whole tree is serialised.
type block struct {
	key         string
	valueLength int    // for string nodes: characters excluding the terminator
	value       []byte // raw value bytes (fixed info for the root, UTF-16 elsewhere)
	valueIsText bool
	children    []*block
}

func (b *block) marshal() []byte {
	buf := new(bytes.Buffer)

	// wLength placeholder, wValueLength, wType, szKey, padding.
	binary.Write(buf, binary.LittleEndian, uint16(0))
	valueLen := b.valueLength
	if valueLen == 0 && len(b.value) > 0 {
		valueLen = len(b.value)
	}
	binary.Write(buf, binary.LittleEndian, uint16(valueLen))
	wType := uint16(0)
	if b.valueIsText {
		wType = 1
	}
	binary.Write(buf, binary.LittleEndian, wType)
	writeUTF16Z(buf, b.key)
	pad4(buf)

	if len(b.value) > 0 {
		buf.Write(b.value)
		pad4(buf)
	}
	for _, child := range b.children {
		buf.Write(child.marshal())
	}

	out := buf.Bytes()
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(out)))
	return out
}

func textBlock(key, value string) *block {
	var v bytes.Buffer
	writeUTF16Z(&v, value)
	return &block{key: key, valueLength: len([]rune(value)) + 1, value: v.Bytes(), valueIsText: true}
}

func containerBlock(key string, children ...*block) *block {
	return &block{key: key, children: children}
}

func buildVersionResource(version, description, product, originalName string) ([]byte, error) {
	quad, err := parseVersionQuad(version)
	if err != nil {
		return nil, err
	}
	ms := uint32(quad[0])<<16 | uint32(quad[1])
	ls := uint32(quad[2])<<16 | uint32(quad[3])
	versionStr := fmt.Sprintf("%d.%d.%d.%d", quad[0], quad[1], quad[2], quad[3])

	// VS_FIXEDFILEINFO, 13 DWORDs.
	fixed := new(bytes.Buffer)
	for _, dw := range []uint32{
		0xFEEF04BD, // dwSignature
		0x00010000, // dwStrucVersion
		ms,         // dwFileVersionMS
		ls,         // dwFileVersionLS
		ms,         // dwProductVersionMS
		ls,         // dwProductVersionLS
		0x3F,       // dwFileFlagsMask
		0x00,       // dwFileFlags
		0x04,       // dwFileOS = VOS_NT_WINDOWS32
		0x01,       // dwFileType = VFT_APP
		0x00,       // dwFileSubtype
		0x00,       // dwFileDateMS
		0x00,       // dwFileDateLS
	} {
		binary.Write(fixed, binary.LittleEndian, dw)
	}

	// StringFileInfo/040904B0/<pairs>
	langPage := fmt.Sprintf("%04X%04X", langUSEnglish, codepageUnicode)
	table := containerBlock(langPage,
		textBlock("CompanyName", "l4fwd"),
		textBlock("FileDescription", description),
		textBlock("FileVersion", versionStr),
		textBlock("InternalName", "l4fwd"),
		textBlock("OriginalFilename", originalName),
		textBlock("ProductName", product),
		textBlock("ProductVersion", versionStr),
	)
	stringFileInfo := containerBlock("StringFileInfo", table)

	// VarFileInfo/Translation/<lang, codepage>
	translation := new(bytes.Buffer)
	binary.Write(translation, binary.LittleEndian, uint32(langUSEnglish))
	binary.Write(translation, binary.LittleEndian, uint32(codepageUnicode))
	varFileInfo := containerBlock("VarFileInfo", &block{key: "Translation", value: translation.Bytes()})

	root := &block{
		key:         "VS_VERSION_INFO",
		valueLength: len(fixed.Bytes()), // bytes of VS_FIXEDFILEINFO
		value:       fixed.Bytes(),
		children:    []*block{stringFileInfo, varFileInfo},
	}
	return root.marshal(), nil
}

func parseVersionQuad(version string) ([4]uint16, error) {
	var quad [4]uint16
	parts := strings.Split(version, ".")
	if len(parts) > 4 {
		return quad, fmt.Errorf("version %q has too many parts", version)
	}
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16)
		if err != nil {
			return quad, fmt.Errorf("version %q: %w", version, err)
		}
		quad[i] = uint16(n)
	}
	return quad, nil
}

func writeUTF16Z(buf *bytes.Buffer, s string) {
	for _, r := range s {
		binary.Write(buf, binary.LittleEndian, uint16(r))
	}
	binary.Write(buf, binary.LittleEndian, uint16(0))
}

func pad4(buf *bytes.Buffer) {
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "embed: "+format+"\n", args...)
	os.Exit(1)
}
