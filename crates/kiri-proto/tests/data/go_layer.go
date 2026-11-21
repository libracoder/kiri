// Writes go_layer.tar: entries filled in as containerd's ChangeWriter fills
// them (Format PAX, whole-second mtimes, no atime/ctime; whiteouts with no
// format, mode 0 and time 0), through Go's archive/tar. The Rust encoder in
// src/layertar.rs must give the same bytes (tests/layertar_go.rs).
//
//	go run go_layer.go > go_layer.tar
package main

import (
	"archive/tar"
	"os"
	"strings"
	"time"
)

func main() {
	tw := tar.NewWriter(os.Stdout)
	t := time.Unix(1700000000, 0)
	add := func(h *tar.Header, body string) {
		if h.Format == 0 && !strings.Contains(h.Name, ".wh.") {
			h.Format = tar.FormatPAX
		}
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
		if body != "" {
			if _, err := tw.Write([]byte(body)); err != nil {
				panic(err)
			}
		}
	}
	add(&tar.Header{Typeflag: tar.TypeDir, Name: "a/", Mode: 0o755, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeReg, Name: "a/hello.txt", Mode: 0o644, Size: 6, ModTime: t, Uid: 1000, Gid: 1000}, "hello\n")
	add(&tar.Header{Typeflag: tar.TypeSymlink, Name: "a/link", Linkname: "hello.txt", Mode: 0o777, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeLink, Name: "a/hard", Linkname: "a/hello.txt", Mode: 0o644, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeReg, Name: strings.Repeat("d", 120) + "/" + strings.Repeat("f", 50), Mode: 0o644, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeReg, Name: strings.Repeat("x", 130), Mode: 0o644, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeDir, Name: strings.Repeat("y", 110) + "/", Mode: 0o755, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeReg, Name: "café", Mode: 0o644, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeReg, Name: "usr/bin/ping", Mode: 0o4755, Size: 3, ModTime: t,
		PAXRecords: map[string]string{"SCHILY.xattr.security.capability": "\x01\x00\x00\x02\x00\x20\x00\x00"}}, "bin")
	add(&tar.Header{Typeflag: tar.TypeReg, Name: "big-uid", Mode: 0o600, Uid: 3000000, Gid: 5, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeReg, Name: "old", Mode: 0o644, ModTime: time.Unix(-5, 0)}, "")
	add(&tar.Header{Typeflag: tar.TypeChar, Name: "dev/null", Mode: 0o666, Devmajor: 1, Devminor: 3, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeFifo, Name: "pipe", Mode: 0o644, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeSymlink, Name: "longlink", Linkname: strings.Repeat("l", 150), Mode: 0o777, ModTime: t}, "")
	add(&tar.Header{Typeflag: tar.TypeDir, Name: "sticky/", Mode: 0o1777, ModTime: t}, "")
	w := time.Unix(0, 0).UTC()
	add(&tar.Header{Typeflag: tar.TypeReg, Name: "etc/.wh.gone", ModTime: w, AccessTime: w, ChangeTime: w}, "")
	if err := tw.Close(); err != nil {
		panic(err)
	}
}
