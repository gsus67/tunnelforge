//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32Update         = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFreeUpdate    = kernel32Update.NewProc("LocalFree")
)

func blobDe(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}
func bytesBlob(b dataBlob) []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	src := unsafe.Slice(b.pbData, int(b.cbData))
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

func protegerSecretoSistema(plano []byte) ([]byte, error) {
	in := blobDe(plano)
	entBytes := []byte("gateway-wisp-access/github-update-token/v1")
	ent := blobDe(entBytes)
	var out dataBlob
	r, _, e := procCryptProtectData.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %v", e)
	}
	defer procLocalFreeUpdate.Call(uintptr(unsafe.Pointer(out.pbData)))
	return bytesBlob(out), nil
}
func desprotegerSecretoSistema(protegido []byte) ([]byte, error) {
	in := blobDe(protegido)
	entBytes := []byte("gateway-wisp-access/github-update-token/v1")
	ent := blobDe(entBytes)
	var out dataBlob
	r, _, e := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %v", e)
	}
	defer procLocalFreeUpdate.Call(uintptr(unsafe.Pointer(out.pbData)))
	return bytesBlob(out), nil
}
