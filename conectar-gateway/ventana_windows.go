// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procFindWindowW      = user32.NewProc("FindWindowW")
	comdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetSaveFileNameW = comdlg32.NewProc("GetSaveFileNameW")
	procCommDlgError     = comdlg32.NewProc("CommDlgExtendedError")
)

type openFileNameW struct {
	LStructSize       uint32
	HwndOwner         uintptr
	HInstance         uintptr
	LpstrFilter       *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpstrFile         *uint16
	NMaxFile          uint32
	LpstrFileTitle    *uint16
	NMaxFileTitle     uint32
	LpstrInitialDir   *uint16
	LpstrTitle        *uint16
	Flags             uint32
	NFileOffset       uint16
	NFileExtension    uint16
	LpstrDefExt       *uint16
	LCustData         uintptr
	LpfnHook          uintptr
	LpTemplateName    *uint16
	PvReserved        uintptr
	DwReserved        uint32
	FlagsEx           uint32
}

// seleccionarDestinoCopia abre el diálogo nativo "Guardar como". Así la
// exportación no decide por el usuario dónde dejar la copia.
func seleccionarDestinoCopia(nombre string) (string, bool, error) {
	const (
		ofnOverwritePrompt = 0x00000002
		ofnNoChangeDir     = 0x00000008
		ofnPathMustExist   = 0x00000800
		ofnExplorer        = 0x00080000
	)

	var archivo [32768]uint16
	inicial, err := syscall.UTF16FromString(nombre)
	if err != nil {
		return "", false, err
	}
	copy(archivo[:], inicial)

	// GetSaveFileNameW exige pares descripción/patrón separados por NUL y un
	// NUL doble al final; por eso no se usa UTF16PtrFromString para el filtro.
	filtro := utf16.Encode([]rune("Copia TunnelForge (*.cgw)\x00*.cgw\x00Todos los archivos (*.*)\x00*.*\x00\x00"))
	titulo, _ := syscall.UTF16PtrFromString("Guardar copia de TunnelForge")
	dir, _ := syscall.UTF16PtrFromString(carpetaDescargas())
	ext, _ := syscall.UTF16PtrFromString("cgw")

	var owner uintptr
	if t, e := syscall.UTF16PtrFromString("TunnelForge"); e == nil {
		owner, _, _ = procFindWindowW.Call(0, uintptr(unsafe.Pointer(t)))
	}

	of := openFileNameW{
		HwndOwner:       owner,
		LpstrFilter:     &filtro[0],
		NFilterIndex:    1,
		LpstrFile:       &archivo[0],
		NMaxFile:        uint32(len(archivo)),
		LpstrInitialDir: dir,
		LpstrTitle:      titulo,
		Flags:           ofnOverwritePrompt | ofnNoChangeDir | ofnPathMustExist | ofnExplorer,
		LpstrDefExt:     ext,
	}
	of.LStructSize = uint32(unsafe.Sizeof(of))

	ok, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&of)))
	if ok == 0 {
		codigo, _, _ := procCommDlgError.Call()
		if codigo == 0 {
			return "", true, nil // Cancelar no es un error.
		}
		return "", false, fmt.Errorf("el selector de destino falló (código Windows 0x%X)", codigo)
	}
	ruta := syscall.UTF16ToString(archivo[:])
	if filepath.Ext(ruta) == "" {
		ruta += ".cgw"
	}
	return ruta, false, nil
}

// seleccionarDestinoWireGuard abre Guardar como para exportar un perfil .conf.
func seleccionarDestinoWireGuard(nombre string) (string, bool, error) {
	const (
		ofnOverwritePrompt = 0x00000002
		ofnNoChangeDir     = 0x00000008
		ofnPathMustExist   = 0x00000800
		ofnExplorer        = 0x00080000
	)
	var archivo [32768]uint16
	inicial, err := syscall.UTF16FromString(nombre)
	if err != nil {
		return "", false, err
	}
	copy(archivo[:], inicial)
	filtro := utf16.Encode([]rune("Configuración WireGuard (*.conf)\x00*.conf\x00Todos los archivos (*.*)\x00*.*\x00\x00"))
	titulo, _ := syscall.UTF16PtrFromString("Exportar perfil WireGuard")
	dir, _ := syscall.UTF16PtrFromString(carpetaDescargas())
	ext, _ := syscall.UTF16PtrFromString("conf")
	var owner uintptr
	if t, e := syscall.UTF16PtrFromString("TunnelForge"); e == nil {
		owner, _, _ = procFindWindowW.Call(0, uintptr(unsafe.Pointer(t)))
	}
	of := openFileNameW{HwndOwner: owner, LpstrFilter: &filtro[0], NFilterIndex: 1, LpstrFile: &archivo[0], NMaxFile: uint32(len(archivo)), LpstrInitialDir: dir, LpstrTitle: titulo, Flags: ofnOverwritePrompt | ofnNoChangeDir | ofnPathMustExist | ofnExplorer, LpstrDefExt: ext}
	of.LStructSize = uint32(unsafe.Sizeof(of))
	ok, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&of)))
	if ok == 0 {
		codigo, _, _ := procCommDlgError.Call()
		if codigo == 0 {
			return "", true, nil
		}
		return "", false, fmt.Errorf("el selector de destino falló (código Windows 0x%X)", codigo)
	}
	ruta := syscall.UTF16ToString(archivo[:])
	if strings.ToLower(filepath.Ext(ruta)) != ".conf" {
		ruta += ".conf"
	}
	return ruta, false, nil
}
