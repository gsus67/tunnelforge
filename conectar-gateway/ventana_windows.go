// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	webview "github.com/webview/webview_go"
)

const (
	smCXScreen    = 0
	smCYScreen    = 1
	swpNoSize     = 0x0001
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010
)

type winRect struct {
	Left, Top, Right, Bottom int32
}

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procFindWindowW      = user32.NewProc("FindWindowW")
	procGetWindowRect    = user32.NewProc("GetWindowRect")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	comdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetSaveFileNameW = comdlg32.NewProc("GetSaveFileNameW")
	procCommDlgError     = comdlg32.NewProc("CommDlgExtendedError")
)

// centrarVentanaWindows localiza la ventana nativa por su título y la centra
// en la pantalla principal. Se reintenta brevemente porque WebView2 termina de
// crear el HWND de forma asíncrona al arrancar el bucle de mensajes.
func centrarVentanaWindows(titulo string) {
	pTitulo, err := syscall.UTF16PtrFromString(titulo)
	if err != nil {
		return
	}
	for i := 0; i < 40; i++ {
		hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(pTitulo)))
		if hwnd != 0 {
			var r winRect
			ok, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
			if ok != 0 {
				ancho := int(r.Right - r.Left)
				alto := int(r.Bottom - r.Top)
				pantallaW, _, _ := procGetSystemMetrics.Call(smCXScreen)
				pantallaH, _, _ := procGetSystemMetrics.Call(smCYScreen)
				x := (int(pantallaW) - ancho) / 2
				y := (int(pantallaH) - alto) / 2
				if x < 0 {
					x = 0
				}
				if y < 0 {
					y = 0
				}
				procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoZOrder|swpNoActivate)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// mostrarVentana abre la interfaz en una ventana nativa de Windows
// (WebView2, componente que Windows 10/11 ya incluye). Si fallara,
// cae al navegador. Bloquea hasta que el usuario cierra la ventana.
func mostrarVentana(url string) {
	defer func() {
		if r := recover(); r != nil {
			abrirNavegador(url)
			select {} // mantener la app viva sirviendo la interfaz
		}
	}()
	w := webview.New(false)
	if w == nil {
		abrirNavegador(url)
		select {}
	}
	defer w.Destroy()
	const titulo = "Conectar Gateway WISP"
	w.SetTitle(titulo)
	w.SetSize(1440, 810, webview.HintNone) // dashboard en dos columnas, cercano al mockup
	w.SetSize(1100, 680, webview.HintMin)  // mínimo funcional; debajo se adapta a una columna
	w.Navigate(url)
	go centrarVentanaWindows(titulo)
	w.Run() // bloquea; al cerrar la ventana, retorna y la app termina
}

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
	filtro := utf16.Encode([]rune("Copia Gateway (*.cgw)\x00*.cgw\x00Todos los archivos (*.*)\x00*.*\x00\x00"))
	titulo, _ := syscall.UTF16PtrFromString("Guardar copia de Gateway WISP Access")
	dir, _ := syscall.UTF16PtrFromString(carpetaDescargas())
	ext, _ := syscall.UTF16PtrFromString("cgw")

	var owner uintptr
	if t, e := syscall.UTF16PtrFromString("Conectar Gateway WISP"); e == nil {
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
