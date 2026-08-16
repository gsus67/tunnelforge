// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows

package main

import (
	"syscall"
	"time"
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
	w.SetSize(1100, 680, webview.HintMin)   // mínimo funcional; debajo se adapta a una columna
	w.Navigate(url)
	go centrarVentanaWindows(titulo)
	w.Run() // bloquea; al cerrar la ventana, retorna y la app termina
}
