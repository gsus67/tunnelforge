// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows

package main

import webview "github.com/webview/webview_go"

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
	w.SetTitle("Conectar Gateway WISP")
	w.SetSize(1060, 940, webview.HintNone) // cabe todo el contenido sin estirar
	w.SetSize(880, 680, webview.HintMin)   // minimo razonable
	w.Navigate(url)
	w.Run() // bloquea; al cerrar la ventana, retorna y la app termina
}
