//go:build !windows

package main

// En Linux/macOS: abrir el navegador y mantener el servidor vivo.
func mostrarVentana(url string) {
	abrirNavegador(url)
	select {}
}
