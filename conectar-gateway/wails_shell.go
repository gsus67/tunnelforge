// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"

	wails "github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// La UI de producción se compila desde TypeScript a frontend/dist.
// Wails la embebe en el ejecutable; no se abre un navegador ni se sirve la UI
// por el puerto HTTP local. El listener loopback queda únicamente para el
// WebSocket del terminal y compatibilidad interna de la API.
//
//go:embed all:frontend/dist
var frontendAssets embed.FS

type AppBridge struct {
	token  string
	wsBase string
}

// GetRuntimeConfig entrega únicamente los datos efímeros que necesita la UI.
// El token nunca se guarda en el frontend ni se escribe en el backup.
func (a *AppBridge) GetRuntimeConfig() map[string]string {
	return map[string]string{
		"token":   a.token,
		"wsBase":  a.wsBase,
		"version": version,
	}
}

func mostrarVentana(token, wsBase string, apiHandler http.Handler) {
	uiAssets, err := fs.Sub(frontendAssets, "frontend/dist")
	if err != nil {
		fmt.Println("ERROR: no se pudo abrir la UI embebida:", err)
		return
	}
	bridge := &AppBridge{token: token, wsBase: wsBase}
	err = wails.Run(&options.App{
		Title:     "Gateway WISP Access",
		Width:     1440,
		Height:    810,
		MinWidth:  1100,
		MinHeight: 680,
		AssetServer: &assetserver.Options{
			Assets:  uiAssets,
			Handler: apiHandler,
		},
		BackgroundColour: &options.RGBA{R: 5, G: 16, B: 29, A: 255},
		Bind:             []interface{}{bridge},
	})
	if err != nil {
		fmt.Println("ERROR: Wails no pudo iniciar la ventana:", err)
	}
}
