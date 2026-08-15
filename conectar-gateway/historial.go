// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)

package main

// Historial de comandos enviados por el terminal, por servidor. Se captura
// del lado de la interfaz (líneas completas terminadas en Enter) y se
// persiste aquí para que sobreviva entre sesiones. No interfiere con el
// historial nativo de la shell remota (flechas arriba/abajo siguen siendo
// del propio bash del servidor).

import (
	"encoding/json"
	"net/http"
	"os"
)

const maxHistorialPorServidor = 30

func rutaHistorial() string { return rutaJunto("historial.json") }

func cargarHistorial() map[string][]string {
	h := map[string][]string{}
	if datos, err := os.ReadFile(rutaHistorial()); err == nil {
		_ = json.Unmarshal(datos, &h)
	}
	return h
}

func guardarHistorial(h map[string][]string) error {
	datos, _ := json.MarshalIndent(h, "", "  ")
	return os.WriteFile(rutaHistorial(), datos, 0600)
}

func manejarHistorial(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	switch r.Method {
	case "GET":
		nombre := r.URL.Query().Get("nombre")
		h := cargarHistorial()
		responder(w, h[nombre])
	case "POST":
		var pet struct{ Nombre, Comando string }
		if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
			responderError(w, err)
			return
		}
		if pet.Nombre == "" || pet.Comando == "" {
			responder(w, map[string]any{"ok": true})
			return
		}
		h := cargarHistorial()
		lista := h[pet.Nombre]
		// evitar duplicado inmediato consecutivo
		if len(lista) == 0 || lista[len(lista)-1] != pet.Comando {
			lista = append(lista, pet.Comando)
		}
		if len(lista) > maxHistorialPorServidor {
			lista = lista[len(lista)-maxHistorialPorServidor:]
		}
		h[pet.Nombre] = lista
		if err := guardarHistorial(h); err != nil {
			responderError(w, err)
			return
		}
		responder(w, map[string]any{"ok": true})
	case "DELETE":
		nombre := r.URL.Query().Get("nombre")
		h := cargarHistorial()
		delete(h, nombre)
		if err := guardarHistorial(h); err != nil {
			responderError(w, err)
			return
		}
		responder(w, map[string]any{"ok": true})
	}
}
