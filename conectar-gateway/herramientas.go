// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const carpetaScriptsRemota = "/tmp/gateway-wisp-access/scripts"

// manejarEjecutarScript sube un script local al servidor conectado mediante
// el canal SFTP existente y devuelve el comando que la terminal integrada
// ejecutará de forma visible. El script queda en una carpeta privada temporal.
func manejarEjecutarScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var pet struct {
		Servidor  string `json:"servidor"`
		RutaLocal string `json:"rutaLocal"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	if strings.TrimSpace(pet.Servidor) == "" || strings.TrimSpace(pet.RutaLocal) == "" {
		responderError(w, fmt.Errorf("servidor y script son obligatorios"))
		return
	}

	local := normalizarRuta(pet.RutaLocal)
	info, err := os.Stat(local)
	if err != nil {
		responderError(w, errorClave(local, err))
		return
	}
	if !info.Mode().IsRegular() {
		responderError(w, fmt.Errorf("selecciona un archivo de script"))
		return
	}
	if info.Size() > 50*1024*1024 {
		responderError(w, fmt.Errorf("el script supera el límite de 50 MB"))
		return
	}

	c, err := clienteSFTP(pet.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	if err := c.MkdirAll(carpetaScriptsRemota); err != nil {
		responderError(w, fmt.Errorf("no pude preparar la carpeta de scripts: %v", err))
		return
	}
	_ = c.Chmod(carpetaScriptsRemota, 0700)

	nombre := filepath.Base(local)
	// Evita nombres especiales/confusos en el servidor; conserva extensión.
	nombre = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, nombre)
	if nombre == "" || nombre == "." || nombre == ".." {
		nombre = "script.sh"
	}
	remoto := path.Join(carpetaScriptsRemota, nombre)

	origen, err := os.Open(local)
	if err != nil {
		responderError(w, errorClave(local, err))
		return
	}
	defer origen.Close()
	destino, err := c.Create(remoto)
	if err != nil {
		responderError(w, fmt.Errorf("no pude crear el script remoto: %v", err))
		return
	}
	n, copiaErr := io.Copy(destino, origen)
	cierreErr := destino.Close()
	if copiaErr != nil {
		responderError(w, fmt.Errorf("error subiendo el script: %v", copiaErr))
		return
	}
	if cierreErr != nil {
		responderError(w, fmt.Errorf("error cerrando el script remoto: %v", cierreErr))
		return
	}
	if err := c.Chmod(remoto, 0700); err != nil {
		responderError(w, fmt.Errorf("no pude marcar el script como ejecutable: %v", err))
		return
	}

	q := shellQuote(remoto)
	ext := strings.ToLower(filepath.Ext(nombre))
	comando := q
	switch ext {
	case ".sh", ".bash":
		comando = "bash -- " + q
	case ".py":
		comando = "python3 -- " + q
	}
	responder(w, map[string]any{"ok": true, "remoto": remoto, "bytes": n, "comando": comando})
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
