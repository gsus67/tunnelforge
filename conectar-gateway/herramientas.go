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

// manejarTestVelocidad prepara un comando de diagnóstico que se ejecuta de forma
// visible en la terminal integrada del servidor conectado. Usa endpoints públicos
// de Cloudflare para medir latencia HTTP, descarga y subida sin instalar paquetes.
func manejarTestVelocidad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var pet struct {
		Servidor string `json:"servidor"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	pet.Servidor = strings.TrimSpace(pet.Servidor)
	if pet.Servidor == "" {
		responderError(w, fmt.Errorf("servidor obligatorio"))
		return
	}
	if _, err := clienteConexionActiva(pet.Servidor); err != nil {
		responderError(w, err)
		return
	}

	script := `set -u
BASE="https://speed.cloudflare.com"
printf '\n=== Gateway WISP · Test de velocidad ===\n'
printf 'Host: '; hostname 2>/dev/null || true
printf 'Destino: Cloudflare edge\n'
if ! command -v curl >/dev/null 2>&1; then
  printf '\nERROR: curl no está instalado en este servidor.\n'
  printf 'Instálalo y vuelve a ejecutar la prueba.\n'
  exit 127
fi
printf 'IP pública: '
IP=$(curl -fsS --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '$1=="ip"{print $2; exit}')
if [ -n "${IP:-}" ]; then printf '%s\n' "$IP"; else printf 'no disponible\n'; fi
printf '\nMidiendo latencia...\n'
LAT=$(curl -o /dev/null -sS --max-time 15 -w '%{time_starttransfer}' "$BASE/__down?bytes=0" 2>/dev/null || true)
if [ -n "${LAT:-}" ]; then
  awk -v t="$LAT" 'BEGIN { if (t+0 > 0) printf "Latencia HTTP: %.1f ms\n", (t+0)*1000; else print "Latencia HTTP: no disponible" }'
else
  printf 'Latencia HTTP: no disponible\n'
fi
printf '\nDescarga: probando 100 MB...\n'
DL=$(curl -o /dev/null -sS --max-time 45 -w '%{size_download} %{time_total}' "$BASE/__down?bytes=100000000" 2>/dev/null || true)
if [ -n "${DL:-}" ]; then
  printf '%s\n' "$DL" | awk '{ if ($2+0 > 0 && $1+0 > 0) printf "Descarga: %.1f Mbps  (%.1f MB en %.2f s)\n", (($1*8)/1000000)/$2, $1/1000000, $2; else print "Descarga: no disponible" }'
else
  printf 'Descarga: no disponible\n'
fi
printf '\nSubida: probando 50 MB...\n'
UP=$(dd if=/dev/zero bs=1M count=50 2>/dev/null | curl -o /dev/null -sS --max-time 45 -w '%{size_upload} %{time_total}' -X POST --data-binary @- "$BASE/__up" 2>/dev/null || true)
if [ -n "${UP:-}" ]; then
  printf '%s\n' "$UP" | awk '{ if ($2+0 > 0 && $1+0 > 0) printf "Subida: %.1f Mbps  (%.1f MB en %.2f s)\n", (($1*8)/1000000)/$2, $1/1000000, $2; else print "Subida: no disponible" }'
else
  printf 'Subida: no disponible\n'
fi
printf '\nPrueba terminada.\n\n'`

	responder(w, map[string]any{
		"ok":      true,
		"comando": "sh -lc " + shellQuote(script),
	})
}
