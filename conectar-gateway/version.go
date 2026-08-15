// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)

package main

// Actualizaciones de la propia app. El repositorio es PRIVADO: revisar
// Releases por la API de GitHub requeriría un token embebido en el
// ejecutable, y eso es un riesgo real (cualquiera puede extraer strings de
// un binario distribuido). Por eso esta app NO trae ningún token: el botón
// abre la página de Releases en TU navegador, que ya tiene tu sesión de
// GitHub — ahí ves si hay una versión nueva y las notas generadas
// automáticamente por GitHub a partir de los mensajes de commit.

import (
	"net/http"
)

const repoReleasesURL = "https://github.com/gsus67/gateway-wisp-access/releases"

func manejarVersion(w http.ResponseWriter, r *http.Request) {
	responder(w, map[string]any{
		"version":     version,
		"releasesURL": repoReleasesURL,
	})
}
