// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

import "net/http"

const repoReleasesURL = "https://github.com/gsus67/gateway-wisp-access/releases"

func manejarVersion(w http.ResponseWriter, r *http.Request) {
	responder(w, map[string]any{"version": version, "releasesURL": repoReleasesURL})
}
