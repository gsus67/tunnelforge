// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

import "net/http"

const repoReleasesURL = "https://github.com/gsus67/tunnelforge/releases"

func manejarVersion(w http.ResponseWriter, r *http.Request) {
	responder(w, map[string]any{"version": version, "releasesURL": repoReleasesURL})
}
