// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows && (!amd64 || !wireguard_embedded)

package main

import "fmt"

func wgEmbeddedAvailable() bool { return false }

func wgEmbeddedDescription() string { return "WireGuard integrado" }

func wgEnsureEmbeddedEngine() (string, error) {
	return "", fmt.Errorf("esta compilación de desarrollo no contiene el motor WireGuard embebido; usa el build oficial de TunnelForge")
}
