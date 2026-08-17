// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows && amd64 && wireguard_embedded

package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

const wgEmbeddedEngineVersion = "WireGuard Windows v1.1 / WireGuardNT 1.1 · host nativo integrado"

// Estos binarios se preparan en GitHub Actions desde las fuentes/descargas
// oficiales de WireGuard y se incrustan dentro de Conectar-Gateway.exe.
// No se guardan en el repositorio.
//
//go:embed wireguard-assets/windows/amd64/wg-service-host.exe
var wgEmbeddedServiceHost []byte

//go:embed wireguard-assets/windows/amd64/tunnel.dll
var wgEmbeddedTunnelDLL []byte

//go:embed wireguard-assets/windows/amd64/wireguard.dll
var wgEmbeddedWireGuardDLL []byte

func wgEmbeddedAvailable() bool {
	return len(wgEmbeddedServiceHost) > 0 && len(wgEmbeddedTunnelDLL) > 0 && len(wgEmbeddedWireGuardDLL) > 0
}

func wgEmbeddedDescription() string { return wgEmbeddedEngineVersion }

func wgWriteEmbeddedFile(path string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("recurso WireGuard embebido vacío: %s", filepath.Base(path))
	}
	want := sha256.Sum256(data)
	if existing, err := os.ReadFile(path); err == nil {
		got := sha256.Sum256(existing)
		if bytes.Equal(got[:], want[:]) {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func wgEnsureEmbeddedEngine() (string, error) {
	if !wgEmbeddedAvailable() {
		return "", fmt.Errorf("esta compilación no contiene el motor WireGuard embebido")
	}
	dir := filepath.Join(wgRuntimeDir(), "engine", "wireguard-v1.1-amd64-host-v2")
	if err := wgWriteEmbeddedFile(filepath.Join(dir, "wg-service-host.exe"), wgEmbeddedServiceHost); err != nil {
		return "", fmt.Errorf("no pude preparar wg-service-host.exe: %w", err)
	}
	if err := wgWriteEmbeddedFile(filepath.Join(dir, "tunnel.dll"), wgEmbeddedTunnelDLL); err != nil {
		return "", fmt.Errorf("no pude preparar tunnel.dll: %w", err)
	}
	if err := wgWriteEmbeddedFile(filepath.Join(dir, "wireguard.dll"), wgEmbeddedWireGuardDLL); err != nil {
		return "", fmt.Errorf("no pude preparar wireguard.dll: %w", err)
	}
	return dir, nil
}
