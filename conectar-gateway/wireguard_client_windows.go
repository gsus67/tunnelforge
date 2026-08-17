// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func wgWindowsCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	// Gateway WISP Access es una app GUI. Los comandos de estado de WireGuard
	// se ejecutan periódicamente; sin HideWindow Windows crea una consola que
	// aparece y desaparece en cada sondeo.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func wgWindowsPaths() (wireguardExe, wgExe string) {
	candidates := []string{}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		candidates = append(candidates, filepath.Join(pf, "WireGuard", "wireguard.exe"))
	}
	if p, err := exec.LookPath("wireguard.exe"); err == nil {
		candidates = append(candidates, p)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			wireguardExe = p
			break
		}
	}
	if wireguardExe != "" {
		p := filepath.Join(filepath.Dir(wireguardExe), "wg.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			wgExe = p
		}
	}
	if wgExe == "" {
		if p, err := exec.LookPath("wg.exe"); err == nil {
			wgExe = p
		}
	}
	return
}

func wgEngineStatus() WGEngineInfo {
	we, wg := wgWindowsPaths()
	info := WGEngineInfo{Name: "WireGuard for Windows", Platform: "windows", CanInstall: true}
	if we == "" {
		info.Message = "Instala el cliente oficial de WireGuard para Windows."
		return info
	}
	info.Installed = true
	info.Path = we
	if wg != "" {
		if out, err := wgWindowsCommand(wg, "--version").CombinedOutput(); err == nil {
			info.Version = strings.TrimSpace(string(out))
		}
	}
	return info
}

func wgInstallEngine() (WGEngineInfo, error) {
	// El driver WireGuardNT debe venir firmado por Microsoft. Por seguridad
	// abrimos el instalador oficial en vez de intentar instalar un driver propio.
	abrirNavegador("https://www.wireguard.com/install/")
	info := wgEngineStatus()
	info.Message = "Abrí la descarga oficial de WireGuard. Instálalo y vuelve a comprobar el motor."
	return info, nil
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func wgRunElevated(exe string, args ...string) error {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = psQuote(a)
	}
	script := fmt.Sprintf("$p=Start-Process -FilePath %s -ArgumentList @(%s) -Verb RunAs -Wait -PassThru; exit $p.ExitCode", psQuote(exe), strings.Join(quoted, ","))
	cmd := wgWindowsCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("WireGuard necesita permisos de administrador: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func wgWindowsServiceStatus(name string) (exists, running bool) {
	service := "WireGuardTunnel$" + name
	// sc.exe es mucho más liviano que crear un proceso PowerShell cada 2 s.
	// HideWindow evita cualquier flash de consola en la aplicación Wails.
	out, err := wgWindowsCommand("sc.exe", "query", service).CombinedOutput()
	if err != nil {
		return false, false
	}
	text := strings.ReplaceAll(string(out), "\r", "")
	for _, line := range strings.Split(text, "\n") {
		// SERVICE_RUNNING = 4. El número de estado es estable aunque Windows
		// traduzca el texto descriptivo de sc.exe.
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, ": 4 ") || strings.HasSuffix(trimmed, ": 4") {
			return true, true
		}
	}
	return true, false
}

func wgConnectProfile(p WGProfile, configPath string) error {
	we, _ := wgWindowsPaths()
	if we == "" {
		return fmt.Errorf("WireGuard for Windows no está instalado")
	}
	name := wgInterfaceName(p.ID)
	exists, running := wgWindowsServiceStatus(name)
	if running {
		return nil
	}
	if exists {
		_ = wgRunElevated(we, "/uninstalltunnelservice", name)
	}
	if err := wgRunElevated(we, "/installtunnelservice", configPath); err != nil {
		return err
	}
	// /installtunnelservice usa inicio automático. Si el usuario no pidió
	// autoconexión, lo cambiamos a manual sin detener la sesión actual.
	mode := "demand"
	if p.AutoConnect {
		mode = "auto"
	}
	_ = wgRunElevated("sc.exe", "config", "WireGuardTunnel$"+name, "start=", mode)
	return nil
}

func wgDisconnectProfile(p WGProfile) error {
	we, _ := wgWindowsPaths()
	if we == "" {
		return fmt.Errorf("WireGuard for Windows no está instalado")
	}
	name := wgInterfaceName(p.ID)
	exists, _ := wgWindowsServiceStatus(name)
	if !exists {
		return nil
	}
	return wgRunElevated(we, "/uninstalltunnelservice", name)
}

func wgTunnelSnapshot(p WGProfile) (WGTunnelSnapshot, error) {
	name := wgInterfaceName(p.ID)
	exists, running := wgWindowsServiceStatus(name)
	snap := WGTunnelSnapshot{Connected: running, Interface: name, Peers: []WGPeerSnapshot{}}
	if !exists || !running {
		return snap, nil
	}
	_, wg := wgWindowsPaths()
	if wg == "" {
		snap.Error = "wg.exe no está disponible para leer estadísticas"
		return snap, nil
	}
	out, err := wgWindowsCommand(wg, "show", name, "dump").CombinedOutput()
	if err != nil {
		snap.Error = "túnel activo; estadísticas requieren permiso del propietario/administrador"
		return snap, nil
	}
	parsed := parseWGDump(string(out))
	parsed.Interface = name
	parsed.Connected = true
	return parsed, nil
}
