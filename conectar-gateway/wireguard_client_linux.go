// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func wgEngineStatus() WGEngineInfo {
	info := WGEngineInfo{Name: "wireguard-tools", Platform: runtime.GOOS, CanInstall: runtime.GOOS == "linux"}
	wg, err1 := exec.LookPath("wg")
	quick, err2 := exec.LookPath("wg-quick")
	if err1 != nil || err2 != nil {
		info.Message = "Faltan wg/wg-quick (wireguard-tools)."
		return info
	}
	info.Installed = true
	info.Path = quick
	if out, err := exec.Command(wg, "--version").CombinedOutput(); err == nil {
		info.Version = strings.TrimSpace(string(out))
	}
	return info
}

func wgPrivileged(name string, args ...string) error {
	if os.Geteuid() == 0 {
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if pk, err := exec.LookPath("pkexec"); err == nil {
		a := append([]string{name}, args...)
		if out, e := exec.Command(pk, a...).CombinedOutput(); e != nil {
			return fmt.Errorf("%s: %v", strings.TrimSpace(string(out)), e)
		}
		return nil
	}
	if sudo, err := exec.LookPath("sudo"); err == nil {
		a := append([]string{"-n", name}, args...)
		if out, e := exec.Command(sudo, a...).CombinedOutput(); e == nil {
			return nil
		} else if len(out) > 0 {
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
	}
	return fmt.Errorf("se requieren permisos de administrador; instala polkit/pkexec o inicia la app desde una sesión con permisos para WireGuard")
}

func wgInstallEngine() (WGEngineInfo, error) {
	if runtime.GOOS != "linux" {
		return wgEngineStatus(), fmt.Errorf("instala wireguard-tools usando el gestor de paquetes del sistema")
	}
	var shell string
	switch {
	case commandExists("apt-get"):
		shell = "apt-get update && apt-get install -y wireguard-tools"
	case commandExists("dnf"):
		shell = "dnf install -y wireguard-tools"
	case commandExists("pacman"):
		shell = "pacman -S --noconfirm wireguard-tools"
	case commandExists("zypper"):
		shell = "zypper --non-interactive install wireguard-tools"
	default:
		return wgEngineStatus(), fmt.Errorf("no reconozco el gestor de paquetes; instala wireguard-tools manualmente")
	}
	if os.Geteuid() == 0 {
		if out, err := exec.Command("sh", "-c", shell).CombinedOutput(); err != nil {
			return wgEngineStatus(), fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
	} else if pk, err := exec.LookPath("pkexec"); err == nil {
		if out, e := exec.Command(pk, "sh", "-c", shell).CombinedOutput(); e != nil {
			return wgEngineStatus(), fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
	} else {
		return wgEngineStatus(), fmt.Errorf("necesito pkexec/polkit para instalar wireguard-tools desde la interfaz")
	}
	return wgEngineStatus(), nil
}

func commandExists(name string) bool { _, err := exec.LookPath(name); return err == nil }

func wgConnectProfile(p WGProfile, configPath string) error {
	quick, err := exec.LookPath("wg-quick")
	if err != nil {
		return fmt.Errorf("wg-quick no está instalado")
	}
	name := wgInterfaceName(p.ID)
	if _, err := os.Stat(filepath.Join("/sys/class/net", name)); err == nil {
		return nil
	}
	return wgPrivileged(quick, "up", configPath)
}

func wgDisconnectProfile(p WGProfile) error {
	quick, err := exec.LookPath("wg-quick")
	if err != nil {
		return fmt.Errorf("wg-quick no está instalado")
	}
	name := wgInterfaceName(p.ID)
	if _, err := os.Stat(filepath.Join("/sys/class/net", name)); os.IsNotExist(err) {
		return nil
	}
	return wgPrivileged(quick, "down", wgRuntimeConfigPath(p))
}

func readIntFile(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var v int64
	fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &v)
	return v
}

func wgTunnelSnapshot(p WGProfile) (WGTunnelSnapshot, error) {
	name := wgInterfaceName(p.ID)
	snap := WGTunnelSnapshot{Interface: name, Peers: []WGPeerSnapshot{}}
	sys := filepath.Join("/sys/class/net", name)
	if _, err := os.Stat(sys); err != nil {
		return snap, nil
	}
	snap.Connected = true
	snap.RXBytes = readIntFile(filepath.Join(sys, "statistics/rx_bytes"))
	snap.TXBytes = readIntFile(filepath.Join(sys, "statistics/tx_bytes"))
	wg, err := exec.LookPath("wg")
	if err == nil {
		if out, e := exec.Command(wg, "show", name, "dump").CombinedOutput(); e == nil {
			parsed := parseWGDump(string(out))
			parsed.Interface = name
			parsed.Connected = true
			if parsed.RXBytes == 0 {
				parsed.RXBytes = snap.RXBytes
			}
			if parsed.TXBytes == 0 {
				parsed.TXBytes = snap.TXBytes
			}
			return parsed, nil
		}
	}
	return snap, nil
}
