// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// seleccionarDestinoCopia usa el selector gráfico disponible en el escritorio.
// No cae silenciosamente a Descargas: si no hay selector, avisa al usuario.
func seleccionarDestinoCopia(nombre string) (string, bool, error) {
	inicial := filepath.Join(carpetaDescargas(), nombre)
	if runtime.GOOS == "darwin" {
		if osa, err := exec.LookPath("osascript"); err == nil {
			script := `set p to choose file name with prompt "Guardar copia de TunnelForge" default name "` + strings.ReplaceAll(nombre, `"`, ``) + `"` + "\n" + `POSIX path of p`
			out, err := exec.Command(osa, "-e", script).Output()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
					return "", true, nil
				}
				return "", false, err
			}
			ruta := strings.TrimSpace(string(out))
			if filepath.Ext(ruta) == "" {
				ruta += ".cgw"
			}
			return ruta, false, nil
		}
	}
	if zenity, err := exec.LookPath("zenity"); err == nil {
		out, err := exec.Command(zenity, "--file-selection", "--save", "--confirm-overwrite", "--title=Guardar copia de TunnelForge", "--filename="+inicial, "--file-filter=Copias TunnelForge | *.cgw").Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				return "", true, nil
			}
			return "", false, err
		}
		ruta := strings.TrimSpace(string(out))
		if filepath.Ext(ruta) == "" {
			ruta += ".cgw"
		}
		return ruta, false, nil
	}
	if kdialog, err := exec.LookPath("kdialog"); err == nil {
		out, err := exec.Command(kdialog, "--getsavefilename", inicial, "Copia TunnelForge (*.cgw)").Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				return "", true, nil
			}
			return "", false, err
		}
		ruta := strings.TrimSpace(string(out))
		if filepath.Ext(ruta) == "" {
			ruta += ".cgw"
		}
		return ruta, false, nil
	}
	return "", false, fmt.Errorf("no encontré un selector gráfico de archivos (zenity/kdialog)")
}

func seleccionarDestinoWireGuard(nombre string) (string, bool, error) {
	inicial := filepath.Join(carpetaDescargas(), nombre)
	if runtime.GOOS == "darwin" {
		if osa, err := exec.LookPath("osascript"); err == nil {
			script := `set p to choose file name with prompt "Exportar perfil WireGuard" default name "` + strings.ReplaceAll(nombre, `"`, ``) + `"` + "\n" + `POSIX path of p`
			out, err := exec.Command(osa, "-e", script).Output()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
					return "", true, nil
				}
				return "", false, err
			}
			ruta := strings.TrimSpace(string(out))
			if strings.ToLower(filepath.Ext(ruta)) != ".conf" {
				ruta += ".conf"
			}
			return ruta, false, nil
		}
	}
	if zenity, err := exec.LookPath("zenity"); err == nil {
		out, err := exec.Command(zenity, "--file-selection", "--save", "--confirm-overwrite", "--title=Exportar perfil WireGuard", "--filename="+inicial, "--file-filter=WireGuard | *.conf").Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				return "", true, nil
			}
			return "", false, err
		}
		ruta := strings.TrimSpace(string(out))
		if strings.ToLower(filepath.Ext(ruta)) != ".conf" {
			ruta += ".conf"
		}
		return ruta, false, nil
	}
	if kdialog, err := exec.LookPath("kdialog"); err == nil {
		out, err := exec.Command(kdialog, "--getsavefilename", inicial, "WireGuard (*.conf)").Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				return "", true, nil
			}
			return "", false, err
		}
		ruta := strings.TrimSpace(string(out))
		if strings.ToLower(filepath.Ext(ruta)) != ".conf" {
			ruta += ".conf"
		}
		return ruta, false, nil
	}
	return "", false, fmt.Errorf("no encontré un selector gráfico de archivos (zenity/kdialog)")
}
