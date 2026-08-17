// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func wgWindowsCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	// Gateway WISP Access es una app GUI. Los comandos de estado se ejecutan
	// periódicamente; sin HideWindow Windows crea una consola que parpadea.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func wgEngineStatus() WGEngineInfo {
	info := WGEngineInfo{
		Installed:  wgEmbeddedAvailable(),
		Name:       "WireGuard integrado",
		Version:    wgEmbeddedDescription(),
		CanInstall: false,
		Platform:   "windows",
	}
	if info.Installed {
		info.Message = "Incluido dentro de Gateway WISP Access · no requiere instalar WireGuard aparte."
	} else {
		info.Message = "Esta compilación no incluye el motor WireGuard embebido. Usa el ejecutable oficial generado por GitHub Actions."
	}
	return info
}

func wgInstallEngine() (WGEngineInfo, error) {
	info := wgEngineStatus()
	if !info.Installed {
		return info, fmt.Errorf("el motor WireGuard embebido no está incluido en esta compilación")
	}
	info.Message = "WireGuard ya viene integrado; no hay nada adicional que instalar."
	return info, nil
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// wgElevacionCancelada = ERROR_CANCELLED. Windows lo devuelve cuando el usuario
// cierra o rechaza el aviso de UAC.
const wgElevacionCancelada = 1223

// wgRunElevated lanza el propio ejecutable con permisos de administrador.
//
// Antes el script terminaba en "exit $p.ExitCode": si Start-Process fallaba o
// el usuario cancelaba el UAC, $p quedaba en $null, PowerShell evaluaba
// "exit $null" como exit 0 y la aplicación daba la conexión por buena aunque el
// servicio nunca se hubiera creado. Ahora el error se propaga de verdad.
func wgRunElevated(exe string, args ...string) error {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = psQuote(a)
	}
	script := fmt.Sprintf("$ErrorActionPreference='Stop'; try { $p=Start-Process -FilePath %s -ArgumentList @(%s) -Verb RunAs -Wait -PassThru } catch { exit %d }; if ($null -eq $p) { exit %d }; exit $p.ExitCode",
		psQuote(exe), strings.Join(quoted, ","), wgElevacionCancelada, wgElevacionCancelada)
	cmd := wgWindowsCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if salida, ok := err.(*exec.ExitError); ok && salida.ExitCode() == wgElevacionCancelada {
		return fmt.Errorf("se canceló el aviso de administrador de Windows; WireGuard necesita esos permisos para crear el servicio del túnel")
	}
	return fmt.Errorf("WireGuard necesita permisos de administrador: %v %s", err, strings.TrimSpace(string(out)))
}

// wgWindowsServiceStatus consulta el SCM directamente en vez de interpretar la
// salida de texto de sc.exe. El parser anterior buscaba ": 4 " en CUALQUIER
// línea, así que también encontraba SERVICE_EXIT_CODE : 4  (0x4) — justo el
// código que devuelve wg-service-host.exe cuando falla LoadLibraryExW de
// tunnel.dll — y daba por RUNNING un servicio que en realidad estaba muerto.
// Además el texto de sc.exe viene traducido según el idioma de Windows.
//
// Se piden únicamente SC_MANAGER_CONNECT y SERVICE_QUERY_STATUS, permisos que
// los usuarios normales sí tienen: no hace falta elevar la aplicación.
func wgWindowsServiceStatus(name string) (exists, running bool) {
	nombre, err := windows.UTF16PtrFromString("WireGuardTunnel$" + name)
	if err != nil {
		return false, false
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(scm)

	servicio, err := windows.OpenService(scm, nombre, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(servicio)

	var estado windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(servicio, &estado); err != nil {
		return true, false
	}
	return true, estado.CurrentState == windows.SERVICE_RUNNING
}

func wgSC(args ...string) error {
	out, err := wgWindowsCommand("sc.exe", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("sc.exe %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}

func wgWindowsCmdQuote(s string) string {
	// Las rutas que pasamos al SCM no contienen comillas; escapamos por
	// seguridad y las encerramos porque casi siempre contienen espacios.
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func wgAdminInstallService(name, configPath, engineDir, startMode string) error {
	if startMode != "auto" {
		startMode = "demand"
	}
	service := "WireGuardTunnel$" + name
	if exists, _ := wgWindowsServiceStatus(name); exists {
		_ = wgSC("stop", service)
		_ = wgSC("delete", service)
		for i := 0; i < 40; i++ {
			if exists, _ := wgWindowsServiceStatus(name); !exists {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	hostPath := filepath.Join(engineDir, "wg-service-host.exe")
	if st, err := os.Stat(hostPath); err != nil || st.IsDir() {
		if err == nil {
			err = fmt.Errorf("es un directorio")
		}
		return fmt.Errorf("host WireGuard embebido no disponible: %s: %w", hostPath, err)
	}
	if _, err := os.Stat(filepath.Join(engineDir, "tunnel.dll")); err != nil {
		return fmt.Errorf("falta tunnel.dll: %w", err)
	}
	if _, err := os.Stat(filepath.Join(engineDir, "wireguard.dll")); err != nil {
		return fmt.Errorf("falta wireguard.dll: %w", err)
	}

	binPath := strings.Join([]string{
		wgWindowsCmdQuote(hostPath),
		"/service",
		wgWindowsCmdQuote(configPath),
	}, " ")

	if err := wgSC("create", service,
		"binPath=", binPath,
		"type=", "own",
		"start=", startMode,
		"error=", "normal",
		"depend=", "Nsi/TcpIp",
		"DisplayName=", "Gateway WISP Access - "+name); err != nil {
		return err
	}
	if err := wgSC("sidtype", service, "unrestricted"); err != nil {
		_ = wgSC("delete", service)
		return err
	}
	if err := wgSC("start", service); err != nil {
		detail := wgWindowsServiceFailureDetail(service, configPath)
		_ = wgSC("delete", service)
		if detail != "" {
			return fmt.Errorf("%w · %s", err, detail)
		}
		return err
	}

	// sc start puede devolver éxito cuando el servicio aún está START_PENDING.
	// Esperamos a RUNNING para no marcar como conectado un túnel que cayó al
	// cargar tunnel.dll, wireguard.dll o la configuración.
	for i := 0; i < 200; i++ {
		if _, running := wgWindowsServiceStatus(name); running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	detail := wgWindowsServiceFailureDetail(service, configPath)
	_ = wgSC("stop", service)
	_ = wgSC("delete", service)
	if detail == "" {
		detail = "el servicio no llegó al estado RUNNING"
	}
	return fmt.Errorf("WireGuard no pudo iniciar: %s", detail)
}

func wgWindowsServiceFailureDetail(service, configPath string) string {
	parts := []string{}
	if out, err := wgWindowsCommand("sc.exe", "queryex", service).CombinedOutput(); err == nil {
		text := strings.TrimSpace(strings.ReplaceAll(string(out), "\r", ""))
		if text != "" {
			parts = append(parts, text)
		}
	}
	if b, err := os.ReadFile(configPath + ".service-host.log"); err == nil {
		text := strings.TrimSpace(strings.ReplaceAll(string(b), "\r", ""))
		if text != "" {
			parts = append(parts, "host: "+text)
		}
	}
	return strings.Join(parts, " · ")
}

func wgAdminRemoveService(name string) error {
	service := "WireGuardTunnel$" + name
	if exists, _ := wgWindowsServiceStatus(name); !exists {
		return nil
	}
	_ = wgSC("stop", service)
	if err := wgSC("delete", service); err != nil {
		return err
	}
	return nil
}

func manejarModoWireGuardEspecial() (bool, int) {
	args := os.Args[1:]
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "--wg-admin-connect":
		if len(args) != 5 {
			return true, 2
		}
		errorPath := filepath.Join(args[3], "admin-connect-error.txt")
		_ = os.Remove(errorPath)
		if err := wgAdminInstallService(args[1], args[2], args[3], args[4]); err != nil {
			_ = os.WriteFile(errorPath, []byte(err.Error()), 0600)
			fmt.Fprintln(os.Stderr, err)
			return true, 1
		}
		_ = os.Remove(errorPath)
		return true, 0
	case "--wg-admin-disconnect":
		if len(args) != 2 {
			return true, 2
		}
		if err := wgAdminRemoveService(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return true, 1
		}
		return true, 0
	default:
		return false, 0
	}
}

func wgConnectProfile(p WGProfile, configPath string) error {
	engineDir, err := wgEnsureEmbeddedEngine()
	if err != nil {
		return err
	}
	name := wgInterfaceName(p.ID)
	exists, running := wgWindowsServiceStatus(name)
	if running {
		return nil
	}
	// Si quedó un servicio viejo, el proceso elevado lo reemplaza en la misma
	// operación para no mostrar varios avisos UAC.
	_ = exists
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	mode := "demand"
	if p.AutoConnect {
		mode = "auto"
	}
	errorPath := filepath.Join(engineDir, "admin-connect-error.txt")
	_ = os.Remove(errorPath)
	_ = os.Remove(wgServiceStatsPath(p))
	if err := wgRunElevated(exe, "--wg-admin-connect", name, configPath, engineDir, mode); err != nil {
		if b, readErr := os.ReadFile(errorPath); readErr == nil && strings.TrimSpace(string(b)) != "" {
			return fmt.Errorf("WireGuard no pudo conectar: %s", strings.TrimSpace(string(b)))
		}
		return err
	}
	_ = os.Remove(errorPath)
	return nil
}

func wgDisconnectProfile(p WGProfile) error {
	name := wgInterfaceName(p.ID)
	if exists, _ := wgWindowsServiceStatus(name); !exists {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := wgRunElevated(exe, "--wg-admin-disconnect", name); err != nil {
		return err
	}
	_ = os.Remove(wgServiceStatsPath(p))
	return nil
}

const (
	wgServiceStatsHeaderSize = 20
	wgServiceStatsPeerSize   = 56
	wgServiceStatsVersion    = 1
	wgServiceStatsMagic      = "GWAWGST1"
)

func wgServiceStatsPath(p WGProfile) string {
	return wgRuntimeConfigPath(p) + ".stats.bin"
}

func wgReadServiceStats(p WGProfile, name string) (WGTunnelSnapshot, error) {
	snap := WGTunnelSnapshot{Connected: true, Interface: name, Peers: []WGPeerSnapshot{}}
	path := wgServiceStatsPath(p)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return snap, fmt.Errorf("esperando telemetría del servicio WireGuard")
		}
		return snap, err
	}
	if st, statErr := os.Stat(path); statErr == nil && time.Since(st.ModTime()) > 8*time.Second {
		return snap, fmt.Errorf("la telemetría del servicio WireGuard está desactualizada")
	}
	if len(b) < wgServiceStatsHeaderSize {
		return snap, fmt.Errorf("telemetría WireGuard demasiado corta")
	}
	if string(b[:8]) != wgServiceStatsMagic {
		return snap, fmt.Errorf("formato de telemetría WireGuard desconocido")
	}
	version := binary.LittleEndian.Uint32(b[8:12])
	if version != wgServiceStatsVersion {
		return snap, fmt.Errorf("versión de telemetría WireGuard no soportada: %d", version)
	}
	snap.ListenPort = int(binary.LittleEndian.Uint16(b[12:14]))
	peerCount := binary.LittleEndian.Uint32(b[16:20])
	if peerCount > 65535 {
		return snap, fmt.Errorf("cantidad de peers WireGuard inválida")
	}
	expected := uint64(wgServiceStatsHeaderSize) + uint64(peerCount)*uint64(wgServiceStatsPeerSize)
	if expected != uint64(len(b)) {
		return snap, fmt.Errorf("telemetría WireGuard truncada o inválida")
	}

	profilePeers := make(map[string]WGPeer, len(p.Peers))
	for _, peer := range p.Peers {
		profilePeers[strings.TrimSpace(peer.PublicKey)] = peer
	}
	offset := wgServiceStatsHeaderSize
	for i := uint32(0); i < peerCount; i++ {
		rec := b[offset : offset+wgServiceStatsPeerSize]
		publicKey := base64.StdEncoding.EncodeToString(rec[:32])
		tx := int64(binary.LittleEndian.Uint64(rec[32:40]))
		rx := int64(binary.LittleEndian.Uint64(rec[40:48]))
		handshake := wgFiletimeToUnix(binary.LittleEndian.Uint64(rec[48:56]))
		ps := WGPeerSnapshot{
			PublicKey:       publicKey,
			LatestHandshake: handshake,
			RXBytes:         rx,
			TXBytes:         tx,
		}
		if stored, ok := profilePeers[publicKey]; ok {
			ps.Endpoint = stored.Endpoint
			ps.AllowedIPs = strings.Join(stored.AllowedIPs, ", ")
		}
		snap.Peers = append(snap.Peers, ps)
		snap.RXBytes += rx
		snap.TXBytes += tx
		if handshake > snap.LatestHandshake {
			snap.LatestHandshake = handshake
		}
		offset += wgServiceStatsPeerSize
	}
	return snap, nil
}

func wgFiletimeToUnix(v uint64) int64 {
	if v == 0 {
		return 0
	}
	const epochDeltaSeconds = uint64(11644473600)
	secs := v / 10000000
	if secs <= epochDeltaSeconds {
		return 0
	}
	return int64(secs - epochDeltaSeconds)
}

func wgTunnelSnapshot(p WGProfile) (WGTunnelSnapshot, error) {
	name := wgInterfaceName(p.ID)
	exists, running := wgWindowsServiceStatus(name)
	snap := WGTunnelSnapshot{Connected: running, Interface: name, Peers: []WGPeerSnapshot{}}
	if !exists || !running {
		return snap, nil
	}
	parsed, err := wgReadServiceStats(p, name)
	if err != nil {
		snap.Error = "túnel activo; " + err.Error()
		return snap, nil
	}
	return parsed, nil
}
