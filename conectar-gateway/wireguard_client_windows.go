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
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	wgWinInterfaceSize = 80
	wgWinPeerSize      = 136
	wgWinAllowedIPSize = 24
	wgWinErrMoreData   = syscall.Errno(234)
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
	out, err := wgWindowsCommand("sc.exe", "query", service).CombinedOutput()
	if err != nil {
		return false, false
	}
	text := strings.ReplaceAll(string(out), "\r", "")
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, ": 4 ") || strings.HasSuffix(trimmed, ": 4") {
			return true, true
		}
	}
	return true, false
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
	return wgRunElevated(exe, "--wg-admin-disconnect", name)
}

func wgReadWireGuardNTConfig(name, engineDir string) ([]byte, error) {
	dll, err := syscall.LoadDLL(filepath.Join(engineDir, "wireguard.dll"))
	if err != nil {
		return nil, err
	}
	defer dll.Release()
	openAdapter, err := dll.FindProc("WireGuardOpenAdapter")
	if err != nil {
		return nil, err
	}
	freeAdapter, err := dll.FindProc("WireGuardFreeAdapter")
	if err != nil {
		return nil, err
	}
	getConfig, err := dll.FindProc("WireGuardGetConfiguration")
	if err != nil {
		return nil, err
	}
	poolW, err := syscall.UTF16PtrFromString("WireGuard")
	if err != nil {
		return nil, err
	}
	nameW, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, _, openErr := openAdapter.Call(
		uintptr(unsafe.Pointer(poolW)),
		uintptr(unsafe.Pointer(nameW)),
	)
	runtime.KeepAlive(poolW)
	runtime.KeepAlive(nameW)
	if handle == 0 {
		return nil, fmt.Errorf("WireGuardOpenAdapter: %v", openErr)
	}
	defer freeAdapter.Call(handle)

	size := uint32(64 * 1024)
	for attempt := 0; attempt < 5; attempt++ {
		if size < wgWinInterfaceSize {
			size = wgWinInterfaceSize
		}
		if size > 16*1024*1024 {
			return nil, fmt.Errorf("configuración WireGuard demasiado grande")
		}
		buf := make([]byte, int(size))
		requested := size
		r, _, callErr := getConfig.Call(
			handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&requested)),
		)
		runtime.KeepAlive(buf)
		if r != 0 {
			if requested > uint32(len(buf)) {
				return nil, fmt.Errorf("WireGuard devolvió un tamaño inválido")
			}
			return buf[:requested], nil
		}
		if errno, ok := callErr.(syscall.Errno); ok && errno == wgWinErrMoreData {
			size = requested
			continue
		}
		return nil, fmt.Errorf("WireGuardGetConfiguration: %v", callErr)
	}
	return nil, fmt.Errorf("WireGuardGetConfiguration cambió de tamaño demasiadas veces")
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

func wgParseWireGuardNTConfig(p WGProfile, name string, buf []byte) (WGTunnelSnapshot, error) {
	snap := WGTunnelSnapshot{Connected: true, Interface: name, Peers: []WGPeerSnapshot{}}
	if len(buf) < wgWinInterfaceSize {
		return snap, fmt.Errorf("respuesta WireGuardNT demasiado corta")
	}
	snap.ListenPort = int(binary.LittleEndian.Uint16(buf[4:6]))
	peersCount := binary.LittleEndian.Uint32(buf[72:76])
	offset := wgWinInterfaceSize
	profilePeers := make(map[string]WGPeer, len(p.Peers))
	for _, peer := range p.Peers {
		profilePeers[strings.TrimSpace(peer.PublicKey)] = peer
	}
	for i := uint32(0); i < peersCount; i++ {
		if offset+wgWinPeerSize > len(buf) {
			return snap, fmt.Errorf("respuesta WireGuardNT truncada en peer %d", i+1)
		}
		peerBuf := buf[offset : offset+wgWinPeerSize]
		publicKey := base64.StdEncoding.EncodeToString(peerBuf[8:40])
		tx := int64(binary.LittleEndian.Uint64(peerBuf[104:112]))
		rx := int64(binary.LittleEndian.Uint64(peerBuf[112:120]))
		handshake := wgFiletimeToUnix(binary.LittleEndian.Uint64(peerBuf[120:128]))
		allowedCount := binary.LittleEndian.Uint32(peerBuf[128:132])
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
		offset += wgWinPeerSize
		skip := uint64(allowedCount) * wgWinAllowedIPSize
		if skip > uint64(len(buf)-offset) {
			return snap, fmt.Errorf("respuesta WireGuardNT truncada en AllowedIPs")
		}
		offset += int(skip)
	}
	return snap, nil
}

func wgTunnelSnapshot(p WGProfile) (WGTunnelSnapshot, error) {
	name := wgInterfaceName(p.ID)
	exists, running := wgWindowsServiceStatus(name)
	snap := WGTunnelSnapshot{Connected: running, Interface: name, Peers: []WGPeerSnapshot{}}
	if !exists || !running {
		return snap, nil
	}
	engineDir, err := wgEnsureEmbeddedEngine()
	if err != nil {
		snap.Error = err.Error()
		return snap, nil
	}
	buf, err := wgReadWireGuardNTConfig(name, engineDir)
	if err != nil {
		snap.Error = "túnel activo; no pude leer estadísticas: " + err.Error()
		return snap, nil
	}
	parsed, err := wgParseWireGuardNTConfig(p, name, buf)
	if err != nil {
		snap.Error = err.Error()
		return snap, nil
	}
	return parsed, nil
}
