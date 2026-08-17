// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

// Integración WireGuard local.
//
// La UI y el almacenamiento pertenecen a Gateway WISP Access. En Windows el
// motor oficial se distribuye embebido dentro de la propia aplicación usando
// tunnel.dll + WireGuardNT; no hace falta instalar WireGuard for Windows. En
// Linux se siguen usando las herramientas wireguard-tools del sistema.
// La generación de claves sigue el algoritmo del embeddable-dll-service
// oficial (MIT), con atribución en TERCEROS.md.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

const wgStoreFormat = "gateway-wisp-access/wireguard/1"

type WGPeer struct {
	Name                string   `json:"name,omitempty"`
	PublicKey           string   `json:"publicKey"`
	PresharedKeyCifr    string   `json:"presharedKeyCifr,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
	ExcludeLocalTraffic bool     `json:"excludeLocalTraffic,omitempty"`
}

type WGProfile struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	PrivateKeyCifr string   `json:"privateKeyCifr,omitempty"`
	PublicKey      string   `json:"publicKey,omitempty"`
	Addresses      []string `json:"addresses"`
	DNS            []string `json:"dns,omitempty"`
	MTU            int      `json:"mtu,omitempty"`
	ListenPort     int      `json:"listenPort,omitempty"`
	Table          string   `json:"table,omitempty"`
	PreUp          []string `json:"preUp,omitempty"`
	PostUp         []string `json:"postUp,omitempty"`
	PreDown        []string `json:"preDown,omitempty"`
	PostDown       []string `json:"postDown,omitempty"`
	AllowHooks     bool     `json:"allowHooks,omitempty"`
	AutoConnect    bool     `json:"autoConnect,omitempty"`
	Notes          string   `json:"notes,omitempty"`
	Peers          []WGPeer `json:"peers"`
	CreatedAt      string   `json:"createdAt,omitempty"`
	UpdatedAt      string   `json:"updatedAt,omitempty"`
}

type WGStore struct {
	Format   string      `json:"format"`
	Profiles []WGProfile `json:"profiles"`
}

type WGPeerSnapshot struct {
	PublicKey       string `json:"publicKey"`
	Endpoint        string `json:"endpoint,omitempty"`
	AllowedIPs      string `json:"allowedIPs,omitempty"`
	LatestHandshake int64  `json:"latestHandshake,omitempty"`
	RXBytes         int64  `json:"rxBytes"`
	TXBytes         int64  `json:"txBytes"`
}

type WGTunnelSnapshot struct {
	Connected       bool             `json:"connected"`
	Interface       string           `json:"interface"`
	RXBytes         int64            `json:"rxBytes"`
	TXBytes         int64            `json:"txBytes"`
	LatestHandshake int64            `json:"latestHandshake,omitempty"`
	ListenPort      int              `json:"listenPort,omitempty"`
	Peers           []WGPeerSnapshot `json:"peers,omitempty"`
	Error           string           `json:"error,omitempty"`
}

type WGEngineInfo struct {
	Installed  bool   `json:"installed"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Path       string `json:"path,omitempty"`
	CanInstall bool   `json:"canInstall"`
	Message    string `json:"message,omitempty"`
	Platform   string `json:"platform"`
}

var wgMu sync.Mutex

func wgStorePath() string  { return rutaJunto("wireguard.json") }
func wgRuntimeDir() string { return rutaJunto("wireguard-runtime") }

func loadWGStore() WGStore {
	st := WGStore{Format: wgStoreFormat, Profiles: []WGProfile{}}
	b, err := os.ReadFile(wgStorePath())
	if err != nil {
		return st
	}
	if json.Unmarshal(b, &st) != nil || st.Format != wgStoreFormat {
		return WGStore{Format: wgStoreFormat, Profiles: []WGProfile{}}
	}
	if st.Profiles == nil {
		st.Profiles = []WGProfile{}
	}
	return st
}

func saveWGStore(st WGStore) error {
	st.Format = wgStoreFormat
	if st.Profiles == nil {
		st.Profiles = []WGProfile{}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(wgStorePath(), b, 0600)
}

func wgNewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func wgInterfaceName(id string) string {
	clean := make([]byte, 0, 24)
	for i := 0; i < len(id) && len(clean) < 10; i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			clean = append(clean, c)
		}
	}
	if len(clean) == 0 {
		clean = []byte("default")
	}
	return "gwa-" + strings.ToLower(string(clean))
}

func wgValidateKey(s string, required bool) error {
	s = strings.TrimSpace(s)
	if s == "" {
		if required {
			return errors.New("falta una clave WireGuard")
		}
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return errors.New("la clave WireGuard debe ser base64 de 32 bytes")
	}
	return nil
}

// Basado en WireGuard embeddable-dll-service/WireGuardGenerateKeypair (MIT).
func wgGenerateKeypair() (priv, pub string, err error) {
	var privateKey, publicKey [32]byte
	n, err := rand.Read(privateKey[:])
	if err != nil || n != len(privateKey) {
		return "", "", fmt.Errorf("no pude generar bytes aleatorios")
	}
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return base64.StdEncoding.EncodeToString(privateKey[:]), base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

func wgGeneratePSK() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("no pude generar la PresharedKey: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func wgPublicFromPrivate(priv string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(b) != 32 {
		return "", errors.New("clave privada WireGuard inválida")
	}
	var p, q [32]byte
	copy(p[:], b)
	curve25519.ScalarBaseMult(&q, &p)
	return base64.StdEncoding.EncodeToString(q[:]), nil
}

func wgNormalizeList(v []string) []string {
	out, seen := []string{}, map[string]bool{}
	for _, item := range v {
		for _, p := range strings.Split(item, ",") {
			p = strings.TrimSpace(p)
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// wgEffectiveAllowedIPs conserva los AllowedIPs visibles del perfil, pero al
// activar "Excluir tráfico local" evita los /0 exactos. WireGuard for Windows
// usa /0 para habilitar su kill-switch; dividir la ruta por defecto en dos /1
// mantiene el túnel completo sin bloquear las rutas locales más específicas.
func wgEffectiveAllowedIPs(peer WGPeer) []string {
	if !peer.ExcludeLocalTraffic {
		return append([]string(nil), peer.AllowedIPs...)
	}
	out := make([]string, 0, len(peer.AllowedIPs)+2)
	for _, raw := range peer.AllowedIPs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			out = append(out, raw)
			continue
		}
		switch p.Masked().String() {
		case "0.0.0.0/0":
			out = append(out, "0.0.0.0/1", "128.0.0.0/1")
		case "::/0":
			out = append(out, "::/1", "8000::/1")
		default:
			out = append(out, raw)
		}
	}
	return wgNormalizeList(out)
}

func wgValidateProfile(p *WGProfile, privatePlain string) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return errors.New("ponle un nombre al perfil")
	}
	if len(p.Name) > 80 {
		return errors.New("nombre de perfil demasiado largo")
	}
	p.Addresses = wgNormalizeList(p.Addresses)
	p.DNS = wgNormalizeList(p.DNS)
	if len(p.Addresses) == 0 {
		return errors.New("falta Address en la interfaz")
	}
	for _, address := range p.Addresses {
		if _, err := netip.ParsePrefix(address); err != nil {
			return fmt.Errorf("Address inválida: %s", address)
		}
	}
	if privatePlain != "" {
		if err := wgValidateKey(privatePlain, true); err != nil {
			return err
		}
		pub, err := wgPublicFromPrivate(privatePlain)
		if err != nil {
			return err
		}
		p.PublicKey = pub
	} else if p.PrivateKeyCifr == "" {
		return errors.New("falta la clave privada")
	}
	if p.MTU < 0 || p.MTU > 65535 {
		return errors.New("MTU inválido")
	}
	if p.ListenPort < 0 || p.ListenPort > 65535 {
		return errors.New("ListenPort inválido")
	}
	if len(p.Peers) == 0 {
		return errors.New("agrega al menos un peer")
	}
	for i := range p.Peers {
		peer := &p.Peers[i]
		peer.Name = strings.TrimSpace(peer.Name)
		peer.Endpoint = strings.TrimSpace(peer.Endpoint)
		peer.AllowedIPs = wgNormalizeList(peer.AllowedIPs)
		if err := wgValidateKey(peer.PublicKey, true); err != nil {
			return fmt.Errorf("peer %d: public key inválida", i+1)
		}
		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("peer %d: falta AllowedIPs", i+1)
		}
		for _, allowed := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(allowed); err != nil {
				return fmt.Errorf("peer %d: AllowedIP inválida: %s", i+1, allowed)
			}
		}
		if peer.Endpoint != "" {
			host, portText, err := net.SplitHostPort(peer.Endpoint)
			if err != nil || strings.TrimSpace(host) == "" {
				return fmt.Errorf("peer %d: Endpoint inválido (usa host:puerto)", i+1)
			}
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("peer %d: puerto de Endpoint inválido", i+1)
			}
		}
		if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
			return fmt.Errorf("peer %d: keepalive inválido", i+1)
		}
	}
	return nil
}

func wgPublicProfile(p WGProfile) map[string]any {
	peers := make([]map[string]any, 0, len(p.Peers))
	for _, x := range p.Peers {
		peers = append(peers, map[string]any{
			"name": x.Name, "publicKey": x.PublicKey, "endpoint": x.Endpoint,
			"allowedIPs": x.AllowedIPs, "persistentKeepalive": x.PersistentKeepalive,
			"excludeLocalTraffic": x.ExcludeLocalTraffic,
			"hasPresharedKey":     x.PresharedKeyCifr != "",
		})
	}
	return map[string]any{
		"id": p.ID, "name": p.Name, "publicKey": p.PublicKey, "addresses": p.Addresses,
		"dns": p.DNS, "mtu": p.MTU, "listenPort": p.ListenPort, "table": p.Table,
		"preUp": p.PreUp, "postUp": p.PostUp, "preDown": p.PreDown, "postDown": p.PostDown,
		"allowHooks": p.AllowHooks, "autoConnect": p.AutoConnect, "notes": p.Notes,
		"peers": peers, "hasPrivateKey": p.PrivateKeyCifr != "", "createdAt": p.CreatedAt, "updatedAt": p.UpdatedAt,
		"interface": wgInterfaceName(p.ID),
	}
}

func wgFindProfile(st *WGStore, id string) (*WGProfile, int) {
	for i := range st.Profiles {
		if st.Profiles[i].ID == id {
			return &st.Profiles[i], i
		}
	}
	return nil, -1
}

func wgProfileConfig(p WGProfile) (string, error) {
	priv, err := descifrar(p.PrivateKeyCifr)
	if err != nil {
		return "", errors.New("no pude descifrar la clave privada del perfil")
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + priv + "\n")
	if len(p.Addresses) > 0 {
		b.WriteString("Address = " + strings.Join(p.Addresses, ", ") + "\n")
	}
	if len(p.DNS) > 0 {
		b.WriteString("DNS = " + strings.Join(p.DNS, ", ") + "\n")
	}
	if p.MTU > 0 {
		b.WriteString(fmt.Sprintf("MTU = %d\n", p.MTU))
	}
	if p.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", p.ListenPort))
	}
	if strings.TrimSpace(p.Table) != "" {
		b.WriteString("Table = " + strings.TrimSpace(p.Table) + "\n")
	}
	if p.AllowHooks {
		for _, s := range p.PreUp {
			if strings.TrimSpace(s) != "" {
				b.WriteString("PreUp = " + s + "\n")
			}
		}
		for _, s := range p.PostUp {
			if strings.TrimSpace(s) != "" {
				b.WriteString("PostUp = " + s + "\n")
			}
		}
		for _, s := range p.PreDown {
			if strings.TrimSpace(s) != "" {
				b.WriteString("PreDown = " + s + "\n")
			}
		}
		for _, s := range p.PostDown {
			if strings.TrimSpace(s) != "" {
				b.WriteString("PostDown = " + s + "\n")
			}
		}
	}
	for _, peer := range p.Peers {
		b.WriteString("\n[Peer]\n")
		if peer.Name != "" {
			b.WriteString("# Name = " + strings.ReplaceAll(peer.Name, "\n", " ") + "\n")
		}
		if peer.ExcludeLocalTraffic {
			b.WriteString("# ExcludeLocalTraffic = true\n")
		}
		b.WriteString("PublicKey = " + peer.PublicKey + "\n")
		if peer.PresharedKeyCifr != "" {
			ps, err := descifrar(peer.PresharedKeyCifr)
			if err != nil {
				return "", errors.New("no pude descifrar una PresharedKey")
			}
			b.WriteString("PresharedKey = " + ps + "\n")
		}
		if peer.Endpoint != "" {
			b.WriteString("Endpoint = " + peer.Endpoint + "\n")
		}
		b.WriteString("AllowedIPs = " + strings.Join(wgEffectiveAllowedIPs(peer), ", ") + "\n")
		if peer.PersistentKeepalive > 0 {
			b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
		}
	}
	return b.String(), nil
}

func wgParseConfig(text, name string) (WGProfile, string, []string, error) {
	p := WGProfile{ID: wgNewID(), Name: strings.TrimSpace(name), Addresses: []string{}, DNS: []string{}, Peers: []WGPeer{}, CreatedAt: time.Now().Format(time.RFC3339)}
	if p.Name == "" {
		p.Name = "WireGuard"
	}
	var private string
	var current string
	var peer *WGPeer
	var warnings []string
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	pendingPeerName := ""
	for n, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			c := strings.TrimSpace(strings.TrimLeft(line, "#;"))
			if eq := strings.Index(c, "="); eq > 0 {
				k, v := strings.ToLower(strings.TrimSpace(c[:eq])), strings.TrimSpace(c[eq+1:])
				switch k {
				case "name", "nombre", "client", "cliente", "peer":
					if current == "peer" && peer != nil {
						peer.Name = v
					} else {
						pendingPeerName = v
					}
				case "excludelocaltraffic":
					if current == "peer" && peer != nil {
						peer.ExcludeLocalTraffic = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes") || strings.EqualFold(v, "si") || strings.EqualFold(v, "sí")
					}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if current == "peer" {
				p.Peers = append(p.Peers, WGPeer{Name: pendingPeerName, AllowedIPs: []string{}})
				peer = &p.Peers[len(p.Peers)-1]
				pendingPeerName = ""
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 1 {
			warnings = append(warnings, fmt.Sprintf("línea %d ignorada", n+1))
			continue
		}
		key, val := strings.ToLower(strings.TrimSpace(line[:eq])), strings.TrimSpace(line[eq+1:])
		switch current {
		case "interface":
			switch key {
			case "privatekey":
				private = val
			case "address":
				p.Addresses = append(p.Addresses, strings.Split(val, ",")...)
			case "dns":
				p.DNS = append(p.DNS, strings.Split(val, ",")...)
			case "mtu":
				p.MTU, _ = strconv.Atoi(val)
			case "listenport":
				p.ListenPort, _ = strconv.Atoi(val)
			case "table":
				p.Table = val
			case "preup":
				p.PreUp = append(p.PreUp, val)
				warnings = append(warnings, "PreUp importado pero desactivado por seguridad")
			case "postup":
				p.PostUp = append(p.PostUp, val)
				warnings = append(warnings, "PostUp importado pero desactivado por seguridad")
			case "predown":
				p.PreDown = append(p.PreDown, val)
				warnings = append(warnings, "PreDown importado pero desactivado por seguridad")
			case "postdown":
				p.PostDown = append(p.PostDown, val)
				warnings = append(warnings, "PostDown importado pero desactivado por seguridad")
			default:
				warnings = append(warnings, "opción de interfaz no soportada: "+key)
			}
		case "peer":
			if peer == nil {
				continue
			}
			switch key {
			case "publickey":
				peer.PublicKey = val
			case "presharedkey":
				if val != "" {
					c, e := cifrar(val)
					if e != nil {
						return p, "", warnings, e
					}
					peer.PresharedKeyCifr = c
				}
			case "endpoint":
				peer.Endpoint = val
			case "allowedips":
				peer.AllowedIPs = append(peer.AllowedIPs, strings.Split(val, ",")...)
			case "persistentkeepalive":
				peer.PersistentKeepalive, _ = strconv.Atoi(val)
			default:
				warnings = append(warnings, "opción de peer no soportada: "+key)
			}
		}
	}
	p.Addresses, p.DNS = wgNormalizeList(p.Addresses), wgNormalizeList(p.DNS)
	if err := wgValidateKey(private, true); err != nil {
		return p, "", warnings, fmt.Errorf("config importada: %w", err)
	}
	pub, err := wgPublicFromPrivate(private)
	if err != nil {
		return p, "", warnings, err
	}
	p.PublicKey = pub
	if err := wgValidateProfile(&p, private); err != nil {
		return p, "", warnings, err
	}
	p.UpdatedAt = p.CreatedAt
	return p, private, warnings, nil
}

func wgRuntimeConfigPath(p WGProfile) string {
	return filepath.Join(wgRuntimeDir(), wgInterfaceName(p.ID)+".conf")
}

func wgWriteRuntimeConfig(p WGProfile) (string, error) {
	cfg, err := wgProfileConfig(p)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(wgRuntimeDir(), 0700); err != nil {
		return "", err
	}
	path := wgRuntimeConfigPath(p)
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		return "", err
	}
	return path, nil
}

func wgRemoveRuntimeConfig(p WGProfile) { _ = os.Remove(wgRuntimeConfigPath(p)) }

func parseWGDump(out string) WGTunnelSnapshot {
	s := WGTunnelSnapshot{Connected: true, Peers: []WGPeerSnapshot{}}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		s.Connected = false
		return s
	}
	first := strings.Split(lines[0], "\t")
	if len(first) >= 3 {
		s.ListenPort, _ = strconv.Atoi(first[2])
	}
	for _, line := range lines[1:] {
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			continue
		}
		ps := WGPeerSnapshot{PublicKey: f[0], Endpoint: f[2], AllowedIPs: f[3]}
		ps.LatestHandshake, _ = strconv.ParseInt(f[4], 10, 64)
		ps.RXBytes, _ = strconv.ParseInt(f[5], 10, 64)
		ps.TXBytes, _ = strconv.ParseInt(f[6], 10, 64)
		s.RXBytes += ps.RXBytes
		s.TXBytes += ps.TXBytes
		if ps.LatestHandshake > s.LatestHandshake {
			s.LatestHandshake = ps.LatestHandshake
		}
		s.Peers = append(s.Peers, ps)
	}
	return s
}

func wgProfileByID(id string) (WGProfile, error) {
	wgMu.Lock()
	defer wgMu.Unlock()
	st := loadWGStore()
	p, _ := wgFindProfile(&st, id)
	if p == nil {
		return WGProfile{}, errors.New("perfil WireGuard no encontrado")
	}
	return *p, nil
}

func manejarWGProfiles(w http.ResponseWriter, r *http.Request) {
	wgMu.Lock()
	defer wgMu.Unlock()
	st := loadWGStore()
	switch r.Method {
	case http.MethodGet:
		out := make([]map[string]any, 0, len(st.Profiles))
		for _, p := range st.Profiles {
			out = append(out, wgPublicProfile(p))
		}
		sort.SliceStable(out, func(i, j int) bool {
			return strings.ToLower(out[i]["name"].(string)) < strings.ToLower(out[j]["name"].(string))
		})
		responder(w, out)
	case http.MethodPost:
		var req struct {
			ID, Name, PrivateKey, Notes, Table               string
			Addresses, DNS, PreUp, PostUp, PreDown, PostDown []string
			MTU, ListenPort                                  int
			AllowHooks, AutoConnect                          bool
			Peers                                            []struct {
				Name, PublicKey, PresharedKey, Endpoint string
				AllowedIPs                              []string
				PersistentKeepalive                     int
				ExcludeLocalTraffic                     bool
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			responderError(w, err)
			return
		}
		var p WGProfile
		existing, idx := wgFindProfile(&st, req.ID)
		if existing != nil {
			p = *existing
		} else {
			p = WGProfile{ID: wgNewID(), CreatedAt: time.Now().Format(time.RFC3339)}
		}
		p.Name = req.Name
		p.Addresses = req.Addresses
		p.DNS = req.DNS
		p.MTU = req.MTU
		p.ListenPort = req.ListenPort
		p.Table = req.Table
		p.PreUp = req.PreUp
		p.PostUp = req.PostUp
		p.PreDown = req.PreDown
		p.PostDown = req.PostDown
		p.AllowHooks = req.AllowHooks
		p.AutoConnect = req.AutoConnect
		p.Notes = req.Notes
		p.Peers = make([]WGPeer, 0, len(req.Peers))
		for i, x := range req.Peers {
			wp := WGPeer{Name: x.Name, PublicKey: strings.TrimSpace(x.PublicKey), Endpoint: x.Endpoint, AllowedIPs: x.AllowedIPs, PersistentKeepalive: x.PersistentKeepalive, ExcludeLocalTraffic: x.ExcludeLocalTraffic}
			if x.PresharedKey != "" {
				if err := wgValidateKey(x.PresharedKey, false); err != nil {
					responderError(w, fmt.Errorf("peer %d: %w", i+1, err))
					return
				}
				c, err := cifrar(x.PresharedKey)
				if err != nil {
					responderError(w, err)
					return
				}
				wp.PresharedKeyCifr = c
			} else if existing != nil && i < len(existing.Peers) && existing.Peers[i].PublicKey == wp.PublicKey {
				wp.PresharedKeyCifr = existing.Peers[i].PresharedKeyCifr
			}
			p.Peers = append(p.Peers, wp)
		}
		if req.PrivateKey != "" {
			c, err := cifrar(req.PrivateKey)
			if err != nil {
				responderError(w, err)
				return
			}
			p.PrivateKeyCifr = c
		}
		if err := wgValidateProfile(&p, req.PrivateKey); err != nil {
			responderError(w, err)
			return
		}
		p.UpdatedAt = time.Now().Format(time.RFC3339)
		if existing != nil {
			st.Profiles[idx] = p
		} else {
			st.Profiles = append(st.Profiles, p)
		}
		if err := saveWGStore(st); err != nil {
			responderError(w, err)
			return
		}
		responder(w, map[string]any{"ok": true, "profile": wgPublicProfile(p)})
	default:
		http.Error(w, "método no permitido", 405)
	}
}

func manejarWGDelete(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		responderError(w, errors.New("solicitud inválida"))
		return
	}
	p, err := wgProfileByID(req.ID)
	if err != nil {
		responderError(w, err)
		return
	}
	snap, _ := wgTunnelSnapshot(p)
	if snap.Connected {
		responderError(w, errors.New("desconecta el túnel antes de eliminarlo"))
		return
	}
	wgMu.Lock()
	defer wgMu.Unlock()
	st := loadWGStore()
	_, idx := wgFindProfile(&st, req.ID)
	if idx < 0 {
		responderError(w, errors.New("perfil no encontrado"))
		return
	}
	st.Profiles = append(st.Profiles[:idx], st.Profiles[idx+1:]...)
	wgRemoveRuntimeConfig(p)
	if err := saveWGStore(st); err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true})
}

func manejarWGGenerateKey(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := wgGenerateKeypair()
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "privateKey": priv, "publicKey": pub})
}

func manejarWGGeneratePSK(w http.ResponseWriter, r *http.Request) {
	psk, err := wgGeneratePSK()
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "presharedKey": psk})
}

func manejarWGImport(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Content string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responderError(w, err)
		return
	}
	p, priv, warns, err := wgParseConfig(req.Content, req.Name)
	if err != nil {
		responderError(w, err)
		return
	}
	c, err := cifrar(priv)
	if err != nil {
		responderError(w, err)
		return
	}
	p.PrivateKeyCifr = c
	wgMu.Lock()
	st := loadWGStore()
	st.Profiles = append(st.Profiles, p)
	err = saveWGStore(st)
	wgMu.Unlock()
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "profile": wgPublicProfile(p), "warnings": warns})
}

func manejarWGReveal(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		responderError(w, errors.New("solicitud inválida"))
		return
	}
	p, err := wgProfileByID(req.ID)
	if err != nil {
		responderError(w, err)
		return
	}
	priv, err := descifrar(p.PrivateKeyCifr)
	if err != nil {
		responderError(w, err)
		return
	}
	ps := make([]string, len(p.Peers))
	for i, x := range p.Peers {
		if x.PresharedKeyCifr != "" {
			ps[i], _ = descifrar(x.PresharedKeyCifr)
		}
	}
	responder(w, map[string]any{"ok": true, "privateKey": priv, "presharedKeys": ps})
}

func manejarWGExport(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		responderError(w, errors.New("solicitud inválida"))
		return
	}
	p, err := wgProfileByID(req.ID)
	if err != nil {
		responderError(w, err)
		return
	}
	cfg, err := wgProfileConfig(p)
	if err != nil {
		responderError(w, err)
		return
	}
	name := wgSafeFilename(p.Name) + ".conf"
	path, cancel, err := seleccionarDestinoWireGuard(name)
	if err != nil {
		responderError(w, err)
		return
	}
	if cancel {
		responder(w, map[string]any{"ok": false, "cancelado": true})
		return
	}
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "path": path})
}

func wgSafeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "wireguard"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	x := strings.Trim(b.String(), "-.")
	if x == "" {
		x = "wireguard"
	}
	if len(x) > 60 {
		x = x[:60]
	}
	return x
}

func manejarWGEngine(w http.ResponseWriter, r *http.Request) { responder(w, wgEngineStatus()) }
func manejarWGInstallEngine(w http.ResponseWriter, r *http.Request) {
	info, err := wgInstallEngine()
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, info)
}

func manejarWGConnect(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		responderError(w, errors.New("solicitud inválida"))
		return
	}
	p, err := wgProfileByID(req.ID)
	if err != nil {
		responderError(w, err)
		return
	}
	eng := wgEngineStatus()
	if !eng.Installed {
		responderError(w, errors.New("el motor WireGuard no está disponible en esta compilación"))
		return
	}
	snap, _ := wgTunnelSnapshot(p)
	if snap.Connected {
		responder(w, map[string]any{"ok": true, "already": true})
		return
	}
	path, err := wgWriteRuntimeConfig(p)
	if err != nil {
		responderError(w, err)
		return
	}
	if err := wgConnectProfile(p, path); err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "interface": wgInterfaceName(p.ID)})
}

func manejarWGDisconnect(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		responderError(w, errors.New("solicitud inválida"))
		return
	}
	p, err := wgProfileByID(req.ID)
	if err != nil {
		responderError(w, err)
		return
	}
	if err := wgDisconnectProfile(p); err != nil {
		responderError(w, err)
		return
	}
	wgRemoveRuntimeConfig(p)
	responder(w, map[string]any{"ok": true})
}

func manejarWGStatus(w http.ResponseWriter, r *http.Request) {
	wgMu.Lock()
	st := loadWGStore()
	profiles := append([]WGProfile(nil), st.Profiles...)
	wgMu.Unlock()
	out := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		snap, err := wgTunnelSnapshot(p)
		if err != nil && snap.Error == "" {
			snap.Error = err.Error()
		}
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "autoConnect": p.AutoConnect, "snapshot": snap})
	}
	responder(w, map[string]any{"engine": wgEngineStatus(), "profiles": out})
}

func wireguardAutoConnect() {
	time.Sleep(1200 * time.Millisecond)
	wgMu.Lock()
	st := loadWGStore()
	profiles := append([]WGProfile(nil), st.Profiles...)
	wgMu.Unlock()
	if !wgEngineStatus().Installed {
		return
	}
	for _, p := range profiles {
		if !p.AutoConnect {
			continue
		}
		snap, _ := wgTunnelSnapshot(p)
		if snap.Connected {
			continue
		}
		path, err := wgWriteRuntimeConfig(p)
		if err != nil {
			continue
		}
		_ = wgConnectProfile(p, path)
	}
}

type WGBackupPeer struct {
	Name                string   `json:"name,omitempty"`
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
	ExcludeLocalTraffic bool     `json:"excludeLocalTraffic,omitempty"`
}

type WGBackupProfile struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	PrivateKey  string         `json:"privateKey"`
	PublicKey   string         `json:"publicKey,omitempty"`
	Addresses   []string       `json:"addresses"`
	DNS         []string       `json:"dns,omitempty"`
	MTU         int            `json:"mtu,omitempty"`
	ListenPort  int            `json:"listenPort,omitempty"`
	Table       string         `json:"table,omitempty"`
	PreUp       []string       `json:"preUp,omitempty"`
	PostUp      []string       `json:"postUp,omitempty"`
	PreDown     []string       `json:"preDown,omitempty"`
	PostDown    []string       `json:"postDown,omitempty"`
	AllowHooks  bool           `json:"allowHooks,omitempty"`
	AutoConnect bool           `json:"autoConnect,omitempty"`
	Notes       string         `json:"notes,omitempty"`
	Peers       []WGBackupPeer `json:"peers"`
	CreatedAt   string         `json:"createdAt,omitempty"`
	UpdatedAt   string         `json:"updatedAt,omitempty"`
}

type WGBackup struct {
	Format   string            `json:"format"`
	Profiles []WGBackupProfile `json:"profiles"`
}

func wgExportForBackup() *WGBackup {
	wgMu.Lock()
	defer wgMu.Unlock()
	st := loadWGStore()
	out := &WGBackup{Format: wgStoreFormat, Profiles: []WGBackupProfile{}}
	for _, p := range st.Profiles {
		priv, err := descifrar(p.PrivateKeyCifr)
		if err != nil {
			continue
		}
		bp := WGBackupProfile{ID: p.ID, Name: p.Name, PrivateKey: priv, PublicKey: p.PublicKey, Addresses: p.Addresses, DNS: p.DNS, MTU: p.MTU, ListenPort: p.ListenPort, Table: p.Table, PreUp: p.PreUp, PostUp: p.PostUp, PreDown: p.PreDown, PostDown: p.PostDown, AllowHooks: p.AllowHooks, AutoConnect: p.AutoConnect, Notes: p.Notes, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, Peers: []WGBackupPeer{}}
		for _, x := range p.Peers {
			ps := ""
			if x.PresharedKeyCifr != "" {
				ps, _ = descifrar(x.PresharedKeyCifr)
			}
			bp.Peers = append(bp.Peers, WGBackupPeer{Name: x.Name, PublicKey: x.PublicKey, PresharedKey: ps, Endpoint: x.Endpoint, AllowedIPs: x.AllowedIPs, PersistentKeepalive: x.PersistentKeepalive, ExcludeLocalTraffic: x.ExcludeLocalTraffic})
		}
		out.Profiles = append(out.Profiles, bp)
	}
	return out
}

func wgImportFromBackup(in *WGBackup, replace bool) bool {
	if in == nil || in.Format != wgStoreFormat {
		return false
	}
	wgMu.Lock()
	defer wgMu.Unlock()
	cur := loadWGStore()
	if replace {
		cur = WGStore{Format: wgStoreFormat, Profiles: []WGProfile{}}
	}
	idx := map[string]int{}
	for i, p := range cur.Profiles {
		idx[p.ID] = i
	}
	for _, bp := range in.Profiles {
		if wgValidateKey(bp.PrivateKey, true) != nil {
			continue
		}
		privC, err := cifrar(bp.PrivateKey)
		if err != nil {
			continue
		}
		p := WGProfile{ID: bp.ID, Name: bp.Name, PrivateKeyCifr: privC, PublicKey: bp.PublicKey, Addresses: bp.Addresses, DNS: bp.DNS, MTU: bp.MTU, ListenPort: bp.ListenPort, Table: bp.Table, PreUp: bp.PreUp, PostUp: bp.PostUp, PreDown: bp.PreDown, PostDown: bp.PostDown, AllowHooks: bp.AllowHooks, AutoConnect: bp.AutoConnect, Notes: bp.Notes, CreatedAt: bp.CreatedAt, UpdatedAt: bp.UpdatedAt, Peers: []WGPeer{}}
		if p.ID == "" {
			p.ID = wgNewID()
		}
		if p.PublicKey == "" {
			p.PublicKey, _ = wgPublicFromPrivate(bp.PrivateKey)
		}
		for _, x := range bp.Peers {
			wp := WGPeer{Name: x.Name, PublicKey: x.PublicKey, Endpoint: x.Endpoint, AllowedIPs: x.AllowedIPs, PersistentKeepalive: x.PersistentKeepalive, ExcludeLocalTraffic: x.ExcludeLocalTraffic}
			if x.PresharedKey != "" {
				if wgValidateKey(x.PresharedKey, false) == nil {
					wp.PresharedKeyCifr, _ = cifrar(x.PresharedKey)
				}
			}
			p.Peers = append(p.Peers, wp)
		}
		if wgValidateProfile(&p, bp.PrivateKey) != nil {
			continue
		}
		if i, ok := idx[p.ID]; ok {
			cur.Profiles[i] = p
		} else {
			cur.Profiles = append(cur.Profiles, p)
			idx[p.ID] = len(cur.Profiles) - 1
		}
	}
	return saveWGStore(cur) == nil
}
