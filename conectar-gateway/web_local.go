// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	webLocalDefaultPort   = 8788
	webLocalCookieName    = "gwa_web_session"
	webLocalSessionTTL    = 12 * time.Hour
	webLocalMaxFailed     = 5
	webLocalLockout       = time.Minute
	webLocalMaxLoginBytes = 4096
)

type webLocalSession struct {
	Expires time.Time
	IP      string
}

type webLocalAttempt struct {
	Failed      int
	LockedUntil time.Time
}

type webLocalState struct {
	Active       bool     `json:"active"`
	Port         int      `json:"port"`
	Code         string   `json:"code,omitempty"`
	Addresses    []string `json:"addresses"`
	Sessions     int      `json:"sessions"`
	Started      string   `json:"started,omitempty"`
	TrustedLAN   bool     `json:"trustedLan"`
	SessionHours int      `json:"sessionHours"`
}

type webLocalManager struct {
	mu          sync.Mutex
	backend     http.Handler
	masterToken string
	server      *http.Server
	listener    net.Listener
	port        int
	code        string
	started     time.Time
	sessions    map[string]webLocalSession
	attempts    map[string]webLocalAttempt
}

func newWebLocalManager(masterToken string, backend http.Handler) *webLocalManager {
	return &webLocalManager{
		backend:     backend,
		masterToken: masterToken,
		sessions:    make(map[string]webLocalSession),
		attempts:    make(map[string]webLocalAttempt),
	}
}

func webLocalRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func webLocalRandomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func webLocalRemoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		return host
	}
	return strings.Trim(remote, "[]")
}

func webLocalPrivateRemote(remote string) bool {
	ip := net.ParseIP(webLocalRemoteIP(remote))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func webLocalOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func webLocalAddresses(port int) []string {
	var out []string
	seen := map[string]bool{}
	// Primero intenta mostrar la IPv4 que usa la ruta por defecto. En equipos
	// con Docker, Hyper-V o VPN suele ser más útil que la primera interfaz que
	// devuelva el sistema.
	if conn, err := net.Dial("udp4", "8.8.8.8:80"); err == nil {
		if udp, ok := conn.LocalAddr().(*net.UDPAddr); ok && udp.IP != nil {
			if v4 := udp.IP.To4(); v4 != nil && (v4.IsPrivate() || v4.IsLinkLocalUnicast()) {
				u := fmt.Sprintf("http://%s:%d", v4.String(), port)
				seen[u] = true
				out = append(out, u)
			}
		}
		_ = conn.Close()
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || (!ip.IsPrivate() && !ip.IsLinkLocalUnicast()) {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				u := fmt.Sprintf("http://%s:%d", v4.String(), port)
				if !seen[u] {
					seen[u] = true
					out = append(out, u)
				}
			}
		}
	}
	return out
}

func (m *webLocalManager) state(includeCode bool) webLocalState {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeExpiredSessionsLocked(time.Now())
	st := webLocalState{
		Active:       m.server != nil,
		Port:         m.port,
		Sessions:     len(m.sessions),
		TrustedLAN:   true,
		SessionHours: int(webLocalSessionTTL / time.Hour),
	}
	if st.Port == 0 {
		st.Port = webLocalDefaultPort
	}
	if st.Active {
		st.Addresses = webLocalAddresses(m.port)
		st.Started = m.started.Format(time.RFC3339)
		if includeCode {
			st.Code = m.code
		}
	}
	return st
}

func (m *webLocalManager) Start(port int) (webLocalState, error) {
	if port == 0 {
		port = webLocalDefaultPort
	}
	if port < 1024 || port > 65535 {
		return webLocalState{}, fmt.Errorf("el puerto debe estar entre 1024 y 65535")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil {
		if m.port != port {
			return webLocalState{}, fmt.Errorf("el servidor web ya está activo en el puerto %d; detenlo antes de cambiarlo", m.port)
		}
		m.purgeExpiredSessionsLocked(time.Now())
		return m.stateLocked(true), nil
	}

	uiAssets, err := fs.Sub(frontendAssets, "frontend/dist")
	if err != nil {
		return webLocalState{}, fmt.Errorf("no pude abrir la interfaz embebida: %w", err)
	}
	code, err := webLocalRandomCode()
	if err != nil {
		return webLocalState{}, fmt.Errorf("no pude generar el código de acceso: %w", err)
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return webLocalState{}, fmt.Errorf("no pude abrir el puerto %d: %w", port, err)
	}

	m.port = port
	m.code = code
	m.started = time.Now()
	m.sessions = make(map[string]webLocalSession)
	m.attempts = make(map[string]webLocalAttempt)
	m.listener = listener
	srv := &http.Server{
		Handler:           m.lanHandler(uiAssets),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	m.server = srv

	go func() {
		err := srv.Serve(listener)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.server == srv {
			m.server = nil
			m.listener = nil
			m.code = ""
			m.started = time.Time{}
			m.sessions = make(map[string]webLocalSession)
			m.attempts = make(map[string]webLocalAttempt)
		}
		if err != nil && err != http.ErrServerClosed {
			fmt.Println("ERROR: servidor web local:", err)
		}
	}()

	return m.stateLocked(true), nil
}

func (m *webLocalManager) Stop() error {
	m.mu.Lock()
	srv := m.server
	listener := m.listener
	m.server = nil
	m.listener = nil
	m.code = ""
	m.started = time.Time{}
	m.sessions = make(map[string]webLocalSession)
	m.attempts = make(map[string]webLocalAttempt)
	m.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	if listener != nil {
		_ = listener.Close()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (m *webLocalManager) RegenerateCode() (webLocalState, error) {
	code, err := webLocalRandomCode()
	if err != nil {
		return webLocalState{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server == nil {
		return webLocalState{}, fmt.Errorf("el servidor web local no está activo")
	}
	m.code = code
	m.sessions = make(map[string]webLocalSession)
	m.attempts = make(map[string]webLocalAttempt)
	return m.stateLocked(true), nil
}

func (m *webLocalManager) stateLocked(includeCode bool) webLocalState {
	m.purgeExpiredSessionsLocked(time.Now())
	st := webLocalState{
		Active:       m.server != nil,
		Port:         m.port,
		Sessions:     len(m.sessions),
		TrustedLAN:   true,
		SessionHours: int(webLocalSessionTTL / time.Hour),
	}
	if st.Port == 0 {
		st.Port = webLocalDefaultPort
	}
	if st.Active {
		st.Addresses = webLocalAddresses(m.port)
		st.Started = m.started.Format(time.RFC3339)
		if includeCode {
			st.Code = m.code
		}
	}
	return st
}

func (m *webLocalManager) purgeExpiredSessionsLocked(now time.Time) {
	for token, session := range m.sessions {
		if !session.Expires.After(now) {
			delete(m.sessions, token)
		}
	}
}

func (m *webLocalManager) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(webLocalCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	ip := webLocalRemoteIP(r.RemoteAddr)
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeExpiredSessionsLocked(now)
	session, ok := m.sessions[cookie.Value]
	return ok && session.IP == ip && session.Expires.After(now)
}

func (m *webLocalManager) setSecurityHeaders(w http.ResponseWriter, api bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if api {
		w.Header().Set("Cache-Control", "no-store")
	}
}

func (m *webLocalManager) lanHandler(uiAssets fs.FS) http.Handler {
	files := http.FileServer(http.FS(uiAssets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAPI := strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/")
		m.setSecurityHeaders(w, isAPI)
		if !webLocalPrivateRemote(r.RemoteAddr) {
			http.Error(w, "acceso permitido solo desde la red local", http.StatusForbidden)
			return
		}
		if !webLocalOriginAllowed(r) {
			http.Error(w, "origen no permitido", http.StatusForbidden)
			return
		}

		switch r.URL.Path {
		case "/api/web/login":
			m.handleLANLogin(w, r)
			return
		case "/api/web/runtime":
			if !m.validSession(r) {
				responderEstadoHTTP(w, http.StatusUnauthorized, map[string]any{"error": "autenticación requerida"})
				return
			}
			wsScheme := "ws"
			if r.TLS != nil {
				wsScheme = "wss"
			}
			responder(w, map[string]any{
				"version": version,
				"wsBase":  wsScheme + "://" + r.Host,
				"web":     true,
			})
			return
		case "/api/web/logout":
			m.handleLANLogout(w, r)
			return
		}

		if isAPI {
			if strings.HasPrefix(r.URL.Path, "/api/web-local/") {
				http.NotFound(w, r)
				return
			}
			if !m.validSession(r) {
				responderEstadoHTTP(w, http.StatusUnauthorized, map[string]any{"error": "sesión web no autorizada"})
				return
			}
			clon := r.Clone(r.Context())
			clon.Header = r.Header.Clone()
			clon.Header.Set("X-Token", m.masterToken)
			m.backend.ServeHTTP(w, clon)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}

func responderEstadoHTTP(w http.ResponseWriter, status int, datos any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(datos)
}

func (m *webLocalManager) handleLANLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ip := webLocalRemoteIP(r.RemoteAddr)
	now := time.Now()
	m.mu.Lock()
	attempt := m.attempts[ip]
	if attempt.LockedUntil.After(now) {
		retry := int(time.Until(attempt.LockedUntil).Seconds())
		if retry < 1 {
			retry = 1
		}
		m.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		responderEstadoHTTP(w, http.StatusTooManyRequests, map[string]any{"error": "demasiados intentos; espera un minuto"})
		return
	}
	code := m.code
	active := m.server != nil
	m.mu.Unlock()
	if !active || code == "" {
		responderEstadoHTTP(w, http.StatusServiceUnavailable, map[string]any{"error": "servidor web local no disponible"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, webLocalMaxLoginBytes)
	var pet struct {
		Code string `json:"code"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderEstadoHTTP(w, http.StatusBadRequest, map[string]any{"error": "solicitud no válida"})
		return
	}
	pet.Code = strings.TrimSpace(pet.Code)
	valid := len(pet.Code) == len(code) && subtle.ConstantTimeCompare([]byte(pet.Code), []byte(code)) == 1
	if !valid {
		m.mu.Lock()
		attempt = m.attempts[ip]
		attempt.Failed++
		if attempt.Failed >= webLocalMaxFailed {
			attempt.Failed = 0
			attempt.LockedUntil = time.Now().Add(webLocalLockout)
		}
		m.attempts[ip] = attempt
		m.mu.Unlock()
		responderEstadoHTTP(w, http.StatusUnauthorized, map[string]any{"error": "código incorrecto"})
		return
	}

	sessionToken, err := webLocalRandomHex(32)
	if err != nil {
		responderEstadoHTTP(w, http.StatusInternalServerError, map[string]any{"error": "no pude crear la sesión"})
		return
	}
	expires := time.Now().Add(webLocalSessionTTL)
	m.mu.Lock()
	m.sessions[sessionToken] = webLocalSession{Expires: expires, IP: ip}
	delete(m.attempts, ip)
	m.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     webLocalCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
		MaxAge:   int(webLocalSessionTTL.Seconds()),
	})
	responder(w, map[string]any{"ok": true, "version": version})
}

func (m *webLocalManager) handleLANLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie(webLocalCookieName); err == nil {
		m.mu.Lock()
		delete(m.sessions, cookie.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     webLocalCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	responder(w, map[string]any{"ok": true})
}

func (m *webLocalManager) manejarEstado(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	responder(w, m.state(true))
}

func (m *webLocalManager) manejarIniciar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var pet struct {
		Port int `json:"port"`
	}
	if err := decodificar(r, &pet); err != nil && err != io.EOF {
		responderError(w, err)
		return
	}
	st, err := m.Start(pet.Port)
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, st)
}

func (m *webLocalManager) manejarDetener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := m.Stop(); err != nil {
		responderError(w, err)
		return
	}
	responder(w, m.state(true))
}

func (m *webLocalManager) manejarRegenerar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	st, err := m.RegenerateCode()
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, st)
}
