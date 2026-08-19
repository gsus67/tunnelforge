package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestWebLocalPrivateRemote(t *testing.T) {
	ok := []string{
		"127.0.0.1:1234",
		"192.168.1.25:5555",
		"10.10.0.2:5555",
		"172.16.20.4:5555",
		"[fd00::25]:5555",
		"169.254.10.20:5555",
	}
	for _, remote := range ok {
		if !webLocalPrivateRemote(remote) {
			t.Fatalf("esperaba permitir %s", remote)
		}
	}
	bad := []string{"8.8.8.8:53", "1.1.1.1:443", "203.0.113.10:8080", "sin-ip"}
	for _, remote := range bad {
		if webLocalPrivateRemote(remote) {
			t.Fatalf("no esperaba permitir %s", remote)
		}
	}
}

func TestWebLocalOrigin(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8788/api/test", nil)
	r.Host = "192.168.1.10:8788"
	r.Header.Set("Origin", "http://192.168.1.10:8788")
	if !webLocalOriginAllowed(r) {
		t.Fatal("el mismo origen debe estar permitido")
	}
	r.Header.Set("Origin", "http://evil.example")
	if webLocalOriginAllowed(r) {
		t.Fatal("un origen distinto debe rechazarse")
	}
}

func TestWebLocalLoginRuntimeAndProxy(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "master-token" {
			t.Fatalf("el proxy no inyectó el token interno")
		}
		responder(w, map[string]any{"ok": true})
	})
	m := newWebLocalManager("master-token", backend)
	m.server = &http.Server{}
	m.port = 8788
	m.code = "123456"
	assets := fstest.MapFS{"index.html": {Data: []byte("ok")}}
	h := m.lanHandler(assets)

	login := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8788/api/web/login", strings.NewReader(`{"code":"123456"}`))
	login.RemoteAddr = "192.168.1.25:5050"
	login.Host = "192.168.1.10:8788"
	login.Header.Set("Origin", "http://192.168.1.10:8788")
	login.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, login)
	if w.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", w.Code, w.Body.String())
	}
	resp := w.Result()
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == webLocalCookieName {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("login no creó cookie de sesión")
	}

	runtimeReq := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8788/api/web/runtime", nil)
	runtimeReq.RemoteAddr = "192.168.1.25:5051"
	runtimeReq.Host = "192.168.1.10:8788"
	runtimeReq.Header.Set("Origin", "http://192.168.1.10:8788")
	runtimeReq.AddCookie(session)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, runtimeReq)
	if rw.Code != http.StatusOK {
		t.Fatalf("runtime: status=%d body=%s", rw.Code, rw.Body.String())
	}
	var runtimeBody map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &runtimeBody); err != nil {
		t.Fatal(err)
	}
	if runtimeBody["wsBase"] != "ws://192.168.1.10:8788" {
		t.Fatalf("wsBase inesperado: %#v", runtimeBody["wsBase"])
	}
	if _, leaked := runtimeBody["token"]; leaked {
		t.Fatal("runtime web no debe exponer el token maestro")
	}

	apiReq := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8788/api/test", nil)
	apiReq.RemoteAddr = "192.168.1.25:5052"
	apiReq.Host = "192.168.1.10:8788"
	apiReq.Header.Set("Origin", "http://192.168.1.10:8788")
	apiReq.AddCookie(session)
	aw := httptest.NewRecorder()
	h.ServeHTTP(aw, apiReq)
	if aw.Code != http.StatusOK {
		t.Fatalf("proxy API: status=%d body=%s", aw.Code, aw.Body.String())
	}

	controlReq := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8788/api/web-local/estado", nil)
	controlReq.RemoteAddr = "192.168.1.25:5053"
	controlReq.Host = "192.168.1.10:8788"
	controlReq.Header.Set("Origin", "http://192.168.1.10:8788")
	controlReq.AddCookie(session)
	cw := httptest.NewRecorder()
	h.ServeHTTP(cw, controlReq)
	if cw.Code != http.StatusNotFound {
		t.Fatalf("el control del servidor LAN no debe exponerse al navegador remoto; status=%d", cw.Code)
	}
}

func TestWebLocalRejectsPublicRemoteAndDesktopControl(t *testing.T) {
	m := newWebLocalManager("master", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("el backend no debía ejecutarse")
	}))
	m.server = &http.Server{}
	m.code = "123456"
	assets := fstest.MapFS{"index.html": {Data: []byte("ok")}}
	h := m.lanHandler(assets)

	publicReq := httptest.NewRequest(http.MethodGet, "http://example/api/web/runtime", nil)
	publicReq.RemoteAddr = "8.8.8.8:1234"
	pw := httptest.NewRecorder()
	h.ServeHTTP(pw, publicReq)
	if pw.Code != http.StatusForbidden {
		t.Fatalf("remote público: esperaba 403, obtuve %d", pw.Code)
	}
}

func TestWebLocalRateLimit(t *testing.T) {
	m := newWebLocalManager("master", http.NotFoundHandler())
	m.server = &http.Server{}
	m.code = "123456"
	assets := fstest.MapFS{"index.html": {Data: []byte("ok")}}
	h := m.lanHandler(assets)

	for i := 0; i < webLocalMaxFailed; i++ {
		r := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8788/api/web/login", strings.NewReader(`{"code":"000000"}`))
		r.RemoteAddr = "192.168.1.90:4000"
		r.Host = "192.168.1.10:8788"
		r.Header.Set("Origin", "http://192.168.1.10:8788")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("intento %d: esperaba 401, obtuve %d", i+1, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8788/api/web/login", strings.NewReader(`{"code":"123456"}`))
	r.RemoteAddr = "192.168.1.90:4001"
	r.Host = "192.168.1.10:8788"
	r.Header.Set("Origin", "http://192.168.1.10:8788")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("esperaba 429 durante el bloqueo, obtuve %d", w.Code)
	}
}
