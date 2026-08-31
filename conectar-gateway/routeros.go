// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//
// Cliente mínimo de RouterOS para el Monitoreo de TunnelForge. Los equipos
// MikroTik se consultan directamente por HTTPS y no requieren agente.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type mikrotikResumen struct {
	CPU, RAM, Disco float64
	UptimeSeg       float64
	RXMbit, TXMbit  float64
	Version, Board  string
	IfaceTrafico    string // interfaz de la que salió el RX/TX del resumen
}

type mikrotikPeer struct {
	Nombre, Interfaz, AllowedIPs, Key, Endpoint string
	RXMbit, TXMbit                              float64
	HandshakeAgeSeg                             float64
}

type mikrotikSample struct {
	t                time.Time
	perKey           map[string][2]float64
	ifaceRx, ifaceTx float64
}

// elegirInterfazTrafico decide de qué interfaz sale el RX/TX del resumen —
// la misma semántica que el agente de Linux (la interfaz de la ruta por
// defecto). Prioridad: override manual del perfil → interfaz de la ruta
// 0.0.0.0/0 activa → primera ether corriendo. Devuelve "" si no encuentra.
func elegirInterfazTrafico(interfaces []map[string]any, rutas []map[string]any, override string) string {
	nombres := make(map[string]bool, len(interfaces))
	for _, it := range interfaces {
		if n := routerOSString(it["name"]); n != "" {
			nombres[n] = true
		}
	}
	if o := strings.TrimSpace(override); o != "" {
		return o // se respeta aunque no aparezca listada todavía
	}
	for _, ruta := range rutas {
		if routerOSString(ruta["dst-address"]) != "0.0.0.0/0" {
			continue
		}
		if routerOSString(ruta["disabled"]) == "true" || routerOSString(ruta["inactive"]) == "true" {
			continue
		}
		if routerOSString(ruta["active"]) == "false" {
			continue
		}
		// ROS7: "immediate-gw" = "1.2.3.4%ether1"; "gateway" a veces ya es
		// el nombre de la interfaz (pppoe-out1, etc.).
		for _, campo := range []string{"immediate-gw", "gateway"} {
			v := routerOSString(ruta[campo])
			if v == "" {
				continue
			}
			if i := strings.LastIndex(v, "%"); i >= 0 {
				v = v[i+1:]
			}
			v = strings.TrimSpace(v)
			if v != "" && nombres[v] {
				return v
			}
		}
	}
	for _, it := range interfaces {
		if routerOSString(it["type"]) != "ether" {
			continue
		}
		if routerOSString(it["disabled"]) == "true" || routerOSString(it["running"]) == "false" {
			continue
		}
		if n := routerOSString(it["name"]); n != "" {
			return n
		}
	}
	return ""
}

func contadoresInterfaz(interfaces []map[string]any, nombre string) (rx, tx float64, ok bool) {
	for _, it := range interfaces {
		if routerOSString(it["name"]) != nombre {
			continue
		}
		return routerOSFloat(it["rx-byte"]), routerOSFloat(it["tx-byte"]), true
	}
	return 0, 0, false
}

var mtSamples sync.Map

type mikrotikPeerCounter struct {
	peer      mikrotikPeer
	sampleKey string
	rx, tx    float64
}

type mikrotikStatusError struct {
	statusCode int
	status     string
}

func (e *mikrotikStatusError) Error() string {
	if e.statusCode == http.StatusUnauthorized {
		return "autenticación rechazada (HTTP 401)"
	}
	return "RouterOS respondió " + e.status
}

type mikrotikClient struct {
	baseURL  string
	usuario  string
	password string
	http     *http.Client
}

func nuevoMikrotikClient(s Servidor, passPlano string) (*mikrotikClient, error) {
	host := strings.TrimSpace(s.Host)
	if host == "" {
		return nil, fmt.Errorf("el host está vacío")
	}
	if !monitoringHostValido(host) {
		return nil, fmt.Errorf("el host %q no es válido", host)
	}
	esquema := "https"
	if s.APIHTTP {
		esquema = "http"
	}
	puerto := s.APIPuerto
	if puerto == 0 {
		if s.APIHTTP {
			puerto = 80
		} else {
			puerto = 443
		}
	}
	if puerto < 1 || puerto > 65535 {
		return nil, fmt.Errorf("el puerto API %d no es válido", puerto)
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	base := (&url.URL{Scheme: esquema, Host: net.JoinHostPort(host, strconv.Itoa(puerto)), Path: "/rest"}).String()
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: s.APIInseguro}} //nolint:gosec // opción explícita por perfil para certificados autofirmados de RouterOS
	return &mikrotikClient{
		baseURL:  base,
		usuario:  s.Usuario,
		password: passPlano,
		http: &http.Client{
			Timeout:   8 * time.Second,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *mikrotikClient) get(path string, destino any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.usuario, c.password)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &mikrotikStatusError{statusCode: resp.StatusCode, status: resp.Status}
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	dec.UseNumber()
	if err := dec.Decode(destino); err != nil {
		return fmt.Errorf("respuesta JSON no válida: %w", err)
	}
	return nil
}

func parseRouterOSDuration(valor string) float64 {
	s := strings.TrimSpace(valor)
	if s == "" {
		return 0
	}
	var total float64
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t")
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 || i >= len(s) {
			return 0
		}
		n, err := strconv.ParseFloat(s[:i], 64)
		if err != nil {
			return 0
		}
		factor := float64(0)
		switch s[i] {
		case 'w':
			factor = 7 * 24 * 60 * 60
		case 'd':
			factor = 24 * 60 * 60
		case 'h':
			factor = 60 * 60
		case 'm':
			factor = 60
		case 's':
			factor = 1
		default:
			return 0
		}
		total += n * factor
		s = s[i+1:]
	}
	return total
}

func routerOSFloat(v any) float64 {
	var f float64
	switch x := v.(type) {
	case json.Number:
		f, _ = x.Float64()
	case float64:
		f = x
	case float32:
		f = float64(x)
	case int:
		f = float64(x)
	case int64:
		f = float64(x)
	case string:
		f, _ = strconv.ParseFloat(strings.TrimSpace(x), 64)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}

func routerOSString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func routerOSPercentUsed(libres, total float64) float64 {
	if total <= 0 {
		return 0
	}
	pct := 100 * (1 - libres/total)
	return math.Max(0, math.Min(100, pct))
}

func parseMikrotikResource(datos []byte) (mikrotikResumen, error) {
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(string(datos)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return mikrotikResumen{}, err
	}
	return mikrotikResumen{
		CPU:       math.Max(0, math.Min(100, routerOSFloat(raw["cpu-load"]))),
		RAM:       routerOSPercentUsed(routerOSFloat(raw["free-memory"]), routerOSFloat(raw["total-memory"])),
		Disco:     routerOSPercentUsed(routerOSFloat(raw["free-hdd-space"]), routerOSFloat(raw["total-hdd-space"])),
		UptimeSeg: parseRouterOSDuration(routerOSString(raw["uptime"])),
		Version:   routerOSString(raw["version"]),
		Board:     routerOSString(raw["board-name"]),
	}, nil
}

func parseMikrotikResourceMap(raw map[string]any) mikrotikResumen {
	return mikrotikResumen{
		CPU:       math.Max(0, math.Min(100, routerOSFloat(raw["cpu-load"]))),
		RAM:       routerOSPercentUsed(routerOSFloat(raw["free-memory"]), routerOSFloat(raw["total-memory"])),
		Disco:     routerOSPercentUsed(routerOSFloat(raw["free-hdd-space"]), routerOSFloat(raw["total-hdd-space"])),
		UptimeSeg: parseRouterOSDuration(routerOSString(raw["uptime"])),
		Version:   routerOSString(raw["version"]),
		Board:     routerOSString(raw["board-name"]),
	}
}

func parseMikrotikPeers(datos []byte) ([]mikrotikPeerCounter, error) {
	var raw []map[string]any
	dec := json.NewDecoder(strings.NewReader(string(datos)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	return parseMikrotikPeerMaps(raw), nil
}

func parseMikrotikPeerMaps(raw []map[string]any) []mikrotikPeerCounter {
	peers := make([]mikrotikPeerCounter, 0, len(raw))
	for i, item := range raw {
		key := routerOSString(item["public-key"])
		interfaz := routerOSString(item["interface"])
		allowed := routerOSString(item["allowed-address"])
		nombre := routerOSString(item["name"])
		if nombre == "" {
			nombre = routerOSString(item["comment"])
		}
		if nombre == "" {
			nombre = allowed
		}
		if nombre == "" {
			abreviada := key
			if len(abreviada) > 8 {
				abreviada = abreviada[:8]
			}
			if abreviada == "" {
				abreviada = strconv.Itoa(i + 1)
			}
			nombre = "peer-" + abreviada
		}
		endpoint := routerOSString(item["current-endpoint-address"])
		endpointPort := routerOSString(item["current-endpoint-port"])
		if endpoint != "" && endpointPort != "" {
			endpoint = net.JoinHostPort(strings.Trim(endpoint, "[]"), endpointPort)
		}
		handshake := -1.0
		if rawHandshake := routerOSString(item["last-handshake"]); rawHandshake != "" {
			handshake = parseRouterOSDuration(rawHandshake)
		}
		sampleKey := key
		if sampleKey == "" {
			sampleKey = interfaz + "\x00" + allowed + "\x00" + nombre
		}
		peers = append(peers, mikrotikPeerCounter{
			peer: mikrotikPeer{
				Nombre: nombre, Interfaz: interfaz, AllowedIPs: allowed, Key: key,
				Endpoint: endpoint, HandshakeAgeSeg: handshake,
			},
			sampleKey: sampleKey,
			rx:        routerOSFloat(item["rx"]),
			tx:        routerOSFloat(item["tx"]),
		})
	}
	return peers
}

// mikrotikAplicarMuestra guarda la muestra actual y devuelve las tasas
// (Mbit/s) calculadas contra la anterior: RX/TX del resumen se sacan de los
// contadores `ifaceRx`/`ifaceTx` (la interfaz de tráfico elegida), y cada
// peer trae su propia tasa a partir de sus contadores WireGuard.
func mikrotikAplicarMuestra(nombre string, ahora time.Time, ifaceRx, ifaceTx float64, contadores []mikrotikPeerCounter) (float64, float64, []mikrotikPeer) {
	actual := mikrotikSample{t: ahora, perKey: make(map[string][2]float64, len(contadores)), ifaceRx: ifaceRx, ifaceTx: ifaceTx}
	for _, p := range contadores {
		actual.perKey[p.sampleKey] = [2]float64{p.rx, p.tx}
	}
	previoAny, existe := mtSamples.Load(nombre)
	dt := float64(0)
	var previo mikrotikSample
	if existe {
		previo, existe = previoAny.(mikrotikSample)
		if existe {
			dt = ahora.Sub(previo.t).Seconds()
		}
	}
	valid := existe && dt >= 0.3 && dt <= 120
	peers := make([]mikrotikPeer, 0, len(contadores))
	for _, contador := range contadores {
		p := contador.peer
		if valid {
			if anterior, ok := previo.perKey[contador.sampleKey]; ok {
				p.RXMbit = math.Max(0, (contador.rx-anterior[0])/dt) * 8 / 1e6
				p.TXMbit = math.Max(0, (contador.tx-anterior[1])/dt) * 8 / 1e6
			}
		}
		peers = append(peers, p)
	}
	var rxMbit, txMbit float64
	if valid {
		rxMbit = math.Max(0, (actual.ifaceRx-previo.ifaceRx)/dt) * 8 / 1e6
		txMbit = math.Max(0, (actual.ifaceTx-previo.ifaceTx)/dt) * 8 / 1e6
	}
	mtSamples.Store(nombre, actual)
	return rxMbit, txMbit, peers
}

func mikrotikConsultar(s Servidor, passPlano string) (mikrotikResumen, []mikrotikPeer, error) {
	c, err := nuevoMikrotikClient(s, passPlano)
	puerto := s.APIPuerto
	if puerto == 0 {
		puerto = 443
	}
	destino := net.JoinHostPort(strings.Trim(strings.TrimSpace(s.Host), "[]"), strconv.Itoa(puerto))
	fallo := func(err error) (mikrotikResumen, []mikrotikPeer, error) {
		return mikrotikResumen{}, nil, fmt.Errorf("no pude consultar la REST API de %s: %w", destino, err)
	}
	if err != nil {
		return fallo(err)
	}
	var recurso map[string]any
	if err := c.get("/system/resource", &recurso); err != nil {
		return fallo(err)
	}
	var rawPeers []map[string]any
	if err := c.get("/interface/wireguard/peers", &rawPeers); err != nil {
		return fallo(err)
	}
	// Interfaces y rutas para el RX/TX del resumen (interfaz de la ruta por
	// defecto, o el override del perfil). Si falla, el resumen sigue con las
	// demás métricas y tráfico 0 en vez de romper.
	var interfaces, rutas []map[string]any
	_ = c.get("/interface", &interfaces)
	_ = c.get("/ip/route", &rutas)
	ifaceRx, ifaceTx := 0.0, 0.0
	ifaceNombre := elegirInterfazTrafico(interfaces, rutas, s.APIInterfaz)
	if ifaceNombre != "" {
		ifaceRx, ifaceTx, _ = contadoresInterfaz(interfaces, ifaceNombre)
	}
	resumen := parseMikrotikResourceMap(recurso)
	resumen.IfaceTrafico = ifaceNombre
	var peers []mikrotikPeer
	resumen.RXMbit, resumen.TXMbit, peers = mikrotikAplicarMuestra(s.Nombre, time.Now(), ifaceRx, ifaceTx, parseMikrotikPeerMaps(rawPeers))
	return resumen, peers, nil
}

// mikrotikDiagnosticar separa disponibilidad, autenticación y detección de
// peers para que el diagnóstico no muestre pasos SSH a un equipo RouterOS.
func mikrotikDiagnosticar(s Servidor, passPlano string) (alcanzable, autenticado bool, peers int, err error) {
	c, err := nuevoMikrotikClient(s, passPlano)
	if err != nil {
		return false, false, 0, err
	}
	var recurso map[string]any
	err = c.get("/system/resource", &recurso)
	if err != nil {
		if _, ok := err.(*mikrotikStatusError); ok {
			return true, false, 0, err
		}
		return false, false, 0, err
	}
	alcanzable, autenticado = true, true
	var rawPeers []map[string]any
	if err = c.get("/interface/wireguard/peers", &rawPeers); err != nil {
		return alcanzable, autenticado, 0, err
	}
	return alcanzable, autenticado, len(rawPeers), nil
}
