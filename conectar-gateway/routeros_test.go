package main

import (
	"math"
	"testing"
	"time"
)

func TestParseRouterOSDuration(t *testing.T) {
	casos := map[string]float64{
		"1w2d3h4m5s": 788645,
		"5m":         300,
		"10s":        10,
		"":           0,
		"3h":         10800,
	}
	for entrada, esperado := range casos {
		if got := parseRouterOSDuration(entrada); got != esperado {
			t.Errorf("parseRouterOSDuration(%q) = %v; quiero %v", entrada, got, esperado)
		}
	}
}

func TestParseMikrotikResource(t *testing.T) {
	datos := []byte(`{
		"cpu-load": 37,
		"free-memory": "250",
		"total-memory": 1000,
		"free-hdd-space": 400,
		"total-hdd-space": "800",
		"uptime": "1d2h",
		"version": "7.20.1",
		"board-name": "RB5009"
	}`)
	got, err := parseMikrotikResource(datos)
	if err != nil {
		t.Fatal(err)
	}
	if got.CPU != 37 || got.RAM != 75 || got.Disco != 50 || got.UptimeSeg != 93600 {
		t.Fatalf("resumen inesperado: %+v", got)
	}
	if got.Version != "7.20.1" || got.Board != "RB5009" {
		t.Fatalf("metadatos inesperados: %+v", got)
	}
}

func TestParseMikrotikPeers(t *testing.T) {
	datos := []byte(`[
		{"name":"oficina","interface":"wg-office","public-key":"key-a","allowed-address":"10.8.0.2/32","current-endpoint-address":"203.0.113.8","current-endpoint-port":"51820","rx":"125000","tx":250000,"last-handshake":"1m5s"},
		{"comment":"respaldo","interface":"wg-backup","public-key":"key-b","allowed-address":"10.9.0.2/32","rx":500,"tx":"750"}
	]`)
	got, err := parseMikrotikPeers(datos)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("cantidad de peers = %d", len(got))
	}
	if got[0].peer.Nombre != "oficina" || got[0].peer.AllowedIPs != "10.8.0.2/32" || got[0].peer.HandshakeAgeSeg != 65 {
		t.Fatalf("primer peer inesperado: %+v", got[0])
	}
	if got[0].rx != 125000 || got[0].tx != 250000 || got[0].peer.Endpoint != "203.0.113.8:51820" {
		t.Fatalf("contadores/endpoint inesperados: %+v", got[0])
	}
	if got[1].peer.Nombre != "respaldo" || got[1].peer.HandshakeAgeSeg != -1 || got[1].rx != 500 || got[1].tx != 750 {
		t.Fatalf("segundo peer inesperado: %+v", got[1])
	}
}

func TestMikrotikAplicarMuestraCalculaTasa(t *testing.T) {
	const nombre = "mt-test-rate"
	mtSamples.Delete(nombre)
	t.Cleanup(func() { mtSamples.Delete(nombre) })
	t0 := time.Unix(1700000000, 0)
	primera := []mikrotikPeerCounter{{peer: mikrotikPeer{Nombre: "peer"}, sampleKey: "key", rx: 1_000_000, tx: 2_000_000}}
	// RX/TX del resumen salen de los contadores de la interfaz, no de la suma
	// de peers.
	rx, tx, peers := mikrotikAplicarMuestra(nombre, t0, 10_000_000, 20_000_000, primera)
	if rx != 0 || tx != 0 || peers[0].RXMbit != 0 || peers[0].TXMbit != 0 {
		t.Fatalf("la primera muestra debe dar tasa cero: rx=%v tx=%v peer=%+v", rx, tx, peers[0])
	}
	segunda := []mikrotikPeerCounter{{peer: mikrotikPeer{Nombre: "peer"}, sampleKey: "key", rx: 2_000_000, tx: 2_500_000}}
	rx, tx, peers = mikrotikAplicarMuestra(nombre, t0.Add(2*time.Second), 11_000_000, 22_000_000, segunda)
	// interfaz: (11M-10M)/2s*8/1e6 = 4 Mbit/s ; (22M-20M)/2s*8/1e6 = 8 Mbit/s
	if math.Abs(rx-4) > 1e-9 || math.Abs(tx-8) > 1e-9 {
		t.Fatalf("tasa resumen inesperada: rx=%v tx=%v", rx, tx)
	}
	// peer: (2M-1M)/2s*8/1e6 = 4 ; (2.5M-2M)/2s*8/1e6 = 2
	if math.Abs(peers[0].RXMbit-4) > 1e-9 || math.Abs(peers[0].TXMbit-2) > 1e-9 {
		t.Fatalf("tasa peer inesperada: %+v", peers[0])
	}
}

func TestElegirInterfazTrafico(t *testing.T) {
	interfaces := []map[string]any{
		{"name": "ether1", "type": "ether", "running": "true", "rx-byte": "100", "tx-byte": "200"},
		{"name": "ether2", "type": "ether", "running": "true"},
		{"name": "wg-hub", "type": "wg", "running": "true"},
	}
	rutas := []map[string]any{
		{"dst-address": "10.0.0.0/24", "gateway": "ether1"},
		{"dst-address": "0.0.0.0/0", "active": "true", "immediate-gw": "203.0.113.1%ether2"},
	}
	if got := elegirInterfazTrafico(interfaces, rutas, ""); got != "ether2" {
		t.Fatalf("ruta por defecto → %q, quiero ether2", got)
	}
	if got := elegirInterfazTrafico(interfaces, rutas, "  wg-hub "); got != "wg-hub" {
		t.Fatalf("override → %q, quiero wg-hub", got)
	}
	if got := elegirInterfazTrafico(interfaces, nil, ""); got != "ether1" {
		t.Fatalf("sin ruta por defecto → %q, quiero la primera ether corriendo", got)
	}
	rx, tx, ok := contadoresInterfaz(interfaces, "ether1")
	if !ok || rx != 100 || tx != 200 {
		t.Fatalf("contadoresInterfaz(ether1) = %v/%v ok=%v", rx, tx, ok)
	}
}
