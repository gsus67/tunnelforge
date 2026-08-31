package main

import (
	"math"
	"testing"
)

func TestParsePingMs(t *testing.T) {
	casos := map[string]float64{
		"12ms":      12,
		"12.5ms":    12.5,
		"980us":     0.98,
		"1s200ms":   1200,
		"12ms345us": 12.345,
		"":          0,
		"7":         7,
	}
	for in, want := range casos {
		if got := parsePingMs(in); math.Abs(got-want) > 1e-6 {
			t.Errorf("parsePingMs(%q) = %v; quiero %v", in, got, want)
		}
	}
	if round1(3.14159) != 3.1 || round1(2.05) != 2.1 {
		t.Errorf("round1 mal: %v %v", round1(3.14159), round1(2.05))
	}
}

func TestReNombreScriptMT(t *testing.T) {
	for _, ok := range []string{"backup", "tf-check_1", "a", "Script.v2"} {
		if !reNombreScriptMT.MatchString(ok) {
			t.Errorf("%q debería ser un nombre de script válido", ok)
		}
	}
	for _, mal := range []string{"", "-x", "con espacio", "raro;drop", "/etc"} {
		if reNombreScriptMT.MatchString(mal) {
			t.Errorf("%q no debería ser válido", mal)
		}
	}
}

func TestReRutaRouterOS(t *testing.T) {
	ok := []string{"/interface", "/ip/address", "/system/routerboard", "/ip/firewall/filter", "/ping", "/ipv6/route"}
	mal := []string{"/", "interface", "/IP/address", "/ip/../secret", "/ip/route;drop", "/ip route", ""}
	for _, p := range ok {
		if !reRutaRouterOS.MatchString(p) {
			t.Errorf("reRutaRouterOS rechazó %q y debería aceptarla", p)
		}
	}
	for _, p := range mal {
		if reRutaRouterOS.MatchString(p) {
			t.Errorf("reRutaRouterOS aceptó %q y debería rechazarla", p)
		}
	}
}

func TestReIDFirewall(t *testing.T) {
	for _, id := range []string{"*1", "*A", "*2F", "1a", "0"} {
		if !reIDFirewall.MatchString(id) {
			t.Errorf("id de firewall %q debería ser válido", id)
		}
	}
	for _, id := range []string{"*1;", "../x", "*", "", "1 2"} {
		if reIDFirewall.MatchString(id) {
			t.Errorf("id de firewall %q debería ser inválido", id)
		}
	}
}

func TestResumenReglaMT(t *testing.T) {
	got := resumenReglaMT(map[string]any{
		"chain":            "input",
		"protocol":         "tcp",
		"dst-port":         "8291",
		"src-address":      "10.0.0.0/24",
		"connection-state": "new",
		"comment":          "winbox",
	})
	quiero := "protocol=tcp src-address=10.0.0.0/24 dst-port=8291 connection-state=new"
	if got != quiero {
		t.Fatalf("resumenReglaMT = %q; quiero %q", got, quiero)
	}
	if resumenReglaMT(map[string]any{"chain": "forward"}) != "" {
		t.Fatalf("una regla sin campos de match debería resumir a vacío")
	}
}
