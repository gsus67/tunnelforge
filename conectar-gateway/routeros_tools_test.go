package main

import "testing"

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
