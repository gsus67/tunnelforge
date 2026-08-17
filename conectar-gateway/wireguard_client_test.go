package main

import (
	"reflect"
	"testing"
)

func TestWGInterfaceNameStableAndSafe(t *testing.T) {
	if got, want := wgInterfaceName("A558-efda36!!extra"), "gwa-a558efda36"; got != want {
		t.Fatalf("wgInterfaceName() = %q, want %q", got, want)
	}
	if got, want := wgInterfaceName("***"), "gwa-default"; got != want {
		t.Fatalf("wgInterfaceName(empty-safe) = %q, want %q", got, want)
	}
}

func TestWGEffectiveAllowedIPsExcludeLocal(t *testing.T) {
	peer := WGPeer{
		AllowedIPs:          []string{"0.0.0.0/0", "::/0", "10.50.0.0/16"},
		ExcludeLocalTraffic: true,
	}
	want := []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.50.0.0/16"}
	if got := wgEffectiveAllowedIPs(peer); !reflect.DeepEqual(got, want) {
		t.Fatalf("wgEffectiveAllowedIPs() = %#v, want %#v", got, want)
	}
}

func TestWGEffectiveAllowedIPsNormal(t *testing.T) {
	in := []string{"0.0.0.0/0", "10.50.0.0/16"}
	peer := WGPeer{AllowedIPs: in}
	got := wgEffectiveAllowedIPs(peer)
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("wgEffectiveAllowedIPs() = %#v, want %#v", got, in)
	}
	got[0] = "changed"
	if in[0] != "0.0.0.0/0" {
		t.Fatal("wgEffectiveAllowedIPs returned the original backing slice")
	}
}

func TestParseWGDump(t *testing.T) {
	const dump = "private\tpublic\t51820\toff\n" +
		"peerkey\tpsk\t203.0.113.10:51820\t0.0.0.0/0\t1700000000\t1234\t5678\t25\n"
	got := parseWGDump(dump)
	if !got.Connected || got.ListenPort != 51820 || got.RXBytes != 1234 || got.TXBytes != 5678 || got.LatestHandshake != 1700000000 {
		t.Fatalf("parseWGDump() unexpected snapshot: %+v", got)
	}
	if len(got.Peers) != 1 || got.Peers[0].PublicKey != "peerkey" || got.Peers[0].Endpoint != "203.0.113.10:51820" {
		t.Fatalf("parseWGDump() unexpected peer: %+v", got.Peers)
	}
}
