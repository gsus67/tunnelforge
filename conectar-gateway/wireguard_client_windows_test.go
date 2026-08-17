//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWGFiletimeToUnix(t *testing.T) {
	const unix = int64(1700000000)
	filetime := (uint64(unix) + 11644473600) * 10000000
	if got := wgFiletimeToUnix(filetime); got != unix {
		t.Fatalf("wgFiletimeToUnix() = %d, want %d", got, unix)
	}
	if got := wgFiletimeToUnix(0); got != 0 {
		t.Fatalf("wgFiletimeToUnix(0) = %d, want 0", got)
	}
}

func TestWGReadServiceStats(t *testing.T) {
	oldBase := baseDir
	baseDir = t.TempDir()
	t.Cleanup(func() { baseDir = oldBase })

	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	publicKey := base64.StdEncoding.EncodeToString(keyBytes)
	p := WGProfile{
		ID: "a558efda36",
		Peers: []WGPeer{{
			PublicKey:  publicKey,
			Endpoint:   "104.238.205.137:47584",
			AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
	if err := os.MkdirAll(filepath.Dir(wgServiceStatsPath(p)), 0700); err != nil {
		t.Fatal(err)
	}

	b := make([]byte, wgServiceStatsHeaderSize+wgServiceStatsPeerSize)
	copy(b[:8], []byte(wgServiceStatsMagic))
	binary.LittleEndian.PutUint32(b[8:12], wgServiceStatsVersion)
	binary.LittleEndian.PutUint16(b[12:14], 51820)
	binary.LittleEndian.PutUint32(b[16:20], 1)
	copy(b[20:52], keyBytes)
	binary.LittleEndian.PutUint64(b[52:60], 5678)
	binary.LittleEndian.PutUint64(b[60:68], 1234)
	const unix = int64(1700000000)
	binary.LittleEndian.PutUint64(b[68:76], (uint64(unix)+11644473600)*10000000)
	if err := os.WriteFile(wgServiceStatsPath(p), b, 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(wgServiceStatsPath(p), now, now); err != nil {
		t.Fatal(err)
	}

	got, err := wgReadServiceStats(p, wgInterfaceName(p.ID))
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenPort != 51820 || got.RXBytes != 1234 || got.TXBytes != 5678 || got.LatestHandshake != unix {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	if len(got.Peers) != 1 || got.Peers[0].Endpoint != p.Peers[0].Endpoint || got.Peers[0].AllowedIPs != "0.0.0.0/0" {
		t.Fatalf("unexpected peer mapping: %+v", got.Peers)
	}
}
