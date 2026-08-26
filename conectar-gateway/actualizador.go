// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// El repositorio de Releases es público: las consultas a la API de GitHub
// se hacen siempre sin autenticación, sin token ni configuración previa.

const (
	updateRepoOwner     = "gsus67"
	updateRepoName      = "tunnelforge"
	updateManifestName  = "update-manifest.json"
	updateSignatureName = "update-manifest.sig"
	updatePublicKeyB64  = "Q6DHUUNnyQj/Zdjr3RP3feqyXndsUDsHciaKEFBtmv0="
)

type updateConfig struct {
	BuscarAlInicio bool `json:"buscarAlInicio"`
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	HTMLURL     string        `json:"html_url"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type updateManifest struct {
	Version string                         `json:"version"`
	Tag     string                         `json:"tag"`
	Assets  map[string]updateManifestAsset `json:"assets"`
}

type updateManifestAsset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type updateInfo struct {
	Disponible bool   `json:"disponible"`
	Actual     string `json:"actual"`
	Nueva      string `json:"nueva,omitempty"`
	Notas      string `json:"notas,omitempty"`
	URL        string `json:"url,omitempty"`
	Publicada  string `json:"publicada,omitempty"`
}

func rutaActualizaciones() string { return rutaJunto("actualizaciones.json") }

func cargarConfigActualizaciones() updateConfig {
	var c updateConfig
	if b, err := os.ReadFile(rutaActualizaciones()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func guardarConfigActualizaciones(c updateConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rutaActualizaciones(), b, 0600)
}

func githubRequest(method, url, accept string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "TunnelForge/"+version)
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		cuerpo, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("GitHub respondió 404: no encontré la release")
		}
		if resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("GitHub respondió 403: límite de consultas anónimas alcanzado, probá de nuevo más tarde")
		}
		return nil, fmt.Errorf("GitHub respondió %s: %s", resp.Status, strings.TrimSpace(string(cuerpo)))
	}
	return resp, nil
}

func ultimaRelease() (githubRelease, error) {
	var rel githubRelease
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", updateRepoOwner, updateRepoName)
	resp, err := githubRequest(http.MethodGet, url, "application/vnd.github+json")
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return rel, err
	}
	if rel.TagName == "" {
		return rel, errors.New("la release no tiene tag")
	}
	return rel, nil
}

func assetPorNombre(rel githubRelease, nombre string) (githubAsset, bool) {
	for _, a := range rel.Assets {
		if a.Name == nombre {
			return a, true
		}
	}
	return githubAsset{}, false
}

func descargarAsset(id int64, limite int64) ([]byte, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/assets/%d", updateRepoOwner, updateRepoName, id)
	resp, err := githubRequest(http.MethodGet, url, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > limite && resp.ContentLength >= 0 {
		return nil, errors.New("asset demasiado grande")
	}
	r := io.LimitReader(resp.Body, limite+1)
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limite {
		return nil, errors.New("asset excede el límite permitido")
	}
	return b, nil
}

func verificarManifest(rel githubRelease) (updateManifest, []byte, error) {
	var m updateManifest
	ma, ok := assetPorNombre(rel, updateManifestName)
	if !ok {
		return m, nil, fmt.Errorf("la release no contiene %s", updateManifestName)
	}
	sa, ok := assetPorNombre(rel, updateSignatureName)
	if !ok {
		return m, nil, fmt.Errorf("la release no contiene %s", updateSignatureName)
	}
	mb, err := descargarAsset(ma.ID, 1<<20)
	if err != nil {
		return m, nil, err
	}
	sb, err := descargarAsset(sa.ID, 4096)
	if err != nil {
		return m, nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(updatePublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return m, nil, errors.New("clave pública de actualización inválida")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), mb, sb) {
		return m, nil, errors.New("FIRMA INVÁLIDA: la actualización no fue firmada por TunnelForge")
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		return m, nil, fmt.Errorf("manifest inválido: %w", err)
	}
	tagVersion := strings.TrimPrefix(rel.TagName, "v")
	if m.Version != tagVersion || m.Tag != rel.TagName {
		return m, nil, errors.New("manifest y tag de GitHub no coinciden")
	}
	return m, mb, nil
}

func compararVersiones(a, b string) int {
	parse := func(s string) []int {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		s = strings.SplitN(s, "-", 2)[0]
		p := strings.Split(s, ".")
		out := make([]int, 3)
		for i := 0; i < len(out) && i < len(p); i++ {
			out[i], _ = strconv.Atoi(p[i])
		}
		return out
	}
	aa, bb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

func buscarActualizacion() (updateInfo, githubRelease, updateManifest, error) {
	info := updateInfo{Actual: version}
	rel, err := ultimaRelease()
	if err != nil {
		return info, rel, updateManifest{}, err
	}
	m, _, err := verificarManifest(rel)
	if err != nil {
		return info, rel, m, err
	}
	info.Nueva = m.Version
	info.Notas = rel.Body
	info.URL = rel.HTMLURL
	info.Publicada = rel.PublishedAt
	info.Disponible = compararVersiones(version, m.Version) < 0
	return info, rel, m, nil
}

func clavePlataformaActualizacion() string {
	if runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
		return "windows-amd64"
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		return "linux-amd64"
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

func prepararEInstalarActualizacion() (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("la actualización automática está habilitada por ahora solo en Windows")
	}
	info, rel, manifest, err := buscarActualizacion()
	if err != nil {
		return "", err
	}
	if !info.Disponible {
		return "", errors.New("ya tienes la versión más reciente")
	}
	ma, ok := manifest.Assets[clavePlataformaActualizacion()]
	if !ok {
		return "", errors.New("la release firmada no contiene un ejecutable para esta plataforma")
	}
	ga, ok := assetPorNombre(rel, ma.Name)
	if !ok {
		return "", fmt.Errorf("GitHub Release no contiene %s", ma.Name)
	}
	if ma.Size <= 0 || ma.Size > 200<<20 {
		return "", errors.New("tamaño del ejecutable inválido en el manifest")
	}
	bin, err := descargarAsset(ga.ID, 200<<20)
	if err != nil {
		return "", err
	}
	if int64(len(bin)) != ma.Size || ga.Size != ma.Size {
		return "", errors.New("el tamaño descargado no coincide con el manifest firmado")
	}
	suma := sha256.Sum256(bin)
	if !strings.EqualFold(hex.EncodeToString(suma[:]), ma.SHA256) {
		return "", errors.New("SHA-256 no coincide: actualización rechazada")
	}

	dir := rutaJunto("updates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	nuevo := filepath.Join(dir, "TunnelForge-"+manifest.Version+".exe")
	if err := os.WriteFile(nuevo, bin, 0700); err != nil {
		return "", err
	}

	actual, err := os.Executable()
	if err != nil {
		return "", err
	}
	helper := filepath.Join(dir, "gateway-updater.exe")
	if err := copiarArchivo(actual, helper, 0700); err != nil {
		return "", fmt.Errorf("crear updater: %w", err)
	}
	cmd := exec.Command(helper, "--apply-update", nuevo, actual)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("iniciar updater: %w", err)
	}
	go func() {
		time.Sleep(900 * time.Millisecond)
		mu.Lock()
		cerrarTodas()
		mu.Unlock()
		os.Exit(0)
	}()
	return manifest.Version, nil
}

func copiarArchivo(origen, destino string, modo os.FileMode) error {
	in, err := os.Open(origen)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destino, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, modo)
	if err != nil {
		return err
	}
	_, cpErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if cpErr != nil {
		return cpErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func manejarModoActualizador() bool {
	if len(os.Args) != 4 || os.Args[1] != "--apply-update" {
		return false
	}
	nuevo, destino := os.Args[2], os.Args[3]
	backup := destino + ".old"
	var ultimo error
	for i := 0; i < 120; i++ {
		_ = os.Remove(backup)
		if err := os.Rename(destino, backup); err == nil {
			ultimo = nil
			break
		} else {
			ultimo = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if ultimo != nil {
		return true
	}
	if err := copiarArchivo(nuevo, destino, 0700); err != nil {
		_ = os.Rename(backup, destino)
		return true
	}
	if err := exec.Command(destino).Start(); err != nil {
		_ = os.Remove(destino)
		_ = os.Rename(backup, destino)
		_ = exec.Command(destino).Start()
		return true
	}
	_ = os.Remove(nuevo)
	// El .old se conserva como rollback hasta el siguiente arranque correcto.
	return true
}

func limpiarBackupActualizacion() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	old := exe + ".old"
	if _, err := os.Stat(old); err == nil {
		go func() { time.Sleep(4 * time.Second); _ = os.Remove(old) }()
	}
}

func manejarActualizaciones(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := cargarConfigActualizaciones()
		responder(w, map[string]any{"version": version, "buscarAlInicio": c.BuscarAlInicio, "repo": "https://github.com/" + updateRepoOwner + "/" + updateRepoName})
	case http.MethodPost:
		var p struct {
			Accion         string `json:"accion"`
			BuscarAlInicio *bool  `json:"buscarAlInicio"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
			responderError(w, err)
			return
		}
		switch p.Accion {
		case "buscar":
			info, _, _, err := buscarActualizacion()
			if err != nil {
				responderError(w, err)
				return
			}
			responder(w, info)
		case "preferencias":
			c := cargarConfigActualizaciones()
			if p.BuscarAlInicio != nil {
				c.BuscarAlInicio = *p.BuscarAlInicio
			}
			if err := guardarConfigActualizaciones(c); err != nil {
				responderError(w, err)
				return
			}
			responder(w, map[string]any{"ok": true})
		case "instalar":
			nueva, err := prepararEInstalarActualizacion()
			if err != nil {
				responderError(w, err)
				return
			}
			responder(w, map[string]any{"ok": true, "version": nueva, "reiniciando": true})
		default:
			responderError(w, errors.New("acción de actualización no válida"))
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
