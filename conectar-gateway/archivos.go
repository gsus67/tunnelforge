// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)

package main

// Gestor de archivos remoto por SFTP, sobre la MISMA conexión SSH ya activa
// (no abre una segunda sesión al servidor). Permite navegar, descargar,
// subir, crear carpetas, renombrar y borrar.
//
// Usa github.com/pkg/sftp (BSD-2-Clause), la implementación estándar de SFTP
// en Go. Y un explorador del disco LOCAL para elegir archivos (útil también
// para localizar la clave SSH sin teclear la ruta a mano).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pkg/sftp"
)

type Archivo struct {
	Nombre     string `json:"nombre"`
	Ruta       string `json:"ruta"`
	Carpeta    bool   `json:"carpeta"`
	Tamano     int64  `json:"tamano"`
	Modo       string `json:"modo"`
	Modificado string `json:"modificado"`
}

// clienteSFTP abre (o reutiliza) el canal SFTP de una conexión activa.
func clienteSFTP(nombre string) (*sftp.Client, error) {
	mu.Lock()
	con := conexiones[nombre]
	mu.Unlock()
	if con == nil {
		return nil, fmt.Errorf("no estás conectado a '%s'", nombre)
	}

	// El lock es por conexión, no global: abrir SFTP puede implicar I/O de red
	// y no debe congelar el resto de la API mientras el servidor responde.
	con.sftpMu.Lock()
	defer con.sftpMu.Unlock()
	if con.sftp != nil {
		return con.sftp, nil
	}
	c, err := sftp.NewClient(con.cliente)
	if err != nil {
		return nil, fmt.Errorf("el servidor no aceptó SFTP: %v", err)
	}
	con.sftp = c
	return c, nil
}

func listarRemoto(c *sftp.Client, ruta string) ([]Archivo, string, error) {
	if ruta == "" || ruta == "~" {
		if wd, err := c.Getwd(); err == nil {
			ruta = wd
		} else {
			ruta = "/"
		}
	}
	ruta = path.Clean(ruta)
	entradas, err := c.ReadDir(ruta)
	if err != nil {
		return nil, ruta, fmt.Errorf("no pude abrir %s: %v", ruta, err)
	}
	var salida []Archivo
	for _, e := range entradas {
		salida = append(salida, Archivo{
			Nombre:     e.Name(),
			Ruta:       path.Join(ruta, e.Name()),
			Carpeta:    e.IsDir(),
			Tamano:     e.Size(),
			Modo:       e.Mode().String(),
			Modificado: e.ModTime().Format("2006-01-02 15:04"),
		})
	}
	sort.Slice(salida, func(i, j int) bool {
		if salida[i].Carpeta != salida[j].Carpeta {
			return salida[i].Carpeta
		}
		return strings.ToLower(salida[i].Nombre) < strings.ToLower(salida[j].Nombre)
	})
	return salida, ruta, nil
}

// manejarArchivos: navegar y operar sobre el servidor remoto.
func manejarArchivos(w http.ResponseWriter, r *http.Request) {
	var pet struct {
		Servidor, Ruta, Accion, Destino string
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	c, err := clienteSFTP(pet.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}

	switch pet.Accion {
	case "", "listar":
		lista, ruta, err := listarRemoto(c, pet.Ruta)
		if err != nil {
			responderError(w, err)
			return
		}
		responder(w, map[string]any{"ruta": ruta, "archivos": lista, "padre": path.Dir(ruta)})

	case "carpeta":
		if err := c.Mkdir(pet.Ruta); err != nil {
			responderError(w, fmt.Errorf("no pude crear la carpeta: %v", err))
			return
		}
		responder(w, map[string]any{"ok": true})

	case "renombrar":
		if err := c.Rename(pet.Ruta, pet.Destino); err != nil {
			responderError(w, fmt.Errorf("no pude renombrar: %v", err))
			return
		}
		responder(w, map[string]any{"ok": true})

	case "borrar":
		info, err := c.Stat(pet.Ruta)
		if err != nil {
			responderError(w, err)
			return
		}
		if info.IsDir() {
			err = c.RemoveDirectory(pet.Ruta)
		} else {
			err = c.Remove(pet.Ruta)
		}
		if err != nil {
			responderError(w, fmt.Errorf("no pude borrar (¿carpeta con contenido?): %v", err))
			return
		}
		responder(w, map[string]any{"ok": true})

	default:
		responderError(w, fmt.Errorf("acción desconocida: %s", pet.Accion))
	}
}

// manejarDescargar: copia un archivo REMOTO al disco local (carpeta Descargas).
func manejarDescargar(w http.ResponseWriter, r *http.Request) {
	var pet struct{ Servidor, Ruta, DestinoLocal string }
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	c, err := clienteSFTP(pet.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	origen, err := c.Open(pet.Ruta)
	if err != nil {
		responderError(w, fmt.Errorf("no pude abrir el archivo remoto: %v", err))
		return
	}
	defer origen.Close()

	carpeta := pet.DestinoLocal
	if carpeta == "" {
		carpeta = carpetaDescargas()
	}
	destino := filepath.Join(carpeta, path.Base(pet.Ruta))
	f, err := os.Create(destino)
	if err != nil {
		responderError(w, fmt.Errorf("no pude escribir en %s: %v", destino, err))
		return
	}
	defer f.Close()
	n, err := io.Copy(f, origen)
	if err != nil {
		responderError(w, fmt.Errorf("error copiando: %v", err))
		return
	}
	responder(w, map[string]any{"ok": true, "destino": destino, "bytes": n})
}

// manejarSubir: copia un archivo LOCAL al servidor remoto.
func manejarSubir(w http.ResponseWriter, r *http.Request) {
	var pet struct{ Servidor, RutaLocal, CarpetaRemota string }
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	c, err := clienteSFTP(pet.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	local := normalizarRuta(pet.RutaLocal)
	origen, err := os.Open(local)
	if err != nil {
		responderError(w, errorClave(local, err))
		return
	}
	defer origen.Close()

	destino := path.Join(pet.CarpetaRemota, filepath.Base(local))
	f, err := c.Create(destino)
	if err != nil {
		responderError(w, fmt.Errorf("no pude crear %s en el servidor: %v", destino, err))
		return
	}
	defer f.Close()
	n, err := io.Copy(f, origen)
	if err != nil {
		responderError(w, fmt.Errorf("error subiendo: %v", err))
		return
	}
	responder(w, map[string]any{"ok": true, "destino": destino, "bytes": n})
}

// manejarLocal: explora el disco LOCAL. Sirve para elegir la clave SSH y
// para escoger archivos a subir sin teclear rutas.
func manejarLocal(w http.ResponseWriter, r *http.Request) {
	ruta := r.URL.Query().Get("ruta")
	if ruta == "" {
		if h, err := os.UserHomeDir(); err == nil {
			ruta = h
		} else {
			ruta = "/"
		}
	}
	ruta = normalizarRuta(ruta)
	entradas, err := os.ReadDir(ruta)
	if err != nil {
		responderError(w, errorClave(ruta, err))
		return
	}
	var salida []Archivo
	for _, e := range entradas {
		if strings.HasPrefix(e.Name(), ".") && !strings.HasPrefix(e.Name(), ".ssh") {
			continue // ocultos fuera, salvo .ssh que es justo lo que se busca
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		salida = append(salida, Archivo{
			Nombre:     e.Name(),
			Ruta:       filepath.Join(ruta, e.Name()),
			Carpeta:    e.IsDir(),
			Tamano:     info.Size(),
			Modificado: info.ModTime().Format("2006-01-02 15:04"),
		})
	}
	sort.Slice(salida, func(i, j int) bool {
		if salida[i].Carpeta != salida[j].Carpeta {
			return salida[i].Carpeta
		}
		return strings.ToLower(salida[i].Nombre) < strings.ToLower(salida[j].Nombre)
	})
	responder(w, map[string]any{"ruta": ruta, "archivos": salida, "padre": filepath.Dir(ruta)})
}

var _ = json.Marshal // (json usado indirectamente por responder)
