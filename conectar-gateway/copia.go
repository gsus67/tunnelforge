// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)

package main

// Exportar / importar la configuración completa.
//
// El paquete se cifra con una contraseña que elige el usuario (scrypt +
// AES-256-GCM), NO con la llave local del equipo: así el archivo es portable
// y sigue siendo seguro aunque se copie por correo, USB o el NAS.
//
// Contenido: servidores (con sus contraseñas si se pide), túneles y,
// opcionalmente, el contenido de las claves SSH privadas.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"
)

const formatoPaquete = "conectar-gateway/1"

type KeyExportada struct {
	Nombre    string `json:"nombre"`    // nombre de archivo original
	Contenido string `json:"contenido"` // base64 de la clave privada
}

type Paquete struct {
	Formato    string                  `json:"formato"`
	Version    string                  `json:"version"`
	Creado     string                  `json:"creado"`
	Servidores []Servidor              `json:"servidores"`
	Tuneles    []Tunel                 `json:"tuneles"`
	Keys       map[string]KeyExportada `json:"keys,omitempty"` // ruta original -> contenido
	Monitoring *MonitoringConfig       `json:"monitoring,omitempty"`
}

type sobre struct {
	Formato string `json:"formato"`
	Sal     string `json:"sal"`
	Nonce   string `json:"nonce"`
	Datos   string `json:"datos"`
}

func claveDesde(password string, sal []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), sal, 32768, 8, 1, 32)
}

func cifrarPaquete(p *Paquete, password string) ([]byte, error) {
	plano, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	sal := make([]byte, 16)
	if _, err := rand.Read(sal); err != nil {
		return nil, err
	}
	clave, err := claveDesde(password, sal)
	if err != nil {
		return nil, err
	}
	bloque, _ := aes.NewCipher(clave)
	gcm, _ := cipher.NewGCM(bloque)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cifrado := gcm.Seal(nil, nonce, plano, nil)
	return json.MarshalIndent(sobre{
		Formato: formatoPaquete,
		Sal:     base64.StdEncoding.EncodeToString(sal),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Datos:   base64.StdEncoding.EncodeToString(cifrado),
	}, "", "  ")
}

func descifrarPaquete(datos []byte, password string) (*Paquete, error) {
	var s sobre
	if err := json.Unmarshal(datos, &s); err != nil {
		return nil, fmt.Errorf("el archivo no es una copia de Conectar Gateway")
	}
	if s.Formato != formatoPaquete {
		return nil, fmt.Errorf("formato de copia no reconocido: %s", s.Formato)
	}
	sal, err1 := base64.StdEncoding.DecodeString(s.Sal)
	nonce, err2 := base64.StdEncoding.DecodeString(s.Nonce)
	cifrado, err3 := base64.StdEncoding.DecodeString(s.Datos)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, fmt.Errorf("archivo dañado")
	}
	clave, err := claveDesde(password, sal)
	if err != nil {
		return nil, err
	}
	bloque, _ := aes.NewCipher(clave)
	gcm, _ := cipher.NewGCM(bloque)
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("archivo dañado")
	}
	plano, err := gcm.Open(nil, nonce, cifrado, nil)
	if err != nil {
		return nil, fmt.Errorf("contraseña incorrecta o archivo alterado")
	}
	var p Paquete
	if err := json.Unmarshal(plano, &p); err != nil {
		return nil, fmt.Errorf("contenido ilegible")
	}
	if p.Formato != formatoPaquete {
		return nil, fmt.Errorf("contenido de copia no reconocido")
	}
	return &p, nil
}

// carpetaDescargas devuelve la carpeta inicial sugerida al abrir "Guardar como".
func carpetaDescargas() string {
	if h, err := os.UserHomeDir(); err == nil {
		d := filepath.Join(h, "Downloads")
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
		return h
	}
	return baseDir
}

func manejarExportar(w http.ResponseWriter, r *http.Request) {
	var pet struct {
		Password         string
		IncluirClaves    bool // contraseñas de los servidores
		IncluirKeys      bool // contenido de las claves SSH privadas
		IncluirMonitoreo bool // Prometheus, targets y puertos
	}
	if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
		responderError(w, err)
		return
	}
	if len(pet.Password) < 8 {
		responderError(w, fmt.Errorf("usa una contraseña de al menos 8 caracteres"))
		return
	}

	mu.Lock()
	lista := cargar()
	tuneles := cargarTuneles()
	mu.Unlock()

	p := &Paquete{
		Formato: formatoPaquete, Version: version,
		Creado:  time.Now().Format("2006-01-02 15:04"),
		Tuneles: tuneles,
		Keys:    map[string]KeyExportada{},
	}
	if pet.IncluirMonitoreo {
		m := cargarMonitoring()
		p.Monitoring = &m
	}

	var omitidas []string
	for _, s := range lista {
		if !pet.IncluirClaves {
			s.PassCifr = ""
		} else if s.PassCifr != "" {
			// re-cifrar bajo la contraseña del paquete: en otro equipo la
			// llave local no existe, así que va en claro DENTRO del cifrado.
			if plano, err := descifrar(s.PassCifr); err == nil {
				s.PassCifr = "plano:" + plano
			} else {
				s.PassCifr = ""
			}
		}
		if pet.IncluirKeys && s.Key != "" {
			if datos, err := os.ReadFile(s.Key); err == nil {
				p.Keys[s.Key] = KeyExportada{
					Nombre:    filepath.Base(s.Key),
					Contenido: base64.StdEncoding.EncodeToString(datos),
				}
			} else {
				omitidas = append(omitidas, s.Key)
			}
		}
		p.Servidores = append(p.Servidores, s)
	}

	cifrado, err := cifrarPaquete(p, pet.Password)
	if err != nil {
		responderError(w, err)
		return
	}
	nombre := fmt.Sprintf("gateway-wisp-access-%s.cgw", time.Now().Format("20060102-1504"))
	ruta, cancelado, err := seleccionarDestinoCopia(nombre)
	if err != nil {
		responderError(w, fmt.Errorf("no pude abrir el selector para guardar la copia: %v", err))
		return
	}
	if cancelado {
		responder(w, map[string]any{"ok": false, "cancelado": true})
		return
	}
	if err := os.WriteFile(ruta, cifrado, 0600); err != nil {
		responderError(w, fmt.Errorf("no pude escribir el archivo: %v", err))
		return
	}
	responder(w, map[string]any{
		"ok": true, "ruta": ruta,
		"servidores": len(p.Servidores), "tuneles": len(p.Tuneles),
		"keys": len(p.Keys), "omitidas": omitidas,
		"monitoring": p.Monitoring != nil,
	})
}

func nombreKeySeguro(nombre string) (string, error) {
	nombre = filepath.Clean(nombre)
	base := filepath.Base(nombre)
	if nombre == "." || nombre == "" || base != nombre || base == "." || base == ".." {
		return "", fmt.Errorf("nombre de clave SSH no válido")
	}
	if len(base) > 255 {
		return "", fmt.Errorf("nombre de clave SSH demasiado largo")
	}
	return base, nil
}

func manejarImportar(w http.ResponseWriter, r *http.Request) {
	var pet struct {
		Password  string
		Contenido string // el .cgw tal cual
		Modo      string // "fusionar" (default) o "reemplazar"
	}
	if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
		responderError(w, err)
		return
	}
	p, err := descifrarPaquete([]byte(pet.Contenido), pet.Password)
	if err != nil {
		responderError(w, err)
		return
	}
	if pet.Modo == "" {
		pet.Modo = "fusionar"
	}
	if pet.Modo != "fusionar" && pet.Modo != "reemplazar" {
		responderError(w, fmt.Errorf("modo de importación no válido"))
		return
	}
	validosTuneles, err := validarTuneles(p.Tuneles)
	if err != nil {
		responderError(w, fmt.Errorf("túneles inválidos en la copia: %v", err))
		return
	}
	for i := range p.Servidores {
		if p.Servidores[i].Tuneles != nil {
			vt, e := validarTuneles(p.Servidores[i].Tuneles)
			if e != nil {
				responderError(w, fmt.Errorf("túneles inválidos en %s: %v", p.Servidores[i].Nombre, e))
				return
			}
			p.Servidores[i].Tuneles = vt
		}
	}

	mu.Lock()
	defer mu.Unlock()

	// Claves SSH: se escriben junto a la configuración y se reapunta la ruta
	dirKeys := filepath.Join(baseDir, "keys")
	rutasNuevas := map[string]string{}
	if len(p.Keys) > 0 {
		if err := os.MkdirAll(dirKeys, 0700); err == nil {
			for rutaVieja, k := range p.Keys {
				datos, err := base64.StdEncoding.DecodeString(k.Contenido)
				if err != nil {
					continue
				}
				nombreSeguro, err := nombreKeySeguro(k.Nombre)
				if err != nil {
					continue
				}
				destino := filepath.Join(dirKeys, nombreSeguro)
				// Defensa adicional: incluso si cambia la normalización de rutas,
				// el destino debe permanecer dentro de baseDir/keys.
				rel, err := filepath.Rel(dirKeys, destino)
				if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
					continue
				}
				if os.WriteFile(destino, datos, 0600) == nil {
					rutasNuevas[rutaVieja] = destino
				}
			}
		}
	}

	actuales := cargar()
	if pet.Modo == "reemplazar" {
		actuales = nil
	}
	indice := map[string]int{}
	for i, s := range actuales {
		indice[s.Nombre] = i
	}

	nuevos, actualizados := 0, 0
	for _, s := range p.Servidores {
		// clave SSH: usar la copia local si vino en el paquete
		if s.Key != "" {
			if nueva, ok := rutasNuevas[s.Key]; ok {
				s.Key = nueva
			}
		}
		// contraseña: re-cifrar con la llave local de ESTE equipo
		if len(s.PassCifr) > 6 && s.PassCifr[:6] == "plano:" {
			if c, err := cifrar(s.PassCifr[6:]); err == nil {
				s.PassCifr = c
			} else {
				s.PassCifr = ""
			}
		}
		if i, existe := indice[s.Nombre]; existe {
			actuales[i] = s
			actualizados++
		} else {
			actuales = append(actuales, s)
			indice[s.Nombre] = len(actuales) - 1
			nuevos++
		}
	}
	if err := guardar(actuales); err != nil {
		responderError(w, fmt.Errorf("no pude guardar los servidores: %v", err))
		return
	}

	tuneles := 0
	if len(validosTuneles) > 0 {
		if err := guardarTuneles(validosTuneles); err == nil {
			tuneles = len(validosTuneles)
		}
	}
	monitoringRestaurado := false
	if p.Monitoring != nil && p.Monitoring.Formato == monitoringFormato {
		mc := *p.Monitoring
		// El backup conserva asignaciones, pero los servicios remotos se revalidan
		// cuando el usuario vuelve a aplicar la selección en Monitoreo.
		if mc.PortStart < 1024 || mc.PortEnd > 65535 || mc.PortEnd < mc.PortStart {
			mc.PortStart, mc.PortEnd = monitoringPuertoInicio, monitoringPuertoFin
		}
		if guardarMonitoring(mc) == nil {
			monitoringRestaurado = true
		}
	}

	responder(w, map[string]any{
		"ok": true, "nuevos": nuevos, "actualizados": actualizados,
		"tuneles": tuneles, "keys": len(rutasNuevas), "monitoring": monitoringRestaurado,
		"creado": p.Creado, "version": p.Version,
	})
}
