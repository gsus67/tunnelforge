// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)

package main

// Carga de claves SSH privadas con diagnóstico claro. Los fallos típicos al
// configurar una key son siempre los mismos, y el mensaje genérico "no pude
// leerla" no ayuda a distinguirlos:
//
//   - la ruta viene con comillas pegadas al copiar desde el Explorador
//   - la ruta usa ~ o %USERPROFILE%
//   - se apuntó a la clave PÚBLICA (.pub) en vez de a la privada
//   - la clave está en formato PuTTY (.ppk), que no es OpenSSH
//   - la clave tiene passphrase (hay que pedirla)
//   - permisos o archivo inexistente

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// normalizarRuta limpia lo que el usuario pegó en el campo de la key.
func normalizarRuta(ruta string) string {
	r := strings.TrimSpace(ruta)
	// comillas al copiar desde el Explorador de Windows o al arrastrar
	r = strings.Trim(r, "\"'")
	r = strings.TrimSpace(r)
	if r == "" {
		return ""
	}
	// ~ y variables de entorno
	if strings.HasPrefix(r, "~") {
		if h, err := os.UserHomeDir(); err == nil {
			r = filepath.Join(h, strings.TrimPrefix(r, "~"))
		}
	}
	r = os.ExpandEnv(r) // %USERPROFILE% en Windows, $HOME en Linux
	return filepath.Clean(r)
}

// errorClave devuelve un mensaje que dice QUÉ hacer, no solo qué falló.
func errorClave(ruta string, err error) error {
	if os.IsNotExist(err) {
		return fmt.Errorf("no existe el archivo de clave: %s — revisa la ruta (puedes usar el botón Buscar)", ruta)
	}
	if os.IsPermission(err) {
		return fmt.Errorf("sin permiso para leer %s — revisa los permisos del archivo", ruta)
	}
	return fmt.Errorf("no pude leer %s: %v", ruta, err)
}

// cargarFirmante lee y parsea la clave. Si necesita passphrase y no se dio,
// devuelve necesitaPassphrase=true en vez de un error.
func cargarFirmante(ruta, passphrase string) (firmante ssh.Signer, necesitaPassphrase bool, err error) {
	ruta = normalizarRuta(ruta)
	if ruta == "" {
		return nil, false, fmt.Errorf("la ruta de la clave está vacía")
	}

	info, err := os.Stat(ruta)
	if err != nil {
		return nil, false, errorClave(ruta, err)
	}
	if info.IsDir() {
		return nil, false, fmt.Errorf("%s es una carpeta, no un archivo de clave", ruta)
	}

	datos, err := os.ReadFile(ruta)
	if err != nil {
		return nil, false, errorClave(ruta, err)
	}

	// Errores de archivo equivocado: mensajes específicos
	if strings.HasSuffix(strings.ToLower(ruta), ".pub") || bytes.HasPrefix(bytes.TrimSpace(datos), []byte("ssh-")) {
		privada := strings.TrimSuffix(ruta, ".pub")
		return nil, false, fmt.Errorf("esa es la clave PÚBLICA. Usa la privada, normalmente el mismo archivo sin .pub: %s", privada)
	}
	if bytes.Contains(datos, []byte("PuTTY-User-Key-File")) {
		return nil, false, fmt.Errorf("la clave está en formato PuTTY (.ppk), que no es compatible. Conviértela con PuTTYgen: Conversions → Export OpenSSH key")
	}
	if !bytes.Contains(datos, []byte("PRIVATE KEY")) {
		return nil, false, fmt.Errorf("%s no parece una clave privada SSH (no encuentro la cabecera PRIVATE KEY)", ruta)
	}

	if passphrase != "" {
		firmante, err = ssh.ParsePrivateKeyWithPassphrase(datos, []byte(passphrase))
		if err != nil {
			if strings.Contains(err.Error(), "decrypt") || strings.Contains(err.Error(), "cannot decode") {
				return nil, true, fmt.Errorf("passphrase incorrecta para la clave")
			}
			return nil, false, fmt.Errorf("no pude usar la clave: %v", err)
		}
		return firmante, false, nil
	}

	firmante, err = ssh.ParsePrivateKey(datos)
	if err != nil {
		if _, esCifrada := err.(*ssh.PassphraseMissingError); esCifrada {
			return nil, true, nil // hay que pedir la passphrase
		}
		return nil, false, fmt.Errorf("no pude usar la clave %s: %v", ruta, err)
	}
	return firmante, false, nil
}

// manejarProbarKey permite validar una clave desde la interfaz ANTES de
// intentar conectar, para saber si el problema es la clave o el servidor.
func manejarProbarKey(w http.ResponseWriter, r *http.Request) {
	var pet struct{ Key, Passphrase string }
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	firmante, necesita, err := cargarFirmante(pet.Key, pet.Passphrase)
	if err != nil {
		responderError(w, err)
		return
	}
	if necesita {
		responder(w, map[string]any{"necesitaPassphrase": true})
		return
	}
	responder(w, map[string]any{
		"ok":        true,
		"tipo":      firmante.PublicKey().Type(),
		"huella":    ssh.FingerprintSHA256(firmante.PublicKey()),
		"rutaFinal": normalizarRuta(pet.Key),
	})
}
