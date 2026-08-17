package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed assets/gateway-wisp.tar.gz
var v313Assets embed.FS

func manejarToolCrearKey(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Servidor string `json:"servidor"`
	}
	if decodificar(r, &p) != nil || strings.TrimSpace(p.Servidor) == "" {
		responderError(w, fmt.Errorf("servidor obligatorio"))
		return
	}
	s, err := perfilServidor(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	cli, err := clienteConexionActiva(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		responderError(w, err)
		return
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		responderError(w, err)
		return
	}
	linea := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " gateway-wisp-access-" + strings.ReplaceAll(s.Nombre, " ", "-")
	ses, err := cli.NewSession()
	if err != nil {
		responderError(w, err)
		return
	}
	ses.Stdin = strings.NewReader(linea + "\n")
	err = ses.Run(`umask 077; mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys" && IFS= read -r k && (grep -Fqx "$k" "$HOME/.ssh/authorized_keys" || printf '%s\n' "$k" >> "$HOME/.ssh/authorized_keys")`)
	ses.Close()
	if err != nil {
		responderError(w, fmt.Errorf("no pude instalar authorized_keys: %v", err))
		return
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		responderError(w, err)
		return
	}
	dir := rutaJunto("keys")
	if err = os.MkdirAll(dir, 0700); err != nil {
		responderError(w, err)
		return
	}
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s.Nombre)
	ruta := filepath.Join(dir, safe+"_ed25519")
	if err = os.WriteFile(ruta, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		responderError(w, err)
		return
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ClientConfig{User: s.Usuario, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		if s.Huella != "" && ssh.FingerprintSHA256(k) != s.Huella {
			return fmt.Errorf("huella inesperada")
		}
		return nil
	}, Timeout: 10 * time.Second}
	test, err := ssh.Dial("tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Puerto)), cfg)
	if err != nil {
		_ = os.Remove(ruta)
		responderError(w, fmt.Errorf("instalé la pública pero la nueva key no superó la prueba: %v", err))
		return
	}
	test.Close()
	mu.Lock()
	lista := cargar()
	ps := buscar(lista, s.Nombre)
	if ps != nil {
		ps.Key = ruta
		if ps.Huella == "" {
			ps.Huella = s.Huella
		}
		err = guardar(lista)
	}
	mu.Unlock()
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "key": ruta, "huella": ssh.FingerprintSHA256(pk)})
}

func manejarToolCambiarPuertoSSH(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Servidor       string `json:"servidor"`
		Puerto         int    `json:"puerto"`
		CerrarAnterior bool   `json:"cerrarAnterior"`
	}
	if err := decodificar(r, &p); err != nil {
		responderError(w, err)
		return
	}
	if p.Puerto < 1 || p.Puerto > 65535 {
		responderError(w, fmt.Errorf("puerto inválido"))
		return
	}
	s, err := perfilServidor(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	old := s.Puerto
	if old == 0 {
		old = 22
	}
	if p.Puerto == old {
		responderError(w, fmt.Errorf("ese ya es el puerto SSH actual"))
		return
	}
	cli, err := clienteConexionActiva(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	if _, err := ejecutarSesion(cli, "ss -lnt | awk '{print $4}' | grep -Eq '[:.]"+strconv.Itoa(p.Puerto)+"$'", ""); err == nil {
		responderError(w, fmt.Errorf("el puerto %d ya está en uso", p.Puerto))
		return
	}
	// Abrir firewall primero cuando existe un backend editable. Si no hay firewall compatible, continuar sin inventar reglas.
	est, _ := obtenerEstadoFirewall(p.Servidor)
	abierto := false
	if est.Editable {
		if _, _, e := aplicarFirewall(p.Servidor, "abrir", p.Puerto, "tcp"); e != nil {
			responderError(w, fmt.Errorf("no pude abrir primero el puerto en firewall: %v", e))
			return
		}
		abierto = true
	}
	script := fmt.Sprintf(`set -e
CFG=/etc/ssh/sshd_config
BAK=/etc/ssh/sshd_config.gateway-wisp-port.bak
cp -a "$CFG" "$BAK"
awk 'BEGIN{m=0} /^[[:space:]]*Match[[:space:]]/{m=1} {if(!m && $0 ~ /^[[:space:]]*Port[[:space:]]+/) print "# gateway-wisp: " $0; else print}' "$CFG" > "$CFG.tmp"
{ printf 'Port %d\n'; cat "$CFG.tmp"; } > "$CFG.new"
cat "$CFG.new" > "$CFG"; rm -f "$CFG.tmp" "$CFG.new"
sshd -t
%s
`, p.Puerto, scriptRecargarSSH())
	if _, err := ejecutarComoRoot(cli, "", script); err != nil {
		if abierto {
			_, _, _ = aplicarFirewall(p.Servidor, "cerrar", p.Puerto, "tcp")
		}
		responderError(w, fmt.Errorf("no pude aplicar el puerto nuevo (se conserva la sesión actual): %v", err))
		return
	}
	// Verificación real con la autenticación guardada del perfil.
	testS := s
	testS.Puerto = p.Puerto
	var auth []ssh.AuthMethod
	if testS.Key != "" {
		signer, need, e := cargarFirmante(testS.Key, "")
		if e == nil && !need {
			auth = append(auth, ssh.PublicKeys(signer))
		}
	}
	if len(auth) == 0 && testS.PassCifr != "" {
		if pw, e := descifrar(testS.PassCifr); e == nil {
			auth = append(auth, ssh.Password(pw))
		}
	}
	if len(auth) == 0 {
		_, _ = ejecutarComoRoot(cli, "", `cp -a /etc/ssh/sshd_config.gateway-wisp-port.bak /etc/ssh/sshd_config; `+scriptRecargarSSH())
		responderError(w, fmt.Errorf("no hay credencial guardada para comprobar una conexión nueva; cambio revertido"))
		return
	}
	cfg := &ssh.ClientConfig{User: s.Usuario, Auth: auth, HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		if s.Huella != "" && ssh.FingerprintSHA256(k) != s.Huella {
			return fmt.Errorf("huella inesperada")
		}
		return nil
	}, Timeout: 10 * time.Second}
	prueba, e := ssh.Dial("tcp", net.JoinHostPort(s.Host, strconv.Itoa(p.Puerto)), cfg)
	if e != nil {
		_, _ = ejecutarComoRoot(cli, "", `cp -a /etc/ssh/sshd_config.gateway-wisp-port.bak /etc/ssh/sshd_config; `+scriptRecargarSSH())
		if abierto {
			_, _, _ = aplicarFirewall(p.Servidor, "cerrar", p.Puerto, "tcp")
		}
		responderError(w, fmt.Errorf("el puerto nuevo no aceptó una conexión SSH; rollback aplicado: %v", e))
		return
	}
	prueba.Close()
	mu.Lock()
	lista := cargar()
	ps := buscar(lista, s.Nombre)
	if ps != nil {
		ps.Puerto = p.Puerto
		err = guardar(lista)
	}
	mu.Unlock()
	if err != nil {
		responderError(w, err)
		return
	}
	if p.CerrarAnterior && est.Editable {
		_, _, _ = aplicarFirewall(p.Servidor, "cerrar", old, "tcp")
	}
	responder(w, map[string]any{"ok": true, "puerto": p.Puerto, "anterior": old})
}

func manejarGatewayWISPPreparar(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Servidor string `json:"servidor"`
	}
	if err := decodificar(r, &p); err != nil {
		responderError(w, err)
		return
	}
	c, err := clienteSFTP(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	data, err := v313Assets.ReadFile("assets/gateway-wisp.tar.gz")
	if err != nil {
		responderError(w, err)
		return
	}
	dir := "/tmp/gateway-wisp-access/gateway-wisp"
	if err = c.MkdirAll(dir); err != nil {
		responderError(w, err)
		return
	}
	f, err := c.Create(path.Join(dir, "gateway-wisp.tar.gz"))
	if err != nil {
		responderError(w, err)
		return
	}
	_, err = io.Copy(f, strings.NewReader(string(data)))
	ce := f.Close()
	if err != nil || ce != nil {
		responderError(w, fmt.Errorf("no pude subir el paquete"))
		return
	}
	cmd := `cd /tmp/gateway-wisp-access/gateway-wisp && rm -rf src && mkdir src && tar -xzf gateway-wisp.tar.gz -C src && cd src/gateway-wisp && sudo bash ./setup-vps-wisp.sh`
	responder(w, map[string]any{"ok": true, "comando": cmd})
}

func manejarGatewayWISPEstado(w http.ResponseWriter, r *http.Request) {
	nombre := strings.TrimSpace(r.URL.Query().Get("servidor"))
	cli, err := clienteConexionActiva(nombre)
	if err != nil {
		responderError(w, err)
		return
	}
	out, _ := ejecutarSesion(cli, `if [ -f /etc/wisp/config.env ]; then echo installed; else echo absent; fi`, "")
	responder(w, map[string]any{"ok": true, "estado": strings.TrimSpace(out)})
}
