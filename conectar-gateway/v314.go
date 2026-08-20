package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
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
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed assets/gateway-wisp.tar.gz
var v314Assets embed.FS

const gatewayWISPBundleVersion = "1.5.0"

// -----------------------------------------------------------------------------
// SSH key: crear/instalar y usar una key local existente
// -----------------------------------------------------------------------------

func instalarPublicaEnSesion(cli *ssh.Client, publica, comentario string) (bool, error) {
	ses, err := cli.NewSession()
	if err != nil {
		return false, err
	}
	defer ses.Close()
	// "publica" no lleva comentario. Si la misma key ya existe con cualquier
	// comentario, no duplicamos la entrada. Si se añade, usamos un comentario
	// único para poder retirar únicamente nuestra línea durante un rollback.
	ses.Stdin = strings.NewReader(strings.TrimSpace(publica) + "\n")
	cmd := `umask 077
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys"
IFS= read -r k
if grep -Fq "$k" "$HOME/.ssh/authorized_keys"; then
  printf '__GW_KEY_EXISTS__\n'
else
  printf '%s %s\n' "$k" ` + shellQuote(comentario) + ` >> "$HOME/.ssh/authorized_keys"
  printf '__GW_KEY_ADDED__\n'
fi`
	out, err := ses.CombinedOutput(cmd)
	if err != nil {
		return false, fmt.Errorf("no pude instalar authorized_keys: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.Contains(string(out), "__GW_KEY_ADDED__"), nil
}

func quitarPublicaGestionada(cli *ssh.Client, comentario string) {
	if cli == nil || strings.TrimSpace(comentario) == "" {
		return
	}
	_, _ = ejecutarSesion(cli, `if [ -f "$HOME/.ssh/authorized_keys" ]; then grep -v `+shellQuote(comentario)+` "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.gwtmp" || true; mv "$HOME/.ssh/authorized_keys.gwtmp" "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; fi`, "")
}

func configKeyIndependiente(s Servidor, signer ssh.Signer) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: s.Usuario,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if strings.TrimSpace(s.Huella) == "" {
				return fmt.Errorf("el perfil no tiene una huella SSH verificada")
			}
			vista := ssh.FingerprintSHA256(k)
			if vista != s.Huella {
				return fmt.Errorf("la huella SSH cambió: esperada %s, recibida %s", s.Huella, vista)
			}
			return nil
		},
		Timeout: 12 * time.Second,
	}
}

func probarKeyIndependiente(s Servidor, signer ssh.Signer) error {
	puerto := s.Puerto
	if puerto <= 0 {
		puerto = 22
	}
	cli, err := ssh.Dial("tcp", net.JoinHostPort(s.Host, strconv.Itoa(puerto)), configKeyIndependiente(s, signer))
	if err != nil {
		return err
	}
	defer cli.Close()
	ses, err := cli.NewSession()
	if err != nil {
		return err
	}
	defer ses.Close()
	out, err := ses.Output("printf __GW_KEY_OK__")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "__GW_KEY_OK__" {
		return fmt.Errorf("respuesta inesperada durante la prueba")
	}
	return nil
}

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
	if strings.TrimSpace(s.Huella) == "" {
		responderError(w, fmt.Errorf("conecta primero al servidor para verificar su huella SSH"))
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
	publica := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	comentario := "gateway-wisp-access-key-" + tokenCorto()
	agregada, err := instalarPublicaEnSesion(cli, publica, comentario)
	if err != nil {
		responderError(w, err)
		return
	}
	rollbackRemoto := func() {
		if agregada {
			quitarPublicaGestionada(cli, comentario)
		}
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		rollbackRemoto()
		responderError(w, err)
		return
	}
	dir := rutaJunto("keys")
	if err = os.MkdirAll(dir, 0700); err != nil {
		rollbackRemoto()
		responderError(w, err)
		return
	}
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s.Nombre)
	// No sobrescribimos una key anterior: una rotación crea un archivo nuevo.
	ruta := filepath.Join(dir, safe+"_ed25519_"+time.Now().Format("20060102-150405"))
	if err = os.WriteFile(ruta, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		rollbackRemoto()
		responderError(w, err)
		return
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		_ = os.Remove(ruta)
		rollbackRemoto()
		responderError(w, err)
		return
	}
	if err = probarKeyIndependiente(s, signer); err != nil {
		_ = os.Remove(ruta)
		rollbackRemoto()
		responderError(w, fmt.Errorf("la pública se instaló, pero la segunda conexión con la nueva key falló; se hizo rollback: %v", err))
		return
	}

	mu.Lock()
	lista := cargar()
	perfil := buscar(lista, s.Nombre)
	if perfil == nil {
		mu.Unlock()
		_ = os.Remove(ruta)
		rollbackRemoto()
		responderError(w, fmt.Errorf("servidor no encontrado al guardar la key"))
		return
	}
	perfil.Key = ruta
	perfil.PassCifr = ""
	err = guardar(lista)
	mu.Unlock()
	if err != nil {
		_ = os.Remove(ruta)
		rollbackRemoto()
		responderError(w, fmt.Errorf("la key funcionó pero no pude guardar el perfil; se revirtió la instalación: %v", err))
		return
	}
	responder(w, map[string]any{
		"ok": true, "key": ruta, "huella": ssh.FingerprintSHA256(pk), "comprobada": true,
		"publicaInstalada": agregada,
	})
}

func manejarToolUsarKey(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Servidor   string `json:"servidor"`
		Key        string `json:"key"`
		Passphrase string `json:"passphrase"`
		Recordar   bool   `json:"recordar"`
	}
	if err := decodificar(r, &p); err != nil {
		responderError(w, err)
		return
	}
	p.Servidor = strings.TrimSpace(p.Servidor)
	p.Key = normalizarRuta(p.Key)
	if p.Servidor == "" || p.Key == "" {
		responderError(w, fmt.Errorf("servidor y key son obligatorios"))
		return
	}
	s, err := perfilServidor(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	if strings.TrimSpace(s.Huella) == "" {
		responderError(w, fmt.Errorf("el perfil todavía no tiene una huella SSH verificada; conecta una vez antes de asignar la key"))
		return
	}
	firmante, necesita, err := cargarFirmante(p.Key, p.Passphrase)
	if err != nil {
		responderError(w, err)
		return
	}
	if necesita {
		responder(w, map[string]any{"necesitaPassphrase": true})
		return
	}

	// Una key local seleccionada desde Herramientas es realmente utilizable:
	// aprovechamos la sesión SSH ya abierta para instalar su parte pública si
	// aún no estaba en authorized_keys. La privada nunca sale de este equipo.
	activa, err := clienteConexionActiva(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	publica := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(firmante.PublicKey())))
	comentario := "gateway-wisp-access-import-" + tokenCorto()
	agregada, err := instalarPublicaEnSesion(activa, publica, comentario)
	if err != nil {
		responderError(w, err)
		return
	}
	rollbackRemoto := func() {
		if agregada {
			quitarPublicaGestionada(activa, comentario)
		}
	}

	if err = probarKeyIndependiente(s, firmante); err != nil {
		rollbackRemoto()
		responderError(w, fmt.Errorf("la key no superó la segunda conexión SSH; si se añadió su pública, fue retirada automáticamente: %v", err))
		return
	}

	var cifrada string
	if p.Recordar && p.Passphrase != "" {
		cifrada, err = cifrar(p.Passphrase)
		if err != nil {
			rollbackRemoto()
			responderError(w, err)
			return
		}
	}
	mu.Lock()
	lista := cargar()
	perfil := buscar(lista, s.Nombre)
	if perfil == nil {
		mu.Unlock()
		rollbackRemoto()
		responderError(w, fmt.Errorf("servidor no encontrado"))
		return
	}
	perfil.Key = p.Key
	perfil.PassCifr = cifrada
	err = guardar(lista)
	mu.Unlock()
	if err != nil {
		rollbackRemoto()
		responderError(w, fmt.Errorf("la key funcionó pero no pude guardar el perfil; se revirtió la pública añadida: %v", err))
		return
	}
	responder(w, map[string]any{
		"ok": true, "key": p.Key, "tipo": firmante.PublicKey().Type(),
		"huellaKey": ssh.FingerprintSHA256(firmante.PublicKey()), "comprobada": true,
		"publicaInstalada": agregada,
	})
}

// -----------------------------------------------------------------------------
// Cambio seguro de puerto SSH en dos fases: PROBAR -> APLICAR
// -----------------------------------------------------------------------------

type cambioPuertoSSH struct {
	Servidor        string
	Token           string
	Anterior        int
	Nuevo           int
	Backup          string
	SocketBackup    string
	ComentarioKey   string
	Firewall        string
	FirewallAbierto bool
	Creado          time.Time
	RollbackUnit    string
	EnCurso         bool
}

var cambiosPuertoSSH = struct {
	sync.Mutex
	m map[string]*cambioPuertoSSH
}{m: map[string]*cambioPuertoSSH{}}

func tokenCorto() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func scriptConfigPuertoSSH(original, destino, socketBackup, token string, puertos []int, crearBackup bool) string {
	var bloques strings.Builder
	bloques.WriteString("# BEGIN GATEWAY-WISP-PORT\n# Gestionado por Gateway WISP Access.\n")
	for _, p := range puertos {
		bloques.WriteString(fmt.Sprintf("Port %d\n", p))
	}
	bloques.WriteString("# END GATEWAY-WISP-PORT\n")
	bloque := bloques.String()
	bloque64 := base64.StdEncoding.EncodeToString([]byte(bloque))
	backupPart := ""
	if crearBackup {
		backupPart = fmt.Sprintf(`cp -p "$CFG" %s || exit 31
if [ -f "$SOCKCFG" ]; then cp -p "$SOCKCFG" %s; fi
`, shellQuote(original), shellQuote(socketBackup))
	}
	portsSocket := ""
	for _, p := range puertos {
		portsSocket += fmt.Sprintf("ListenStream=%d\\n", p)
	}
	return fmt.Sprintf(`set -eu
CFG=/etc/ssh/sshd_config
SOCKCFG=/etc/systemd/system/ssh.socket.d/gateway-wisp-port.conf
[ -f "$CFG" ] || { echo __GW_NO_SSHD_CONFIG__; exit 30; }
%s
TMP="$(mktemp)"; STRIP="$(mktemp)"; trap 'rm -f "$TMP" "$STRIP"' EXIT
awk '
  $0 == "# BEGIN GATEWAY-WISP-PORT" {skip=1; next}
  $0 == "# END GATEWAY-WISP-PORT" {skip=0; next}
  skip {next}
  {
    line=$0; t=line; sub(/^[[:space:]]+/, "", t); low=tolower(t)
    if (low ~ /^match[[:space:]]+/) inmatch=1
    if (!inmatch && t !~ /^#/ && tolower(t) ~ /^port[[:space:]]+/) { print "# Gateway WISP previous: " line; next }
    print line
  }
' "$CFG" > "$STRIP"
printf %%s %s | base64 -d > "$TMP"
cat "$STRIP" >> "$TMP"
chmod --reference="$CFG" "$TMP" 2>/dev/null || chmod 600 "$TMP"
chown --reference="$CFG" "$TMP" 2>/dev/null || true
cat "$TMP" > "$CFG"
SSHDBIN="$(command -v sshd 2>/dev/null || true)"; [ -x "$SSHDBIN" ] || SSHDBIN=/usr/sbin/sshd
"$SSHDBIN" -t || { echo __GW_SSHD_TEST_FAIL__; exit 32; }
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh.socket 2>/dev/null; then
  mkdir -p /etc/systemd/system/ssh.socket.d
  printf '[Socket]\nListenStream=\n%s' > "$SOCKCFG"
  systemctl daemon-reload
  systemctl restart ssh.socket
fi
%s
`, backupPart, bloque64, portsSocket, scriptRecargarSSH())
}

func programarGuardPuertoSSH(cli *ssh.Client, sudoPassword string, st *cambioPuertoSSH, usuario string) string {
	if st == nil {
		return ""
	}
	unit := "gateway-wisp-ssh-rollback-" + st.Token
	rollback := fmt.Sprintf(`set -e
CFG=/etc/ssh/sshd_config
if [ -f %s ]; then cp -p %s "$CFG"; fi
SSHDBIN="$(command -v sshd 2>/dev/null || true)"; [ -x "$SSHDBIN" ] || SSHDBIN=/usr/sbin/sshd
"$SSHDBIN" -t || exit 1
SOCKCFG=/etc/systemd/system/ssh.socket.d/gateway-wisp-port.conf
if [ -f %s ]; then mkdir -p /etc/systemd/system/ssh.socket.d; cp -p %s "$SOCKCFG"; else rm -f "$SOCKCFG"; fi
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload; systemctl is-active --quiet ssh.socket 2>/dev/null && systemctl restart ssh.socket || true; fi
%s
HOME_DIR=$(getent passwd %s 2>/dev/null | cut -d: -f6)
if [ -n "$HOME_DIR" ] && [ -f "$HOME_DIR/.ssh/authorized_keys" ]; then
  grep -v %s "$HOME_DIR/.ssh/authorized_keys" > "$HOME_DIR/.ssh/authorized_keys.gwtmp" || true
  mv "$HOME_DIR/.ssh/authorized_keys.gwtmp" "$HOME_DIR/.ssh/authorized_keys"
  chmod 600 "$HOME_DIR/.ssh/authorized_keys" || true
  chown %s "$HOME_DIR/.ssh/authorized_keys" 2>/dev/null || true
fi
`, shellQuote(st.Backup), shellQuote(st.Backup), shellQuote(st.SocketBackup), shellQuote(st.SocketBackup), scriptRecargarSSH(), shellQuote(usuario), shellQuote(st.ComentarioKey), shellQuote(usuario+":"+usuario))
	b64 := base64.StdEncoding.EncodeToString([]byte(rollback))
	launcher := fmt.Sprintf(`set -e
if command -v systemd-run >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
  systemd-run --quiet --unit=%s --on-active=5m /bin/sh -c %s
  printf '__GW_GUARD_OK__\n'
else
  printf '__GW_GUARD_NONE__\n'
fi`, shellQuote(unit), shellQuote("printf %s "+b64+" | base64 -d | sh"))
	out, err := ejecutarComoRoot(cli, sudoPassword, launcher)
	if err != nil || !strings.Contains(out, "__GW_GUARD_OK__") {
		return ""
	}
	return unit
}

func cancelarGuardPuertoSSH(cli *ssh.Client, sudoPassword, unit string) {
	if strings.TrimSpace(unit) == "" || cli == nil {
		return
	}
	script := fmt.Sprintf(`systemctl stop %s.timer %s.service >/dev/null 2>&1 || true
systemctl reset-failed %s.service >/dev/null 2>&1 || true`, shellQuote(unit), shellQuote(unit), shellQuote(unit))
	_, _ = ejecutarComoRoot(cli, sudoPassword, script)
}

func manejarToolPuertoSSHProbar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var p struct {
		Servidor     string `json:"servidor"`
		Puerto       int    `json:"puerto"`
		SudoPassword string `json:"sudoPassword"`
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

	// Reservamos el servidor antes del I/O remoto. Antes se comprobaba el mapa
	// y se insertaba al final, permitiendo que dos peticiones simultáneas
	// modificaran sshd en paralelo.
	token := tokenCorto()
	cambiosPuertoSSH.Lock()
	if st := cambiosPuertoSSH.m[p.Servidor]; st != nil {
		cambiosPuertoSSH.Unlock()
		responderError(w, fmt.Errorf("ya hay una prueba de puerto pendiente (%d → %d); aplícala o cancélala primero", st.Anterior, st.Nuevo))
		return
	}
	cambiosPuertoSSH.m[p.Servidor] = &cambioPuertoSSH{Servidor: p.Servidor, Token: token, Anterior: old, Nuevo: p.Puerto, Creado: time.Now()}
	cambiosPuertoSSH.Unlock()
	reservado := true
	defer func() {
		if !reservado {
			return
		}
		cambiosPuertoSSH.Lock()
		if actual := cambiosPuertoSSH.m[p.Servidor]; actual != nil && actual.Token == token {
			delete(cambiosPuertoSSH.m, p.Servidor)
		}
		cambiosPuertoSSH.Unlock()
	}()

	comentario := "gateway-wisp-port-test-" + token
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		responderError(w, err)
		return
	}
	pk, _ := ssh.NewPublicKey(pub)
	linea := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + comentario
	ses, err := cli.NewSession()
	if err != nil {
		responderError(w, err)
		return
	}
	ses.Stdin = strings.NewReader(linea + "\n")
	err = ses.Run(`umask 077; mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; IFS= read -r k; printf '%s\n' "$k" >> "$HOME/.ssh/authorized_keys"`)
	_ = ses.Close()
	if err != nil {
		responderError(w, fmt.Errorf("no pude preparar la credencial temporal de prueba: %v", err))
		return
	}
	quitarTempKey := func() {
		_, _ = ejecutarSesion(cli, `if [ -f "$HOME/.ssh/authorized_keys" ]; then grep -v `+shellQuote(comentario)+` "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.gwtmp" || true; mv "$HOME/.ssh/authorized_keys.gwtmp" "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; fi`, "")
	}

	backup := "/etc/ssh/sshd_config.gateway-wisp-port." + token + ".bak"
	sockBackup := "/etc/systemd/system/ssh.socket.d/gateway-wisp-port.conf." + token + ".bak"

	// Abrir el puerto en firewall antes de tocar sshd. Se hace dentro del mismo
	// script privilegiado para permitir sudo con contraseña si el usuario lo necesita.
	fwScript := fmt.Sprintf(`set -eu
NEW=%d
TOKEN=%s
FW=none
if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow "$NEW/tcp" >/dev/null; FW=ufw
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
  Z=$(firewall-cmd --get-zone-of-interface="$IF" 2>/dev/null || true); [ -n "$Z" ] && [ "$Z" != 'no zone' ] || Z=$(firewall-cmd --get-default-zone)
  firewall-cmd --zone="$Z" --add-port="$NEW/tcp" >/dev/null
  firewall-cmd --permanent --zone="$Z" --add-port="$NEW/tcp" >/dev/null
  FW=firewalld
elif command -v nft >/dev/null 2>&1 && nft list chain inet filter input >/dev/null 2>&1; then
  if [ -f /etc/wisp/config.env ] && [ -f /etc/nftables.conf ] && grep -Fq 'firewall.d/*.nft' /etc/nftables.conf; then
    nft add rule inet filter input tcp dport "$NEW" accept comment "gateway-wisp-ssh-stage-$TOKEN"
    FW=nftables
  else
    echo __GW_NFT_UNSAFE__
    exit 45
  fi
fi
printf '__GW_FW__%%s\n' "$FW"
`, p.Puerto, shellQuote(token))
	fwOut, err := ejecutarComoRoot(cli, p.SudoPassword, fwScript)
	if err != nil {
		quitarTempKey()
		if strings.Contains(err.Error(), "__GW_NFT_UNSAFE__") {
			responderError(w, fmt.Errorf("se detectó un nftables personalizado sin persistencia gestionada por Gateway WISP; por seguridad no cambiaré el puerto SSH automáticamente"))
			return
		}
		responderError(w, fmt.Errorf("no pude preparar el firewall/privilegios: %v", err))
		return
	}
	fw := "none"
	if i := strings.Index(fwOut, "__GW_FW__"); i >= 0 {
		fw = strings.TrimSpace(strings.Split(fwOut[i+9:], "\n")[0])
	}

	cfgScript := scriptConfigPuertoSSH(backup, "/etc/ssh/sshd_config", sockBackup, token, []int{old, p.Puerto}, true)
	if _, err := ejecutarComoRoot(cli, p.SudoPassword, cfgScript); err != nil {
		_ = rollbackFirewallPuerto(cli, p.SudoPassword, fw, old, p.Puerto, token, false)
		quitarTempKey()
		responderError(w, fmt.Errorf("sshd no pudo quedar escuchando temporalmente en ambos puertos; no se aplicó el cambio: %v", err))
		return
	}

	// Segunda conexión REAL por el puerto nuevo con una key temporal en memoria.
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ClientConfig{
		User: s.Usuario,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if s.Huella == "" || ssh.FingerprintSHA256(k) != s.Huella {
				return fmt.Errorf("huella SSH inesperada durante la prueba")
			}
			return nil
		},
		Timeout: 12 * time.Second,
	}
	prueba, err := ssh.Dial("tcp", net.JoinHostPort(s.Host, strconv.Itoa(p.Puerto)), cfg)
	if err != nil {
		_ = restaurarPuertoOriginal(cli, p.SudoPassword, backup, sockBackup)
		_ = rollbackFirewallPuerto(cli, p.SudoPassword, fw, old, p.Puerto, token, false)
		quitarTempKey()
		responderError(w, fmt.Errorf("el nuevo puerto NO superó la prueba SSH; se restauró el estado anterior: %v", err))
		return
	}
	ps, err := prueba.NewSession()
	if err == nil {
		out, e := ps.Output("printf __GW_PORT_OK__")
		err = e
		if err == nil && strings.TrimSpace(string(out)) != "__GW_PORT_OK__" {
			err = fmt.Errorf("respuesta inesperada")
		}
		_ = ps.Close()
	}
	_ = prueba.Close()
	if err != nil {
		_ = restaurarPuertoOriginal(cli, p.SudoPassword, backup, sockBackup)
		_ = rollbackFirewallPuerto(cli, p.SudoPassword, fw, old, p.Puerto, token, false)
		quitarTempKey()
		responderError(w, fmt.Errorf("la conexión abrió, pero la sesión de prueba falló; rollback aplicado: %v", err))
		return
	}

	stage := &cambioPuertoSSH{
		Servidor: p.Servidor, Token: token, Anterior: old, Nuevo: p.Puerto,
		Backup: backup, SocketBackup: sockBackup, ComentarioKey: comentario,
		Firewall: fw, FirewallAbierto: fw != "none", Creado: time.Now(),
	}
	// Protección adicional ante cierre/crash de la app: en servidores con
	// systemd, un timer restaura el puerto anterior en 5 minutos si el flujo
	// no llega a Aplicar o Cancelar. La sesión actual nunca se cierra aquí.
	stage.RollbackUnit = programarGuardPuertoSSH(cli, p.SudoPassword, stage, s.Usuario)
	cambiosPuertoSSH.Lock()
	cambiosPuertoSSH.m[p.Servidor] = stage
	cambiosPuertoSSH.Unlock()
	reservado = false

	responder(w, map[string]any{
		"ok": true, "probado": true, "token": token, "anterior": old, "nuevo": p.Puerto,
		"firewall": fw, "rollbackGuard": stage.RollbackUnit != "",
		"mensaje": fmt.Sprintf("Prueba correcta: Gateway abrió una SEGUNDA conexión SSH interna por %d. El perfil sigue en %d hasta que pulses Aplicar.", p.Puerto, old),
	})
}

func restaurarPuertoOriginal(cli *ssh.Client, sudoPassword, backup, socketBackup string) error {
	script := fmt.Sprintf(`set -e
CFG=/etc/ssh/sshd_config
[ -f %s ] && cp -p %s "$CFG"
SSHDBIN="$(command -v sshd 2>/dev/null || true)"; [ -x "$SSHDBIN" ] || SSHDBIN=/usr/sbin/sshd
"$SSHDBIN" -t
SOCKCFG=/etc/systemd/system/ssh.socket.d/gateway-wisp-port.conf
if [ -f %s ]; then mkdir -p /etc/systemd/system/ssh.socket.d; cp -p %s "$SOCKCFG"; else rm -f "$SOCKCFG"; fi
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload; systemctl is-active --quiet ssh.socket 2>/dev/null && systemctl restart ssh.socket || true; fi
%s
`, shellQuote(backup), shellQuote(backup), shellQuote(socketBackup), shellQuote(socketBackup), scriptRecargarSSH())
	_, err := ejecutarComoRoot(cli, sudoPassword, script)
	return err
}

func rollbackFirewallPuerto(cli *ssh.Client, sudoPassword, backend string, old, nuevo int, token string, cerrarAnterior bool) error {
	oldPart := ""
	if cerrarAnterior {
		oldPart = fmt.Sprintf("OLD=%d\n", old)
	}
	script := fmt.Sprintf(`set -eu
NEW=%d
TOKEN=%s
%s
case %s in
  ufw)
    ufw --force delete allow "$NEW/tcp" >/dev/null 2>&1 || true
    ;;
  firewalld)
    IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}'); Z=$(firewall-cmd --get-zone-of-interface="$IF" 2>/dev/null || true); [ -n "$Z" ] && [ "$Z" != 'no zone' ] || Z=$(firewall-cmd --get-default-zone)
    firewall-cmd --zone="$Z" --remove-port="$NEW/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --zone="$Z" --remove-port="$NEW/tcp" >/dev/null 2>&1 || true
    ;;
  nftables)
    H=$(nft -a list chain inet filter input 2>/dev/null | awk '/gateway-wisp-ssh-stage-'"$TOKEN"'/ {for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}')
    for h in $H; do nft delete rule inet filter input handle "$h" 2>/dev/null || true; done
    ;;
esac
`, nuevo, shellQuote(token), oldPart, shellQuote(backend))
	_, err := ejecutarComoRoot(cli, sudoPassword, script)
	return err
}

func manejarToolPuertoSSHAplicar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var p struct {
		Servidor       string `json:"servidor"`
		Token          string `json:"token"`
		CerrarAnterior bool   `json:"cerrarAnterior"`
		SudoPassword   string `json:"sudoPassword"`
	}
	if err := decodificar(r, &p); err != nil {
		responderError(w, err)
		return
	}
	cambiosPuertoSSH.Lock()
	st := cambiosPuertoSSH.m[p.Servidor]
	if st == nil || st.Token != p.Token || st.EnCurso {
		cambiosPuertoSSH.Unlock()
		responderError(w, fmt.Errorf("no hay una prueba de puerto válida pendiente"))
		return
	}
	st.EnCurso = true
	copia := *st
	cambiosPuertoSSH.Unlock()
	defer func() {
		cambiosPuertoSSH.Lock()
		if actual := cambiosPuertoSSH.m[p.Servidor]; actual != nil && actual.Token == p.Token {
			actual.EnCurso = false
		}
		cambiosPuertoSSH.Unlock()
	}()

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

	// Reutilizamos una key temporal nueva para comprobar el estado FINAL.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	comentarioFinal := "gateway-wisp-port-final-" + copia.Token
	linea := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + comentarioFinal
	ses, err := cli.NewSession()
	if err != nil {
		responderError(w, err)
		return
	}
	ses.Stdin = strings.NewReader(linea + "\n")
	err = ses.Run(`umask 077; mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; IFS= read -r k; printf '%s\n' "$k" >> "$HOME/.ssh/authorized_keys"`)
	_ = ses.Close()
	if err != nil {
		responderError(w, err)
		return
	}
	quitar := func(comment string) {
		_, _ = ejecutarSesion(cli, `grep -v `+shellQuote(comment)+` "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.gwtmp" || true; mv "$HOME/.ssh/authorized_keys.gwtmp" "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"`, "")
	}
	defer quitar(comentarioFinal)

	finalScript := scriptConfigPuertoSSH(copia.Backup, "/etc/ssh/sshd_config", copia.SocketBackup, copia.Token, []int{copia.Nuevo}, false)
	// Mantener config.env sincronizado si este servidor usa Gateway WISP.
	finalScript += fmt.Sprintf(`
if [ -f /etc/wisp/config.env ]; then
  TMPENV="$(mktemp)"; grep -v '^SSH_PORT=' /etc/wisp/config.env > "$TMPENV" || true; printf 'SSH_PORT="%d"\n' >> "$TMPENV"; install -m 600 "$TMPENV" /etc/wisp/config.env; rm -f "$TMPENV"
fi
`, copia.Nuevo)
	if _, err := ejecutarComoRoot(cli, p.SudoPassword, finalScript); err != nil {
		quitar(copia.ComentarioKey)
		responderError(w, fmt.Errorf("no pude aplicar el puerto final; la fase de prueba sigue pendiente: %v", err))
		return
	}

	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ClientConfig{
		User: s.Usuario,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if s.Huella == "" || ssh.FingerprintSHA256(k) != s.Huella {
				return fmt.Errorf("huella SSH inesperada")
			}
			return nil
		},
		Timeout: 12 * time.Second,
	}
	prueba, err := ssh.Dial("tcp", net.JoinHostPort(s.Host, strconv.Itoa(copia.Nuevo)), cfg)
	if err != nil {
		_ = restaurarPuertoOriginal(cli, p.SudoPassword, copia.Backup, copia.SocketBackup)
		cancelarGuardPuertoSSH(cli, p.SudoPassword, copia.RollbackUnit)
		quitar(copia.ComentarioKey)
		_ = rollbackFirewallPuerto(cli, p.SudoPassword, copia.Firewall, copia.Anterior, copia.Nuevo, copia.Token, false)
		cambiosPuertoSSH.Lock()
		delete(cambiosPuertoSSH.m, p.Servidor)
		cambiosPuertoSSH.Unlock()
		responderError(w, fmt.Errorf("la comprobación FINAL falló; se restauró el puerto %d: %v", copia.Anterior, err))
		return
	}
	_ = prueba.Close()

	mu.Lock()
	lista := cargar()
	perfil := buscar(lista, s.Nombre)
	if perfil == nil {
		err = fmt.Errorf("servidor no encontrado al guardar el puerto")
	} else {
		perfil.Puerto = copia.Nuevo
		err = guardar(lista)
	}
	mu.Unlock()
	if err != nil {
		// Si no podemos persistir el nuevo puerto en el perfil local, no dejamos
		// el servidor cambiado a medias: restauramos el puerto anterior.
		_ = restaurarPuertoOriginal(cli, p.SudoPassword, copia.Backup, copia.SocketBackup)
		_ = rollbackFirewallPuerto(cli, p.SudoPassword, copia.Firewall, copia.Anterior, copia.Nuevo, copia.Token, false)
		cancelarGuardPuertoSSH(cli, p.SudoPassword, copia.RollbackUnit)
		quitar(copia.ComentarioKey)
		cambiosPuertoSSH.Lock()
		delete(cambiosPuertoSSH.m, p.Servidor)
		cambiosPuertoSSH.Unlock()
		responderError(w, fmt.Errorf("el nuevo puerto funcionó, pero no pude guardar el perfil; el servidor fue restaurado: %v", err))
		return
	}

	// Si es Gateway WISP, config.env queda sincronizado. No ejecutamos aquí
	// un actualizador completo del servidor: el include persistente conserva
	// reglas administradas y una futura actualización renderizará SSH_PORT.
	if _, e := ejecutarComoRoot(cli, p.SudoPassword, fmt.Sprintf(`if [ -f /etc/wisp/config.env ]; then
  mkdir -p /etc/wisp/firewall.d
  printf 'tcp dport %d accept comment "gateway-wisp-ssh-port"\n' > /etc/wisp/firewall.d/20-ssh-port.nft
  chmod 600 /etc/wisp/firewall.d/20-ssh-port.nft
fi`, copia.Nuevo)); e != nil {
		// No se invalida un cambio SSH ya probado por no existir la integración WISP.
	}
	if p.CerrarAnterior {
		// Para ufw/firewalld sí podemos retirar explícitamente el anterior.
		if copia.Firewall == "ufw" || copia.Firewall == "firewalld" {
			closeScript := fmt.Sprintf(`OLD=%d
case %s in
ufw) ufw --force delete allow "$OLD/tcp" >/dev/null 2>&1 || true ;;
firewalld) IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}'); Z=$(firewall-cmd --get-zone-of-interface="$IF" 2>/dev/null || true); [ -n "$Z" ] && [ "$Z" != 'no zone' ] || Z=$(firewall-cmd --get-default-zone); firewall-cmd --zone="$Z" --remove-port="$OLD/tcp" >/dev/null 2>&1 || true; firewall-cmd --permanent --zone="$Z" --remove-port="$OLD/tcp" >/dev/null 2>&1 || true ;;
esac`, copia.Anterior, shellQuote(copia.Firewall))
			_, _ = ejecutarComoRoot(cli, p.SudoPassword, closeScript)
		}
	}

	cancelarGuardPuertoSSH(cli, p.SudoPassword, copia.RollbackUnit)
	quitar(copia.ComentarioKey)
	_, _ = ejecutarComoRoot(cli, p.SudoPassword, "rm -f "+shellQuote(copia.Backup)+" "+shellQuote(copia.SocketBackup))
	cambiosPuertoSSH.Lock()
	delete(cambiosPuertoSSH.m, p.Servidor)
	cambiosPuertoSSH.Unlock()
	responder(w, map[string]any{
		"ok": true, "aplicado": true, "puerto": copia.Nuevo, "anterior": copia.Anterior,
		"mensaje": fmt.Sprintf("Puerto %d aplicado al perfil después de dos pruebas SSH independientes.", copia.Nuevo),
	})
}

func manejarToolPuertoSSHCancelar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var p struct {
		Servidor     string `json:"servidor"`
		Token        string `json:"token"`
		SudoPassword string `json:"sudoPassword"`
	}
	if err := decodificar(r, &p); err != nil {
		responderError(w, err)
		return
	}
	cambiosPuertoSSH.Lock()
	st := cambiosPuertoSSH.m[p.Servidor]
	if st == nil || st.Token != p.Token {
		cambiosPuertoSSH.Unlock()
		responder(w, map[string]any{"ok": true, "cancelado": true})
		return
	}
	if st.EnCurso {
		cambiosPuertoSSH.Unlock()
		responderError(w, fmt.Errorf("el cambio de puerto ya se está procesando"))
		return
	}
	st.EnCurso = true
	copia := *st
	cambiosPuertoSSH.Unlock()
	defer func() {
		cambiosPuertoSSH.Lock()
		if actual := cambiosPuertoSSH.m[p.Servidor]; actual != nil && actual.Token == p.Token {
			actual.EnCurso = false
		}
		cambiosPuertoSSH.Unlock()
	}()
	cli, err := clienteConexionActiva(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	if err := restaurarPuertoOriginal(cli, p.SudoPassword, copia.Backup, copia.SocketBackup); err != nil {
		responderError(w, fmt.Errorf("no pude restaurar la configuración SSH: %v", err))
		return
	}
	_ = rollbackFirewallPuerto(cli, p.SudoPassword, copia.Firewall, copia.Anterior, copia.Nuevo, copia.Token, false)
	cancelarGuardPuertoSSH(cli, p.SudoPassword, copia.RollbackUnit)
	_, _ = ejecutarSesion(cli, `grep -v `+shellQuote(copia.ComentarioKey)+` "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.gwtmp" || true; mv "$HOME/.ssh/authorized_keys.gwtmp" "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"`, "")
	cambiosPuertoSSH.Lock()
	delete(cambiosPuertoSSH.m, p.Servidor)
	cambiosPuertoSSH.Unlock()
	responder(w, map[string]any{"ok": true, "cancelado": true, "puerto": copia.Anterior})
}

// Compatibilidad: el endpoint viejo ya no aplica cambios en un solo paso.
func manejarToolCambiarPuertoSSH(w http.ResponseWriter, r *http.Request) {
	responderError(w, fmt.Errorf("el cambio de puerto ahora se realiza en dos fases: Probar nuevo puerto y Aplicar cambio"))
}

// -----------------------------------------------------------------------------
// Gateway WISP modular embebido
// -----------------------------------------------------------------------------

func prepararGatewayWISP(servidor string) (string, error) {
	c, err := clienteSFTP(servidor)
	if err != nil {
		return "", err
	}
	data, err := v314Assets.ReadFile("assets/gateway-wisp.tar.gz")
	if err != nil {
		return "", err
	}
	dir := "/tmp/gateway-wisp-access/gateway-wisp"
	if err = c.MkdirAll(dir); err != nil {
		return "", err
	}
	_ = c.Chmod("/tmp/gateway-wisp-access", 0700)
	_ = c.Chmod(dir, 0700)
	remoto := path.Join(dir, "gateway-wisp.tar.gz")
	f, err := c.Create(remoto)
	if err != nil {
		return "", err
	}
	_, copiaErr := io.Copy(f, bytes.NewReader(data))
	cierreErr := f.Close()
	if copiaErr != nil {
		return "", copiaErr
	}
	if cierreErr != nil {
		return "", cierreErr
	}
	_ = c.Chmod(remoto, 0600)

	// Extraer y verificar desde el backend, no escribiendo comandos a ciegas
	// en el PTY. Así el botón queda listo incluso si xterm todavía está abriendo.
	cli, err := clienteConexionActiva(servidor)
	if err != nil {
		return "", err
	}
	root := path.Join(dir, "src/gateway-wisp")
	cmd := fmt.Sprintf(`set -eu
cd %s
rm -rf src
mkdir -m 700 src
tar -xzf gateway-wisp.tar.gz -C src
chmod -R go-rwx src
[ -x %s ]
printf '__GW_BUNDLE_READY__\n'`, shellQuote(dir), shellQuote(path.Join(root, "gateway-wisp-manager")))
	out, err := ejecutarSesion(cli, cmd, "")
	if err != nil {
		return "", fmt.Errorf("no pude preparar el paquete Gateway WISP: %v", err)
	}
	if !strings.Contains(out, "__GW_BUNDLE_READY__") {
		return "", fmt.Errorf("el paquete se transfirió pero no pasó la verificación")
	}
	return root, nil
}

func comandoGatewayWISP(root, args string) string {
	return fmt.Sprintf(`cd %s && if [ ! -x ./gateway-wisp-manager ]; then printf 'ERROR: paquete modular incompleto.\n'; else if [ "$(id -u)" -eq 0 ]; then ./gateway-wisp-manager %s; else sudo ./gateway-wisp-manager %s; fi; fi`, shellQuote(root), args, args)
}

func manejarGatewayWISPPreparar(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Servidor string `json:"servidor"`
	}
	if err := decodificar(r, &p); err != nil {
		responderError(w, err)
		return
	}
	root, err := prepararGatewayWISP(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "preparado": true, "root": root, "versionPaquete": gatewayWISPBundleVersion})
}

func manejarGatewayWISPComando(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Servidor   string `json:"servidor"`
		Accion     string `json:"accion"`
		Componente string `json:"componente"`
	}
	if err := decodificar(r, &p); err != nil {
		responderError(w, err)
		return
	}
	p.Servidor = strings.TrimSpace(p.Servidor)
	p.Accion = strings.TrimSpace(p.Accion)
	p.Componente = strings.TrimSpace(p.Componente)
	if p.Servidor == "" {
		responderError(w, fmt.Errorf("servidor obligatorio"))
		return
	}
	validComp := map[string]bool{"system": true, "wireguard": true, "firewall": true, "qos": true, "dns": true, "wgdashboard": true, "crowdsec": true, "netdata": true, "panel": true, "maintenance": true}
	var args string
	switch p.Accion {
	case "instalar-todo":
		args = "install full"
	case "desinstalar-todo":
		args = "uninstall full"
	case "instalar-componente":
		if !validComp[p.Componente] {
			responderError(w, fmt.Errorf("componente inválido"))
			return
		}
		args = "component install " + p.Componente
	case "desinstalar-componente":
		if !validComp[p.Componente] {
			responderError(w, fmt.Errorf("componente inválido"))
			return
		}
		args = "component uninstall " + p.Componente
	default:
		responderError(w, fmt.Errorf("acción inválida"))
		return
	}
	root, err := prepararGatewayWISP(p.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	cmd := comandoGatewayWISP(root, args)
	responder(w, map[string]any{"ok": true, "comando": cmd, "versionPaquete": gatewayWISPBundleVersion})
}

func manejarGatewayWISPEstado(w http.ResponseWriter, r *http.Request) {
	nombre := strings.TrimSpace(r.URL.Query().Get("servidor"))
	cli, err := clienteConexionActiva(nombre)
	if err != nil {
		responderError(w, err)
		return
	}
	cmd := `printf 'VERSION='; cat /etc/wisp/version 2>/dev/null || echo absent
printf 'CONFIG='; [ -f /etc/wisp/config.env ] && echo yes || echo no
printf 'system='; [ -f /etc/sysctl.d/99-wisp-gateway.conf ] && echo installed || echo absent
printf 'wireguard='; command -v wg >/dev/null 2>&1 && echo installed || echo absent
printf 'firewall='; command -v nft >/dev/null 2>&1 && echo installed || echo absent
printf 'qos='; [ -f /etc/systemd/system/qos-cake-wg0.service ] && echo installed || echo absent
printf 'dns='; if command -v ctrld >/dev/null 2>&1 || systemctl list-unit-files 2>/dev/null | grep -Eq '^(AdGuardHome|dns)\.service'; then echo installed; else echo absent; fi
printf 'wgdashboard='; [ -x /root/WGDashboard/src/wgd.sh ] && echo installed || echo absent
printf 'crowdsec='; command -v cscli >/dev/null 2>&1 && echo installed || echo absent
printf 'netdata='; if command -v netdata >/dev/null 2>&1 || systemctl list-unit-files 2>/dev/null | grep -q '^netdata.service'; then echo installed; else echo absent; fi
printf 'panel='; [ -f /etc/systemd/system/panel-wisp.service ] && echo installed || echo absent
printf 'maintenance='; [ -f /etc/systemd/system/backup-wisp.timer ] && echo installed || echo absent`
	out, _ := ejecutarSesion(cli, cmd, "")
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "="); i > 0 {
			res[line[:i]] = strings.TrimSpace(line[i+1:])
		}
	}
	instalado := res["CONFIG"] == "yes" || (res["VERSION"] != "" && res["VERSION"] != "absent")
	responder(w, map[string]any{
		"ok": true, "instalado": instalado, "version": res["VERSION"], "versionPaquete": gatewayWISPBundleVersion,
		"componentes": map[string]string{
			"system": res["system"], "wireguard": res["wireguard"], "firewall": res["firewall"], "qos": res["qos"], "dns": res["dns"],
			"wgdashboard": res["wgdashboard"], "crowdsec": res["crowdsec"], "netdata": res["netdata"], "panel": res["panel"], "maintenance": res["maintenance"],
		},
	})
}
