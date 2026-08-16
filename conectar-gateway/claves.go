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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// manejarCrearInstalarKey crea una ED25519 local, instala solamente la clave
// publica en authorized_keys usando la contrasena actual y actualiza el perfil.
func manejarCrearInstalarKey(w http.ResponseWriter, r *http.Request) {
	var pet struct {
		Nombre, Host, Usuario, Password string
		Puerto                          int
		AceptarHuella                   bool
		Tuneles                         []Tunel
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	pet.Nombre = strings.TrimSpace(pet.Nombre)
	pet.Host = strings.TrimSpace(pet.Host)
	pet.Usuario = strings.TrimSpace(pet.Usuario)
	if pet.Nombre == "" || pet.Host == "" || pet.Usuario == "" || pet.Password == "" {
		responderError(w, fmt.Errorf("nombre, host, usuario y contraseña actual son obligatorios"))
		return
	}
	if pet.Puerto == 0 {
		pet.Puerto = 22
	}

	mu.Lock()
	lista := cargar()
	existente := buscar(lista, pet.Nombre)
	huellaGuardada := ""
	if existente != nil {
		huellaGuardada = existente.Huella
	}
	mu.Unlock()

	var huellaVista string
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		huellaVista = ssh.FingerprintSHA256(key)
		if huellaGuardada == "" {
			if pet.AceptarHuella {
				return nil
			}
			return fmt.Errorf("confirmar-huella")
		}
		if huellaGuardada != huellaVista {
			return fmt.Errorf("la huella SSH cambió: guardada %s, recibida %s", huellaGuardada, huellaVista)
		}
		return nil
	}
	cfg := &ssh.ClientConfig{User: pet.Usuario, Auth: []ssh.AuthMethod{
		ssh.Password(pet.Password),
		ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			a := make([]string, len(qs))
			for i := range a {
				a[i] = pet.Password
			}
			return a, nil
		}),
	}, HostKeyCallback: cb, Timeout: 12 * time.Second}
	cli, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", pet.Host, pet.Puerto), cfg)
	if err != nil {
		if huellaVista != "" && huellaGuardada == "" && !pet.AceptarHuella {
			responder(w, map[string]any{"confirmarHuella": huellaVista})
			return
		}
		responderError(w, fmt.Errorf("no pude autenticar con la contraseña actual: %v", err))
		return
	}
	defer cli.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		responderError(w, err)
		return
	}
	bloque, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		responderError(w, err)
		return
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bloque})
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		responderError(w, err)
		return
	}
	publica := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " gateway-wisp-" + strings.ReplaceAll(pet.Nombre, " ", "-")

	ses, err := cli.NewSession()
	if err != nil {
		responderError(w, err)
		return
	}
	ses.Stdin = strings.NewReader(publica + "\n")
	err = ses.Run(`umask 077; mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys" && IFS= read -r gateway_key && (grep -Fqx "$gateway_key" "$HOME/.ssh/authorized_keys" 2>/dev/null || printf '%s\n' "$gateway_key" >> "$HOME/.ssh/authorized_keys")`)
	ses.Close()
	if err != nil {
		responderError(w, fmt.Errorf("conecté, pero no pude instalar authorized_keys: %v", err))
		return
	}

	dir := rutaJunto("keys")
	if err := os.MkdirAll(dir, 0700); err != nil {
		responderError(w, err)
		return
	}
	seguro := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, pet.Nombre)
	if seguro == "" {
		seguro = "servidor"
	}
	ruta := filepath.Join(dir, seguro+"_ed25519")
	if err := os.WriteFile(ruta, privPEM, 0600); err != nil {
		responderError(w, err)
		return
	}

	// Antes de cambiar el perfil a key, comprobamos una NUEVA conexión SSH
	// usando exactamente la privada recién creada. Así nunca ofrecemos
	// endurecer SSH si la key no quedó realmente operativa en el servidor.
	firmanteNuevo, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		_ = os.Remove(ruta)
		responderError(w, fmt.Errorf("no pude preparar la key nueva: %v", err))
		return
	}
	cfgKey := &ssh.ClientConfig{
		User: pet.Usuario,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(firmanteNuevo)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			vista := ssh.FingerprintSHA256(key)
			esperada := huellaGuardada
			if esperada == "" {
				esperada = huellaVista
			}
			if esperada == "" || vista != esperada {
				return fmt.Errorf("huella SSH inesperada al comprobar la key")
			}
			return nil
		},
		Timeout: 12 * time.Second,
	}
	prueba, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", pet.Host, pet.Puerto), cfgKey)
	if err != nil {
		_ = os.Remove(ruta)
		responderError(w, fmt.Errorf("la clave pública se instaló, pero el servidor no aceptó la nueva key al comprobarla: %v", err))
		return
	}
	_ = prueba.Close()

	mu.Lock()
	lista = cargar()
	s := buscar(lista, pet.Nombre)
	if s == nil {
		lista = append(lista, Servidor{Nombre: pet.Nombre})
		s = &lista[len(lista)-1]
	}
	s.Host = pet.Host
	s.Puerto = pet.Puerto
	s.Usuario = pet.Usuario
	if pet.Tuneles != nil {
		validados, e := validarTuneles(pet.Tuneles)
		if e != nil {
			mu.Unlock()
			responderError(w, e)
			return
		}
		s.Tuneles = validados
	}
	s.Key = ruta
	s.PassCifr = ""
	if s.Huella == "" {
		s.Huella = huellaVista
	}
	err = guardar(lista)
	mu.Unlock()
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "key": ruta, "publica": publica, "huella": ssh.FingerprintSHA256(sshPub)})
}

// ejecutarSesion ejecuta un comando en una conexión SSH ya autenticada.
func ejecutarSesion(cli *ssh.Client, comando, entrada string) (string, error) {
	ses, err := cli.NewSession()
	if err != nil {
		return "", err
	}
	defer ses.Close()
	if entrada != "" {
		ses.Stdin = strings.NewReader(entrada)
	}
	salida, err := ses.CombinedOutput(comando)
	texto := strings.TrimSpace(string(salida))
	if err != nil {
		if texto != "" {
			return texto, fmt.Errorf("%v: %s", err, texto)
		}
		return texto, err
	}
	return texto, nil
}

// conectarPerfilSoloKey abre una conexión nueva usando la key guardada y
// exige exactamente la huella TOFU del perfil. Se usa antes y después del
// endurecimiento para evitar bloquear el acceso al servidor.
func conectarPerfilSoloKey(s Servidor) (*ssh.Client, error) {
	if strings.TrimSpace(s.Key) == "" {
		return nil, fmt.Errorf("el perfil no tiene una key SSH configurada")
	}
	if strings.TrimSpace(s.Huella) == "" {
		return nil, fmt.Errorf("el perfil no tiene una huella SSH verificada")
	}
	firmante, necesita, err := cargarFirmante(s.Key, "")
	if err != nil {
		return nil, err
	}
	if necesita {
		return nil, fmt.Errorf("la key del perfil tiene passphrase; el asistente de seguridad solo usa la key generada por Gateway")
	}
	cfg := &ssh.ClientConfig{
		User: s.Usuario,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(firmante)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			vista := ssh.FingerprintSHA256(key)
			if vista != s.Huella {
				return fmt.Errorf("la huella SSH cambió: esperada %s, recibida %s", s.Huella, vista)
			}
			return nil
		},
		Timeout: 12 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Puerto), cfg)
}

// probarPasswordRemoto intenta autenticar deliberadamente SIN ninguna key.
// Devuelve true si el servidor todavía acepta la contraseña por PasswordAuthentication
// o keyboard-interactive. Se usa como prueba real después del hardening: no basta
// con confiar en sshd -T porque Match/Include pueden variar entre distribuciones.
func probarPasswordRemoto(s Servidor, password string) (bool, error) {
	if strings.TrimSpace(password) == "" {
		return false, fmt.Errorf("no hay contraseña para comprobar que el login por contraseña quedó cerrado")
	}
	cfg := &ssh.ClientConfig{
		User: s.Usuario,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				a := make([]string, len(qs))
				for i := range a {
					a[i] = password
				}
				return a, nil
			}),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			vista := ssh.FingerprintSHA256(key)
			if vista != s.Huella {
				return fmt.Errorf("la huella SSH cambió: esperada %s, recibida %s", s.Huella, vista)
			}
			return nil
		},
		Timeout: 8 * time.Second,
	}
	cli, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Puerto), cfg)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "no supported methods") || strings.Contains(msg, "permission denied") {
			return false, nil
		}
		return false, err
	}
	_ = cli.Close()
	return true, nil
}

// ejecutarComoRoot ejecuta un script fijo como root. Si el usuario remoto no
// es root, usa sudo -S con la contraseña que el usuario acaba de utilizar para
// instalar la key. El script completo viaja codificado en base64 para evitar
// problemas de comillas o interpolación del shell.
func ejecutarComoRoot(cli *ssh.Client, password, script string) (string, error) {
	uid, err := ejecutarSesion(cli, "id -u", "")
	if err != nil {
		return "", fmt.Errorf("no pude comprobar los privilegios remotos: %v", err)
	}
	codificado := base64.StdEncoding.EncodeToString([]byte(script))
	base := fmt.Sprintf("sh -c 'printf %%s %s | base64 -d | sh'", codificado)
	if strings.TrimSpace(uid) == "0" {
		return ejecutarSesion(cli, base, "")
	}
	if password == "" {
		return "", fmt.Errorf("el usuario remoto no es root y se necesita su contraseña para ejecutar sudo")
	}
	cmd := fmt.Sprintf("sudo -S -p '' %s", base)
	return ejecutarSesion(cli, cmd, password+"\n")
}

func scriptRecargarSSH() string {
	return `
reload_ok=0
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload sshd >/dev/null 2>&1 && reload_ok=1 || true
  if [ "$reload_ok" -eq 0 ]; then systemctl reload ssh >/dev/null 2>&1 && reload_ok=1 || true; fi
fi
if [ "$reload_ok" -eq 0 ] && command -v service >/dev/null 2>&1; then
  service sshd reload >/dev/null 2>&1 && reload_ok=1 || true
  if [ "$reload_ok" -eq 0 ]; then service ssh reload >/dev/null 2>&1 && reload_ok=1 || true; fi
fi
if [ "$reload_ok" -eq 0 ] && command -v pkill >/dev/null 2>&1; then
  pkill -HUP -x sshd >/dev/null 2>&1 && reload_ok=1 || true
fi
[ "$reload_ok" -eq 1 ]
`
}

// manejarAsegurarSSH se ofrece únicamente DESPUÉS de que una key nueva haya
// sido instalada y comprobada. Deshabilita contraseñas e interacción por
// teclado, mantiene public-key y deja root en modo key-only. No desactiva root
// por completo porque hacerlo bloquearía perfiles que administran el gateway
// directamente como root.
func manejarAsegurarSSH(w http.ResponseWriter, r *http.Request) {
	var pet struct {
		Nombre   string `json:"nombre"`
		Password string `json:"password"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	pet.Nombre = strings.TrimSpace(pet.Nombre)
	if pet.Nombre == "" {
		responderError(w, fmt.Errorf("falta el nombre del servidor"))
		return
	}

	mu.Lock()
	lista := cargar()
	p := buscar(lista, pet.Nombre)
	if p == nil {
		mu.Unlock()
		responderError(w, fmt.Errorf("servidor no encontrado"))
		return
	}
	servidor := *p
	mu.Unlock()

	// La key debe funcionar ANTES de tocar sshd.
	cli, err := conectarPerfilSoloKey(servidor)
	if err != nil {
		responderError(w, fmt.Errorf("no voy a cerrar contraseñas porque la key no superó la comprobación previa: %v", err))
		return
	}
	defer cli.Close()

	// OpenSSH usa el primer valor obtenido para muchas directivas. Para no
	// depender de la posición de Include/sshd_config.d, Gateway coloca un bloque
	// gestionado al principio del archivo principal. También comenta las
	// directivas globales conflictivas preexistentes para que el resultado sea
	// legible, pero deja intactos los bloques Match.
	config := `# BEGIN GATEWAY-WISP-HARDENING
# Gestionado por Gateway WISP Access. No editar dentro de este bloque.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
# END GATEWAY-WISP-HARDENING
`
	config64 := base64.StdEncoding.EncodeToString([]byte(config))
	aplicar := fmt.Sprintf(`set -u
CFG=/etc/ssh/sshd_config
ORIG=/etc/ssh/sshd_config.gateway-wisp.original.bak
BAK=/etc/ssh/sshd_config.gateway-wisp.last.bak
TMP="$(mktemp)" || exit 30
STRIPPED="$(mktemp)" || { rm -f "$TMP"; exit 30; }
cleanup(){ rm -f "$TMP" "$STRIPPED"; }
trap cleanup EXIT
[ -f "$CFG" ] || { echo __GATEWAY_NO_CONFIG__; exit 31; }
[ -f "$ORIG" ] || cp -p "$CFG" "$ORIG" || exit 32
cp -p "$CFG" "$BAK" || exit 32
%s || exit 33
printf %%s %s | base64 -d > "$TMP" || exit 34
cat "$STRIPPED" >> "$TMP" || exit 35
chmod --reference="$CFG" "$TMP" 2>/dev/null || chmod 600 "$TMP"
chown --reference="$CFG" "$TMP" 2>/dev/null || chown root:root "$TMP"
cat "$TMP" > "$CFG" || exit 36
if ! sshd -t; then
  cp -p "$BAK" "$CFG"
  echo __GATEWAY_CONFIG_INVALID__
  exit 40
fi
EFF="$(sshd -T 2>/dev/null)"
echo "$EFF" | grep -q '^pubkeyauthentication yes$' || { cp -p "$BAK" "$CFG"; echo __GATEWAY_NOT_EFFECTIVE__; exit 41; }
echo "$EFF" | grep -q '^passwordauthentication no$' || { cp -p "$BAK" "$CFG"; echo __GATEWAY_NOT_EFFECTIVE__; exit 41; }
echo "$EFF" | grep -q '^kbdinteractiveauthentication no$' || { cp -p "$BAK" "$CFG"; echo __GATEWAY_NOT_EFFECTIVE__; exit 41; }
ROOTMODE="$(echo "$EFF" | awk '$1=="permitrootlogin" {print $2; exit}')"
case "$ROOTMODE" in
  prohibit-password|without-password) ;;
  *) cp -p "$BAK" "$CFG"; echo __GATEWAY_NOT_EFFECTIVE__; exit 41 ;;
esac
%s
if [ "$reload_ok" -ne 1 ]; then
  cp -p "$BAK" "$CFG"
  echo __GATEWAY_RELOAD_FAILED__
  exit 42
fi
echo __GATEWAY_OK__
`, scriptNormalizarSSHGlobal(), config64, scriptRecargarSSH())

	salida, err := ejecutarComoRoot(cli, pet.Password, aplicar)
	if err != nil {
		switch {
		case strings.Contains(salida, "__GATEWAY_NO_CONFIG__"):
			responderError(w, fmt.Errorf("no existe /etc/ssh/sshd_config en este servidor"))
		case strings.Contains(salida, "__GATEWAY_CONFIG_INVALID__"):
			responderError(w, fmt.Errorf("la configuración SSH no pasó 'sshd -t'; se restauró el archivo anterior"))
		case strings.Contains(salida, "__GATEWAY_NOT_EFFECTIVE__"):
			responderError(w, fmt.Errorf("OpenSSH no aplicó los valores seguros esperados; Gateway restauró la configuración anterior"))
		case strings.Contains(salida, "__GATEWAY_RELOAD_FAILED__"):
			responderError(w, fmt.Errorf("la configuración era válida, pero no pude recargar SSH; Gateway restauró el archivo anterior"))
		default:
			responderError(w, fmt.Errorf("no pude asegurar SSH: %v", err))
		}
		return
	}

	rollback := fmt.Sprintf(`CFG=/etc/ssh/sshd_config
BAK=/etc/ssh/sshd_config.gateway-wisp.last.bak
[ -f "$BAK" ] && cp -p "$BAK" "$CFG"
sshd -t || exit 50
%s
`, scriptRecargarSSH())

	// La key debe seguir funcionando DESPUÉS de recargar.
	prueba, err := conectarPerfilSoloKey(servidor)
	if err != nil {
		_, _ = ejecutarComoRoot(cli, pet.Password, rollback)
		responderError(w, fmt.Errorf("la key dejó de funcionar después del cambio; Gateway restauró la configuración anterior: %v", err))
		return
	}
	_ = prueba.Close()

	// Prueba negativa REAL: la contraseña ya no debe abrir una conexión nueva,
	// tampoco mediante keyboard-interactive.
	aceptaPassword, err := probarPasswordRemoto(servidor, pet.Password)
	if err != nil {
		_, _ = ejecutarComoRoot(cli, pet.Password, rollback)
		responderError(w, fmt.Errorf("no pude verificar de forma fiable que el login por contraseña quedó cerrado; restauré la configuración: %v", err))
		return
	}
	if aceptaPassword {
		_, _ = ejecutarComoRoot(cli, pet.Password, rollback)
		responderError(w, fmt.Errorf("el servidor TODAVÍA aceptó una conexión nueva con contraseña; Gateway restauró el cambio para no dar una falsa sensación de seguridad"))
		return
	}

	responder(w, map[string]any{
		"ok":                     true,
		"passwordAuthentication": false,
		"pubkeyAuthentication":   true,
		"rootLogin":              "key-only",
		"passwordProbado":        true,
		"backup":                 "/etc/ssh/sshd_config.gateway-wisp.last.bak",
	})
}

// estadoSeguridadSSH inspecciona el bloque gestionado por Gateway en una
// conexion ya abierta. El estado "desconocido" evita afirmar que un servidor
// esta seguro solo por una heuristica.
func estadoSeguridadSSH(cli *ssh.Client) (string, error) {
	out, err := ejecutarSesion(cli, `CFG=/etc/ssh/sshd_config
[ -r "$CFG" ] || { echo unknown; exit 0; }
if grep -Fq '# BEGIN GATEWAY-WISP-HARDENING' "$CFG"; then
  echo secure
elif grep -Fq '# BEGIN GATEWAY-WISP-PASSWORD-ACCESS' "$CFG"; then
  echo password
else
  echo unknown
fi`, "")
	if err != nil {
		return "unknown", err
	}
	switch strings.TrimSpace(out) {
	case "secure", "password":
		return strings.TrimSpace(out), nil
	default:
		return "unknown", nil
	}
}

func clienteConexionActiva(nombre string) (*ssh.Client, error) {
	mu.Lock()
	c := conexiones[nombre]
	mu.Unlock()
	if c == nil || c.cliente == nil {
		return nil, fmt.Errorf("el servidor no esta conectado")
	}
	return c.cliente, nil
}

// manejarEstadoSeguridadSSH devuelve el estado del bloque administrado por
// Gateway. No modifica nada y se usa para rotular el boton discreto de cada
// servidor conectado.
func manejarEstadoSeguridadSSH(w http.ResponseWriter, r *http.Request) {
	nombre := strings.TrimSpace(r.URL.Query().Get("nombre"))
	if nombre == "" {
		responderError(w, fmt.Errorf("falta el nombre del servidor"))
		return
	}
	cli, err := clienteConexionActiva(nombre)
	if err != nil {
		responderError(w, err)
		return
	}
	modo, err := estadoSeguridadSSH(cli)
	if err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "modo": modo})
}

// scriptNormalizarSSHGlobal elimina los bloques administrados anteriormente por
// Gateway y comenta directivas globales conflictivas del archivo principal.
// Deliberadamente deja intacto todo lo que aparezca desde el primer Match para
// no alterar reglas condicionales por usuario, grupo, red, etc.
func scriptNormalizarSSHGlobal() string {
	return `awk '
  $0 == "# BEGIN GATEWAY-WISP-HARDENING" {skip=1; next}
  $0 == "# END GATEWAY-WISP-HARDENING" {skip=0; next}
  $0 == "# BEGIN GATEWAY-WISP-PASSWORD-ACCESS" {skip=1; next}
  $0 == "# END GATEWAY-WISP-PASSWORD-ACCESS" {skip=0; next}
  skip {next}
  {
    line=$0
    trimmed=line
    sub(/^[[:space:]]+/, "", trimmed)
    low=tolower(trimmed)
    if (low ~ /^match[[:space:]]+/) in_match=1
    if (!in_match && trimmed !~ /^#/ && trimmed != "") {
      split(trimmed, parts, /[[:space:]]+/)
      key=tolower(parts[1])
      if (key == "pubkeyauthentication" ||
          key == "passwordauthentication" ||
          key == "kbdinteractiveauthentication" ||
          key == "challengeresponseauthentication" ||
          key == "permitrootlogin") {
        print "# Gateway WISP previous: " line
        next
      }
    }
    print line
  }
' "$CFG" > "$STRIPPED"`
}

// manejarPermitirPasswordSSH vuelve a permitir PasswordAuthentication para
// cuentas normales, pero mantiene root exclusivamente por key. El cambio se
// hace con backup, sshd -t, comprobacion efectiva y rollback si falla.
func manejarPermitirPasswordSSH(w http.ResponseWriter, r *http.Request) {
	var pet struct {
		Nombre   string `json:"nombre"`
		Password string `json:"password"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	pet.Nombre = strings.TrimSpace(pet.Nombre)
	if pet.Nombre == "" {
		responderError(w, fmt.Errorf("falta el nombre del servidor"))
		return
	}

	mu.Lock()
	lista := cargar()
	p := buscar(lista, pet.Nombre)
	if p == nil {
		mu.Unlock()
		responderError(w, fmt.Errorf("servidor no encontrado"))
		return
	}
	servidor := *p
	mu.Unlock()

	// La key debe seguir siendo util antes de modificar sshd.
	cli, err := conectarPerfilSoloKey(servidor)
	if err != nil {
		responderError(w, fmt.Errorf("no voy a cambiar SSH porque la key no funciona: %v", err))
		return
	}
	defer cli.Close()

	config := `# BEGIN GATEWAY-WISP-PASSWORD-ACCESS
# Gestionado por Gateway WISP Access. Password para usuarios normales; root solo por key.
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
# END GATEWAY-WISP-PASSWORD-ACCESS
`
	config64 := base64.StdEncoding.EncodeToString([]byte(config))
	normalizar := scriptNormalizarSSHGlobal()
	aplicar := fmt.Sprintf(`set -u
CFG=/etc/ssh/sshd_config
BAK=/etc/ssh/sshd_config.gateway-wisp.before-password.bak
TMP="$(mktemp)" || exit 30
STRIPPED="$(mktemp)" || { rm -f "$TMP"; exit 30; }
cleanup(){ rm -f "$TMP" "$STRIPPED"; }
trap cleanup EXIT
[ -f "$CFG" ] || { echo __GATEWAY_NO_CONFIG__; exit 31; }
cp -p "$CFG" "$BAK" || exit 32
%s || exit 33
printf %%s %s | base64 -d > "$TMP" || exit 34
cat "$STRIPPED" >> "$TMP" || exit 35
chmod --reference="$CFG" "$TMP" 2>/dev/null || chmod 600 "$TMP"
chown --reference="$CFG" "$TMP" 2>/dev/null || chown root:root "$TMP"
cat "$TMP" > "$CFG" || exit 36
if ! sshd -t; then
  cp -p "$BAK" "$CFG"
  echo __GATEWAY_CONFIG_INVALID__
  exit 40
fi
EFF="$(sshd -T 2>/dev/null)"
echo "$EFF" | grep -q '^pubkeyauthentication yes$' || { cp -p "$BAK" "$CFG"; echo __GATEWAY_NOT_EFFECTIVE__; exit 41; }
echo "$EFF" | grep -q '^passwordauthentication yes$' || { cp -p "$BAK" "$CFG"; echo __GATEWAY_NOT_EFFECTIVE__; exit 41; }
ROOTMODE="$(echo "$EFF" | awk '$1=="permitrootlogin" {print $2; exit}')"
case "$ROOTMODE" in
  prohibit-password|without-password) ;;
  *) cp -p "$BAK" "$CFG"; echo __GATEWAY_NOT_EFFECTIVE__; exit 41 ;;
esac
%s
if [ "$reload_ok" -ne 1 ]; then
  cp -p "$BAK" "$CFG"
  echo __GATEWAY_RELOAD_FAILED__
  exit 42
fi
echo __GATEWAY_OK__
`, normalizar, config64, scriptRecargarSSH())

	salida, err := ejecutarComoRoot(cli, pet.Password, aplicar)
	if err != nil {
		switch {
		case strings.Contains(salida, "__GATEWAY_NO_CONFIG__"):
			responderError(w, fmt.Errorf("no existe /etc/ssh/sshd_config en este servidor"))
		case strings.Contains(salida, "__GATEWAY_CONFIG_INVALID__"):
			responderError(w, fmt.Errorf("la configuracion SSH no paso sshd -t; se restauro el archivo anterior"))
		case strings.Contains(salida, "__GATEWAY_NOT_EFFECTIVE__"):
			responderError(w, fmt.Errorf("OpenSSH no aplico PasswordAuthentication yes; se restauro el archivo anterior"))
		case strings.Contains(salida, "__GATEWAY_RELOAD_FAILED__"):
			responderError(w, fmt.Errorf("no pude recargar SSH; se restauro el archivo anterior"))
		default:
			responderError(w, fmt.Errorf("no pude permitir contraseña: %v", err))
		}
		return
	}

	rollback := fmt.Sprintf(`CFG=/etc/ssh/sshd_config
BAK=/etc/ssh/sshd_config.gateway-wisp.before-password.bak
[ -f "$BAK" ] && cp -p "$BAK" "$CFG"
sshd -t || exit 50
%s
`, scriptRecargarSSH())

	prueba, err := conectarPerfilSoloKey(servidor)
	if err != nil {
		_, _ = ejecutarComoRoot(cli, pet.Password, rollback)
		responderError(w, fmt.Errorf("la key dejo de funcionar; Gateway restauro la configuracion anterior: %v", err))
		return
	}
	_ = prueba.Close()

	// Para usuarios no-root, si se proporciono contraseña, comprobamos que una
	// conexion nueva por password funcione. Root permanece intencionalmente key-only.
	verificado := false
	if servidor.Usuario != "root" && strings.TrimSpace(pet.Password) != "" {
		acepta, e := probarPasswordRemoto(servidor, pet.Password)
		if e != nil || !acepta {
			_, _ = ejecutarComoRoot(cli, pet.Password, rollback)
			if e != nil {
				responderError(w, fmt.Errorf("no pude verificar el acceso por contraseña; restaure el cambio: %v", e))
			} else {
				responderError(w, fmt.Errorf("PasswordAuthentication quedo habilitado, pero la contraseña indicada no autentico; restaure el cambio"))
			}
			return
		}
		verificado = true
	}

	responder(w, map[string]any{
		"ok":                     true,
		"passwordAuthentication": true,
		"pubkeyAuthentication":   true,
		"rootLogin":              "key-only",
		"passwordProbado":        verificado,
	})
}
