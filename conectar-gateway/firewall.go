// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var cambiosFirewall sync.Mutex

type estadoFirewall struct {
	Backend     string `json:"backend"`
	Nombre      string `json:"nombre"`
	Estado      string `json:"estado"`
	Editable    bool   `json:"editable"`
	Reglas      string `json:"reglas"`
	Zona        string `json:"zona,omitempty"`
	PuertoSSH   int    `json:"puertoSSH"`
	Nota        string `json:"nota,omitempty"`
	Privilegios bool   `json:"privilegios"`
}

func perfilServidor(nombre string) (Servidor, error) {
	mu.Lock()
	defer mu.Unlock()
	lista := cargar()
	s := buscar(lista, nombre)
	if s == nil {
		return Servidor{}, fmt.Errorf("servidor no encontrado")
	}
	return *s, nil
}

func comandoRemotoExiste(cli *ssh.Client, nombre string) bool {
	_, err := ejecutarSesion(cli, "command -v "+shellQuote(nombre)+" >/dev/null 2>&1", "")
	return err == nil
}

func tienePrivilegiosFirewall(cli *ssh.Client, password string) bool {
	uid, err := ejecutarSesion(cli, "id -u", "")
	if err == nil && strings.TrimSpace(uid) == "0" {
		return true
	}
	_, err = ejecutarSesion(cli, "sudo -n true", "")
	if err == nil {
		return true
	}
	if password != "" {
		_, err = ejecutarComoRoot(cli, password, "true")
		return err == nil
	}
	return false
}

func ejecutarFirewallPriv(cli *ssh.Client, password, comando string) (string, error) {
	uid, err := ejecutarSesion(cli, "id -u", "")
	if err == nil && strings.TrimSpace(uid) == "0" {
		return ejecutarSesion(cli, "sh -c "+shellQuote(comando), "")
	}
	if _, err := ejecutarSesion(cli, "sudo -n true", ""); err != nil {
		if password == "" {
			return "", fmt.Errorf("se necesitan permisos root o la contraseña de sudo para modificar el firewall")
		}
		return ejecutarComoRoot(cli, password, comando)
	}
	return ejecutarSesion(cli, "sudo -n sh -c "+shellQuote(comando), "")
}

func limitarSalidaFirewall(s string) string {
	s = strings.TrimSpace(s)
	const max = 16000
	if len(s) > max {
		return s[:max] + "\n… salida recortada …"
	}
	return s
}

func zonaFirewallSegura(s string) bool {
	if s == "" || len(s) > 80 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func zonaFirewalld(cli *ssh.Client, password string) string {
	out, err := ejecutarFirewallPriv(cli, password, `IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}'); Z=""; if [ -n "$IF" ]; then Z=$(firewall-cmd --get-zone-of-interface="$IF" 2>/dev/null || true); fi; if [ -z "$Z" ] || [ "$Z" = "no zone" ]; then Z=$(firewall-cmd --get-default-zone 2>/dev/null || true); fi; printf '%s\n' "$Z"`)
	if err != nil {
		return ""
	}
	z := strings.TrimSpace(out)
	if !zonaFirewallSegura(z) {
		return ""
	}
	return z
}

func obtenerEstadoFirewall(nombre, password string) (estadoFirewall, error) {
	cli, err := clienteConexionActiva(nombre)
	if err != nil {
		return estadoFirewall{}, err
	}
	perfil, err := perfilServidor(nombre)
	if err != nil {
		return estadoFirewall{}, err
	}
	sshPort := perfil.Puerto
	if sshPort <= 0 {
		sshPort = 22
	}
	priv := tienePrivilegiosFirewall(cli, password)

	ufwExiste := comandoRemotoExiste(cli, "ufw")
	firewalldExiste := comandoRemotoExiste(cli, "firewall-cmd")
	nftExiste := comandoRemotoExiste(cli, "nft")

	// Primero se prefieren gestores activos: son los que realmente gobiernan
	// el filtrado del servidor. LC_ALL=C evita depender del idioma del sistema.
	if ufwExiste && priv {
		out, e := ejecutarFirewallPriv(cli, password, "LC_ALL=C ufw status numbered 2>/dev/null")
		if e == nil && strings.Contains(out, "Status: active") {
			return estadoFirewall{Backend: "ufw", Nombre: "UFW", Estado: "activo", Editable: true, Reglas: limitarSalidaFirewall(out), PuertoSSH: sshPort, Privilegios: true}, nil
		}
	}
	if firewalldExiste {
		var out string
		var e error
		if priv {
			out, e = ejecutarFirewallPriv(cli, password, "LC_ALL=C firewall-cmd --state 2>/dev/null")
		} else {
			out, e = ejecutarSesion(cli, "LC_ALL=C firewall-cmd --state 2>/dev/null", "")
		}
		if e == nil && strings.TrimSpace(out) == "running" {
			z := ""
			reglas := "firewalld está activo."
			if priv {
				z = zonaFirewalld(cli, password)
				if z != "" {
					puertos, _ := ejecutarFirewallPriv(cli, password, "LC_ALL=C firewall-cmd --zone="+shellQuote(z)+" --list-ports 2>/dev/null")
					servicios, _ := ejecutarFirewallPriv(cli, password, "LC_ALL=C firewall-cmd --zone="+shellQuote(z)+" --list-services 2>/dev/null")
					reglas = fmt.Sprintf("Zona: %s\nPuertos: %s\nServicios: %s", z, strings.TrimSpace(puertos), strings.TrimSpace(servicios))
				}
			}
			nota := ""
			if !priv {
				nota = "Estado visible, pero para modificar reglas necesitas root o sudo sin contraseña."
			}
			return estadoFirewall{Backend: "firewalld", Nombre: "firewalld", Estado: "activo", Editable: true, Reglas: limitarSalidaFirewall(reglas), Zona: z, PuertoSSH: sshPort, Nota: nota, Privilegios: priv}, nil
		}
	}

	if nftExiste {
		reglas := "nftables detectado."
		edita := false
		nota := "Gateway solo modifica reglas nftables creadas por Gateway; no toca reglas personalizadas existentes. Los cambios directos de nftables son runtime."
		if priv {
			if out, e := ejecutarFirewallPriv(cli, password, "LC_ALL=C nft -a list ruleset 2>/dev/null | sed -n '1,160p'"); e == nil {
				reglas = out
			}
			if _, e := ejecutarFirewallPriv(cli, password, "nft list chain inet filter input >/dev/null 2>&1"); e == nil {
				edita = true
			} else {
				nota = "nftables está disponible, pero no existe la cadena 'inet filter input'. Por seguridad Gateway no crea una estructura de firewall nueva automáticamente."
			}
		} else {
			nota = "nftables detectado; para consultar/modificar el ruleset necesitas root o sudo sin contraseña."
		}
		return estadoFirewall{Backend: "nftables", Nombre: "nftables", Estado: "detectado", Editable: edita || !priv, Reglas: limitarSalidaFirewall(reglas), PuertoSSH: sshPort, Nota: nota, Privilegios: priv}, nil
	}

	// Si no hay un gestor activo, todavía informamos si alguno está instalado.
	if ufwExiste {
		nota := "UFW está instalado pero no aparece activo. Gateway no activa un firewall automáticamente para evitar bloquear el acceso SSH."
		reglas := "UFW instalado · inactivo o sin privilegios para consultar el estado."
		if priv {
			if out, e := ejecutarFirewallPriv(cli, password, "LC_ALL=C ufw status numbered 2>/dev/null"); e == nil {
				reglas = out
			}
		}
		return estadoFirewall{Backend: "ufw", Nombre: "UFW", Estado: "inactivo", Editable: !priv, Reglas: limitarSalidaFirewall(reglas), PuertoSSH: sshPort, Nota: nota, Privilegios: priv}, nil
	}
	if firewalldExiste {
		return estadoFirewall{Backend: "firewalld", Nombre: "firewalld", Estado: "inactivo", Editable: false, Reglas: "firewalld está instalado pero no está ejecutándose.", PuertoSSH: sshPort, Nota: "Gateway no inicia el firewall automáticamente.", Privilegios: priv}, nil
	}

	return estadoFirewall{Backend: "none", Nombre: "Sin firewall compatible", Estado: "no detectado", Editable: false, Reglas: "No se detectó UFW, firewalld ni nftables.", PuertoSSH: sshPort, Nota: "La herramienta no instala paquetes ni habilita servicios automáticamente.", Privilegios: priv}, nil
}

func crearBackupFirewall(cli *ssh.Client, password, backend string) (string, error) {
	dir := "/tmp/gateway-wisp-access/firewall-backups/" + time.Now().UTC().Format("20060102-150405.000000000")
	var cmd string
	switch backend {
	case "ufw":
		cmd = "mkdir -p " + shellQuote(dir) + " && tar -czf " + shellQuote(dir+"/ufw.tgz") + " /etc/ufw 2>/dev/null && LC_ALL=C ufw status numbered > " + shellQuote(dir+"/status.txt")
	case "firewalld":
		cmd = "mkdir -p " + shellQuote(dir) + " && if [ -d /etc/firewalld ]; then tar -czf " + shellQuote(dir+"/firewalld.tgz") + " /etc/firewalld 2>/dev/null; else tar -czf " + shellQuote(dir+"/firewalld.tgz") + " --files-from /dev/null; fi && LC_ALL=C firewall-cmd --list-all-zones > " + shellQuote(dir+"/status.txt")
	case "nftables":
		cmd = "mkdir -p " + shellQuote(dir) + " && nft list ruleset > " + shellQuote(dir+"/ruleset.nft")
	default:
		return "", fmt.Errorf("backend de firewall no compatible")
	}
	if _, err := ejecutarFirewallPriv(cli, password, cmd); err != nil {
		return "", fmt.Errorf("no pude crear la copia de seguridad del firewall: %v", err)
	}
	return dir, nil
}

func restaurarBackupFirewall(cli *ssh.Client, password, backend, dir string) error {
	var cmd string
	switch backend {
	case "ufw":
		cmd = "tar -xzf " + shellQuote(dir+"/ufw.tgz") + " -C / && ufw reload"
	case "firewalld":
		cmd = "tar -xzf " + shellQuote(dir+"/firewalld.tgz") + " -C / && firewall-cmd --reload"
	case "nftables":
		cmd = "nft -f " + shellQuote(dir+"/ruleset.nft")
	default:
		return fmt.Errorf("backend no restaurable")
	}
	_, err := ejecutarFirewallPriv(cli, password, cmd)
	return err
}

func comprobarPuertoSSHDesdeLocal(nombre string) error {
	p, err := perfilServidor(nombre)
	if err != nil {
		return err
	}
	puerto := p.Puerto
	if puerto <= 0 {
		puerto = 22
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(p.Host, strconv.Itoa(puerto)), 4*time.Second)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func aplicarFirewall(nombre, accion string, puerto int, protocolo, password string) (estadoFirewall, string, error) {
	cambiosFirewall.Lock()
	defer cambiosFirewall.Unlock()
	if puerto < 1 || puerto > 65535 {
		return estadoFirewall{}, "", fmt.Errorf("puerto inválido")
	}
	protocolo = strings.ToLower(strings.TrimSpace(protocolo))
	if protocolo != "tcp" && protocolo != "udp" {
		return estadoFirewall{}, "", fmt.Errorf("protocolo inválido")
	}
	if accion != "abrir" && accion != "cerrar" {
		return estadoFirewall{}, "", fmt.Errorf("acción inválida")
	}

	estado, err := obtenerEstadoFirewall(nombre, password)
	if err != nil {
		return estadoFirewall{}, "", err
	}
	if !estado.Editable {
		return estadoFirewall{}, "", fmt.Errorf("%s no está disponible para cambios seguros: %s", estado.Nombre, estado.Nota)
	}
	if accion == "cerrar" && protocolo == "tcp" && puerto == estado.PuertoSSH {
		return estadoFirewall{}, "", fmt.Errorf("el puerto %d/tcp es el SSH usado por este perfil y está protegido para evitar que pierdas acceso", puerto)
	}

	cli, err := clienteConexionActiva(nombre)
	if err != nil {
		return estadoFirewall{}, "", err
	}
	backup, err := crearBackupFirewall(cli, password, estado.Backend)
	if err != nil {
		return estadoFirewall{}, "", err
	}

	puertoSpec := strconv.Itoa(puerto) + "/" + protocolo
	rollback := func(causa error) (estadoFirewall, string, error) {
		if rerr := restaurarBackupFirewall(cli, password, estado.Backend, backup); rerr != nil {
			return estadoFirewall{}, backup, fmt.Errorf("%v; además falló el rollback automático: %v. Backup: %s", causa, rerr, backup)
		}
		return estadoFirewall{}, backup, fmt.Errorf("%v; Gateway restauró el firewall desde %s", causa, backup)
	}

	switch estado.Backend {
	case "ufw":
		cmd := "LC_ALL=C ufw allow " + puertoSpec
		if accion == "cerrar" {
			cmd = "LC_ALL=C ufw --force delete allow " + puertoSpec
		}
		if _, err := ejecutarFirewallPriv(cli, password, cmd); err != nil {
			return rollback(err)
		}
		if err := comprobarPuertoSSHDesdeLocal(nombre); err != nil {
			return rollback(fmt.Errorf("el puerto SSH dejó de responder después del cambio: %v", err))
		}

	case "firewalld":
		z := estado.Zona
		if !zonaFirewallSegura(z) {
			return estadoFirewall{}, backup, fmt.Errorf("no pude determinar una zona segura de firewalld")
		}
		opRuntime := "--add-port=" + puertoSpec
		opPermanente := opRuntime
		inverso := "--remove-port=" + puertoSpec
		if accion == "cerrar" {
			opRuntime = "--remove-port=" + puertoSpec
			opPermanente = opRuntime
			inverso = "--add-port=" + puertoSpec
		}
		base := "LC_ALL=C firewall-cmd --zone=" + shellQuote(z) + " "
		if _, err := ejecutarFirewallPriv(cli, password, base+opRuntime); err != nil {
			return estadoFirewall{}, backup, err
		}
		if err := comprobarPuertoSSHDesdeLocal(nombre); err != nil {
			_, _ = ejecutarFirewallPriv(cli, password, base+inverso)
			return rollback(fmt.Errorf("el puerto SSH dejó de responder después del cambio: %v", err))
		}
		if _, err := ejecutarFirewallPriv(cli, password, base+"--permanent "+opPermanente); err != nil {
			_, _ = ejecutarFirewallPriv(cli, password, base+inverso)
			return rollback(fmt.Errorf("el cambio runtime funcionó, pero no pude guardarlo como permanente: %v", err))
		}

	case "nftables":
		tag := "gateway-wisp-access:" + puertoSpec
		if accion == "abrir" {
			cmd := "nft -a list chain inet filter input | grep -F -- " + shellQuote(tag) + " >/dev/null 2>&1 || nft add rule inet filter input " + protocolo + " dport " + strconv.Itoa(puerto) + " accept comment " + shellQuote(tag)
			if _, err := ejecutarFirewallPriv(cli, password, cmd); err != nil {
				return rollback(err)
			}
		} else {
			if _, err := ejecutarFirewallPriv(cli, password, "nft -a list chain inet filter input | grep -F -- "+shellQuote(tag)+" >/dev/null 2>&1"); err != nil {
				return estadoFirewall{}, backup, fmt.Errorf("ese puerto no tiene una regla nftables creada por Gateway; por seguridad no se eliminan reglas ajenas")
			}
			cmd := "for h in $(nft -a list chain inet filter input | grep -F -- " + shellQuote(tag) + " | sed -n 's/.* handle \\([0-9][0-9]*\\).*/\\1/p'); do nft delete rule inet filter input handle \"$h\"; done"
			if _, err := ejecutarFirewallPriv(cli, password, cmd); err != nil {
				return rollback(err)
			}
		}
		if err := comprobarPuertoSSHDesdeLocal(nombre); err != nil {
			return rollback(fmt.Errorf("el puerto SSH dejó de responder después del cambio: %v", err))
		}
	default:
		return estadoFirewall{}, backup, fmt.Errorf("backend de firewall no compatible")
	}

	nuevo, err := obtenerEstadoFirewall(nombre, password)
	if err != nil {
		return estadoFirewall{}, backup, err
	}
	return nuevo, backup, nil
}

func manejarFirewall(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nombre := strings.TrimSpace(r.URL.Query().Get("servidor"))
		if nombre == "" {
			responderError(w, fmt.Errorf("servidor obligatorio"))
			return
		}
		estado, err := obtenerEstadoFirewall(nombre, "")
		if err != nil {
			responderError(w, err)
			return
		}
		responder(w, estado)
	case http.MethodPost:
		var pet struct {
			Servidor  string `json:"servidor"`
			Accion    string `json:"accion"`
			Puerto    int    `json:"puerto"`
			Protocolo string `json:"protocolo"`
			Password  string `json:"sudoPassword"`
		}
		if err := decodificar(r, &pet); err != nil {
			responderError(w, err)
			return
		}
		nuevo, backup, err := aplicarFirewall(strings.TrimSpace(pet.Servidor), strings.TrimSpace(pet.Accion), pet.Puerto, pet.Protocolo, pet.Password)
		if err != nil {
			responderError(w, err)
			return
		}
		responder(w, map[string]any{"ok": true, "estado": nuevo, "backup": backup})
	default:
		responderError(w, fmt.Errorf("método no permitido"))
	}
}
