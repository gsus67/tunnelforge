// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//
// Monitoreo centralizado de Gateway WISP Access.
// Grafana/Prometheus/node_exporter se ejecutan como programas independientes;
// esta aplicación únicamente los instala/configura y los comunica por SSH.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	monitoringFormato      = "gateway-wisp-access/monitoring-1"
	monitoringPuertoInicio = 19100
	monitoringPuertoFin    = 19999
)

type MonitoringTarget struct {
	Servidor   string `json:"servidor"`
	LocalPort  int    `json:"localPort"`
	RemotePort int    `json:"remotePort"`
	PeerWG     bool   `json:"peerWireGuard"`
}

type MonitoringConfig struct {
	Formato       string             `json:"formato"`
	MonitorServer string             `json:"monitorServer"`
	PortStart     int                `json:"portStart"`
	PortEnd       int                `json:"portEnd"`
	GrafanaUser   string             `json:"grafanaUser"`
	GrafanaPass   string             `json:"grafanaPassword"`
	Targets       []MonitoringTarget `json:"targets"`
	Preparado     bool               `json:"preparado"`
	Actualizado   string             `json:"actualizado,omitempty"`
}

func monitoringDefault() MonitoringConfig {
	return MonitoringConfig{
		Formato:     monitoringFormato,
		PortStart:   monitoringPuertoInicio,
		PortEnd:     monitoringPuertoFin,
		GrafanaUser: "admin",
		Targets:     []MonitoringTarget{},
	}
}

func cargarMonitoring() MonitoringConfig {
	cfg := monitoringDefault()
	datos, err := os.ReadFile(rutaJunto("monitoring.enc"))
	if err != nil || len(datos) == 0 {
		return cfg
	}
	plano, err := descifrar(strings.TrimSpace(string(datos)))
	if err != nil {
		return cfg
	}
	var guardada MonitoringConfig
	if json.Unmarshal([]byte(plano), &guardada) != nil || guardada.Formato != monitoringFormato {
		return cfg
	}
	if guardada.PortStart < 1024 || guardada.PortStart > 65535 {
		guardada.PortStart = monitoringPuertoInicio
	}
	if guardada.PortEnd < guardada.PortStart || guardada.PortEnd > 65535 {
		guardada.PortEnd = monitoringPuertoFin
	}
	if guardada.GrafanaUser == "" {
		guardada.GrafanaUser = "admin"
	}
	if guardada.Targets == nil {
		guardada.Targets = []MonitoringTarget{}
	}
	return guardada
}

func guardarMonitoring(cfg MonitoringConfig) error {
	cfg.Formato = monitoringFormato
	cfg.Actualizado = time.Now().Format(time.RFC3339)
	if cfg.Targets == nil {
		cfg.Targets = []MonitoringTarget{}
	}
	datos, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	enc, err := cifrar(string(datos))
	if err != nil {
		return err
	}
	return os.WriteFile(rutaJunto("monitoring.enc"), []byte(enc), 0600)
}

func monitoringPublica(cfg MonitoringConfig) map[string]any {
	return map[string]any{
		"formato":              cfg.Formato,
		"monitorServer":        cfg.MonitorServer,
		"portStart":            cfg.PortStart,
		"portEnd":              cfg.PortEnd,
		"grafanaUser":          cfg.GrafanaUser,
		"tieneGrafanaPassword": cfg.GrafanaPass != "",
		"targets":              cfg.Targets,
		"preparado":            cfg.Preparado,
		"actualizado":          cfg.Actualizado,
	}
}

func monitoringPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func monitoringDatosServidor(nombre string) (*Conexion, Servidor, string, error) {
	mu.Lock()
	con := conexiones[nombre]
	lista := cargar()
	mu.Unlock()
	if con == nil {
		return nil, Servidor{}, "", fmt.Errorf("%s no está conectado", nombre)
	}
	s := buscar(lista, nombre)
	if s == nil {
		return nil, Servidor{}, "", fmt.Errorf("no existe el perfil %s", nombre)
	}
	copia := *s
	pass := ""
	if copia.PassCifr != "" {
		if p, err := descifrar(copia.PassCifr); err == nil {
			pass = p
		}
	}
	return con, copia, pass, nil
}

func monitoringRoot(nombre, script string) (string, error) {
	con, _, pass, err := monitoringDatosServidor(nombre)
	if err != nil {
		return "", err
	}
	uid, err := ejecutarSesion(con.cliente, "id -u", "")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(uid) == "0" || pass != "" {
		return ejecutarComoRoot(con.cliente, pass, script)
	}
	// También soporta perfiles con sudo NOPASSWD sin obligar a guardar una contraseña.
	codificado := base64.StdEncoding.EncodeToString([]byte(script))
	cmd := fmt.Sprintf("sudo -n sh -c 'printf %%s %s | base64 -d | sh'", codificado)
	out, e := ejecutarSesion(con.cliente, cmd, "")
	if e != nil {
		return out, fmt.Errorf("se requieren privilegios root o sudo NOPASSWD: %v", e)
	}
	return out, nil
}

func shellQ(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func safeUnit(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "server"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

func monitoringHostValido(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(".-_:[]", r) {
			continue
		}
		return false
	}
	return true
}

func monitoringUsuarioValido(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		return false
	}
	return true
}

func monitoringGrafanaUserValido(s string) bool { return monitoringUsuarioValido(s) && len(s) <= 64 }

func monitoringInstallerMonitor(cfg MonitoringConfig) string {
	// Grafana OSS se instala desde el repositorio oficial en Debian/Ubuntu.
	// Prometheus usa el paquete de la distribución y corre con una unidad propia
	// ligada a 127.0.0.1 para no exponer ni Grafana ni Prometheus a Internet.
	return fmt.Sprintf(`set -eu
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Por seguridad, la instalación automática de 3.2.0 soporta Debian/Ubuntu en esta primera versión." >&2
  exit 42
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y prometheus prometheus-node-exporter openssh-client ca-certificates wget gnupg
mkdir -p /etc/apt/keyrings
wget -q -O /etc/apt/keyrings/grafana.asc https://apt.grafana.com/gpg-full.key
chmod 0644 /etc/apt/keyrings/grafana.asc
printf 'deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main\n' > /etc/apt/sources.list.d/grafana.list
apt-get update
apt-get install -y grafana

install -d -m 0700 /var/lib/gateway-wisp-monitor
install -d -m 0755 /etc/gateway-wisp-monitor /var/lib/gateway-wisp-prometheus
if [ ! -s /var/lib/gateway-wisp-monitor/id_ed25519 ]; then
  ssh-keygen -q -t ed25519 -N '' -C gateway-wisp-monitor -f /var/lib/gateway-wisp-monitor/id_ed25519
fi
: > /var/lib/gateway-wisp-monitor/known_hosts
chmod 0600 /var/lib/gateway-wisp-monitor/known_hosts

cat > /etc/gateway-wisp-monitor/prometheus.yml <<'PROM'
global:
  scrape_interval: 5s
  evaluation_interval: 5s
scrape_configs: []
PROM
cat > /etc/systemd/system/gateway-wisp-prometheus.service <<'UNIT'
[Unit]
Description=Gateway WISP Access Prometheus
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=prometheus
ExecStart=/usr/bin/prometheus --config.file=/etc/gateway-wisp-monitor/prometheus.yml --storage.tsdb.path=/var/lib/gateway-wisp-prometheus --web.listen-address=127.0.0.1:9090
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
chown -R prometheus:prometheus /var/lib/gateway-wisp-prometheus /etc/gateway-wisp-monitor
chmod 0750 /etc/gateway-wisp-monitor
systemctl disable --now prometheus.service >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now gateway-wisp-prometheus.service

mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
cat > /etc/grafana/provisioning/datasources/gateway-wisp.yml <<'DS'
apiVersion: 1
datasources:
  - name: Gateway WISP Prometheus
    uid: gateway-wisp-prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
DS
cat > /etc/grafana/provisioning/dashboards/gateway-wisp.yml <<'DB'
apiVersion: 1
providers:
  - name: Gateway WISP Access
    orgId: 1
    folder: Gateway WISP
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
DB

cat > /etc/grafana/grafana.ini <<'GRAF'
[server]
http_addr = 127.0.0.1
http_port = 3000
root_url = http://127.0.0.1:3000/monitor/grafana/
serve_from_sub_path = true
[security]
admin_user = %s
admin_password = %s
cookie_secure = false
cookie_samesite = strict
allow_embedding = true
[auth.anonymous]
enabled = true
org_role = Viewer
[users]
allow_sign_up = false
[analytics]
reporting_enabled = false
check_for_updates = true
GRAF
systemctl enable --now grafana-server.service
systemctl restart grafana-server.service
printf 'MONITOR_OK\n'
`, cfg.GrafanaUser, cfg.GrafanaPass)
}

func dashboardOverviewJSON() string {
	// Dashboard original de Gateway WISP Access, no copiado de Grafana.com.
	return `{"annotations":{"list":[]},"editable":true,"graphTooltip":1,"panels":[{"type":"stat","title":"Servidores UP","id":1,"gridPos":{"h":4,"w":6,"x":0,"y":0},"targets":[{"expr":"sum(up{job=\"gateway-wisp\"})","refId":"A"}]},{"type":"timeseries","title":"CPU por servidor (%)","id":2,"gridPos":{"h":8,"w":12,"x":0,"y":4},"targets":[{"expr":"100 - (avg by (server) (rate(node_cpu_seconds_total{job=\"gateway-wisp\",mode=\"idle\"}[2m])) * 100)","legendFormat":"{{server}}","refId":"A"}]},{"type":"timeseries","title":"RAM por servidor (%)","id":3,"gridPos":{"h":8,"w":12,"x":12,"y":4},"targets":[{"expr":"100 * (1 - (node_memory_MemAvailable_bytes{job=\"gateway-wisp\"} / node_memory_MemTotal_bytes{job=\"gateway-wisp\"}))","legendFormat":"{{server}}","refId":"A"}]},{"type":"timeseries","title":"Tráfico RX (Mbit/s)","id":4,"gridPos":{"h":8,"w":12,"x":0,"y":12},"targets":[{"expr":"sum by (server) (rate(node_network_receive_bytes_total{job=\"gateway-wisp\",device!~\"lo\"}[1m])) * 8 / 1000000","legendFormat":"{{server}}","refId":"A"}]},{"type":"timeseries","title":"Tráfico TX (Mbit/s)","id":5,"gridPos":{"h":8,"w":12,"x":12,"y":12},"targets":[{"expr":"sum by (server) (rate(node_network_transmit_bytes_total{job=\"gateway-wisp\",device!~\"lo\"}[1m])) * 8 / 1000000","legendFormat":"{{server}}","refId":"A"}]}],"refresh":"5s","schemaVersion":39,"tags":["gateway-wisp-access"],"templating":{"list":[]},"time":{"from":"now-6h","to":"now"},"title":"Gateway WISP - Infraestructura","uid":"gateway-wisp-overview","version":1}`
}

func dashboardWireGuardJSON() string {
	return `{"annotations":{"list":[]},"editable":true,"graphTooltip":1,"panels":[{"type":"stat","title":"Peers con handshake reciente","id":1,"gridPos":{"h":4,"w":6,"x":0,"y":0},"targets":[{"expr":"count((time() - gateway_wisp_wireguard_peer_latest_handshake_seconds) < 180)","refId":"A"}]},{"type":"timeseries","title":"RX por peer (Mbit/s)","id":2,"gridPos":{"h":9,"w":12,"x":0,"y":4},"targets":[{"expr":"irate(gateway_wisp_wireguard_peer_receive_bytes_total[30s]) * 8 / 1000000","legendFormat":"{{server}} · {{allowed_ips}}","refId":"A"}]},{"type":"timeseries","title":"TX por peer (Mbit/s)","id":3,"gridPos":{"h":9,"w":12,"x":12,"y":4},"targets":[{"expr":"irate(gateway_wisp_wireguard_peer_transmit_bytes_total[30s]) * 8 / 1000000","legendFormat":"{{server}} · {{allowed_ips}}","refId":"A"}]},{"type":"table","title":"Peers WireGuard","id":4,"gridPos":{"h":10,"w":24,"x":0,"y":13},"targets":[{"expr":"gateway_wisp_wireguard_peer_latest_handshake_seconds","format":"table","instant":true,"refId":"A"}]}],"refresh":"5s","schemaVersion":39,"tags":["gateway-wisp-access","wireguard"],"templating":{"list":[]},"time":{"from":"now-3h","to":"now"},"title":"Gateway WISP - WireGuard Peers","uid":"gateway-wisp-wireguard","version":1}`
}

func monitoringEscribirDashboards(cfg MonitoringConfig) error {
	ov := base64.StdEncoding.EncodeToString([]byte(dashboardOverviewJSON()))
	wg := base64.StdEncoding.EncodeToString([]byte(dashboardWireGuardJSON()))
	script := fmt.Sprintf(`set -eu
install -d -m 0755 /var/lib/grafana/dashboards
printf %%s %s | base64 -d > /var/lib/grafana/dashboards/gateway-wisp-overview.json
printf %%s %s | base64 -d > /var/lib/grafana/dashboards/gateway-wisp-wireguard.json
chown grafana:grafana /var/lib/grafana/dashboards/*.json
systemctl restart grafana-server.service
`, shellQ(ov), shellQ(wg))
	_, err := monitoringRoot(cfg.MonitorServer, script)
	return err
}

func monitoringInstalarAgente(nombre string) error {
	script := `set -eu
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update >/dev/null
  apt-get install -y prometheus-node-exporter wireguard-tools >/dev/null
  install -d -m 0755 /var/lib/node_exporter/textfile_collector /usr/local/lib/gateway-wisp-access
  if [ -f /etc/default/prometheus-node-exporter ]; then
    printf 'ARGS="--web.listen-address=127.0.0.1:9100 --collector.textfile.directory=/var/lib/node_exporter/textfile_collector"\n' > /etc/default/prometheus-node-exporter
  fi
  systemctl enable prometheus-node-exporter.service >/dev/null 2>&1 || true
  systemctl restart prometheus-node-exporter.service
else
  echo "La instalación automática del agente de 3.2.0 soporta Debian/Ubuntu en esta primera versión. Instala node_exporter manualmente en otras distribuciones." >&2
  exit 43
fi
cat > /usr/local/lib/gateway-wisp-access/wg-peer-metrics.sh <<'WGEOF'
#!/bin/sh
set -eu
OUT=/var/lib/node_exporter/textfile_collector/wireguard.prom.tmp
FINAL=/var/lib/node_exporter/textfile_collector/wireguard.prom
mkdir -p "$(dirname "$FINAL")"
{
 echo '# HELP gateway_wisp_wireguard_peer_receive_bytes_total Bytes recibidos por peer WireGuard.'
 echo '# TYPE gateway_wisp_wireguard_peer_receive_bytes_total counter'
 echo '# HELP gateway_wisp_wireguard_peer_transmit_bytes_total Bytes transmitidos por peer WireGuard.'
 echo '# TYPE gateway_wisp_wireguard_peer_transmit_bytes_total counter'
 echo '# HELP gateway_wisp_wireguard_peer_latest_handshake_seconds Timestamp Unix del último handshake.'
 echo '# TYPE gateway_wisp_wireguard_peer_latest_handshake_seconds gauge'
 wg show all dump 2>/dev/null | awk 'BEGIN{FS="\t"} NF>=8 && $1 !~ /^private-key$/ {gsub(/\\/,"\\\\",$1); gsub(/"/,"\\\"",$1); gsub(/\\/,"\\\\",$2); gsub(/"/,"\\\"",$2); gsub(/\\/,"\\\\",$5); gsub(/"/,"\\\"",$5); print "gateway_wisp_wireguard_peer_receive_bytes_total{interface=\""$1"\",peer=\""$2"\",allowed_ips=\""$5"\"} "$7; print "gateway_wisp_wireguard_peer_transmit_bytes_total{interface=\""$1"\",peer=\""$2"\",allowed_ips=\""$5"\"} "$8; print "gateway_wisp_wireguard_peer_latest_handshake_seconds{interface=\""$1"\",peer=\""$2"\",allowed_ips=\""$5"\"} "$6}'
} > "$OUT"
mv "$OUT" "$FINAL"
WGEOF
chmod 0755 /usr/local/lib/gateway-wisp-access/wg-peer-metrics.sh
cat > /etc/systemd/system/gateway-wisp-wg-metrics.service <<'UNIT'
[Unit]
Description=Gateway WISP Access WireGuard peer metrics
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/lib/gateway-wisp-access/wg-peer-metrics.sh
UNIT
cat > /etc/systemd/system/gateway-wisp-wg-metrics.timer <<'UNIT'
[Unit]
Description=Collect WireGuard peer metrics every 5 seconds
[Timer]
OnBootSec=10s
OnUnitActiveSec=5s
AccuracySec=1s
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now gateway-wisp-wg-metrics.timer
systemctl start gateway-wisp-wg-metrics.service || true
printf AGENT_OK
`
	_, err := monitoringRoot(nombre, script)
	return err
}

func monitoringMonitorPublicKey(cfg MonitoringConfig) (string, error) {
	return monitoringRoot(cfg.MonitorServer, "set -eu; cat /var/lib/gateway-wisp-monitor/id_ed25519.pub")
}

func monitoringInstalarPublicaTarget(nombre, publica string) error {
	con, _, _, err := monitoringDatosServidor(nombre)
	if err != nil {
		return err
	}
	publica = strings.TrimSpace(publica)
	cmd := fmt.Sprintf("umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -Fqx %s ~/.ssh/authorized_keys || printf '%%s\\n' %s >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys", shellQ(publica), shellQ(publica))
	_, err = ejecutarSesion(con.cliente, cmd, "")
	return err
}

func monitoringKnownHost(cfg MonitoringConfig, target Servidor) error {
	cmd := fmt.Sprintf("ssh-keyscan -T 6 -p %d %s 2>/dev/null || true", target.Puerto, shellQ(target.Host))
	out, err := monitoringRoot(cfg.MonitorServer, cmd)
	if err != nil {
		return err
	}
	var lineaOK string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		linea := strings.TrimSpace(sc.Text())
		if linea == "" || strings.HasPrefix(linea, "#") {
			continue
		}
		partes := strings.Fields(linea)
		if len(partes) < 3 {
			continue
		}
		pub, _, _, _, e := ssh.ParseAuthorizedKey([]byte(partes[1] + " " + partes[2]))
		if e != nil {
			continue
		}
		if ssh.FingerprintSHA256(pub) == target.Huella {
			lineaOK = linea
			break
		}
	}
	if lineaOK == "" {
		return fmt.Errorf("la huella obtenida desde el monitor no coincide con la huella verificada de %s", target.Nombre)
	}
	script := fmt.Sprintf("set -eu; install -d -m 0700 /var/lib/gateway-wisp-monitor; touch /var/lib/gateway-wisp-monitor/known_hosts; grep -Fqx %s /var/lib/gateway-wisp-monitor/known_hosts || printf '%%s\\n' %s >> /var/lib/gateway-wisp-monitor/known_hosts; chmod 0600 /var/lib/gateway-wisp-monitor/known_hosts", shellQ(lineaOK), shellQ(lineaOK))
	_, err = monitoringRoot(cfg.MonitorServer, script)
	return err
}

func monitoringPuertoLibre(cfg MonitoringConfig) (int, error) {
	usados := map[int]bool{}
	for _, t := range cfg.Targets {
		usados[t.LocalPort] = true
	}
	out, err := monitoringRoot(cfg.MonitorServer, "ss -H -ltn 2>/dev/null | awk '{print $4}' || true")
	if err != nil {
		return 0, err
	}
	for _, tok := range strings.Fields(out) {
		i := strings.LastIndex(tok, ":")
		if i < 0 {
			continue
		}
		if p, e := strconv.Atoi(strings.Trim(tok[i+1:], "[]")); e == nil {
			usados[p] = true
		}
	}
	for p := cfg.PortStart; p <= cfg.PortEnd; p++ {
		if !usados[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no quedan puertos libres en el rango %d-%d", cfg.PortStart, cfg.PortEnd)
}

func monitoringRegenerarPrometheus(cfg MonitoringConfig) error {
	var b strings.Builder
	b.WriteString("global:\n  scrape_interval: 5s\n  evaluation_interval: 5s\nscrape_configs:\n  - job_name: 'gateway-wisp'\n")
	targets := append([]MonitoringTarget(nil), cfg.Targets...)
	if len(targets) == 0 {
		b.WriteString("    static_configs: []\n")
	} else {
		b.WriteString("    static_configs:\n")
	}
	sort.Slice(targets, func(i, j int) bool {
		return strings.ToLower(targets[i].Servidor) < strings.ToLower(targets[j].Servidor)
	})
	for _, t := range targets {
		b.WriteString(fmt.Sprintf("      - targets: ['127.0.0.1:%d']\n        labels:\n          server: %s\n", t.LocalPort, strconv.Quote(t.Servidor)))
	}
	enc := base64.StdEncoding.EncodeToString([]byte(b.String()))
	script := fmt.Sprintf("set -eu; printf %%s %s | base64 -d > /etc/gateway-wisp-monitor/prometheus.yml.new; /usr/bin/promtool check config /etc/gateway-wisp-monitor/prometheus.yml.new >/dev/null; mv /etc/gateway-wisp-monitor/prometheus.yml.new /etc/gateway-wisp-monitor/prometheus.yml; chown prometheus:prometheus /etc/gateway-wisp-monitor/prometheus.yml; systemctl restart gateway-wisp-prometheus.service", shellQ(enc))
	_, err := monitoringRoot(cfg.MonitorServer, script)
	return err
}

func monitoringCrearTunel(cfg MonitoringConfig, target Servidor, localPort int) error {
	unit := "gateway-wisp-monitor-" + safeUnit(target.Nombre)
	cmd := fmt.Sprintf(`/usr/bin/ssh -N -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/var/lib/gateway-wisp-monitor/known_hosts -i /var/lib/gateway-wisp-monitor/id_ed25519 -p %d -L 127.0.0.1:%d:127.0.0.1:9100 %s@%s`, target.Puerto, localPort, target.Usuario, target.Host)
	service := fmt.Sprintf(`[Unit]
Description=Gateway WISP monitor tunnel - %s
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
`, safeUnit(target.Nombre), cmd)
	enc := base64.StdEncoding.EncodeToString([]byte(service))
	script := fmt.Sprintf("set -eu; printf %%s %s | base64 -d > /etc/systemd/system/%s.service; chmod 0644 /etc/systemd/system/%s.service; systemctl daemon-reload; systemctl enable --now %s.service; sleep 1; systemctl is-active --quiet %s.service", shellQ(enc), unit, unit, unit, unit)
	_, err := monitoringRoot(cfg.MonitorServer, script)
	return err
}

func monitoringQuitarTunel(cfg MonitoringConfig, target string) error {
	unit := "gateway-wisp-monitor-" + safeUnit(target)
	_, err := monitoringRoot(cfg.MonitorServer, fmt.Sprintf("systemctl disable --now %s.service >/dev/null 2>&1 || true; rm -f /etc/systemd/system/%s.service; systemctl daemon-reload", unit, unit))
	return err
}

func monitoringAplicarTarget(cfg *MonitoringConfig, nombre string) error {
	if cfg.MonitorServer == "" {
		return fmt.Errorf("primero selecciona el servidor Prometheus/Grafana")
	}
	if !cfg.Preparado {
		return fmt.Errorf("primero prepara el servidor de monitoreo")
	}
	_, target, _, err := monitoringDatosServidor(nombre)
	if err != nil {
		return err
	}
	if !monitoringHostValido(target.Host) || !monitoringUsuarioValido(target.Usuario) {
		return fmt.Errorf("host o usuario SSH no válido para un túnel persistente")
	}
	if target.Huella == "" {
		return fmt.Errorf("%s no tiene huella SSH verificada", nombre)
	}
	for _, t := range cfg.Targets {
		if t.Servidor == nombre {
			return nil
		}
	}
	if err := monitoringInstalarAgente(nombre); err != nil {
		return fmt.Errorf("instalando agente en %s: %w", nombre, err)
	}
	if nombre == cfg.MonitorServer {
		cfg.Targets = append(cfg.Targets, MonitoringTarget{Servidor: nombre, LocalPort: 9100, RemotePort: 9100, PeerWG: true})
		if err := guardarMonitoring(*cfg); err != nil {
			return err
		}
		return monitoringRegenerarPrometheus(*cfg)
	}
	pub, err := monitoringMonitorPublicKey(*cfg)
	if err != nil {
		return err
	}
	if err := monitoringInstalarPublicaTarget(nombre, pub); err != nil {
		return err
	}
	if err := monitoringKnownHost(*cfg, target); err != nil {
		return err
	}
	port, err := monitoringPuertoLibre(*cfg)
	if err != nil {
		return err
	}
	if err := monitoringCrearTunel(*cfg, target, port); err != nil {
		return err
	}
	cfg.Targets = append(cfg.Targets, MonitoringTarget{Servidor: nombre, LocalPort: port, RemotePort: 9100, PeerWG: true})
	if err := guardarMonitoring(*cfg); err != nil {
		return err
	}
	return monitoringRegenerarPrometheus(*cfg)
}

func manejarMonitoringEstado(w http.ResponseWriter, r *http.Request) {
	cfg := cargarMonitoring()
	mu.Lock()
	lista := cargar()
	conectados := map[string]bool{}
	for n := range conexiones {
		conectados[n] = true
	}
	mu.Unlock()
	servidores := make([]map[string]any, 0, len(lista))
	monitorizados := map[string]MonitoringTarget{}
	for _, t := range cfg.Targets {
		monitorizados[t.Servidor] = t
	}
	for _, s := range lista {
		item := map[string]any{"nombre": s.Nombre, "host": s.Host, "puerto": s.Puerto, "usuario": s.Usuario, "conectado": conectados[s.Nombre]}
		if t, ok := monitorizados[s.Nombre]; ok {
			item["monitorizado"] = true
			item["localPort"] = t.LocalPort
		} else {
			item["monitorizado"] = false
		}
		servidores = append(servidores, item)
	}
	grafanaOnline := monitoringServicioOnline(cfg, 3000)
	prometheusOnline := monitoringServicioOnline(cfg, 9090)
	responder(w, map[string]any{"ok": true, "config": monitoringPublica(cfg), "servidores": servidores, "grafanaProxy": "/monitor/grafana/", "grafanaOnline": grafanaOnline, "prometheusOnline": prometheusOnline})
}

func manejarMonitoringConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var pet struct {
		MonitorServer   string `json:"monitorServer"`
		PortStart       int    `json:"portStart"`
		PortEnd         int    `json:"portEnd"`
		GrafanaUser     string `json:"grafanaUser"`
		GrafanaPassword string `json:"grafanaPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
		responderError(w, err)
		return
	}
	cfg := cargarMonitoring()
	if pet.PortStart == 0 {
		pet.PortStart = monitoringPuertoInicio
	}
	if pet.PortEnd == 0 {
		pet.PortEnd = monitoringPuertoFin
	}
	if pet.PortStart < 1024 || pet.PortEnd > 65535 || pet.PortEnd < pet.PortStart || pet.PortEnd-pet.PortStart < 20 {
		responderError(w, fmt.Errorf("usa un rango válido de al menos 21 puertos"))
		return
	}
	if pet.MonitorServer == "" {
		responderError(w, fmt.Errorf("selecciona el servidor de monitoreo"))
		return
	}
	if cfg.MonitorServer != "" && cfg.MonitorServer != pet.MonitorServer && len(cfg.Targets) > 0 {
		responderError(w, fmt.Errorf("quita primero los targets antes de cambiar el servidor de monitoreo"))
		return
	}
	cfg.MonitorServer = pet.MonitorServer
	cfg.PortStart = pet.PortStart
	cfg.PortEnd = pet.PortEnd
	if strings.TrimSpace(pet.GrafanaUser) != "" {
		u := strings.TrimSpace(pet.GrafanaUser)
		if !monitoringGrafanaUserValido(u) {
			responderError(w, fmt.Errorf("usuario Grafana no válido"))
			return
		}
		cfg.GrafanaUser = u
	}
	if pet.GrafanaPassword != "" {
		if strings.ContainsAny(pet.GrafanaPassword, "\r\n") || len(pet.GrafanaPassword) > 128 {
			responderError(w, fmt.Errorf("contraseña Grafana no válida"))
			return
		}
		if len(pet.GrafanaPassword) < 10 {
			responderError(w, fmt.Errorf("la contraseña de Grafana debe tener al menos 10 caracteres"))
			return
		}
		cfg.GrafanaPass = pet.GrafanaPassword
	}
	if cfg.GrafanaPass == "" {
		p, e := monitoringPassword()
		if e != nil {
			responderError(w, e)
			return
		}
		cfg.GrafanaPass = p
	}
	if err := guardarMonitoring(cfg); err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "config": monitoringPublica(cfg)})
}

func manejarMonitoringPreparar(w http.ResponseWriter, r *http.Request) {
	cfg := cargarMonitoring()
	if cfg.MonitorServer == "" {
		responderError(w, fmt.Errorf("configura el servidor de monitoreo"))
		return
	}
	if cfg.GrafanaPass == "" {
		p, e := monitoringPassword()
		if e != nil {
			responderError(w, e)
			return
		}
		cfg.GrafanaPass = p
	}
	out, err := monitoringRoot(cfg.MonitorServer, monitoringInstallerMonitor(cfg))
	if err != nil {
		responderError(w, fmt.Errorf("preparando monitor: %v — %s", err, out))
		return
	}
	cfg.Preparado = true
	if err := guardarMonitoring(cfg); err != nil {
		responderError(w, err)
		return
	}
	if err := monitoringEscribirDashboards(cfg); err != nil {
		responderError(w, fmt.Errorf("instalado, pero falló el dashboard: %v", err))
		return
	}
	responder(w, map[string]any{"ok": true, "mensaje": "Prometheus y Grafana quedaron preparados en localhost del servidor monitor."})
}

func manejarMonitoringTargets(w http.ResponseWriter, r *http.Request) {
	var pet struct {
		Servidores []string `json:"servidores"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
		responderError(w, err)
		return
	}
	cfg := cargarMonitoring()
	deseados := map[string]bool{}
	for _, n := range pet.Servidores {
		n = strings.TrimSpace(n)
		if n != "" {
			deseados[n] = true
		}
	}
	actuales := append([]MonitoringTarget(nil), cfg.Targets...)
	for _, t := range actuales {
		if !deseados[t.Servidor] {
			if t.Servidor != cfg.MonitorServer {
				_ = monitoringQuitarTunel(cfg, t.Servidor)
			}
			nueva := cfg.Targets[:0]
			for _, x := range cfg.Targets {
				if x.Servidor != t.Servidor {
					nueva = append(nueva, x)
				}
			}
			cfg.Targets = nueva
			_ = guardarMonitoring(cfg)
		}
	}
	nombres := make([]string, 0, len(deseados))
	for n := range deseados {
		nombres = append(nombres, n)
	}
	sort.Strings(nombres)
	for _, n := range nombres {
		if err := monitoringAplicarTarget(&cfg, n); err != nil {
			responderError(w, err)
			return
		}
	}
	if err := monitoringRegenerarPrometheus(cfg); err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "targets": cfg.Targets})
}

func manejarMonitoringCredenciales(w http.ResponseWriter, r *http.Request) {
	cfg := cargarMonitoring()
	if cfg.GrafanaPass == "" {
		responderError(w, fmt.Errorf("Grafana aún no está configurada"))
		return
	}
	responder(w, map[string]any{"ok": true, "usuario": cfg.GrafanaUser, "password": cfg.GrafanaPass})
}

// Proxy de Grafana dentro de la propia WebView. El primer request requiere el
// token local de la app y deja una cookie HttpOnly restringida a este path.
func crearGrafanaProxy(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookieOK := false
		if c, e := r.Cookie("gwmon"); e == nil && c.Value == token {
			cookieOK = true
		}
		if !cookieOK && r.URL.Query().Get("t") == token {
			http.SetCookie(w, &http.Cookie{Name: "gwmon", Value: token, Path: "/monitor/grafana/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			cookieOK = true
		}
		if !cookieOK {
			http.Error(w, "no autorizado", 403)
			return
		}
		q := r.URL.Query()
		q.Del("t")
		r.URL.RawQuery = q.Encode()
		cfg := cargarMonitoring()
		if cfg.MonitorServer == "" || !cfg.Preparado {
			http.Error(w, "monitoreo no configurado", 503)
			return
		}
		mu.Lock()
		con := conexiones[cfg.MonitorServer]
		mu.Unlock()
		if con == nil {
			http.Error(w, "conecta el servidor de monitoreo para ver Grafana", 503)
			return
		}
		target, _ := url.Parse("http://127.0.0.1:3000")
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return con.cliente.Dial("tcp", "127.0.0.1:3000")
		}}
		proxy.ModifyResponse = func(resp *http.Response) error {
			if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, "http://127.0.0.1:3000/monitor/grafana/") {
				resp.Header.Set("Location", strings.TrimPrefix(loc, "http://127.0.0.1:3000"))
			}
			return nil
		}
		proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, e error) {
			http.Error(rw, "Grafana no disponible: "+e.Error(), 502)
		}
		proxy.ServeHTTP(w, r)
	}
}

// Comprobación rápida de servicios ligados a localhost en el monitor.
func monitoringServicioOnline(cfg MonitoringConfig, puerto int) bool {
	if cfg.MonitorServer == "" || !cfg.Preparado {
		return false
	}
	mu.Lock()
	con := conexiones[cfg.MonitorServer]
	mu.Unlock()
	if con == nil {
		return false
	}
	c, err := con.cliente.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", puerto))
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	return n > 0 && strings.Contains(string(buf[:n]), "HTTP/")
}
