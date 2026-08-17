// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//
// Monitoreo centralizado de Gateway WISP Access.
// Prometheus/node_exporter se ejecutan como programas independientes;
// esta aplicación los instala/configura y los comunica por SSH.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	Targets       []MonitoringTarget `json:"targets"`
	Preparado     bool               `json:"preparado"`
	Actualizado   string             `json:"actualizado,omitempty"`
}

// MonitoringProgress permite que la UI muestre qué está ocurriendo durante
// instalaciones que pueden tardar varios minutos.
type MonitoringProgress struct {
	Operacion  string   `json:"operacion"`
	Etapa      string   `json:"etapa"`
	Porcentaje int      `json:"porcentaje"`
	Activo     bool     `json:"activo"`
	Mostrar    bool     `json:"mostrar"`
	Log        []string `json:"log"`
}

var monProgress = struct {
	sync.Mutex
	P MonitoringProgress
}{}

func monitoringProgresoInicio(op, etapa string) {
	monProgress.Lock()
	monProgress.P = MonitoringProgress{Operacion: op, Etapa: etapa, Porcentaje: 3, Activo: true, Mostrar: true, Log: []string{etapa}}
	monProgress.Unlock()
}
func monitoringProgreso(etapa string, pct int) {
	monProgress.Lock()
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	monProgress.P.Etapa = etapa
	monProgress.P.Porcentaje = pct
	monProgress.P.Mostrar = true
	if len(monProgress.P.Log) == 0 || monProgress.P.Log[len(monProgress.P.Log)-1] != etapa {
		monProgress.P.Log = append(monProgress.P.Log, etapa)
	}
	if len(monProgress.P.Log) > 12 {
		monProgress.P.Log = monProgress.P.Log[len(monProgress.P.Log)-12:]
	}
	monProgress.Unlock()
}
func monitoringProgresoLog(linea string) {
	linea = strings.TrimSpace(linea)
	if linea == "" {
		return
	}
	monProgress.Lock()
	monProgress.P.Mostrar = true
	for _, l := range strings.Split(linea, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			monProgress.P.Log = append(monProgress.P.Log, l)
		}
	}
	if len(monProgress.P.Log) > 18 {
		monProgress.P.Log = monProgress.P.Log[len(monProgress.P.Log)-18:]
	}
	monProgress.Unlock()
}

func monitoringProgresoFin(etapa string, ok bool) {
	monProgress.Lock()
	monProgress.P.Etapa = etapa
	monProgress.P.Porcentaje = 100
	monProgress.P.Activo = false
	monProgress.P.Mostrar = true
	if !ok {
		monProgress.P.Porcentaje = 100
	}
	monProgress.P.Log = append(monProgress.P.Log, etapa)
	if len(monProgress.P.Log) > 12 {
		monProgress.P.Log = monProgress.P.Log[len(monProgress.P.Log)-12:]
	}
	monProgress.Unlock()
}
func manejarMonitoringProgreso(w http.ResponseWriter, r *http.Request) {
	monProgress.Lock()
	p := monProgress.P
	p.Log = append([]string(nil), monProgress.P.Log...)
	monProgress.Unlock()
	responder(w, p)
}

func monitoringDefault() MonitoringConfig {
	return MonitoringConfig{
		Formato:   monitoringFormato,
		PortStart: monitoringPuertoInicio,
		PortEnd:   monitoringPuertoFin,
		Targets:   []MonitoringTarget{},
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
		"formato":       cfg.Formato,
		"monitorServer": cfg.MonitorServer,
		"portStart":     cfg.PortStart,
		"portEnd":       cfg.PortEnd,
		"targets":       cfg.Targets,
		"preparado":     cfg.Preparado,
		"actualizado":   cfg.Actualizado,
	}
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

func monitoringPreflightScript() string {
	return `set -eu
command -v apt-get >/dev/null 2>&1 || { echo "Sistema no soportado: preparación automática requiere Debian/Ubuntu" >&2; exit 42; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd es necesario para el monitor persistente" >&2; exit 44; }
export DEBIAN_FRONTEND=noninteractive
# Esperar bloqueos de apt/dpkg en vez de fallar en el primer intento.
i=0
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
  i=$((i+1)); [ "$i" -lt 60 ] || { echo "apt/dpkg sigue bloqueado después de 120 s" >&2; exit 45; }
  sleep 2
done
mkdir -p /etc/gateway-wisp-monitor
printf 'PRECHECK_OK\n'
`
}

func monitoringPackagesScript() string {
	return `set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -o Acquire::Retries=3
apt-get install -y prometheus prometheus-node-exporter openssh-client ca-certificates wget
printf 'PACKAGES_OK\n'
`
}

func monitoringConfigureScript(cfg MonitoringConfig) string {
	return `set -eu
install -d -m 0700 /var/lib/gateway-wisp-monitor
install -d -m 0755 /etc/gateway-wisp-monitor /var/lib/gateway-wisp-prometheus
if [ ! -s /var/lib/gateway-wisp-monitor/id_ed25519 ]; then
  ssh-keygen -q -t ed25519 -N '' -C gateway-wisp-monitor -f /var/lib/gateway-wisp-monitor/id_ed25519
fi
touch /var/lib/gateway-wisp-monitor/known_hosts
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
/usr/bin/promtool check config /etc/gateway-wisp-monitor/prometheus.yml
systemctl disable --now prometheus.service >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now gateway-wisp-prometheus.service
systemctl restart gateway-wisp-prometheus.service
`
}

func monitoringVerifyScript() string {
	return `set -eu
systemctl is-active --quiet gateway-wisp-prometheus.service
for i in 1 2 3 4 5 6; do
  if wget -q -T 3 -O /dev/null http://127.0.0.1:9090/-/ready; then
    echo PROMETHEUS_OK
    exit 0
  fi
  sleep 2
done
echo "Prometheus no respondió en 127.0.0.1:9090" >&2
exit 47`
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
  echo "La instalación automática del agente de Monitoreo soporta Debian/Ubuntu. Instala node_exporter manualmente en otras distribuciones." >&2
  exit 43
fi
cat > /usr/local/lib/gateway-wisp-access/wg-peer-metrics.sh <<'WGEOF'
#!/bin/sh
set -eu
OUT=/var/lib/node_exporter/textfile_collector/wireguard.prom.tmp
FINAL=/var/lib/node_exporter/textfile_collector/wireguard.prom
mkdir -p "$(dirname "$FINAL")"
esc(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
refresh_wgd_names(){
  cache=/run/gateway-wisp-peer-names.tsv
  stale=1
  if [ -s "$cache" ]; then
    now=$(date +%s); mt=$(stat -c %Y "$cache" 2>/dev/null || echo 0); [ $((now-mt)) -lt 60 ] && stale=0
  fi
  [ "$stale" -eq 0 ] && return 0
  tmp="$cache.tmp"
  : > "$tmp"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$tmp" <<'PYWG' || true
import glob, os, sqlite3, sys
out=sys.argv[1]
patterns=[
 '/root/WGDashboard/src/db/*.db','/root/WGDashboard/src/db/*.sqlite*','/root/WGDashboard/src/*.db','/root/WGDashboard/src/*.sqlite*',
 '/opt/WGDashboard/src/db/*.db','/opt/WGDashboard/src/db/*.sqlite*','/opt/WGDashboard/src/*.db','/opt/WGDashboard/src/*.sqlite*'
]
seen=set(); rows=[]
for pat in patterns:
 for path in glob.glob(pat):
  if path in seen or not os.path.isfile(path): continue
  seen.add(path)
  try:
   con=sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=1)
   for (table,) in con.execute("select name from sqlite_master where type='table'"):
    try: cols=[r[1] for r in con.execute(f'pragma table_info("{table}")')]
    except Exception: continue
    norm={c.lower().replace('-','_'):c for c in cols}
    kcol=next((norm[k] for k in ('public_key','publickey','peer_public_key','peerpublickey','id') if k in norm),None)
    ncol=next((norm[k] for k in ('name','peer_name','peername','client_name','clientname') if k in norm),None)
    if not kcol or not ncol: continue
    try:
     for key,name in con.execute(f'SELECT "{kcol}", "{ncol}" FROM "{table}"'):
      if key and name and str(name).strip(): rows.append((str(key).strip(),str(name).strip()))
    except Exception: pass
   con.close()
  except Exception: pass
with open(out,'a',encoding='utf-8') as f:
 for k,n in rows:
  n=n.replace('\t',' ').replace('\n',' ').strip()
  if k and n: f.write(k+'\t'+n+'\n')
PYWG
  fi
  mv "$tmp" "$cache" 2>/dev/null || true
}
peer_name(){
  key="$1"; fallback="$2"; found=""
  refresh_wgd_names
  if [ -r /run/gateway-wisp-peer-names.tsv ]; then
    found=$(awk -F '\t' -v k="$key" '$1==k {sub(/^[^\t]*\t/,""); print; exit}' /run/gateway-wisp-peer-names.tsv 2>/dev/null || true)
  fi
  if [ -z "$found" ]; then
    for f in /etc/wireguard/*.conf; do
      [ -r "$f" ] || continue
      n=$(awk -v k="$key" '
        function clean(x){sub(/^[[:space:]]*#[[:space:]]*/,"",x); sub(/^[[:space:]]+|[[:space:]]+$/,"",x); return x}
        function maybe(x, y){y=clean(x); if(y ~ /^-?WGP-?[[:space:]]*Peer[[:space:]]*:/){sub(/^.*Peer[[:space:]]*:[[:space:]]*/,"",y);return y} if(y ~ /^(Name|Nombre|Client|Cliente|Peer)[[:space:]]*[:=]/){sub(/^[^:=]*[:=][[:space:]]*/,"",y);return y} return ""}
        BEGIN{inpeer=0; pending=""; name=""}
        /^[[:space:]]*#/ {v=maybe($0); if(v!=""){if(inpeer)name=v;else pending=v}; next}
        /^[[:space:]]*\[Peer\][[:space:]]*$/ {inpeer=1; name=pending; pending=""; next}
        inpeer && /^[[:space:]]*PublicKey[[:space:]]*=/ {x=$0;sub(/^[^=]*=[[:space:]]*/,"",x);sub(/[[:space:]]+$/,"",x); if(x==k){print name;exit}; inpeer=0;name="";next}
      ' "$f" 2>/dev/null || true)
      [ -n "$n" ] && { found="$n"; break; }
    done
  fi
  [ -n "$found" ] && printf '%s' "$found" || printf '%s' "$fallback"
}
{
 echo '# HELP gateway_wisp_wireguard_peer_receive_bytes_total Bytes recibidos por peer WireGuard.'
 echo '# TYPE gateway_wisp_wireguard_peer_receive_bytes_total counter'
 echo '# HELP gateway_wisp_wireguard_peer_transmit_bytes_total Bytes transmitidos por peer WireGuard.'
 echo '# TYPE gateway_wisp_wireguard_peer_transmit_bytes_total counter'
 echo '# HELP gateway_wisp_wireguard_peer_latest_handshake_seconds Timestamp Unix del último handshake.'
 echo '# TYPE gateway_wisp_wireguard_peer_latest_handshake_seconds gauge'
 wg show all dump 2>/dev/null | awk 'BEGIN{FS="\t"} NF>=8 && $1 !~ /^private-key$/ {print $1 "\t" $2 "\t" $5 "\t" $6 "\t" $7 "\t" $8}' | while IFS="$(printf '\t')" read -r iface peer allowed hs rx tx; do
   short=$(printf '%s' "$peer" | cut -c1-8)
   name=$(peer_name "$peer" "$allowed")
   [ -n "$name" ] || name="peer-$short"
   ei=$(esc "$iface"); ep=$(esc "$peer"); ea=$(esc "$allowed"); en=$(esc "$name")
   printf 'gateway_wisp_wireguard_peer_receive_bytes_total{interface="%s",peer="%s",peer_name="%s",allowed_ips="%s"} %s\n' "$ei" "$ep" "$en" "$ea" "$rx"
   printf 'gateway_wisp_wireguard_peer_transmit_bytes_total{interface="%s",peer="%s",peer_name="%s",allowed_ips="%s"} %s\n' "$ei" "$ep" "$en" "$ea" "$tx"
   printf 'gateway_wisp_wireguard_peer_latest_handshake_seconds{interface="%s",peer="%s",peer_name="%s",allowed_ips="%s"} %s\n' "$ei" "$ep" "$en" "$ea" "$hs"
 done
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
		return fmt.Errorf("primero selecciona el servidor de monitoreo")
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
	var yaExiste bool
	for _, t := range cfg.Targets {
		if t.Servidor == nombre {
			yaExiste = true
			break
		}
	}
	if err := monitoringInstalarAgente(nombre); err != nil {
		return fmt.Errorf("instalando agente en %s: %w", nombre, err)
	}
	if yaExiste {
		return nil
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
	prometheusOnline := monitoringServicioOnline(cfg, 9090)
	responder(w, map[string]any{"ok": true, "config": monitoringPublica(cfg), "servidores": servidores, "prometheusOnline": prometheusOnline})
}

func manejarMonitoringConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var pet struct {
		MonitorServer string `json:"monitorServer"`
		PortStart     int    `json:"portStart"`
		PortEnd       int    `json:"portEnd"`
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
	if err := guardarMonitoring(cfg); err != nil {
		responderError(w, err)
		return
	}
	responder(w, map[string]any{"ok": true, "config": monitoringPublica(cfg)})
}

func manejarMonitoringPreparar(w http.ResponseWriter, r *http.Request) {
	monitoringProgresoInicio("Preparar monitor", "Validando configuración y privilegios…")
	cfg := cargarMonitoring()
	fail := func(stage, out string, err error) {
		monitoringProgresoLog(out)
		monitoringProgresoFin(stage, false)
		responderError(w, fmt.Errorf("%s: %v", stage, err))
	}
	if cfg.MonitorServer == "" {
		monitoringProgresoFin("Selecciona primero el servidor de monitoreo.", false)
		responderError(w, fmt.Errorf("configura el servidor de monitoreo"))
		return
	}
	monitoringProgreso("1/4 · Preflight: sistema, systemd y bloqueos de paquetes…", 10)
	out, err := monitoringRoot(cfg.MonitorServer, monitoringPreflightScript())
	monitoringProgresoLog(out)
	if err != nil {
		fail("Falló el preflight", out, err)
		return
	}
	monitoringProgreso("2/4 · Instalando Prometheus, node_exporter y herramientas…", 35)
	out, err = monitoringRoot(cfg.MonitorServer, monitoringPackagesScript())
	monitoringProgresoLog(out)
	if err != nil {
		fail("Falló la instalación de paquetes base", out, err)
		return
	}
	monitoringProgreso("3/4 · Creando Prometheus y la infraestructura SSH segura…", 70)
	out, err = monitoringRoot(cfg.MonitorServer, monitoringConfigureScript(cfg))
	monitoringProgresoLog(out)
	if err != nil {
		fail("Falló la configuración de Prometheus", out, err)
		return
	}
	monitoringProgreso("4/4 · Verificando Prometheus por HTTP local…", 94)
	out, err = monitoringRoot(cfg.MonitorServer, monitoringVerifyScript())
	monitoringProgresoLog(out)
	if err != nil {
		fail("Prometheus no respondió correctamente", out, err)
		return
	}
	cfg.Preparado = true
	if err = guardarMonitoring(cfg); err != nil {
		fail("No pude guardar el estado de monitoreo", "", err)
		return
	}
	monitoringProgresoFin("Prometheus preparado y verificado.", true)
	responder(w, map[string]any{"ok": true, "mensaje": "Monitor preparado y verificado. Prometheus está listo."})
}

func manejarMonitoringTargets(w http.ResponseWriter, r *http.Request) {
	monitoringProgresoInicio("Aplicar monitoreo", "Calculando cambios de targets…")
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
			monitoringProgreso("Quitando monitoreo de "+t.Servidor+"…", 12)
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
	for i, n := range nombres {
		pct := 20
		if len(nombres) > 0 {
			pct = 20 + ((i+1)*65)/len(nombres)
		}
		monitoringProgreso("Preparando agente y túnel SSH para "+n+"…", pct)
		if err := monitoringAplicarTarget(&cfg, n); err != nil {
			monitoringProgresoFin("Falló al configurar "+n+".", false)
			responderError(w, err)
			return
		}
	}
	monitoringProgreso("Regenerando y validando configuración de Prometheus…", 92)
	if err := monitoringRegenerarPrometheus(cfg); err != nil {
		monitoringProgresoFin("Prometheus rechazó la nueva configuración.", false)
		responderError(w, err)
		return
	}
	monitoringProgresoFin("Selección aplicada y verificada.", true)
	responder(w, map[string]any{"ok": true, "targets": cfg.Targets})
}

type prometheusVectorResponse struct {
	Status string `json:"status"`
	Data   struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Value  []any             `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

func monitoringPromQuery(cfg MonitoringConfig, query string) ([]struct {
	Metric map[string]string
	Value  float64
}, error) {
	mu.Lock()
	con := conexiones[cfg.MonitorServer]
	mu.Unlock()
	if con == nil {
		return nil, fmt.Errorf("conecta el servidor de monitoreo")
	}
	q := url.QueryEscape(query)
	c, err := con.cliente.Dial("tcp", "127.0.0.1:9090")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	fmt.Fprintf(c, "GET /api/v1/query?query=%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", q)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Prometheus respondió %s", resp.Status)
	}
	var pr prometheusVectorResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	out := make([]struct {
		Metric map[string]string
		Value  float64
	}, 0, len(pr.Data.Result))
	for _, r := range pr.Data.Result {
		if len(r.Value) < 2 {
			continue
		}
		f, e := strconv.ParseFloat(fmt.Sprint(r.Value[1]), 64)
		if e != nil {
			continue
		}
		out = append(out, struct {
			Metric map[string]string
			Value  float64
		}{r.Metric, f})
	}
	return out, nil
}

func manejarMonitoringResumen(w http.ResponseWriter, r *http.Request) {
	cfg := cargarMonitoring()
	if cfg.MonitorServer == "" || !cfg.Preparado {
		responderError(w, fmt.Errorf("prepara primero el monitoreo"))
		return
	}
	type srv struct {
		Nombre                          string  `json:"nombre"`
		Online                          bool    `json:"online"`
		CPU, RAM, Disco, RX, TX, Uptime float64 `json:"cpu"`
	}
	// Mapas por servidor. Las consultas son instantáneas y pequeñas.
	queries := map[string]string{
		"up":     `up{job="gateway-wisp"}`,
		"cpu":    `100 - (avg by (server) (rate(node_cpu_seconds_total{job="gateway-wisp",mode="idle"}[2m])) * 100)`,
		"ram":    `100 * (1 - (node_memory_MemAvailable_bytes{job="gateway-wisp"} / node_memory_MemTotal_bytes{job="gateway-wisp"}))`,
		"disk":   `100 * (1 - (node_filesystem_avail_bytes{job="gateway-wisp",mountpoint="/",fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{job="gateway-wisp",mountpoint="/",fstype!~"tmpfs|overlay"}))`,
		"rx":     `sum by (server) (rate(node_network_receive_bytes_total{job="gateway-wisp",device!~"lo|docker.*|veth.*|br-.*"}[1m])) * 8 / 1000000`,
		"tx":     `sum by (server) (rate(node_network_transmit_bytes_total{job="gateway-wisp",device!~"lo|docker.*|veth.*|br-.*"}[1m])) * 8 / 1000000`,
		"uptime": `time() - node_boot_time_seconds{job="gateway-wisp"}`,
	}
	vals := map[string]map[string]float64{}
	for key, q := range queries {
		rows, _ := monitoringPromQuery(cfg, q)
		m := map[string]float64{}
		for _, v := range rows {
			if n := v.Metric["server"]; n != "" {
				m[n] = v.Value
			}
		}
		vals[key] = m
	}
	servers := make([]map[string]any, 0, len(cfg.Targets))
	online := 0
	var cpuSum, ramSum, rxSum, txSum float64
	samples := 0
	for _, t := range cfg.Targets {
		n := t.Servidor
		up := vals["up"][n] > 0
		if up {
			online++
		}
		cpu := vals["cpu"][n]
		ram := vals["ram"][n]
		if up {
			cpuSum += cpu
			ramSum += ram
			samples++
		}
		rx := vals["rx"][n]
		tx := vals["tx"][n]
		rxSum += rx
		txSum += tx
		servers = append(servers, map[string]any{"nombre": n, "online": up, "cpu": cpu, "ram": ram, "disco": vals["disk"][n], "rxMbit": rx, "txMbit": tx, "uptime": vals["uptime"][n]})
	}
	sort.Slice(servers, func(i, j int) bool {
		return strings.ToLower(fmt.Sprint(servers[i]["nombre"])) < strings.ToLower(fmt.Sprint(servers[j]["nombre"]))
	})
	avgCPU, avgRAM := 0.0, 0.0
	if samples > 0 {
		avgCPU = cpuSum / float64(samples)
		avgRAM = ramSum / float64(samples)
	}
	responder(w, map[string]any{"ok": true, "total": len(cfg.Targets), "online": online, "cpuPromedio": avgCPU, "ramPromedio": avgRAM, "rxMbit": rxSum, "txMbit": txSum, "servidores": servers})
}

func manejarMonitoringPeers(w http.ResponseWriter, r *http.Request) {
	cfg := cargarMonitoring()
	if cfg.MonitorServer == "" || !cfg.Preparado {
		responderError(w, fmt.Errorf("prepara primero el monitoreo"))
		return
	}
	rx, err := monitoringPromQuery(cfg, `irate(gateway_wisp_wireguard_peer_receive_bytes_total[30s]) * 8 / 1000000`)
	if err != nil {
		responderError(w, err)
		return
	}
	tx, _ := monitoringPromQuery(cfg, `irate(gateway_wisp_wireguard_peer_transmit_bytes_total[30s]) * 8 / 1000000`)
	hs, _ := monitoringPromQuery(cfg, `time() - gateway_wisp_wireguard_peer_latest_handshake_seconds`)
	type peer struct {
		Nombre       string  `json:"nombre"`
		Servidor     string  `json:"servidor"`
		Interfaz     string  `json:"interfaz"`
		AllowedIPs   string  `json:"allowedIps"`
		Key          string  `json:"key"`
		RxMbit       float64 `json:"rxMbit"`
		TxMbit       float64 `json:"txMbit"`
		HandshakeAge float64 `json:"handshakeAge"`
	}
	m := map[string]*peer{}
	keyOf := func(mm map[string]string) string {
		return mm["server"] + "\x00" + mm["interface"] + "\x00" + mm["peer"]
	}
	ensure := func(mm map[string]string) *peer {
		k := keyOf(mm)
		p := m[k]
		if p == nil {
			name := strings.TrimSpace(mm["peer_name"])
			if name == "" {
				name = strings.TrimSpace(mm["allowed_ips"])
			}
			if name == "" {
				pk := mm["peer"]
				if len(pk) > 8 {
					pk = pk[:8]
				}
				name = "peer-" + pk
			}
			p = &peer{Nombre: name, Servidor: mm["server"], Interfaz: mm["interface"], AllowedIPs: mm["allowed_ips"], Key: mm["peer"]}
			m[k] = p
		}
		return p
	}
	for _, v := range rx {
		ensure(v.Metric).RxMbit = v.Value
	}
	for _, v := range tx {
		ensure(v.Metric).TxMbit = v.Value
	}
	for _, v := range hs {
		ensure(v.Metric).HandshakeAge = v.Value
	}
	peers := make([]peer, 0, len(m))
	for _, p := range m {
		peers = append(peers, *p)
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Servidor == peers[j].Servidor {
			return strings.ToLower(peers[i].Nombre) < strings.ToLower(peers[j].Nombre)
		}
		return strings.ToLower(peers[i].Servidor) < strings.ToLower(peers[j].Servidor)
	})
	responder(w, map[string]any{"ok": true, "peers": peers})
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

// manejarMonitoringDiagnostico comprueba la cadena de monitoreo sin modificarla:
// sesión SSH, node_exporter, túnel persistente y visibilidad desde Prometheus.
func manejarMonitoringDiagnostico(w http.ResponseWriter, r *http.Request) {
	cfg := cargarMonitoring()
	var pet struct {
		Servidor string `json:"servidor"`
	}
	if r.Method == http.MethodPost {
		_ = json.NewDecoder(r.Body).Decode(&pet)
	}
	if strings.TrimSpace(pet.Servidor) == "" {
		responderError(w, fmt.Errorf("selecciona un servidor para diagnosticar"))
		return
	}
	var target *MonitoringTarget
	for i := range cfg.Targets {
		if cfg.Targets[i].Servidor == pet.Servidor {
			target = &cfg.Targets[i]
			break
		}
	}
	if target == nil {
		responderError(w, fmt.Errorf("%s no está monitorizado", pet.Servidor))
		return
	}
	pasos := []map[string]any{}
	mu.Lock()
	conTarget := conexiones[pet.Servidor]
	conMonitor := conexiones[cfg.MonitorServer]
	mu.Unlock()
	sshOK := conTarget != nil
	pasos = append(pasos, map[string]any{"nombre": "SSH", "ok": sshOK})
	nodeOK := false
	if conTarget != nil {
		if c, e := conTarget.cliente.Dial("tcp", "127.0.0.1:9100"); e == nil {
			nodeOK = true
			_ = c.Close()
		}
	}
	pasos = append(pasos, map[string]any{"nombre": "node_exporter", "ok": nodeOK})
	tunnelOK := false
	if conMonitor != nil {
		if c, e := conMonitor.cliente.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", target.LocalPort)); e == nil {
			tunnelOK = true
			_ = c.Close()
		}
	}
	pasos = append(pasos, map[string]any{"nombre": "Túnel SSH", "ok": tunnelOK})
	promOK := false
	if cfg.Preparado {
		if vals, e := monitoringPromQuery(cfg, fmt.Sprintf(`up{server=%q}`, pet.Servidor)); e == nil {
			for _, v := range vals {
				if v.Value > 0 {
					promOK = true
					break
				}
			}
		}
	}
	pasos = append(pasos, map[string]any{"nombre": "Prometheus", "ok": promOK})
	responder(w, map[string]any{"ok": true, "servidor": pet.Servidor, "saludable": sshOK && nodeOK && tunnelOK && promOK, "pasos": pasos})
}
