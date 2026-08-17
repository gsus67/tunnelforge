// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
// ============================================================================
// Conectar Gateway v2 — túneles SSH con interfaz gráfica
// ============================================================================
// Aplicación autocontenida de un solo ejecutable:
//   - Motor SSH propio embebido (golang.org/x/crypto/ssh, librería oficial Go)
//   - Interfaz gráfica servida localmente (se abre sola en el navegador)
//   - Guarda servidores con key SSH o contraseña (cifrada con AES-256-GCM;
//     la llave de cifrado vive en secreto.bin, permisos 0600). Los datos van
//     al perfil del usuario (%APPDATA% / ~/.config), o junto al ejecutable si
//     existe un archivo "portable" a su lado.
//   - Verificación de huella del servidor (TOFU) con confirmación visual
//   - Túneles: 8888 panel · 10086 WGDashboard · 19999 Netdata · 6060/60601
//
// ============================================================================
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const version = "3.2.1"

// Tunel: un puerto que se reenvia del servidor a tu PC, con su nombre.
type Tunel struct {
	Puerto   int    `json:"puerto"`
	Nombre   string `json:"nombre"`
	Ruta     string `json:"ruta,omitempty"`     // ruta para el enlace, ej. "/metrics"
	AbrirWeb bool   `json:"abrirWeb,omitempty"` // abrir automaticamente al conectar
}

// Tuneles por defecto (los del gateway WISP). Se pueden quitar o agregar
// desde la interfaz; quedan guardados en ajustes.json.
func tunelesPorDefecto() []Tunel {
	return []Tunel{
		{Puerto: 8888, Nombre: "Panel"},
		{Puerto: 10086, Nombre: "WGDashboard"},
		{Puerto: 19999, Nombre: "Netdata"},
		{Puerto: 6060, Nombre: "CrowdSec", Ruta: "/metrics"},
		{Puerto: 60601, Nombre: "Bouncer", Ruta: "/metrics"},
	}
}

func cargarTuneles() []Tunel {
	datos, err := os.ReadFile(rutaJunto("ajustes.json"))
	if err != nil {
		return tunelesPorDefecto() // primera vez: los del gateway
	}
	var a struct {
		Tuneles []Tunel `json:"tuneles"`
	}
	if json.Unmarshal(datos, &a) != nil || a.Tuneles == nil {
		return tunelesPorDefecto()
	}
	return a.Tuneles // puede estar vacio a proposito: el usuario los quito todos
}

func guardarTuneles(lista []Tunel) error {
	if lista == nil {
		lista = []Tunel{}
	}
	datos, _ := json.MarshalIndent(map[string]any{"tuneles": lista}, "", "  ")
	return os.WriteFile(rutaJunto("ajustes.json"), datos, 0600)
}

func validarTuneles(lista []Tunel) ([]Tunel, error) {
	validados := make([]Tunel, len(lista))
	copy(validados, lista)
	vistos := map[int]bool{}
	for i := range validados {
		if validados[i].Puerto < 1 || validados[i].Puerto > 65535 {
			return nil, fmt.Errorf("puerto inválido: %d", validados[i].Puerto)
		}
		if vistos[validados[i].Puerto] {
			return nil, fmt.Errorf("puerto repetido: %d", validados[i].Puerto)
		}
		vistos[validados[i].Puerto] = true
		validados[i].Nombre = strings.TrimSpace(validados[i].Nombre)
		if validados[i].Nombre == "" {
			validados[i].Nombre = fmt.Sprintf("Puerto %d", validados[i].Puerto)
		}
		if len(validados[i].Nombre) > 120 {
			return nil, fmt.Errorf("nombre de túnel demasiado largo")
		}
		if len(validados[i].Ruta) > 512 {
			return nil, fmt.Errorf("ruta de túnel demasiado larga")
		}
	}
	return validados, nil
}

//go:embed ui.html
var interfaz embed.FS

//go:embed static
var estaticos embed.FS

// ---------------------------------------------------------------------------
// Modelo y almacenamiento
// ---------------------------------------------------------------------------
type Servidor struct {
	Nombre   string  `json:"nombre"`
	Host     string  `json:"host"`
	Puerto   int     `json:"puerto"`
	Usuario  string  `json:"usuario"`
	Key      string  `json:"key,omitempty"`
	PassCifr string  `json:"passwordCifrada,omitempty"`
	Huella   string  `json:"huella,omitempty"`
	Favorito bool    `json:"favorito,omitempty"`
	Tuneles  []Tunel `json:"tuneles"`
}

var (
	mu      sync.Mutex
	baseDir string
)

func rutaJunto(nombre string) string { return filepath.Join(baseDir, nombre) }

func cargar() []Servidor {
	var lista []Servidor
	if datos, err := os.ReadFile(rutaJunto("conexiones.json")); err == nil {
		_ = json.Unmarshal(datos, &lista)
	}
	return lista
}
func guardar(lista []Servidor) error {
	datos, _ := json.MarshalIndent(lista, "", "  ")
	return os.WriteFile(rutaJunto("conexiones.json"), datos, 0600)
}
func buscar(lista []Servidor, nombre string) *Servidor {
	for i := range lista {
		if lista[i].Nombre == nombre {
			return &lista[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Cifrado de contraseñas guardadas (AES-256-GCM, secreto local)
// ---------------------------------------------------------------------------
func secreto() ([]byte, error) {
	ruta := rutaJunto("secreto.bin")
	if s, err := os.ReadFile(ruta); err == nil && len(s) == 32 {
		return s, nil
	}
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	if err := os.WriteFile(ruta, s, 0600); err != nil {
		return nil, err
	}
	return s, nil
}

func cifrar(texto string) (string, error) {
	clave, err := secreto()
	if err != nil {
		return "", err
	}
	bloque, _ := aes.NewCipher(clave)
	gcm, _ := cipher.NewGCM(bloque)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(texto), nil)), nil
}

func descifrar(cifrado string) (string, error) {
	clave, err := secreto()
	if err != nil {
		return "", err
	}
	datos, err := base64.StdEncoding.DecodeString(cifrado)
	if err != nil {
		return "", err
	}
	bloque, _ := aes.NewCipher(clave)
	gcm, _ := cipher.NewGCM(bloque)
	if len(datos) < gcm.NonceSize() {
		return "", fmt.Errorf("dato corrupto")
	}
	plano, err := gcm.Open(nil, datos[:gcm.NonceSize()], datos[gcm.NonceSize():], nil)
	return string(plano), err
}

// ---------------------------------------------------------------------------
// Conexión activa y túneles
// ---------------------------------------------------------------------------
type Conexion struct {
	cliente  *ssh.Client
	escuchas map[int]net.Listener // puerto local -> escucha actualmente asignada a este servidor
	servidor string
	desde    time.Time
	tuneles  []Tunel
	rx, tx   int64        // bytes de los túneles (atomic); se conserva como respaldo
	sftp     *sftp.Client // canal SFTP (perezoso: solo si se usa el gestor)
	sftpMu   sync.Mutex   // evita abrir dos canales SFTP simultáneos
	done     chan struct{}

	traficoMu         sync.RWMutex
	traficoRXBps      int64 // tráfico real de la interfaz principal del servidor
	traficoTXBps      int64
	traficoRXTotal    int64
	traficoTXTotal    int64
	traficoInterfaz   string
	traficoDisponible bool
}

// Varias conexiones simultáneas a distintos servidores. Los puertos locales
// compartidos se asignan al servidor marcado como destino de localhost.
var (
	conexiones        = map[string]*Conexion{}
	conectando        = map[string]bool{}
	servidorLocalhost string
)

func tieneTunel(c *Conexion, puerto int) bool {
	for _, t := range c.tuneles {
		if t.Puerto == puerto {
			return true
		}
	}
	return false
}

func conexionAntes(a, b *Conexion) bool {
	if b == nil {
		return true
	}
	if a.desde.Equal(b.desde) {
		return strings.ToLower(a.servidor) < strings.ToLower(b.servidor)
	}
	return a.desde.Before(b.desde)
}

func conexionMasAntiguaLocked() *Conexion {
	var elegida *Conexion
	for _, c := range conexiones {
		if conexionAntes(c, elegida) {
			elegida = c
		}
	}
	return elegida
}

func propietarioPuertoLocked(puerto int) *Conexion {
	if seleccionada := conexiones[servidorLocalhost]; seleccionada != nil && tieneTunel(seleccionada, puerto) {
		return seleccionada
	}
	var elegida *Conexion
	for _, c := range conexiones {
		if tieneTunel(c, puerto) && conexionAntes(c, elegida) {
			elegida = c
		}
	}
	return elegida
}

func puertosAbiertosLocked(c *Conexion) []int {
	puertos := make([]int, 0, len(c.escuchas))
	for _, t := range c.tuneles {
		if _, ok := c.escuchas[t.Puerto]; ok {
			puertos = append(puertos, t.Puerto)
		}
	}
	return puertos
}

func iniciarEscuchaTunelLocked(c *Conexion, puerto int) error {
	if c.escuchas == nil {
		c.escuchas = make(map[int]net.Listener)
	}
	if _, existe := c.escuchas[puerto]; existe {
		return nil
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", puerto))
	if err != nil {
		return err
	}
	c.escuchas[puerto] = l
	go func(l net.Listener, con *Conexion, p int) {
		for {
			local, err := l.Accept()
			if err != nil {
				return
			}
			go puente(local, con.cliente, p, &con.rx, &con.tx)
		}
	}(l, c, puerto)
	return nil
}

// reasignarPuertosLocked mantiene una única escucha local por puerto. Si el
// usuario selecciona otro servidor para localhost, las nuevas conexiones a
// localhost:puerto empiezan a viajar por ese servidor sin reconectarlo.
func reasignarPuertosLocked() {
	if len(conexiones) == 0 {
		servidorLocalhost = ""
		return
	}
	if conexiones[servidorLocalhost] == nil {
		if c := conexionMasAntiguaLocked(); c != nil {
			servidorLocalhost = c.servidor
		}
	}

	puertos := map[int]bool{}
	for _, c := range conexiones {
		for _, t := range c.tuneles {
			puertos[t.Puerto] = true
		}
	}
	deseado := make(map[int]*Conexion, len(puertos))
	for p := range puertos {
		deseado[p] = propietarioPuertoLocked(p)
	}

	// Primero soltamos los puertos que cambian de propietario.
	for _, c := range conexiones {
		for p, l := range c.escuchas {
			if deseado[p] != c {
				_ = l.Close()
				delete(c.escuchas, p)
			}
		}
	}

	// Después abrimos los puertos en su propietario deseado. Si otro programa
	// del equipo ocupa el puerto, simplemente queda no disponible.
	listaPuertos := make([]int, 0, len(deseado))
	for p := range deseado {
		listaPuertos = append(listaPuertos, p)
	}
	sort.Ints(listaPuertos)
	for _, p := range listaPuertos {
		owner := deseado[p]
		if owner == nil {
			continue
		}
		if _, ok := owner.escuchas[p]; !ok {
			_ = iniciarEscuchaTunelLocked(owner, p)
		}
	}
}

func detenerConexionLocked(c *Conexion) {
	for p, l := range c.escuchas {
		_ = l.Close()
		delete(c.escuchas, p)
	}
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	c.sftpMu.Lock()
	if c.sftp != nil {
		_ = c.sftp.Close()
		c.sftp = nil
	}
	c.sftpMu.Unlock()
	_ = c.cliente.Close()
}

// cerrarConexion se llama con mu bloqueado.
func cerrarConexion(nombre string) {
	c, ok := conexiones[nombre]
	if !ok {
		return
	}
	detenerConexionLocked(c)
	delete(conexiones, nombre)
	if servidorLocalhost == nombre {
		servidorLocalhost = ""
	}
	reasignarPuertosLocked()
}

// cerrarTodas se llama con mu bloqueado.
func cerrarTodas() {
	for _, c := range conexiones {
		detenerConexionLocked(c)
	}
	conexiones = map[string]*Conexion{}
	servidorLocalhost = ""
}

// contador: envoltorio que suma a un contador atomico cada byte que pasa
type contador struct {
	io.Writer
	n *int64
}

func (c *contador) Write(p []byte) (int, error) {
	n, err := c.Writer.Write(p)
	atomic.AddInt64(c.n, int64(n))
	return n, err
}

func puente(local net.Conn, cliente *ssh.Client, puerto int, rx, tx *int64) {
	remoto, err := cliente.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", puerto))
	if err != nil {
		local.Close()
		return
	}
	// rx = lo que baja el cliente local (viene del servidor); tx = lo que sube
	go func() { _, _ = io.Copy(&contador{remoto, tx}, local); remoto.Close() }()
	_, _ = io.Copy(&contador{local, rx}, remoto)
	local.Close()
}

// leerContadoresRed obtiene los contadores de la interfaz con ruta por defecto.
// Son lecturas mínimas de sysfs; no generan tráfico de Internet ni hacen tests.
func leerContadoresRed(c *Conexion) (string, int64, int64, error) {
	sesion, err := c.cliente.NewSession()
	if err != nil {
		return "", 0, 0, err
	}
	defer sesion.Close()
	cmd := `IF=$(awk '$2=="00000000"{print $1; exit}' /proc/net/route 2>/dev/null); if [ -z "$IF" ]; then IF=$(ls /sys/class/net 2>/dev/null | grep -v '^lo$' | head -n1); fi; RX=$(cat "/sys/class/net/$IF/statistics/rx_bytes" 2>/dev/null); TX=$(cat "/sys/class/net/$IF/statistics/tx_bytes" 2>/dev/null); printf '%s %s %s\n' "$IF" "$RX" "$TX"`
	type salida struct {
		datos []byte
		err   error
	}
	ch := make(chan salida, 1)
	go func() {
		datos, e := sesion.Output(cmd)
		ch <- salida{datos: datos, err: e}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return "", 0, 0, r.err
		}
		var interfaz string
		var rx, tx int64
		if _, err := fmt.Sscanf(strings.TrimSpace(string(r.datos)), "%s %d %d", &interfaz, &rx, &tx); err != nil || interfaz == "" {
			return "", 0, 0, fmt.Errorf("no pude leer contadores de red")
		}
		return interfaz, rx, tx, nil
	case <-time.After(2500 * time.Millisecond):
		_ = sesion.Close()
		return "", 0, 0, fmt.Errorf("timeout leyendo tráfico")
	}
}

func monitorTraficoServidor(c *Conexion) {
	const intervalo = 3 * time.Second
	var prevRX, prevTX int64
	var prevInterfaz string
	var prevTime time.Time
	fallos := 0

	muestrear := func() {
		interfaz, rx, tx, err := leerContadoresRed(c)
		if err != nil {
			fallos++
			if fallos >= 2 {
				c.traficoMu.Lock()
				c.traficoDisponible = false
				c.traficoRXBps = 0
				c.traficoTXBps = 0
				c.traficoMu.Unlock()
			}
			return
		}
		fallos = 0
		ahora := time.Now()
		var rxBps, txBps int64
		if !prevTime.IsZero() && interfaz == prevInterfaz {
			dt := ahora.Sub(prevTime).Seconds()
			if dt > 0 && rx >= prevRX && tx >= prevTX {
				rxBps = int64(float64(rx-prevRX) / dt)
				txBps = int64(float64(tx-prevTX) / dt)
			}
		}
		prevRX, prevTX, prevInterfaz, prevTime = rx, tx, interfaz, ahora
		c.traficoMu.Lock()
		c.traficoRXBps = rxBps
		c.traficoTXBps = txBps
		c.traficoRXTotal = rx
		c.traficoTXTotal = tx
		c.traficoInterfaz = interfaz
		c.traficoDisponible = true
		c.traficoMu.Unlock()
	}

	muestrear()
	ticker := time.NewTicker(intervalo)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			muestrear()
		case <-c.done:
			return
		}
	}
}

func conectar(s *Servidor, password string, aceptarHuella bool) (map[string]any, error) {
	// ---- autenticación ----
	var auth []ssh.AuthMethod
	if s.Key != "" {
		// la passphrase puede venir en esta peticion, o guardada cifrada
		frase := password
		if frase == "" && s.PassCifr != "" {
			if p, err := descifrar(s.PassCifr); err == nil {
				frase = p
			}
		}
		firmante, necesita, err := cargarFirmante(s.Key, frase)
		if err != nil {
			return nil, err
		}
		if necesita {
			return map[string]any{"necesitaPassphrase": true}, nil
		}
		auth = append(auth, ssh.PublicKeys(firmante))
	} else {
		pass := password
		if pass == "" && s.PassCifr != "" {
			var err error
			if pass, err = descifrar(s.PassCifr); err != nil {
				return nil, fmt.Errorf("no pude descifrar la contraseña guardada")
			}
		}
		if pass == "" {
			return map[string]any{"necesitaPassword": true}, nil
		}
		auth = append(auth,
			ssh.Password(pass),
			ssh.KeyboardInteractive(func(_, _ string, pregs []string, _ []bool) ([]string, error) {
				r := make([]string, len(pregs))
				for i := range r {
					r[i] = pass
				}
				return r, nil
			}))
	}

	// ---- verificación de huella (TOFU) ----
	var huellaVista string
	huellaOriginal := s.Huella
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		huellaVista = ssh.FingerprintSHA256(key)
		if s.Huella == "" {
			if aceptarHuella {
				s.Huella = huellaVista
				return nil
			}
			return fmt.Errorf("confirmar-huella")
		}
		if s.Huella != huellaVista {
			return fmt.Errorf("¡la huella del servidor CAMBIÓ! Guardada %s, recibida %s. Posible suplantación; si reinstalaste el VPS, borra y re-agrega el servidor", s.Huella, huellaVista)
		}
		return nil
	}

	config := &ssh.ClientConfig{User: s.Usuario, Auth: auth, HostKeyCallback: callback, Timeout: 12 * time.Second}
	cliente, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Puerto), config)
	if err != nil {
		if huellaVista != "" && s.Huella == "" && !aceptarHuella {
			return map[string]any{"confirmarHuella": huellaVista}, nil
		}
		return nil, err
	}

	if huellaOriginal == "" && aceptarHuella && huellaVista != "" {
		mu.Lock()
		actuales := cargar()
		if actual := buscar(actuales, s.Nombre); actual != nil && actual.Huella == "" {
			actual.Huella = huellaVista
			_ = guardar(actuales)
		}
		mu.Unlock()
	}

	// ---- túneles locales ----
	tuneles := s.Tuneles
	if tuneles == nil {
		mu.Lock()
		tuneles = cargarTuneles() // compatibilidad con perfiles de versiones anteriores
		mu.Unlock()
	}
	con := &Conexion{
		cliente:  cliente,
		servidor: s.Nombre,
		desde:    time.Now(),
		tuneles:  append([]Tunel(nil), tuneles...),
		escuchas: make(map[int]net.Listener),
		done:     make(chan struct{}),
	}

	go func() { // keepalive
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if _, _, err := cliente.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}()
	mu.Lock()
	if anterior := conexiones[con.servidor]; anterior != nil {
		mu.Unlock()
		_ = cliente.Close()
		return nil, fmt.Errorf("ya estás conectado a '%s'", con.servidor)
	}
	conexiones[con.servidor] = con
	if servidorLocalhost == "" {
		servidorLocalhost = con.servidor
	}
	reasignarPuertosLocked()
	abiertos := puertosAbiertosLocked(con)
	sinTuneles := len(abiertos) == 0
	abiertosSet := map[int]bool{}
	for _, p := range abiertos {
		abiertosSet[p] = true
	}
	var omitidos []int
	for _, t := range con.tuneles {
		if !abiertosSet[t.Puerto] {
			omitidos = append(omitidos, t.Puerto)
		}
	}
	mu.Unlock()

	go monitorTraficoServidor(con)
	go func() { // detectar caída de la sesión
		_ = cliente.Wait()
		mu.Lock()
		if conexiones[con.servidor] == con {
			cerrarConexion(con.servidor)
		}
		mu.Unlock()
	}()

	resultado := map[string]any{"ok": true, "puertos": abiertos, "sinTuneles": sinTuneles}
	var abrir []string
	for _, t := range con.tuneles {
		if t.AbrirWeb && abiertosSet[t.Puerto] {
			abrir = append(abrir, fmt.Sprintf("http://localhost:%d%s", t.Puerto, t.Ruta))
		}
	}
	if len(abrir) > 0 {
		resultado["abrirWeb"] = abrir
	}
	if len(omitidos) > 0 {
		resultado["puertosOmitidos"] = omitidos
	}
	return resultado, nil
}

// ---------------------------------------------------------------------------
// API HTTP local
// ---------------------------------------------------------------------------
func decodificar(r *http.Request, destino any) error {
	return json.NewDecoder(r.Body).Decode(destino)
}

func responder(w http.ResponseWriter, datos any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(datos)
}
func responderError(w http.ResponseWriter, err error) {
	responder(w, map[string]string{"error": err.Error()})
}

func main() {
	if manejarModoActualizador() {
		return
	}
	limpiarBackupActualizacion()
	for _, a := range os.Args[1:] {
		if a == "--version" || a == "-v" {
			fmt.Println("conectar-gateway", version)
			return
		}
	}
	exe, _ := os.Executable()
	dirExe := filepath.Dir(exe)

	// Datos en el perfil del usuario (sobreviven aunque muevas el .exe).
	// Modo portable: si existe un archivo "portable" junto al .exe, los
	// datos viven junto al .exe (util para llevarlo en el NAS/USB).
	if _, err := os.Stat(filepath.Join(dirExe, "portable")); err == nil {
		baseDir = dirExe
	} else if cfg, err := os.UserConfigDir(); err == nil {
		baseDir = filepath.Join(cfg, "conectar-gateway")
		_ = os.MkdirAll(baseDir, 0700)
		// Migracion: si hay datos de versiones viejas junto al .exe, traerlos
		for _, f := range []string{"conexiones.json", "secreto.bin"} {
			viejoF := filepath.Join(dirExe, f)
			nuevoF := filepath.Join(baseDir, f)
			if _, err := os.Stat(nuevoF); os.IsNotExist(err) {
				if datos, err := os.ReadFile(viejoF); err == nil {
					_ = os.WriteFile(nuevoF, datos, 0600)
				}
			}
		}
	} else {
		baseDir = dirExe
	}

	token := os.Getenv("CG_TOKEN")
	if token == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		token = hex.EncodeToString(b)
	}
	puertoGUI := os.Getenv("CG_PORT")
	if puertoGUI == "" {
		puertoGUI = "8787" // puerto fijo de la interfaz (URL estable)
	}

	mux := http.NewServeMux()
	proteger := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("t") != token && r.Header.Get("X-Token") != token {
				http.Error(w, "no autorizado", 403)
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("/", proteger(func(w http.ResponseWriter, r *http.Request) {
		datos, _ := interfaz.ReadFile("ui.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(datos)
	}))

	// Recursos estaticos del terminal (xterm.js) — sin token: solo assets
	mux.Handle("/static/", http.FileServer(http.FS(estaticos)))
	// Terminal SSH integrado (WebSocket, protegido por token)
	mux.HandleFunc("/ws/terminal", proteger(manejarTerminal))

	mux.HandleFunc("/api/servidores", proteger(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			lista := cargar()
			salida := make([]map[string]any, 0, len(lista))
			for _, s := range lista {
				salida = append(salida, map[string]any{
					"nombre": s.Nombre, "host": s.Host, "puerto": s.Puerto,
					"usuario": s.Usuario, "key": s.Key,
					"tienePassword": s.PassCifr != "", "confiado": s.Huella != "",
					"favorito": s.Favorito, "tuneles": func() []Tunel {
						if s.Tuneles != nil {
							return s.Tuneles
						}
						return cargarTuneles()
					}(),
				})
			}
			responder(w, salida)
		case "POST":
			var pet struct {
				Nombre, Host, Usuario, Key, Password string
				Puerto                               int
				GuardarPassword                      bool
				Favorito                             *bool // puntero: distinguir "no lo mandó" de "false"
				Tuneles                              *[]Tunel
			}
			if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
				responderError(w, err)
				return
			}
			if pet.Nombre == "" || pet.Host == "" || pet.Usuario == "" {
				responderError(w, fmt.Errorf("nombre, host y usuario son obligatorios"))
				return
			}
			if pet.Puerto == 0 {
				pet.Puerto = 22
			}
			lista := cargar()
			s := buscar(lista, pet.Nombre)
			if s == nil {
				lista = append(lista, Servidor{Nombre: pet.Nombre})
				s = &lista[len(lista)-1]
			}
			s.Host, s.Puerto, s.Usuario = pet.Host, pet.Puerto, pet.Usuario
			s.Key = normalizarRuta(pet.Key)
			if pet.Favorito != nil {
				s.Favorito = *pet.Favorito
			}
			if pet.Tuneles != nil {
				validados, err := validarTuneles(*pet.Tuneles)
				if err != nil {
					responderError(w, err)
					return
				}
				s.Tuneles = validados
			}
			if pet.GuardarPassword && pet.Password != "" {
				c, err := cifrar(pet.Password)
				if err != nil {
					responderError(w, err)
					return
				}
				s.PassCifr = c
			} else if !pet.GuardarPassword {
				s.PassCifr = ""
			}
			if err := guardar(lista); err != nil {
				responderError(w, fmt.Errorf("no pude guardar: %v", err))
				return
			}
			responder(w, map[string]any{"ok": true})
		case "DELETE":
			nombre := r.URL.Query().Get("nombre")
			lista := cargar()
			nueva := lista[:0]
			for _, s := range lista {
				if s.Nombre != nombre {
					nueva = append(nueva, s)
				}
			}
			if err := guardar(nueva); err != nil {
				responderError(w, fmt.Errorf("no pude guardar: %v", err))
				return
			}
			responder(w, map[string]any{"ok": true})
		}
	}))

	mux.HandleFunc("/api/tuneles", proteger(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			responder(w, cargarTuneles())
		case "POST":
			var lista []Tunel
			if err := json.NewDecoder(r.Body).Decode(&lista); err != nil {
				responderError(w, err)
				return
			}
			validada, err := validarTuneles(lista)
			if err != nil {
				responderError(w, err)
				return
			}
			if err := guardarTuneles(validada); err != nil {
				responderError(w, fmt.Errorf("no pude guardar: %v", err))
				return
			}
			responder(w, map[string]any{"ok": true, "aviso": len(conexiones) > 0})
		case "DELETE": // restaurar los de fábrica
			if err := guardarTuneles(tunelesPorDefecto()); err != nil {
				responderError(w, err)
				return
			}
			responder(w, cargarTuneles())
		}
	}))

	mux.HandleFunc("/api/exportar", proteger(manejarExportar))
	mux.HandleFunc("/api/importar", proteger(manejarImportar))
	mux.HandleFunc("/api/historial", proteger(manejarHistorial))
	mux.HandleFunc("/api/version", proteger(manejarVersion))
	mux.HandleFunc("/api/actualizaciones", proteger(manejarActualizaciones))
	mux.HandleFunc("/api/probar-key", proteger(manejarProbarKey))
	mux.HandleFunc("/api/crear-instalar-key", proteger(manejarCrearInstalarKey))
	mux.HandleFunc("/api/asegurar-ssh", proteger(manejarAsegurarSSH))
	mux.HandleFunc("/api/ssh-seguridad/estado", proteger(manejarEstadoSeguridadSSH))
	mux.HandleFunc("/api/ssh-seguridad/permitir-password", proteger(manejarPermitirPasswordSSH))
	mux.HandleFunc("/api/archivos", proteger(manejarArchivos))
	mux.HandleFunc("/api/archivos/descargar", proteger(manejarDescargar))
	mux.HandleFunc("/api/archivos/subir", proteger(manejarSubir))
	mux.HandleFunc("/api/local", proteger(manejarLocal))
	mux.HandleFunc("/api/herramientas/ejecutar-script", proteger(manejarEjecutarScript))
	mux.HandleFunc("/api/herramientas/test-velocidad", proteger(manejarTestVelocidad))
	mux.HandleFunc("/api/herramientas/firewall", proteger(manejarFirewall))
	mux.HandleFunc("/api/herramientas/crear-key", proteger(manejarToolCrearKey))
	mux.HandleFunc("/api/herramientas/usar-key", proteger(manejarToolUsarKey))
	mux.HandleFunc("/api/herramientas/cambiar-puerto-ssh", proteger(manejarToolCambiarPuertoSSH))
	mux.HandleFunc("/api/herramientas/ssh-puerto/probar", proteger(manejarToolPuertoSSHProbar))
	mux.HandleFunc("/api/herramientas/ssh-puerto/aplicar", proteger(manejarToolPuertoSSHAplicar))
	mux.HandleFunc("/api/herramientas/ssh-puerto/cancelar", proteger(manejarToolPuertoSSHCancelar))
	mux.HandleFunc("/api/herramientas/gateway-wisp/preparar", proteger(manejarGatewayWISPPreparar))
	mux.HandleFunc("/api/herramientas/gateway-wisp/comando", proteger(manejarGatewayWISPComando))
	mux.HandleFunc("/api/herramientas/gateway-wisp/estado", proteger(manejarGatewayWISPEstado))
	mux.HandleFunc("/api/monitoring/estado", proteger(manejarMonitoringEstado))
	mux.HandleFunc("/api/monitoring/config", proteger(manejarMonitoringConfig))
	mux.HandleFunc("/api/monitoring/preparar", proteger(manejarMonitoringPreparar))
	mux.HandleFunc("/api/monitoring/targets", proteger(manejarMonitoringTargets))
	mux.HandleFunc("/api/monitoring/credenciales", proteger(manejarMonitoringCredenciales))
	mux.HandleFunc("/api/monitoring/progreso", proteger(manejarMonitoringProgreso))
	mux.HandleFunc("/api/monitoring/peers", proteger(manejarMonitoringPeers))
	mux.HandleFunc("/api/monitoring/diagnostico", proteger(manejarMonitoringDiagnostico))
	mux.HandleFunc("/monitor/grafana/", crearGrafanaProxy(token))

	// Reordenar servidores (arrastrar en la interfaz): recibe la lista de
	// nombres en el nuevo orden y reescribe el archivo respetando ese orden.
	mux.HandleFunc("/api/servidores/orden", proteger(func(w http.ResponseWriter, r *http.Request) {
		var nombres []string
		if err := json.NewDecoder(r.Body).Decode(&nombres); err != nil {
			responderError(w, err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		actuales := cargar()
		indice := map[string]Servidor{}
		for _, s := range actuales {
			indice[s.Nombre] = s
		}
		var reordenados []Servidor
		vistos := map[string]bool{}
		for _, n := range nombres {
			if sv, ok := indice[n]; ok && !vistos[n] {
				reordenados = append(reordenados, sv)
				vistos[n] = true
			}
		}
		// cualquier servidor que no vino en la lista (por si acaso) se agrega al final
		for _, sv := range actuales {
			if !vistos[sv.Nombre] {
				reordenados = append(reordenados, sv)
			}
		}
		if err := guardar(reordenados); err != nil {
			responderError(w, err)
			return
		}
		responder(w, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/conectar", proteger(func(w http.ResponseWriter, r *http.Request) {
		var pet struct {
			Nombre, Password string
			AceptarHuella    bool
		}
		if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
			responderError(w, err)
			return
		}
		mu.Lock()
		if _, ya := conexiones[pet.Nombre]; ya || conectando[pet.Nombre] {
			mu.Unlock()
			responderError(w, fmt.Errorf("ya estás conectado o conectando a '%s'", pet.Nombre))
			return
		}
		lista := cargar()
		s := buscar(lista, pet.Nombre)
		if s == nil {
			mu.Unlock()
			responderError(w, fmt.Errorf("servidor no encontrado"))
			return
		}
		copiaServidor := *s
		conectando[pet.Nombre] = true
		mu.Unlock()
		defer func() {
			mu.Lock()
			delete(conectando, pet.Nombre)
			mu.Unlock()
		}()

		res, err := conectar(&copiaServidor, pet.Password, pet.AceptarHuella)
		if err != nil {
			responderError(w, err)
			return
		}
		responder(w, res)
	}))

	mux.HandleFunc("/api/desconectar", proteger(func(w http.ResponseWriter, r *http.Request) {
		var pet struct{ Nombre string }
		_ = json.NewDecoder(r.Body).Decode(&pet)
		mu.Lock()
		if pet.Nombre == "" {
			cerrarTodas()
		} else {
			cerrarConexion(pet.Nombre)
		}
		mu.Unlock()
		responder(w, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/localhost-servidor", proteger(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var pet struct{ Nombre string }
		if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
			responderError(w, err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if conexiones[pet.Nombre] == nil {
			responderError(w, fmt.Errorf("servidor no conectado"))
			return
		}
		servidorLocalhost = pet.Nombre
		reasignarPuertosLocked()
		responder(w, map[string]any{
			"ok": true, "servidor": servidorLocalhost,
			"puertos": puertosAbiertosLocked(conexiones[servidorLocalhost]),
		})
	}))

	mux.HandleFunc("/api/estado", proteger(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		// También reintenta puertos que pudieran haber estado ocupados temporalmente.
		reasignarPuertosLocked()
		type conexionEstado struct {
			nombre string
			con    *Conexion
		}
		ordenadas := make([]conexionEstado, 0, len(conexiones))
		for nombre, c := range conexiones {
			ordenadas = append(ordenadas, conexionEstado{nombre: nombre, con: c})
		}
		sort.SliceStable(ordenadas, func(i, j int) bool {
			a, b := ordenadas[i], ordenadas[j]
			if a.con.desde.Equal(b.con.desde) {
				return strings.ToLower(a.nombre) < strings.ToLower(b.nombre)
			}
			return a.con.desde.Before(b.con.desde)
		})

		lista := make([]map[string]any, 0, len(ordenadas))
		for _, item := range ordenadas {
			nombre, c := item.nombre, item.con
			puertos := puertosAbiertosLocked(c)
			c.traficoMu.RLock()
			traficoRXBps := c.traficoRXBps
			traficoTXBps := c.traficoTXBps
			traficoRXTotal := c.traficoRXTotal
			traficoTXTotal := c.traficoTXTotal
			traficoInterfaz := c.traficoInterfaz
			traficoDisponible := c.traficoDisponible
			c.traficoMu.RUnlock()
			lista = append(lista, map[string]any{
				"servidor": nombre,
				"puertos":  puertos,
				"tuneles":  c.tuneles,
				"desde":    c.desde.Format("15:04:05"),
				"rx":       atomic.LoadInt64(&c.rx), "tx": atomic.LoadInt64(&c.tx),
				"traficoRxBps": traficoRXBps, "traficoTxBps": traficoTXBps,
				"traficoRxTotal": traficoRXTotal, "traficoTxTotal": traficoTXTotal,
				"traficoInterfaz": traficoInterfaz, "traficoDisponible": traficoDisponible,
				"localhost": nombre == servidorLocalhost,
			})
		}
		responder(w, map[string]any{
			"conectado": len(lista) > 0, "conexiones": lista, "version": version,
			"localhostSeleccionado": servidorLocalhost,
		})
	}))

	// Abre una URL en el navegador POR DEFECTO del sistema.
	// Solo se permiten URLs locales (los tuneles): nada de destinos externos.
	mux.HandleFunc("/api/abrir", proteger(func(w http.ResponseWriter, r *http.Request) {
		var pet struct{ URL string }
		if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
			responderError(w, err)
			return
		}
		u, err := neturl.Parse(pet.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			responderError(w, fmt.Errorf("URL no válida"))
			return
		}
		anfitrion := u.Hostname()
		permitido := anfitrion == "localhost" || anfitrion == "127.0.0.1" || anfitrion == "::1"
		// ademas, los enlaces de creditos de la propia interfaz
		for _, d := range []string{"github.com", "pkg.go.dev"} {
			if anfitrion == d || strings.HasSuffix(anfitrion, "."+d) {
				permitido = true
			}
		}
		if !permitido {
			responderError(w, fmt.Errorf("destino no permitido"))
			return
		}
		abrirNavegador(u.String())
		responder(w, map[string]any{"ok": true})
	}))

	escucha, err := net.Listen("tcp", "127.0.0.1:"+puertoGUI)
	if err != nil {
		// Puerto fijo ocupado: probablemente ya hay una instancia corriendo.
		// Reutilizamos su sesion guardada y abrimos su interfaz, en vez de
		// dejar una segunda copia dando vueltas.
		if datos, e := os.ReadFile(filepath.Join(baseDir, "sesion")); e == nil && len(datos) > 0 {
			mostrarVentana(fmt.Sprintf("http://127.0.0.1:%s/?t=%s", puertoGUI, string(datos)))
			os.Exit(0)
		}
		escucha, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("ERROR: no pude abrir el puerto de la interfaz:", err)
			os.Exit(1)
		}
	} else {
		// Dejar el token para que una segunda ejecucion abra esta misma sesion
		_ = os.WriteFile(filepath.Join(baseDir, "sesion"), []byte(token), 0600)
		defer os.Remove(filepath.Join(baseDir, "sesion"))
	}
	url := fmt.Sprintf("http://%s/?t=%s", escucha.Addr().String(), token)
	fmt.Println("Interfaz en:", url)
	go func() { _ = http.Serve(escucha, mux) }()

	if os.Getenv("CG_NO_BROWSER") != "" {
		select {} // modo servicio (pruebas): solo la API
	}
	mostrarVentana(url) // ventana nativa en Windows; navegador en otros

	// Ventana cerrada: cerrar tuneles y terminar el proceso de verdad.
	// Sin el Exit, el servidor HTTP y las goroutines seguirian vivos y
	// Windows no dejaria borrar/mover/renombrar el ejecutable.
	mu.Lock()
	cerrarTodas()
	mu.Unlock()
	_ = escucha.Close()
	os.Exit(0)
}

func abrirNavegador(url string) {
	switch runtime.GOOS {
	case "windows":
		// "start" respeta el navegador por defecto del usuario
		if exec.Command("cmd", "/c", "start", "", url).Start() != nil {
			_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		}
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}
