// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
// ============================================================================
// Conectar Gateway v2 — túneles SSH con interfaz gráfica
// ============================================================================
// Aplicación autocontenida de un solo ejecutable:
//   - Motor SSH propio embebido (golang.org/x/crypto/ssh, librería oficial Go)
//   - Interfaz gráfica servida localmente (se abre sola en el navegador)
//   - Guarda servidores con key SSH o contraseña (cifrada con AES-256-GCM;
//     la llave de cifrado vive en secreto.bin junto al ejecutable, 0600)
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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const version = "2.3.1"

// Tunel: un puerto que se reenvia del servidor a tu PC, con su nombre.
type Tunel struct {
	Puerto int    `json:"puerto"`
	Nombre string `json:"nombre"`
	Ruta   string `json:"ruta,omitempty"` // ruta para el enlace, ej. "/metrics"
}

// Tuneles por defecto (los del gateway WISP). Se pueden quitar o agregar
// desde la interfaz; quedan guardados en ajustes.json.
func tunelesPorDefecto() []Tunel {
	return []Tunel{
		{8888, "Panel", ""},
		{10086, "WGDashboard", ""},
		{19999, "Netdata", ""},
		{6060, "CrowdSec", "/metrics"},
		{60601, "Bouncer", "/metrics"},
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

//go:embed ui.html
var interfaz embed.FS

//go:embed static
var estaticos embed.FS

// ---------------------------------------------------------------------------
// Modelo y almacenamiento
// ---------------------------------------------------------------------------
type Servidor struct {
	Nombre   string `json:"nombre"`
	Host     string `json:"host"`
	Puerto   int    `json:"puerto"`
	Usuario  string `json:"usuario"`
	Key      string `json:"key,omitempty"`
	PassCifr string `json:"passwordCifrada,omitempty"`
	Huella   string `json:"huella,omitempty"`
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
	escuchas []net.Listener
	servidor string
	desde    time.Time
	abiertos []int
}

var activa *Conexion

func cerrarActiva() {
	if activa == nil {
		return
	}
	for _, l := range activa.escuchas {
		l.Close()
	}
	activa.cliente.Close()
	activa = nil
}

func puente(local net.Conn, cliente *ssh.Client, puerto int) {
	remoto, err := cliente.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", puerto))
	if err != nil {
		local.Close()
		return
	}
	go func() { _, _ = io.Copy(remoto, local); remoto.Close() }()
	_, _ = io.Copy(local, remoto)
	local.Close()
}

func conectar(s *Servidor, lista []Servidor, password string, aceptarHuella bool) (map[string]any, error) {
	// ---- autenticación ----
	var auth []ssh.AuthMethod
	if s.Key != "" {
		datos, err := os.ReadFile(s.Key)
		if err != nil {
			return nil, fmt.Errorf("no pude leer la key: %v", err)
		}
		firmante, err := ssh.ParsePrivateKey(datos)
		if err != nil {
			return nil, fmt.Errorf("key inválida o con passphrase (usa una key sin passphrase, o contraseña): %v", err)
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
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		huellaVista = ssh.FingerprintSHA256(key)
		if s.Huella == "" {
			if aceptarHuella {
				s.Huella = huellaVista
				_ = guardar(lista)
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

	// ---- túneles locales ----
	con := &Conexion{cliente: cliente, servidor: s.Nombre, desde: time.Now()}
	for _, t := range cargarTuneles() {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", t.Puerto))
		if err != nil {
			continue // puerto local ocupado: se omite ese túnel
		}
		con.escuchas = append(con.escuchas, l)
		con.abiertos = append(con.abiertos, t.Puerto)
		go func(l net.Listener, puerto int) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go puente(c, cliente, puerto)
			}
		}(l, t.Puerto)
	}
	if len(con.escuchas) == 0 {
		cliente.Close()
		return nil, fmt.Errorf("ningún túnel pudo abrirse (¿puertos locales ocupados, o no hay túneles configurados?)")
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
	go func() { // detectar caída de la sesión
		_ = cliente.Wait()
		mu.Lock()
		if activa == con {
			for _, l := range con.escuchas {
				l.Close()
			}
			activa = nil
		}
		mu.Unlock()
	}()

	activa = con
	return map[string]any{"ok": true, "puertos": con.abiertos}, nil
}

// ---------------------------------------------------------------------------
// API HTTP local
// ---------------------------------------------------------------------------
func responder(w http.ResponseWriter, datos any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(datos)
}
func responderError(w http.ResponseWriter, err error) {
	responder(w, map[string]string{"error": err.Error()})
}

func main() {
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
				})
			}
			responder(w, salida)
		case "POST":
			var pet struct {
				Nombre, Host, Usuario, Key, Password string
				Puerto                               int
				GuardarPassword                      bool
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
			s.Host, s.Puerto, s.Usuario, s.Key = pet.Host, pet.Puerto, pet.Usuario, pet.Key
			if pet.Key != "" {
				s.PassCifr = ""
			} else if pet.GuardarPassword && pet.Password != "" {
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
			vistos := map[int]bool{}
			for i := range lista {
				if lista[i].Puerto < 1 || lista[i].Puerto > 65535 {
					responderError(w, fmt.Errorf("puerto inválido: %d", lista[i].Puerto))
					return
				}
				if vistos[lista[i].Puerto] {
					responderError(w, fmt.Errorf("puerto repetido: %d", lista[i].Puerto))
					return
				}
				vistos[lista[i].Puerto] = true
				if lista[i].Nombre == "" {
					lista[i].Nombre = fmt.Sprintf("Puerto %d", lista[i].Puerto)
				}
			}
			if err := guardarTuneles(lista); err != nil {
				responderError(w, fmt.Errorf("no pude guardar: %v", err))
				return
			}
			responder(w, map[string]any{"ok": true, "aviso": activa != nil})
		case "DELETE": // restaurar los de fábrica
			if err := guardarTuneles(tunelesPorDefecto()); err != nil {
				responderError(w, err)
				return
			}
			responder(w, cargarTuneles())
		}
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
		defer mu.Unlock()
		if activa != nil {
			responderError(w, fmt.Errorf("ya hay una conexión activa con '%s'; desconecta primero", activa.servidor))
			return
		}
		lista := cargar()
		s := buscar(lista, pet.Nombre)
		if s == nil {
			responderError(w, fmt.Errorf("servidor no encontrado"))
			return
		}
		res, err := conectar(s, lista, pet.Password, pet.AceptarHuella)
		if err != nil {
			responderError(w, err)
			return
		}
		responder(w, res)
	}))

	mux.HandleFunc("/api/desconectar", proteger(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cerrarActiva()
		mu.Unlock()
		responder(w, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/estado", proteger(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if activa == nil {
			responder(w, map[string]any{"conectado": false, "version": version})
			return
		}
		// enlaces: solo los tuneles que realmente se abrieron
		abiertos := map[int]bool{}
		for _, p := range activa.abiertos {
			abiertos[p] = true
		}
		var activos []Tunel
		for _, t := range cargarTuneles() {
			if abiertos[t.Puerto] {
				activos = append(activos, t)
			}
		}
		responder(w, map[string]any{
			"conectado": true, "servidor": activa.servidor,
			"puertos": activa.abiertos, "tuneles": activos,
			"desde": activa.desde.Format("15:04:05"), "version": version,
		})
	}))

	mux.HandleFunc("/api/salir", proteger(func(w http.ResponseWriter, r *http.Request) {
		responder(w, map[string]any{"ok": true})
		go func() {
			time.Sleep(300 * time.Millisecond)
			mu.Lock()
			cerrarActiva()
			mu.Unlock()
			_ = os.Remove(filepath.Join(baseDir, "sesion"))
			os.Exit(0)
		}()
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
	cerrarActiva()
	mu.Unlock()
	_ = escucha.Close()
	os.Exit(0)
}

func abrirNavegador(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}
