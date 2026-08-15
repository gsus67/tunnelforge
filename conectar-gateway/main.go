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

const version = "2.0.0"

var puertos = []int{8888, 10086, 19999, 6060, 60601}

//go:embed ui.html
var interfaz embed.FS

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
func guardar(lista []Servidor) {
	datos, _ := json.MarshalIndent(lista, "", "  ")
	_ = os.WriteFile(rutaJunto("conexiones.json"), datos, 0600)
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
				guardar(lista)
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
	for _, p := range puertos {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue // puerto local ocupado: se omite ese túnel
		}
		con.escuchas = append(con.escuchas, l)
		con.abiertos = append(con.abiertos, p)
		go func(l net.Listener, puerto int) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go puente(c, cliente, puerto)
			}
		}(l, p)
	}
	if len(con.escuchas) == 0 {
		cliente.Close()
		return nil, fmt.Errorf("ningún túnel pudo abrirse (¿puertos locales ocupados?)")
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
	baseDir = filepath.Dir(exe)

	token := os.Getenv("CG_TOKEN")
	if token == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		token = hex.EncodeToString(b)
	}
	puertoGUI := os.Getenv("CG_PORT")
	if puertoGUI == "" {
		puertoGUI = "0"
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
			guardar(lista)
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
			guardar(nueva)
			responder(w, map[string]any{"ok": true})
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
		responder(w, map[string]any{
			"conectado": true, "servidor": activa.servidor,
			"puertos": activa.abiertos, "desde": activa.desde.Format("15:04:05"),
			"version": version,
		})
	}))

	mux.HandleFunc("/api/salir", proteger(func(w http.ResponseWriter, r *http.Request) {
		responder(w, map[string]any{"ok": true})
		go func() {
			time.Sleep(300 * time.Millisecond)
			mu.Lock()
			cerrarActiva()
			mu.Unlock()
			os.Exit(0)
		}()
	}))

	escucha, err := net.Listen("tcp", "127.0.0.1:"+puertoGUI)
	if err != nil {
		fmt.Println("ERROR: no pude abrir el puerto de la interfaz:", err)
		os.Exit(1)
	}
	url := fmt.Sprintf("http://%s/?t=%s", escucha.Addr().String(), token)
	fmt.Println("Interfaz en:", url)
	if os.Getenv("CG_NO_BROWSER") == "" {
		abrirNavegador(url)
	}
	_ = http.Serve(escucha, mux)
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
