// ============================================================================
// Conectar Gateway — túneles SSH a los paneles del gateway WISP
// ============================================================================
// Aplicación autocontenida: trae su PROPIO motor SSH (golang.org/x/crypto/ssh,
// la librería oficial del proyecto Go). No depende de PuTTY, OpenSSH ni nada
// instalado en el sistema. Un solo ejecutable.
//
// Qué hace:
//   - Guarda tus servidores (IP, puerto, usuario, key o contraseña al vuelo)
//     en conexiones.json junto al ejecutable.
//   - Abre los túneles locales: 8888 (panel), 10086 (WGDashboard),
//     19999 (Netdata), 6060 y 60601 (métricas Prometheus).
//   - Verifica la huella del servidor (TOFU: primera vez la confirmas tú,
//     después exige que no cambie — protección contra suplantación).
//   - Abre el navegador en el panel al conectar.
// ============================================================================
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const version = "1.0.0"

var puertos = []int{8888, 10086, 19999, 6060, 60601}

type Servidor struct {
	Nombre  string `json:"nombre"`
	Host    string `json:"host"`
	Puerto  int    `json:"puerto"`
	Usuario string `json:"usuario"`
	Key     string `json:"key,omitempty"`    // ruta a la clave privada; vacío = contraseña
	Huella  string `json:"huella,omitempty"` // fingerprint SHA256 del host (TOFU)
}

func rutaConfig() string {
	exe, err := os.Executable()
	if err != nil {
		return "conexiones.json"
	}
	return filepath.Join(filepath.Dir(exe), "conexiones.json")
}

func cargar() []Servidor {
	var lista []Servidor
	datos, err := os.ReadFile(rutaConfig())
	if err == nil {
		_ = json.Unmarshal(datos, &lista)
	}
	return lista
}

func guardar(lista []Servidor) {
	datos, _ := json.MarshalIndent(lista, "", "  ")
	_ = os.WriteFile(rutaConfig(), datos, 0600)
}

var lector = bufio.NewReader(os.Stdin)

func pregunta(texto string) string {
	fmt.Print(texto)
	linea, err := lector.ReadString('\n')
	if err != nil {
		fmt.Println()
		os.Exit(0) // EOF (stdin cerrado): salir limpio
	}
	return strings.TrimSpace(linea)
}

func preguntaSecreta(texto string) string {
	fmt.Print(texto)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		// terminal no interactiva: caer a lectura normal
		return pregunta("")
	}
	return string(pass)
}

func navegador(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("cmd", "/c", "start", "", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}

// ---------------------------------------------------------------------------
// Autenticación
// ---------------------------------------------------------------------------
func metodosAuth(s *Servidor) ([]ssh.AuthMethod, error) {
	if s.Key != "" {
		datos, err := os.ReadFile(s.Key)
		if err != nil {
			return nil, fmt.Errorf("no pude leer la key %s: %w", s.Key, err)
		}
		firmante, err := ssh.ParsePrivateKey(datos)
		if err != nil {
			if _, esCifrada := err.(*ssh.PassphraseMissingError); esCifrada {
				frase := preguntaSecreta("Passphrase de la key: ")
				firmante, err = ssh.ParsePrivateKeyWithPassphrase(datos, []byte(frase))
			}
			if err != nil {
				return nil, fmt.Errorf("key inválida: %w", err)
			}
		}
		return []ssh.AuthMethod{ssh.PublicKeys(firmante)}, nil
	}
	// Sin key: contraseña (se pide al conectar, nunca se guarda en disco)
	pedir := func() (string, error) {
		return preguntaSecreta(fmt.Sprintf("Contraseña de %s@%s: ", s.Usuario, s.Host)), nil
	}
	return []ssh.AuthMethod{
		ssh.PasswordCallback(pedir),
		ssh.KeyboardInteractive(func(_, _ string, preguntas []string, ecos []bool) ([]string, error) {
			resp := make([]string, len(preguntas))
			for i, p := range preguntas {
				if ecos[i] {
					resp[i] = pregunta(p + " ")
				} else {
					resp[i] = preguntaSecreta(p + " ")
				}
			}
			return resp, nil
		}),
	}, nil
}

// Verificación de huella del servidor: primera vez confirmas, después se exige
func verificarHost(s *Servidor, lista []Servidor) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		huella := ssh.FingerprintSHA256(key)
		if s.Huella == "" {
			fmt.Printf("\nPrimera conexión a %s.\nHuella del servidor: %s\n", s.Host, huella)
			if !strings.HasPrefix(strings.ToLower(pregunta("¿Confiar en este servidor? [s/n]: ")), "s") {
				return fmt.Errorf("conexión rechazada por el usuario")
			}
			s.Huella = huella
			guardar(lista)
			return nil
		}
		if s.Huella != huella {
			return fmt.Errorf("¡ALERTA! La huella del servidor CAMBIÓ.\n  Guardada: %s\n  Recibida: %s\nPosible suplantación (MITM). Si reinstalaste el VPS, borra el servidor y agrégalo de nuevo", s.Huella, huella)
		}
		return nil
	}
}

// ---------------------------------------------------------------------------
// Túneles
// ---------------------------------------------------------------------------
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

func conectar(s *Servidor, lista []Servidor) {
	auth, err := metodosAuth(s)
	if err != nil {
		fmt.Println("  ERROR:", err)
		return
	}
	config := &ssh.ClientConfig{
		User:            s.Usuario,
		Auth:            auth,
		HostKeyCallback: verificarHost(s, lista),
		Timeout:         12 * time.Second,
	}
	direccion := fmt.Sprintf("%s:%d", s.Host, s.Puerto)
	fmt.Printf("\nConectando a %s ...\n", direccion)

	cliente, err := ssh.Dial("tcp", direccion, config)
	if err != nil {
		fmt.Println("  ERROR de conexión:", err)
		return
	}
	defer cliente.Close()

	// Keepalive para que el túnel no muera por inactividad
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if _, _, err := cliente.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}()

	// Levantar los listeners locales
	var escuchas []net.Listener
	for _, p := range puertos {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			fmt.Printf("  AVISO: puerto local %d ocupado (¿otra conexión abierta?). Se omite.\n", p)
			continue
		}
		escuchas = append(escuchas, l)
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
	if len(escuchas) == 0 {
		fmt.Println("  ERROR: ningún túnel pudo abrirse.")
		return
	}
	defer func() {
		for _, l := range escuchas {
			l.Close()
		}
	}()

	fmt.Printf("\n  ✔ CONECTADO — túneles activos: %v\n", puertos)
	fmt.Println("  Panel:      http://localhost:8888")
	fmt.Println("  WGDashboard http://localhost:10086   Netdata http://localhost:19999")
	navegador("http://localhost:8888")

	// Detectar caída de la sesión en segundo plano
	caida := make(chan struct{})
	go func() { _ = cliente.Wait(); close(caida) }()

	fin := make(chan struct{})
	go func() { pregunta("\n[ENTER] para desconectar... "); close(fin) }()

	select {
	case <-fin:
		fmt.Println("Desconectado.")
	case <-caida:
		fmt.Println("\nLa conexión con el servidor se cayó.")
	}
}

// ---------------------------------------------------------------------------
// Menú
// ---------------------------------------------------------------------------
func nuevoServidor(lista []Servidor) []Servidor {
	fmt.Println("\n── Nuevo servidor ──")
	s := Servidor{Puerto: 22}
	s.Nombre = pregunta("Nombre (ej. gateway-1): ")
	s.Host = pregunta("IP o host: ")
	if p := pregunta("Puerto SSH [22]: "); p != "" {
		fmt.Sscanf(p, "%d", &s.Puerto)
	}
	s.Usuario = pregunta("Usuario: ")
	s.Key = pregunta("Ruta de la key SSH (vacío = usar contraseña al conectar): ")
	if s.Nombre == "" || s.Host == "" || s.Usuario == "" {
		fmt.Println("  Cancelado: nombre, host y usuario son obligatorios.")
		return lista
	}
	lista = append(lista, s)
	guardar(lista)
	fmt.Printf("  Guardado '%s'.\n", s.Nombre)
	return lista
}

func main() {
	for _, a := range os.Args[1:] {
		if a == "--version" || a == "-v" {
			fmt.Println("conectar-gateway", version)
			return
		}
	}
	fmt.Println("==============================================")
	fmt.Println(" Conectar Gateway WISP — túneles SSH  v" + version)
	fmt.Println("==============================================")

	for {
		lista := cargar()
		fmt.Println("\nServidores:")
		if len(lista) == 0 {
			fmt.Println("  (ninguno todavía)")
		}
		for i, s := range lista {
			auth := "contraseña"
			if s.Key != "" {
				auth = "key"
			}
			fmt.Printf("  [%d] %-16s %s@%s:%d  (%s)\n", i+1, s.Nombre, s.Usuario, s.Host, s.Puerto, auth)
		}
		fmt.Println("\n  [n] nuevo servidor   [b] borrar   [q] salir")
		op := strings.ToLower(pregunta("> "))

		switch {
		case op == "q" || op == "salir":
			return
		case op == "n":
			nuevoServidor(lista)
		case op == "b":
			idx := 0
			fmt.Sscanf(pregunta("Número a borrar: "), "%d", &idx)
			if idx >= 1 && idx <= len(lista) {
				nombre := lista[idx-1].Nombre
				lista = append(lista[:idx-1], lista[idx:]...)
				guardar(lista)
				fmt.Printf("  '%s' borrado.\n", nombre)
			}
		default:
			idx := 0
			fmt.Sscanf(op, "%d", &idx)
			if idx >= 1 && idx <= len(lista) {
				conectar(&lista[idx-1], lista)
			} else if op != "" {
				fmt.Println("  Opción no válida.")
			}
		}
	}
}
