// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)
//
// Herramientas de un servidor MikroTik: firewall (/ip/firewall/filter) y una
// consola contra la REST API de RouterOS. Todo pasa por el mismo cliente
// HTTPS+Basic que usa el Monitoreo (routeros.go).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// do ejecuta un método arbitrario contra <baseURL>/rest<path>. `path` debe
// empezar por "/". `body` (si no es nil) se manda como JSON.
func (c *mikrotikClient) do(metodo, path string, body any) (int, []byte, error) {
	var lector io.Reader
	if body != nil {
		datos, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		lector = bytes.NewReader(datos)
	}
	req, err := http.NewRequest(metodo, c.baseURL+path, lector)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(c.usuario, c.password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	datos, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, datos, nil
}

// alcanzable comprueba que la REST API sigue respondiendo (para avisar tras un
// cambio de firewall que pueda haber cortado el acceso).
func (c *mikrotikClient) alcanzable() bool {
	code, _, err := c.do(http.MethodGet, "/system/resource", nil)
	return err == nil && code >= 200 && code < 300
}

func clienteMikrotikPorNombre(nombre string) (*mikrotikClient, Servidor, error) {
	perfil, pass, err := monitoringPerfilServidor(strings.TrimSpace(nombre))
	if err != nil {
		return nil, Servidor{}, err
	}
	if !perfil.esMikrotik() {
		return nil, Servidor{}, fmt.Errorf("%s no es un servidor MikroTik", perfil.Nombre)
	}
	cli, err := nuevoMikrotikClient(perfil, pass)
	if err != nil {
		return nil, Servidor{}, err
	}
	return cli, perfil, nil
}

// --- Firewall ---------------------------------------------------------------

type reglaFirewallMT struct {
	ID       string `json:"id"`
	Chain    string `json:"chain"`
	Action   string `json:"action"`
	Disabled bool   `json:"disabled"`
	Dynamic  bool   `json:"dynamic"`
	Comment  string `json:"comment"`
	Detalle  string `json:"detalle"`
}

func resumenReglaMT(m map[string]any) string {
	orden := []string{"protocol", "src-address", "dst-address", "src-port", "dst-port", "in-interface", "out-interface", "connection-state", "connection-nat-state", "src-address-list", "dst-address-list"}
	var partes []string
	for _, k := range orden {
		if v := routerOSString(m[k]); v != "" {
			partes = append(partes, k+"="+v)
		}
	}
	return strings.Join(partes, " ")
}

func listarFirewallMT(cli *mikrotikClient) ([]reglaFirewallMT, error) {
	code, datos, err := cli.do(http.MethodGet, "/ip/firewall/filter", nil)
	if err != nil {
		return nil, fmt.Errorf("no pude consultar el firewall: %w", err)
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("RouterOS respondió %d al listar el firewall", code)
	}
	var crudas []map[string]any
	if err := json.Unmarshal(datos, &crudas); err != nil {
		return nil, fmt.Errorf("respuesta de firewall no válida: %w", err)
	}
	reglas := make([]reglaFirewallMT, 0, len(crudas))
	for _, m := range crudas {
		reglas = append(reglas, reglaFirewallMT{
			ID:       routerOSString(m[".id"]),
			Chain:    routerOSString(m["chain"]),
			Action:   routerOSString(m["action"]),
			Disabled: routerOSString(m["disabled"]) == "true",
			Dynamic:  routerOSString(m["dynamic"]) == "true",
			Comment:  routerOSString(m["comment"]),
			Detalle:  resumenReglaMT(m),
		})
	}
	return reglas, nil
}

var reIDFirewall = regexp.MustCompile(`^\*?[0-9A-Fa-f]+$`)

func manejarMikrotikFirewall(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cli, _, err := clienteMikrotikPorNombre(r.URL.Query().Get("servidor"))
		if err != nil {
			responderError(w, err)
			return
		}
		reglas, err := listarFirewallMT(cli)
		if err != nil {
			responderError(w, err)
			return
		}
		responder(w, map[string]any{"ok": true, "reglas": reglas, "alcanzable": true})

	case http.MethodPost:
		var pet struct {
			Servidor  string `json:"servidor"`
			Op        string `json:"op"` // toggle | delete | add
			ID        string `json:"id"`
			Confirmar bool   `json:"confirmar"`
			Regla     struct {
				Chain    string `json:"chain"`
				Action   string `json:"action"`
				Protocol string `json:"protocol"`
				DstPort  string `json:"dstPort"`
				SrcAddr  string `json:"srcAddress"`
				Comment  string `json:"comment"`
			} `json:"regla"`
		}
		if err := decodificar(r, &pet); err != nil {
			responderError(w, err)
			return
		}
		cli, _, err := clienteMikrotikPorNombre(pet.Servidor)
		if err != nil {
			responderError(w, err)
			return
		}
		// Un cambio en la cadena input puede cortar el acceso a la API: se
		// exige confirmación explícita del frontend para esos casos.
		necesitaConfirmar := false
		switch pet.Op {
		case "toggle", "delete":
			if !reIDFirewall.MatchString(strings.TrimPrefix(pet.ID, "*")) {
				responderError(w, fmt.Errorf("id de regla inválido"))
				return
			}
			reglas, lerr := listarFirewallMT(cli)
			if lerr != nil {
				responderError(w, lerr)
				return
			}
			var actual *reglaFirewallMT
			for i := range reglas {
				if reglas[i].ID == pet.ID {
					actual = &reglas[i]
					break
				}
			}
			if actual == nil {
				responderError(w, fmt.Errorf("esa regla ya no existe; actualizá la lista"))
				return
			}
			if actual.Dynamic {
				responderError(w, fmt.Errorf("es una regla dinámica de RouterOS; no se puede tocar desde acá"))
				return
			}
			if actual.Chain == "input" && (actual.Action == "accept" || pet.Op == "delete") {
				necesitaConfirmar = true
			}
			if necesitaConfirmar && !pet.Confirmar {
				responder(w, map[string]any{"ok": false, "necesitaConfirmar": true,
					"aviso": "Esta regla está en la cadena input; tocarla puede cortarte el acceso a la API. Tené Winbox o la consola a mano."})
				return
			}
			switch pet.Op {
			case "toggle":
				nuevo := "yes"
				if actual.Disabled {
					nuevo = "no"
				}
				code, body, derr := cli.do(http.MethodPatch, "/ip/firewall/filter/"+pet.ID, map[string]string{"disabled": nuevo})
				if derr != nil || code < 200 || code >= 300 {
					responderError(w, fmt.Errorf("RouterOS rechazó el cambio (%d): %s", code, recorte(body)))
					return
				}
			case "delete":
				code, body, derr := cli.do(http.MethodDelete, "/ip/firewall/filter/"+pet.ID, nil)
				if derr != nil || code < 200 || code >= 300 {
					responderError(w, fmt.Errorf("RouterOS rechazó el borrado (%d): %s", code, recorte(body)))
					return
				}
			}

		case "add":
			chain := strings.ToLower(strings.TrimSpace(pet.Regla.Chain))
			action := strings.ToLower(strings.TrimSpace(pet.Regla.Action))
			if chain != "input" && chain != "forward" && chain != "output" {
				responderError(w, fmt.Errorf("chain inválida (input/forward/output)"))
				return
			}
			if action != "accept" && action != "drop" && action != "reject" {
				responderError(w, fmt.Errorf("action inválida (accept/drop/reject)"))
				return
			}
			if chain == "input" && !pet.Confirmar {
				responder(w, map[string]any{"ok": false, "necesitaConfirmar": true,
					"aviso": "Vas a agregar una regla en la cadena input. Una regla drop/reject mal puesta puede cortarte el acceso."})
				return
			}
			cuerpo := map[string]string{"chain": chain, "action": action}
			if v := strings.TrimSpace(pet.Regla.Protocol); v != "" {
				cuerpo["protocol"] = strings.ToLower(v)
			}
			if v := strings.TrimSpace(pet.Regla.DstPort); v != "" {
				cuerpo["dst-port"] = v
			}
			if v := strings.TrimSpace(pet.Regla.SrcAddr); v != "" {
				cuerpo["src-address"] = v
			}
			com := strings.TrimSpace(pet.Regla.Comment)
			if com == "" {
				com = "TunnelForge"
			}
			cuerpo["comment"] = com
			code, body, derr := cli.do(http.MethodPut, "/ip/firewall/filter", cuerpo)
			if derr != nil || code < 200 || code >= 300 {
				responderError(w, fmt.Errorf("RouterOS rechazó la regla nueva (%d): %s", code, recorte(body)))
				return
			}

		default:
			responderError(w, fmt.Errorf("operación inválida"))
			return
		}

		// Comprobar que no nos quedamos afuera.
		time.Sleep(200 * time.Millisecond)
		vivo := cli.alcanzable()
		reglas, _ := listarFirewallMT(cli)
		out := map[string]any{"ok": true, "reglas": reglas, "alcanzable": vivo}
		if !vivo {
			out["aviso"] = "El cambio se aplicó pero la REST API dejó de responder. Revisá el firewall desde Winbox o la consola del router."
		}
		responder(w, out)

	default:
		responderError(w, fmt.Errorf("método no permitido"))
	}
}

// --- Consola RouterOS -----------------------------------------------------

// Los command paths de RouterOS son minúsculas con "/", "-" y "_" — nunca
// llevan puntos (los puntos van en los valores, no en la ruta).
var reRutaRouterOS = regexp.MustCompile(`^/[a-z0-9](?:[a-z0-9_-]|/[a-z0-9])*$`)

func recorte(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 600 {
		return s[:600] + "…"
	}
	return s
}

func manejarMikrotikComando(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var pet struct {
		Servidor  string          `json:"servidor"`
		Metodo    string          `json:"metodo"`
		Path      string          `json:"path"`
		Body      json.RawMessage `json:"body"`
		Confirmar bool            `json:"confirmar"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	metodo := strings.ToUpper(strings.TrimSpace(pet.Metodo))
	switch metodo {
	case "", http.MethodGet:
		metodo = http.MethodGet
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if !pet.Confirmar {
			responder(w, map[string]any{"ok": false, "necesitaConfirmar": true,
				"aviso": metodo + " modifica el router. Confirmá para ejecutarlo."})
			return
		}
	default:
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	path := strings.TrimSpace(pet.Path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	if strings.Contains(path, "..") || !reRutaRouterOS.MatchString(path) {
		responderError(w, fmt.Errorf("ruta inválida: usá algo como /interface, /ip/address, /system/routerboard"))
		return
	}
	cli, _, err := clienteMikrotikPorNombre(pet.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	var body any
	if len(pet.Body) > 0 && string(pet.Body) != "null" {
		var tmp any
		if err := json.Unmarshal(pet.Body, &tmp); err != nil {
			responderError(w, fmt.Errorf("el cuerpo JSON no es válido: %w", err))
			return
		}
		body = tmp
	}
	code, datos, err := cli.do(metodo, path, body)
	if err != nil {
		responderError(w, fmt.Errorf("no pude ejecutar el comando: %w", err))
		return
	}
	// Pretty-print si es JSON; si no, texto crudo recortado.
	pretty := strings.TrimSpace(string(datos))
	var tmp any
	if json.Unmarshal(datos, &tmp) == nil {
		if b, e := json.MarshalIndent(tmp, "", "  "); e == nil {
			pretty = string(b)
		}
	}
	if len(pretty) > 60000 {
		pretty = pretty[:60000] + "\n… salida recortada …"
	}
	responder(w, map[string]any{"ok": code >= 200 && code < 300, "status": code, "metodo": metodo, "path": path, "cuerpo": pretty})
}

// --- Scripts RouterOS ----------------------------------------------------

var reNombreScriptMT = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func prettyJSON(datos []byte) string {
	s := strings.TrimSpace(string(datos))
	var tmp any
	if json.Unmarshal(datos, &tmp) == nil {
		if b, e := json.MarshalIndent(tmp, "", "  "); e == nil {
			s = string(b)
		}
	}
	if len(s) > 40000 {
		s = s[:40000] + "\n… salida recortada …"
	}
	return s
}

func idDeRespuesta(datos []byte) string {
	var obj map[string]any
	if json.Unmarshal(datos, &obj) == nil {
		for _, k := range []string{".id", "ret", "id"} {
			if v := routerOSString(obj[k]); v != "" {
				return v
			}
		}
	}
	var arr []map[string]any
	if json.Unmarshal(datos, &arr) == nil && len(arr) > 0 {
		for _, k := range []string{".id", "ret", "id"} {
			if v := routerOSString(arr[0][k]); v != "" {
				return v
			}
		}
	}
	return ""
}

func manejarMikrotikScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var pet struct {
		Servidor string `json:"servidor"`
		Op       string `json:"op"` // run | save
		Nombre   string `json:"nombre"`
		Source   string `json:"source"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	pet.Source = strings.TrimSpace(pet.Source)
	if pet.Source == "" {
		responderError(w, fmt.Errorf("el script está vacío"))
		return
	}
	if len(pet.Source) > 200*1024 {
		responderError(w, fmt.Errorf("el script supera el límite de 200 KB"))
		return
	}
	cli, _, err := clienteMikrotikPorNombre(pet.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}

	if pet.Op == "save" {
		nombre := strings.TrimSpace(pet.Nombre)
		if !reNombreScriptMT.MatchString(nombre) {
			responderError(w, fmt.Errorf("nombre inválido (letras, números, . _ -)"))
			return
		}
		code, body, derr := cli.do(http.MethodPut, "/system/script", map[string]string{"name": nombre, "source": pet.Source})
		if derr != nil || code < 200 || code >= 300 {
			responderError(w, fmt.Errorf("RouterOS no guardó el script (%d): %s", code, recorte(body)))
			return
		}
		responder(w, map[string]any{"ok": true, "guardado": nombre,
			"nota": "Guardado en /system/script. Ejecutalo desde la pestaña Consola con POST /system/script/run y {\"number\":\"" + nombre + "\"} o desde Winbox."})
		return
	}

	// run: ejecución asíncrona vía /rest/execute (RouterOS 7.10+).
	cli.http.Timeout = 30 * time.Second
	code, body, derr := cli.do(http.MethodPost, "/execute", map[string]string{"script": pet.Source})
	if derr != nil {
		responderError(w, fmt.Errorf("no pude lanzar el script: %w", derr))
		return
	}
	if code == http.StatusNotFound {
		responderError(w, fmt.Errorf("este RouterOS no tiene /rest/execute. Usá la pestaña Consola para comandos sueltos, o Guardá el script y ejecutalo desde Winbox"))
		return
	}
	if code < 200 || code >= 300 {
		responderError(w, fmt.Errorf("RouterOS rechazó el script (%d): %s", code, recorte(body)))
		return
	}
	id := idDeRespuesta(body)
	// RouterOS 7.x lanza el script de forma asíncrona y NO deja recuperar su
	// salida por REST (`GET /rest/execute/<id>` da "no such command"). Lo
	// mejor que se puede devolver es lo que el script haya escrito con `:log`.
	time.Sleep(700 * time.Millisecond)
	var lineas []string
	if _, lb, le := cli.do(http.MethodGet, "/log", nil); le == nil {
		var log []map[string]any
		if json.Unmarshal(lb, &log) == nil {
			desde := len(log) - 15
			if desde < 0 {
				desde = 0
			}
			for _, x := range log[desde:] {
				lineas = append(lineas, routerOSString(x["time"])+"  "+routerOSString(x["topics"])+"  "+routerOSString(x["message"]))
			}
		}
	}
	salida := "Script ejecutado"
	if id != "" {
		salida += " (id " + id + ")"
	}
	salida += ".\nRouterOS no devuelve la salida de `:put` por REST — usá `:log info \"...\"` para ver resultados acá o revisá /system/script en el router."
	if len(lineas) > 0 {
		salida += "\n\n— últimas líneas de /log —\n" + strings.Join(lineas, "\n")
	}
	responder(w, map[string]any{"ok": true, "salida": salida})
}

// --- Test de velocidad --------------------------------------------------

func manejarMikrotikSpeedtest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, fmt.Errorf("método no permitido"))
		return
	}
	var pet struct {
		Servidor string `json:"servidor"`
		Bytes    int64  `json:"bytes"`
	}
	if err := decodificar(r, &pet); err != nil {
		responderError(w, err)
		return
	}
	bytesDL := pet.Bytes
	if bytesDL <= 0 {
		bytesDL = 25_000_000
	}
	if bytesDL > 100_000_000 {
		bytesDL = 100_000_000
	}
	cli, _, err := clienteMikrotikPorNombre(pet.Servidor)
	if err != nil {
		responderError(w, err)
		return
	}
	cli.http.Timeout = 60 * time.Second

	res := map[string]any{"ok": true}

	// Latencia
	if _, body, e := cli.do(http.MethodPost, "/ping", map[string]string{"address": "1.1.1.1", "count": "4"}); e == nil {
		var filas []map[string]any
		if json.Unmarshal(body, &filas) == nil {
			var suma float64
			var n int
			var loss string
			for _, f := range filas {
				if t := parsePingMs(routerOSString(f["time"])); t > 0 {
					suma += t
					n++
				}
				if v := routerOSString(f["packet-loss"]); v != "" {
					loss = v
				}
				if v := parsePingMs(routerOSString(f["avg-rtt"])); v > 0 {
					res["latenciaMs"] = round1(v)
				}
			}
			if _, ok := res["latenciaMs"]; !ok && n > 0 {
				res["latenciaMs"] = round1(suma / float64(n))
			}
			if loss != "" {
				res["perdida"] = loss + "%"
			}
		}
	}

	// Descarga vía /tool/fetch contra speed.cloudflare.com
	url := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytesDL)
	code, body, e := cli.do(http.MethodPost, "/tool/fetch", map[string]string{
		"url": url, "mode": "https", "keep-result": "no",
	})
	if e != nil {
		res["avisoDescarga"] = "No se pudo medir la descarga: " + e.Error()
	} else if code < 200 || code >= 300 {
		res["avisoDescarga"] = fmt.Sprintf("RouterOS rechazó /tool/fetch (%d): %s", code, recorte(body))
	} else {
		// /tool/fetch devuelve un array de secciones; la última con
		// status=finished trae downloaded (KiB) y duration.
		fin := seccionFetchFinal(body)
		kib := routerOSFloat(fin["downloaded"])
		dur := parseRouterOSDuration(routerOSString(fin["duration"]))
		if dur <= 0 {
			dur = routerOSFloat(fin["duration"])
		}
		if kib > 0 && dur > 0 {
			mbps := (kib * 1024 * 8) / dur / 1e6
			res["descargaMbps"] = round1(mbps)
			res["descargaMB"] = round1(kib / 1024)
			res["segundos"] = round1(dur)
		} else if kib > 0 {
			res["descargaMB"] = round1(kib / 1024)
			res["avisoDescarga"] = "descargó " + fmt.Sprintf("%.1f", kib/1024) + " MB pero RouterOS reportó duración 0 — probá con un tamaño mayor"
		} else {
			res["avisoDescarga"] = "RouterOS no devolvió tamaño de la descarga (" + prettyJSON(body) + ")"
		}
	}
	res["nota"] = "Descarga medida con /tool/fetch contra speed.cloudflare.com. La subida no se mide desde RouterOS."
	responder(w, res)
}

func parsePingMs(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// formatos posibles: "12ms345us", "1s200ms", "980us", "12.3ms"
	var total float64
	num := ""
	flush := func(unidad string) {
		if num == "" {
			return
		}
		v, _ := strconv.ParseFloat(num, 64)
		switch unidad {
		case "s":
			total += v * 1000
		case "ms":
			total += v
		case "us":
			total += v / 1000
		}
		num = ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || c == '.' {
			num += string(c)
			continue
		}
		if c == 'u' && i+1 < len(s) && s[i+1] == 's' {
			flush("us")
			i++
		} else if c == 'm' && i+1 < len(s) && s[i+1] == 's' {
			flush("ms")
			i++
		} else if c == 's' {
			flush("s")
		}
	}
	if num != "" { // número suelto = ms
		v, _ := strconv.ParseFloat(num, 64)
		total += v
	}
	return total
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

// seccionFetchFinal toma la respuesta (array) de /tool/fetch y devuelve la
// sección "finished" (o la última). Tolera que venga como objeto suelto.
func seccionFetchFinal(body []byte) map[string]any {
	var arr []map[string]any
	if json.Unmarshal(body, &arr) == nil && len(arr) > 0 {
		for i := len(arr) - 1; i >= 0; i-- {
			if routerOSString(arr[i]["status"]) == "finished" {
				return arr[i]
			}
		}
		return arr[len(arr)-1]
	}
	var obj map[string]any
	_ = json.Unmarshal(body, &obj)
	if obj == nil {
		return map[string]any{}
	}
	return obj
}
