// Copyright (c) 2026 Gsus — Licencia MIT (ver LICENSE)

package main

// Terminal SSH integrado: abre una sesión interactiva (PTY) sobre la
// conexión SSH activa y la puentea por WebSocket hacia xterm.js en la
// interfaz. Mismo motor SSH embebido; cero dependencias externas.

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

func manejarTerminal(w http.ResponseWriter, r *http.Request) {
	nombre := r.URL.Query().Get("nombre")
	mu.Lock()
	con := conexiones[nombre]
	mu.Unlock()
	if con == nil {
		http.Error(w, "no estás conectado a ese servidor", 400)
		return
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Wails sirve la UI desde su origen interno wails.localhost mientras
		// el PTY sigue en el listener loopback. Autorizamos únicamente ese
		// origen, además del mismo host que coder/websocket permite por defecto.
		OriginPatterns: []string{"wails.localhost"},
	})
	if err != nil {
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	ctx, cancelar := context.WithCancel(r.Context())
	defer cancelar()

	sesion, err := con.cliente.NewSession()
	if err != nil {
		_ = ws.Write(ctx, websocket.MessageBinary, []byte("ERROR abriendo sesión: "+err.Error()+"\r\n"))
		return
	}
	defer sesion.Close()

	modos := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sesion.RequestPty("xterm-256color", 30, 110, modos); err != nil {
		_ = ws.Write(ctx, websocket.MessageBinary, []byte("ERROR pidiendo PTY: "+err.Error()+"\r\n"))
		return
	}

	stdin, err := sesion.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := sesion.StdoutPipe()
	if err != nil {
		return
	}
	if err := sesion.Shell(); err != nil {
		_ = ws.Write(ctx, websocket.MessageBinary, []byte("ERROR abriendo shell: "+err.Error()+"\r\n"))
		return
	}

	// salida del servidor -> navegador
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				if ws.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		cancelar()
	}()

	// fin de la shell (exit) -> cerrar el websocket
	go func() {
		_ = sesion.Wait()
		cancelar()
	}()

	// teclas y resize del navegador -> servidor
	for {
		tipo, datos, err := ws.Read(ctx)
		if err != nil {
			return
		}
		switch tipo {
		case websocket.MessageBinary:
			if _, err := stdin.Write(datos); err != nil {
				return
			}
		case websocket.MessageText:
			var ctl struct{ Cols, Rows int }
			if json.Unmarshal(datos, &ctl) == nil && ctl.Cols > 0 && ctl.Rows > 0 {
				_ = sesion.WindowChange(ctl.Rows, ctl.Cols)
			}
		}
	}
}
