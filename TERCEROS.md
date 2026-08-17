# Software y librerías de terceros

Gateway WISP Access se distribuye bajo **MIT**, pero interactúa con software de terceros que conserva sus propias licencias. La aplicación no relicencia esos proyectos.

## Librerías enlazadas o incluidas en la aplicación

| Proyecto | Uso | Licencia |
|---|---|---|
| [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) | Motor SSH, túneles y autenticación | BSD-3-Clause © The Go Authors |
| [xterm.js](https://github.com/xtermjs/xterm.js) | Terminal de la interfaz | MIT © The xterm.js authors |
| [webview/webview_go](https://github.com/webview/webview_go) | Ventana nativa | MIT © Serge Zaitsev |
| [coder/websocket](https://github.com/coder/websocket) | WebSocket del terminal | ISC © Coder Technologies |
| [golang.org/x/crypto/scrypt](https://pkg.go.dev/golang.org/x/crypto/scrypt) | Derivación de clave para backups | BSD-3-Clause © The Go Authors |
| [pkg/sftp](https://github.com/pkg/sftp) | Gestor de archivos remoto | BSD-2-Clause © The pkg/sftp authors |
| [Go](https://go.dev) | Lenguaje y biblioteca estándar | BSD-3-Clause © The Go Authors |

## Servicios externos que la función Monitoreo puede instalar/configurar

Estos componentes **no se incorporan al binario de Gateway WISP Access**. Se instalan como programas independientes en los servidores elegidos y mantienen íntegramente sus respectivas licencias:

| Proyecto | Uso | Licencia |
|---|---|---|
| [Prometheus](https://github.com/prometheus/prometheus) | Base de datos y recolección de métricas | Apache-2.0 |
| [Prometheus node_exporter](https://github.com/prometheus/node_exporter) | Métricas del sistema Linux y textfile collector | Apache-2.0 |
| [WireGuard tools](https://git.zx2c4.com/wireguard-tools/) | Lectura de peers/contadores WireGuard | GPL-2.0 |

Los scripts y métricas `gateway_wisp_*` generados por Gateway WISP Access son código propio del proyecto y se distribuyen bajo MIT. Los componentes anteriores se ejecutan como procesos independientes y no se enlazan con el binario de la aplicación.

**Compatibilidad histórica:** las versiones 3.2.0–3.2.2 podían instalar Grafana OSS como servicio independiente. Desde v3.2.3 la aplicación no instala ni utiliza Grafana. Una actualización no lo elimina automáticamente de servidores donde ya esté presente.

Las fuentes de la interfaz (Barlow Condensed, JetBrains Mono) se cargan desde Google Fonts bajo SIL Open Font License.

## Migración futura de interfaz

El directorio `frontend-next/` contiene únicamente código TypeScript propio y documentación de migración. **Wails todavía no forma parte del binario distribuido en esta versión**, por lo que no se declara como dependencia enlazada hasta que la migración pase a producción.
