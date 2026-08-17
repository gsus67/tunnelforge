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
| [Grafana OSS](https://github.com/grafana/grafana) | Dashboards y visualización | AGPL-3.0-only (con excepciones indicadas por el proyecto) |
| [Prometheus](https://github.com/prometheus/prometheus) | Base de datos y recolección de métricas | Apache-2.0 |
| [Prometheus node_exporter](https://github.com/prometheus/node_exporter) | Métricas del sistema Linux | Apache-2.0 |
| [WireGuard tools](https://git.zx2c4.com/wireguard-tools/) | Lectura de peers/contadores WireGuard | GPL-2.0 |

Gateway WISP Access instala **Grafana OSS**, no Grafana Enterprise. Los dashboards y scripts `gateway_wisp_*` generados por esta aplicación son originales del proyecto Gateway WISP Access y se distribuyen bajo MIT.

La interfaz puede mostrar Grafana mediante un proxy local sobre SSH. Grafana sigue ejecutándose como un servicio independiente en el servidor de monitoreo y no se enlaza con el código de Gateway WISP Access.

Las fuentes de la interfaz (Barlow Condensed, JetBrains Mono) se cargan desde Google Fonts bajo SIL Open Font License.
