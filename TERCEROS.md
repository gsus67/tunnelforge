# Software y librerías de terceros

Gateway WISP Access se distribuye bajo **MIT**, pero interactúa con software de terceros que conserva sus propias licencias. La aplicación no relicencia esos proyectos.

## Librerías enlazadas o incluidas en la aplicación

| Proyecto | Uso | Licencia |
|---|---|---|
| [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) | Motor SSH, túneles y autenticación | BSD-3-Clause © The Go Authors |
| [xterm.js](https://github.com/xtermjs/xterm.js) | Terminal de la interfaz | MIT © The xterm.js authors |
| [Wails v2](https://github.com/wailsapp/wails) | Shell de escritorio nativo Windows/Linux y puente Go↔frontend | MIT © Wails contributors |
| [coder/websocket](https://github.com/coder/websocket) | WebSocket del terminal | ISC © Coder Technologies |
| [golang.org/x/crypto/scrypt](https://pkg.go.dev/golang.org/x/crypto/scrypt) | Derivación de clave para backups | BSD-3-Clause © The Go Authors |
| [pkg/sftp](https://github.com/pkg/sftp) | Gestor de archivos remoto | BSD-2-Clause © The pkg/sftp authors |
| [Go](https://go.dev) | Lenguaje y biblioteca estándar | BSD-3-Clause © The Go Authors |
| [TypeScript](https://github.com/microsoft/TypeScript) | Compilación del frontend (dependencia de build; no se distribuye como runtime separado) | Apache-2.0 © Microsoft |

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

## Integración WireGuard local

Desde v3.4.0 la aplicación puede administrar túneles WireGuard locales. Desde **v3.4.3**, el build oficial de Windows incorpora el motor y un host nativo mínimo dentro de `Conectar-Gateway.exe`; Linux continúa utilizando las herramientas de la distribución.

| Componente | Uso | Distribución/licencia |
|---|---|---|
| [WireGuard for Windows · embeddable-dll-service](https://git.zx2c4.com/wireguard-windows/tree/embeddable-dll-service/) | `tunnel.dll`, servicio de túnel embebible cargado por el host nativo privado de Gateway WISP Access | MIT © WireGuard LLC. Se compila durante GitHub Actions desde el tag oficial v1.1 fijado a un commit concreto |
| [WireGuardNT](https://git.zx2c4.com/wireguard-nt/) | `wireguard.dll`, driver/API oficial usados por `tunnel.dll` y para leer estadísticas | Se utiliza el **binario precompilado oficial** incluido en `wireguard-nt-1.1.zip`, bajo su *Prebuilt Binaries License*, que permite distribuirlo junto a software que lo usa mediante la API permitida |
| [wireguard-tools](https://git.zx2c4.com/wireguard-tools/) | `wg` / `wg-quick` en Linux | GPL-2.0; se instala como paquete independiente del sistema |
| [embeddable-dll-service / main.go](https://git.zx2c4.com/wireguard-windows/tree/embeddable-dll-service/main.go) | Referencia para generación local de pares Curve25519 | MIT © WireGuard LLC; la pequeña adaptación incluida conserva atribución en el código fuente |

En Windows, `wg-service-host.exe`, `tunnel.dll` y `wireguard.dll` se incrustan como recursos dentro del ejecutable de Gateway WISP Access y se extraen a un directorio privado de runtime cuando se necesita iniciar un túnel. `wg-service-host.exe` es código propio MIT y únicamente carga `tunnel.dll` mediante la exportación documentada `WireGuardTunnelService`. El usuario **no instala WireGuard for Windows ni `wg.exe`**. La creación/control del servicio VPN sí requiere elevación UAC de Windows.

El workflow no compila un WireGuardNT/driver modificado: toma el `wireguard.dll` precompilado distribuido por WireGuard dentro de la dependencia oficial y conserva sus avisos y términos. Gateway WISP Access usa únicamente las funciones públicas de la API de WireGuardNT para leer estado y estadísticas.

Los hooks `PreUp`, `PostUp`, `PreDown` y `PostDown` de un `.conf` pueden ejecutar comandos. Por seguridad la aplicación los conserva al importar pero no los activa sin una acción explícita del usuario.

**Marca/nombre:** Gateway WISP Access no es el cliente oficial de WireGuard. El término “WireGuard” se utiliza únicamente para identificar compatibilidad con el protocolo y los componentes correspondientes.

## Interfaz de escritorio

Desde v3.3.0 Gateway WISP Access usa **Wails v2.13.0** en producción. Se eligió la rama estable de Wails para evitar depender de Wails v3 mientras siga publicado como prerelease. Wails conserva su licencia MIT y utiliza WebView2 en Windows y WebKitGTK en Linux como componentes del sistema.
