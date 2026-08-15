# Conectar Gateway

Cliente SSH de escritorio para administrar gateways: abre los túneles a los
paneles del servidor de un clic y trae terminal SSH integrado.

Un solo ejecutable, **sin dependencias**: trae su propio motor SSH y su propia
interfaz. No necesita PuTTY, ni el cliente OpenSSH del sistema, ni instalación.

Pensado para los gateways de [`gateway-wisp-wireguard`](https://github.com/gsus67/gateway-wisp-wireguard),
pero sirve para **cualquier servidor SSH**: los túneles son configurables.

---

## Qué hace

- **Guarda tus servidores** con key SSH o contraseña, y conecta con un clic
- **Abre todos los túneles a la vez** y muestra accesos directos a cada panel
- **Terminal SSH integrado**: shell interactiva completa dentro de la app
- **Verifica la identidad del servidor**: si su huella cambia, se niega a conectar
- Todo local: la interfaz solo escucha en `127.0.0.1`

---

## Instalación

Descarga el ejecutable de la pestaña **[Releases](../../releases)**:

| Archivo | Sistema |
|---|---|
| `Conectar-Gateway.exe` | Windows 10/11 (64 bits) |
| `conectar-gateway-linux` | Linux (64 bits) |

Ponlo donde quieras y ábrelo. **No hay instalador ni dependencias.**

En Windows se abre en su propia ventana; en Linux, en el navegador
(`http://127.0.0.1:8787`).

---

## Uso

1. **Agregar un servidor** — en el formulario: nombre, IP, puerto SSH, usuario y
   la ruta de tu key SSH *o* la contraseña. Marca *Recordar contraseña* si
   quieres guardarla cifrada; si no, se pide al conectar y no queda en disco.

2. **Conectar** — clic en *Conectar*. La primera vez muestra la huella del
   servidor para que la verifiques; a partir de ahí se exige que no cambie.

3. **Usar los paneles** — con la conexión activa aparecen los accesos directos;
   se abren en tu navegador por defecto.

4. **Terminal** — el botón `>_` de cada servidor abre una shell interactiva
   completa (colores, `htop`, `nano`, autocompletado, Ctrl+C).

5. **Desconectar** — cierra los túneles. Cerrar la ventana también los cierra.

### Copia de seguridad

La sección **Copia de seguridad** exporta toda tu configuración a un archivo
`.cgw`: servidores, túneles, y opcionalmente las contraseñas guardadas y el
contenido de tus claves SSH privadas.

El archivo se cifra con **una contraseña que tú eliges** (scrypt + AES-256-GCM),
no con la llave de este equipo: por eso se puede llevar a otra PC, a un USB o al
NAS y seguir siendo seguro. Sin esa contraseña el contenido es irrecuperable.

Al importar en otro equipo, la app restaura los servidores, aplica los túneles,
guarda las claves SSH en su carpeta de configuración y reapunta las rutas
automáticamente. Puedes **fusionar** con lo que ya tengas (por defecto, los
nombres repetidos se actualizan) o **reemplazar todo**.

### Túneles

Vienen configurados los cinco del gateway WISP, y se pueden quitar, renombrar
o ampliar desde la sección **Túneles**:

| Puerto | Servicio |
|---|---|
| 8888 | Panel del gateway |
| 10086 | WGDashboard |
| 19999 | Netdata |
| 6060 | Métricas de CrowdSec |
| 60601 | Métricas del bouncer |

Cada túnel admite una **ruta web** opcional (por ejemplo `/metrics`), que se
añade al enlace. Los cambios aplican en la siguiente conexión.

---

## Seguridad

- **Contraseñas cifradas** con AES-256-GCM. La llave se genera en la primera
  ejecución y vive en `secreto.bin`, con permisos restringidos. Las contraseñas
  no guardadas se piden al conectar y nunca tocan el disco.
- **Verificación de huella (TOFU)**: la primera conexión pide confirmar la
  huella del servidor; si más tarde cambia, la app se niega a conectar y avisa.
  Protege contra suplantación del servidor.
- **Nada expuesto**: la interfaz escucha solo en `127.0.0.1`, protegida por un
  token de sesión aleatorio.
- **Enlaces restringidos**: la app solo abre en el navegador direcciones de tus
  túneles locales; cualquier otro destino se rechaza.

### Dónde se guardan tus datos

En el perfil del usuario, así sobreviven a mover o actualizar el ejecutable:

| Sistema | Ruta |
|---|---|
| Windows | `%APPDATA%\conectar-gateway\` |
| Linux | `~/.config/conectar-gateway/` |

Ahí quedan `conexiones.json` (servidores y huellas), `secreto.bin` (llave de
cifrado), `ajustes.json` (túneles) y `keys/` (claves SSH importadas de una
copia). Nada de esto se sube al repositorio.

**Modo portable**: crea un archivo vacío llamado `portable` junto al ejecutable
y los datos se guardarán a su lado — útil para llevarlo en un USB o un NAS.

---

## Cómo está hecho

| Pieza | Librería |
|---|---|
| Motor SSH: conexión, túneles y terminal | [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) |
| Ventana nativa (usa el WebView2 de Windows) | [webview](https://github.com/webview/webview_go) |
| Terminal de la interfaz (el mismo de VS Code) | [xterm.js](https://github.com/xtermjs/xterm.js) |
| Canal del terminal | [coder/websocket](https://github.com/coder/websocket) |

Todo va **embebido en el ejecutable**: no descarga nada en tiempo de ejecución.
Detalle de licencias en [TERCEROS.md](TERCEROS.md).

Si WebView2 no estuviera disponible, la app cae al navegador en lugar de fallar.

---

## Compilar desde el código

Requiere **Go 1.22+**. Para Windows, además, el compilador cruzado de C/C++
(la ventana nativa usa CGO):

```bash
cd conectar-gateway

# Windows (ventana nativa, icono y metadatos)
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
  CGO_CXXFLAGS="-I$PWD/winhdr" GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -H windowsgui" -o Conectar-Gateway.exe .

# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" -o conectar-gateway-linux .
```

En Debian/Ubuntu, el compilador cruzado se instala con:
`sudo apt install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64`

Los binarios que salen son idénticos a los de Releases: GitHub Actions ejecuta
estos mismos comandos.

---

## Estructura

```
conectar-gateway/
  main.go              Servidor local, API, conexión SSH y túneles
  terminal.go          Terminal SSH sobre WebSocket
  ventana_windows.go   Ventana nativa (Windows)
  ventana_otros.go     Navegador (Linux/macOS)
  copia.go             Exportar / importar configuración cifrada
  ui.html              Interfaz
  static/              xterm.js embebido
  icono.ico            Icono e identidad del ejecutable
herramientas/          Scripts de apoyo para trabajar con los repos
```

---

## Versionado

`MAYOR.menor.parche` — SemVer:

- **parche** (2.3.**1**): correcciones
- **menor** (2.**3**.0): funcionalidad nueva compatible
- **MAYOR** (**3**.0.0): cambio estructural o que rompe compatibilidad
- Los proyectos nuevos arrancan en **0.1.0**; el 1.0.0 se gana con estabilidad

Publicar una versión: al subir un tag `vX.Y.Z`, GitHub Actions compila y adjunta
los binarios al Release automáticamente.

---

## Licencia

Copyright (c) 2026 Gsus — Licencia MIT (ver [LICENSE](LICENSE)).
