# TunnelForge

Cliente de escritorio para Windows y Linux: SSH con túneles y terminal,
WireGuard local y monitoreo de servidores, en un solo ejecutable. Abre los
túneles a los paneles del servidor de un clic y trae terminal SSH integrado.

Un solo ejecutable de la aplicación: trae su propio motor SSH y toda la interfaz. No necesita PuTTY ni el cliente OpenSSH del sistema. En Windows usa WebView2 (incluido normalmente en Windows 10/11) y en Linux usa WebKitGTK del sistema.

Pensado para los gateways de [`gateway-wisp-wireguard`](https://github.com/gsus67/gateway-wisp-wireguard),
pero sirve para **cualquier servidor SSH**: los túneles son configurables.

Consulta el historial acumulado de versiones en **[CHANGELOG.md](CHANGELOG.md)**.

### Flujo de publicación seguro

Para evitar crear tags de versiones que todavía no compilan, primero se suben los cambios a `main` **sin tag**. El workflow ejecuta validaciones de Go, TypeScript, host WireGuard y builds completos de Windows/Linux. Solo cuando ambos jobs están verdes se crea el tag `vX.Y.Z`; el job de Release depende de esos builds y no publica si alguno falla.

## Dashboard

Vista principal para administrar servidores guardados, conexiones SSH activas, túneles, terminal, archivos y estado de actualizaciones desde una sola ventana.

---


## Acceso web local

Desde la propia aplicación puedes iniciar un servidor web para la LAN y abrir **la misma interfaz** desde un teléfono, tablet u otra PC usando la IP privada del equipo. El modo está apagado por defecto, usa un código aleatorio de 6 dígitos, no configura UPnP ni port-forwarding y el navegador remoto nunca recibe el token maestro de la API.

El acceso web está pensado para una **red local de confianza**. La sesión se guarda en una cookie HttpOnly ligada a la IP del cliente y el servidor se detiene automáticamente al cerrar TunnelForge. Los accesos a paneles que solo escuchan en `localhost` (por ejemplo, túneles web SSH) **no se republican en la LAN**; al pulsarlos desde el navegador remoto, TunnelForge los abre en la PC que ejecuta la aplicación.

---

## WireGuard

TunnelForge mantiene WireGuard con configuración y estadísticas estrictamente separadas, mide el tráfico de Monitoreo sobre la interfaz principal del servidor y muestra el tráfico en Dashboard y Monitoreo en un formato compacto con flechas (`↑`/`↓`) en lugar de las palabras “Subida” y “Descarga”. WireGuard está completamente integrado en el ejecutable de Windows y no requiere instalar WireGuard for Windows ni depender de `wireguard.exe`/`wg.exe`.

TunnelForge incluye WireGuard local para Windows y Linux. El build oficial de Windows incorpora `tunnel.dll`, el `wireguard.dll` precompilado oficial de WireGuardNT y un host nativo mínimo (`wg-service-host.exe`) como recursos internos del propio `TunnelForge.exe`. La app los extrae a su directorio privado de runtime únicamente cuando se usa WireGuard.

- Perfiles múltiples con búsqueda, estado conectado/desconectado y autoconexión.
- Importación y exportación de archivos `.conf`.
- Generación local de **PrivateKey/PublicKey** y **PresharedKey**.
- Múltiples peers por perfil, con nombre amigable, Endpoint, AllowedIPs, PersistentKeepalive y opción para excluir el tráfico local/LAN del túnel.
- Configuración de Address, DNS, MTU, ListenPort y Table.
- Atajo de túnel completo IPv4 + IPv6 (`0.0.0.0/0, ::/0`) y bypass LAN por peer usando rutas `/1` equivalentes cuando se activa **Excluir tráfico local**.
- Tráfico RX/TX en **Mbit/s**, totales transferidos, interfaz activa y último handshake cuando el motor del sistema expone esas métricas.
- Estado en vivo por peer cuando `wg` permite leer sus contadores.
- Vista centrada en el estado del túnel: RX/TX, totales, handshake, interfaz y una fila por peer; la configuración completa se abre con **⚙ Configuración**.
- PrivateKey y PresharedKey se guardan cifradas en el almacenamiento local de TunnelForge.
- Los perfiles pueden incluirse en el backup portable `.cgw`; sus secretos viajan dentro del contenedor cifrado del backup y se vuelven a cifrar al restaurar.
- Los hooks `PreUp`, `PostUp`, `PreDown` y `PostDown` importados se conservan, pero quedan **deshabilitados por defecto** hasta que el usuario los autoriza expresamente.

En Windows **no hace falta instalar ningún cliente WireGuard aparte**: TunnelForge registra un servicio `WireGuardTunnel$...` cuyo ejecutable es el host nativo privado extraído desde la propia aplicación; ese host carga el motor oficial `tunnel.dll`. Para el usuario sigue siendo una sola aplicación, sin instalador adicional. Las estadísticas RX/TX y handshake las consulta el host del servicio mediante la API de WireGuardNT y entrega a la UI únicamente telemetría sin secretos; la aplicación completa no necesita ejecutarse como administrador. En Linux se mantiene `wireguard-tools` (`wg`/`wg-quick`) del sistema y puede instalarse mediante el gestor de paquetes compatible cuando hay `pkexec`.

> TunnelForge no es el cliente oficial de WireGuard. El nombre WireGuard se utiliza para describir compatibilidad e integración con el software/protocolo correspondiente; cada componente externo conserva su licencia y autoría. Consulte [TERCEROS.md](TERCEROS.md).

---

## Monitoreo

TunnelForge puede preparar un servidor central con **Prometheus** y monitorizar únicamente los perfiles que el usuario seleccione. Los agentes `node_exporter` quedan ligados a `127.0.0.1:9100`; Prometheus accede a ellos mediante túneles SSH persistentes administrados por la aplicación.

- Puertos locales de túnel asignados automáticamente (rango 19100–19999 configurable).
- Resumen nativo de CPU, RAM, disco y tráfico RX/TX en Mbit/s por servidor.
- Vista compacta de peers WireGuard, un peer por fila, con nombre amigable, RX/TX en Mbit/s y último handshake.
- Búsqueda y orden de peers por nombre, descarga, subida o actividad.
- Diagnóstico por servidor para comprobar SSH, node_exporter, túnel y Prometheus sin cambiar la configuración.
- Progreso visible durante la preparación de Prometheus y al aplicar targets.
- Configuración de Monitoreo cifrada localmente.
- Nombres de peers obtenidos de WGDashboard cuando existe una base SQLite compatible y con fallback a comentarios WireGuard/AllowedIPs.
- La copia `.cgw` puede transportar toda la configuración de Monitoreo junto con servidores, túneles y claves SSH.

**Grafana no es necesario ni lo instala la aplicación**: la vista nativa cubre el resumen y los peers, mientras Prometheus permanece como motor de recolección e historial. Si una versión anterior instaló Grafana en un servidor, la actualización no lo desinstala automáticamente para evitar eliminar software que el usuario pueda estar utilizando por separado.

La instalación automática inicial está deliberadamente limitada a **Debian/Ubuntu** para evitar aplicar comandos de paquetes no verificados sobre distribuciones distintas. Consulte `TERCEROS.md` para las licencias de Prometheus, node_exporter y WireGuard tools.

### Arquitectura de escritorio

La interfaz de producción usa **Go + Wails + TypeScript**. Wails ofrece la ventana nativa en Windows y Linux; el backend Go maneja SSH, SFTP, túneles, cifrado, updater y Monitoreo. El frontend vive en `conectar-gateway/frontend/` y se compila desde TypeScript antes de generar el binario.

La API existente se reutiliza dentro del `AssetServer` de Wails para reducir regresiones; únicamente la Terminal mantiene un WebSocket loopback en `127.0.0.1`, protegido por token y con el origen interno de Wails autorizado explícitamente.

La API loopback protegida sigue existiendo como canal interno para el WebSocket de Terminal y compatibilidad de los módulos ya estabilizados. La UI también puede publicarse **de forma opcional** en la LAN mediante el módulo Web local autenticado; ese servidor es independiente del listener loopback y permanece apagado hasta que el usuario lo inicia.

## Qué hace

- **Guarda tus servidores** con key SSH o contraseña, y conecta con un clic
- **Varias conexiones a la vez**: puedes tener dos o más gateways conectados
  en paralelo (ver [limitación de puertos](#varias-conexiones-a-la-vez) abajo)
- **Abre todos los túneles a la vez** y muestra accesos directos a cada panel
- **Tráfico en vivo** por conexión: velocidad de subida/bajada y total transferido
- **Terminal SSH integrado**, con **historial de comandos** que persiste entre sesiones
- **Favoritos y orden manual**: marca con ★ o arrastra para reordenar la lista
- **Buscador** de servidores por nombre, host o usuario
- **Gestor de archivos (SFTP)**: navega el servidor y tu equipo lado a lado,
  sube y baja archivos, crea carpetas, renombra, borra y edita texto UTF-8
- **Herramientas por servidor**: scripts, test de velocidad, firewall y administración SSH segura desde una ventana con terminal interactiva.
- **Tráfico real**: RX/TX de la interfaz principal del servidor mostrado en Mbit/s.
- **Web local opcional**: publica la misma interfaz en la LAN para usar TunnelForge desde teléfono, tablet u otra PC con código de acceso.
- **Firewall seguro**: protege el puerto SSH, crea backup antes de cambios y evita reescribir reglas nftables personalizadas.
- **SSH administrado**: crea/instala keys, carga una key local existente y cambia el puerto SSH solo después de verificar una segunda conexión real.

- **Copia de seguridad** cifrada: exporta e importa toda tu configuración
- **Verifica la identidad del servidor**: si su huella cambia, se niega a conectar
- **Avisa si una conexión se cae** sola (sin que la hayas cerrado tú)
- Atajos: `Esc` cierra modales y terminal, `Ctrl+Enter` guarda el formulario
  o confirma la contraseña
- Todo local: la UI vive dentro de Wails; solo el canal interno/terminal mantiene un listener protegido en `127.0.0.1`

---

## Instalación

Descarga el ejecutable de la pestaña **[Releases](../../releases)**:

| Archivo | Sistema |
|---|---|
| `TunnelForge.exe` | Windows 10/11 (64 bits) |
| `tunnelforge-linux` | Linux (64 bits) |

Ponlo donde quieras y ábrelo. La aplicación no necesita PuTTY ni OpenSSH para sus funciones SSH. Wails usa el WebView del sistema. En **Windows**, WireGuard ya viene dentro del ejecutable oficial; en **Linux**, la VPN local requiere `wireguard-tools` del sistema.

En **Windows y Linux** se abre en su propia ventana Wails. En Windows se requiere Microsoft WebView2 (normalmente ya instalado). En Linux se requiere GTK3 + WebKitGTK 4.1; en Debian/Ubuntu modernos se cubre con los paquetes `libgtk-3-0` y `libwebkit2gtk-4.1-0`.

---

## Uso

1. **Agregar un servidor** — en el formulario: nombre, IP, puerto SSH, usuario y
   la ruta de tu key SSH *o* la contraseña. Marca *Recordar contraseña* si
   quieres guardarla cifrada; si no, se pide al conectar y no queda en disco.

2. **Conectar** — clic en *Conectar*. La primera vez muestra la huella del
   servidor para que la verifiques; a partir de ahí se exige que no cambie.

3. **Usar los paneles** — con la conexión activa aparecen los accesos directos;
   se abren en tu navegador por defecto.

4. **Terminal** — el botón con icono de terminal de cada servidor conectado
   abre una shell interactiva completa (colores, `htop`, `nano`,
   autocompletado, Ctrl+C), con un panel de **historial** al costado: los
   últimos comandos enviados a ese servidor, clicables para reenviar. Es
   historial propio de la app, no reemplaza el de la shell remota (las
   flechas ↑↓ siguen siendo las del `bash` del servidor).

5. **Desconectar** — cierra los túneles. Cerrar la ventana también los cierra.

### Copia de seguridad

La sección **Copia de seguridad** exporta toda tu configuración a un archivo
`.cgw`: servidores, túneles, Monitoreo, perfiles de WireGuard y, opcionalmente, las contraseñas guardadas y el
contenido de tus claves SSH privadas.

El archivo se cifra con **una contraseña que tú eliges** (scrypt + AES-256-GCM),
no con la llave de este equipo: por eso se puede llevar a otra PC, a un USB o al
NAS y seguir siendo seguro. Sin esa contraseña el contenido es irrecuperable.

Al importar en otro equipo, la app restaura los servidores, aplica los túneles,
guarda las claves SSH en su carpeta de configuración y reapunta las rutas
automáticamente. Puedes **fusionar** con lo que ya tengas (por defecto, los
nombres repetidos se actualizan) o **reemplazar todo**.

### Archivos

El botón **Archivos** de cada servidor conectado abre un explorador de dos paneles
sobre la conexión SSH que ya tienes (no abre una segunda sesión): el servidor a la izquierda y
tu equipo a la derecha. Botón **⬆ Subir** en un archivo local para enviarlo a
la carpeta remota abierta, **⬇ Bajar** en uno remoto para traerlo. También
crea carpetas, renombra y borra en el servidor.

Los documentos remotos de texto UTF-8 de hasta 2 MB se pueden abrir con
**Editar**. El guardado reemplaza el archivo de forma atómica, conserva sus
permisos y avisa si cambió en el servidor desde que se abrió.

Requiere que el servidor tenga el subsistema SFTP activo, que viene por
defecto en Debian y la mayoría de distribuciones.

### Claves SSH

Si la clave da problemas, el botón **Probar** dice exactamente qué pasa:
ruta inexistente, apuntar a la clave pública `.pub` por error, formato PuTTY
`.ppk` (no compatible: conviértela con PuTTYgen), permisos, o que la clave
tenga **passphrase** — en ese caso la app la pide al conectar y puedes
guardarla cifrada como cualquier contraseña.

El botón **Buscar…** abre el explorador para elegir el archivo sin teclear la
ruta. Las rutas se normalizan solas: se aceptan comillas pegadas al copiar
desde el Explorador, `~` y variables como `%USERPROFILE%`.

### Varias conexiones a la vez

Puedes conectar a más de un servidor en paralelo. Cada perfil mantiene sus
propios túneles. Si varios servidores usan el mismo puerto local (por ejemplo
8888), el selector discreto de **localhost activo** decide cuál responde en
`localhost:puerto`; cambiar la selección reasigna esos puertos sin tener que
cerrar las conexiones SSH. Terminal y SFTP siguen siendo independientes.

### Túneles por servidor

Vienen configurados los cinco del gateway WISP. El bloque **Túneles de este servidor** aparece plegado por defecto dentro de **Agregar / editar servidor**; al abrirlo se pueden quitar, renombrar o ampliar. Cada perfil mantiene sus propios túneles y puede marcar **Auto web** para abrir un panel al conectar:

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
- **Endurecimiento SSH opcional**: después de generar e instalar una key, TunnelForge
  comprueba que realmente funciona y puede desactivar el login por contraseña.
  Mantiene `root` únicamente por key (`PermitRootLogin prohibit-password`) para
  no bloquear perfiles administrativos. Valida con `sshd -t`/`sshd -T`, recarga
  SSH y vuelve a probar la key; ante un fallo intenta revertir el cambio.
- **Nada expuesto**: la interfaz escucha solo en `127.0.0.1`, protegida por un
  token de sesión aleatorio.
- **Enlaces restringidos**: la app solo abre en el navegador direcciones de tus
  túneles locales; cualquier otro destino se rechaza.
- **Interfaz endurecida contra XSS**: nombres de servidores, archivos, errores y
  datos importados se insertan como texto mediante el DOM, no como HTML ejecutable.
- **Exportación con destino elegible**: al exportar una copia cifrada se abre **Guardar como…** para elegir dónde crear el `.cgw`.
- **Importaciones validadas**: las claves SSH restauradas no pueden escapar de
  `keys/` mediante rutas manipuladas, y los túneles importados pasan las mismas
  validaciones de puertos y duplicados que los creados desde la interfaz.

### Actualizaciones

El panel de la app aparece plegado y muestra un semáforo de estado: verde (al día), amarillo (pendiente/no comprobado) y rojo (actualización disponible).

El repositorio de Releases es **público**, así que buscar e instalar
actualizaciones no requiere ninguna credencial ni configuración: el panel de
Actualizaciones tiene un solo paso, comprobar e instalar.

El actualizador no confía únicamente en GitHub ni en un SHA-256 publicado al lado
del binario. Cada Release lleva un `update-manifest.json` firmado con **Ed25519**;
la aplicación contiene solo la clave pública y rechaza cualquier manifest cuya
firma no sea válida. Después comprueba el SHA-256 y tamaño del ejecutable contra
ese manifest firmado antes de instalarlo.

Para publicar Releases firmadas, el repositorio necesita una sola vez el secret
de Actions `UPDATE_SIGNING_PRIVATE_KEY_PEM`. La clave privada de firma **no debe
subirse al repositorio ni incluirse en el ejecutable**. El workflow comprueba que
el secret corresponde a la clave pública embebida antes de publicar.

En Windows, **Actualizar ahora** descarga y verifica el nuevo ejecutable, arranca
un actualizador auxiliar, cierra TunnelForge, reemplaza el `.exe` y vuelve a abrirlo.
La app no instala automáticamente versiones inferiores a la actual. En Linux, por
ahora, la comprobación de Releases funciona pero el reemplazo automático del
binario está deshabilitado.

### Dónde se guardan tus datos

En el perfil del usuario, así sobreviven a mover o actualizar el ejecutable:

| Sistema | Ruta |
|---|---|
| Windows | `%APPDATA%\conectar-gateway\` |
| Linux | `~/.config/conectar-gateway/` |

Ahí quedan `conexiones.json` (servidores, huellas y favoritos), `secreto.bin`
(llave de cifrado), `ajustes.json` (túneles), `historial.json` (últimos
comandos por servidor) y `keys/` (claves SSH importadas de una copia). Nada
de esto se sube al repositorio.

**Modo portable**: crea un archivo vacío llamado `portable` junto al ejecutable
y los datos se guardarán a su lado — útil para llevarlo en un USB o un NAS.

---

## Cómo está hecho

| Pieza | Librería |
|---|---|
| Motor SSH: conexión, túneles y terminal | [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) |
| Ventana nativa Windows/Linux | [Wails v2.13](https://github.com/wailsapp/wails) |
| Terminal de la interfaz (el mismo de VS Code) | [xterm.js](https://github.com/xtermjs/xterm.js) |
| Canal del terminal | [coder/websocket](https://github.com/coder/websocket) |

La lógica Go, el frontend TypeScript compilado y xterm.js van **embebidos en el ejecutable**. Wails utiliza el motor web del sistema: WebView2 en Windows y WebKitGTK en Linux. Detalle de licencias en [TERCEROS.md](TERCEROS.md).

---

## Compilar desde el código

Requiere **Go 1.25+**, Node.js y **Wails v2.13.0**. El proyecto fija Go 1.25 porque el módulo de Wails v2.13.0 declara esa versión de Go:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.13.0
cd conectar-gateway
go mod tidy
```

El repositorio conserva `frontend/dist/.keep` a propósito: Wails genera bindings antes de que el frontend final exista y `//go:embed all:frontend/dist` necesita al menos un archivo en un checkout limpio. El contenido real de `frontend/dist` es generado durante el build y no se versiona.

Windows (build completo con WireGuard embebido):

```powershell
.\herramientas\preparar-wireguard-windows.ps1
cd conectar-gateway
wails build -clean -tags wireguard_embedded -o TunnelForge
```

El script fija **WireGuard for Windows v1.1** a un commit concreto, ejecuta su `embeddable-dll-service` oficial y coloca temporalmente `tunnel.dll` + el `wireguard.dll` precompilado oficial en `wireguard-assets/`. Esos DLL están ignorados por Git y se incrustan en el `.exe` únicamente cuando se compila con `-tags wireguard_embedded`. GitHub Actions hace este paso automáticamente.

Linux (Debian/Ubuntu moderno):

```bash
sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev
wails build -clean -tags webkit2_41 -o tunnelforge-linux
```

GitHub Actions ejecuta `go mod tidy` antes de compilar para completar `go.sum`, construye Windows y Linux en runners nativos separados y reúne ambos artefactos para el Release firmado.

---

## Estructura

```
conectar-gateway/
  main.go              API interna, conexión SSH y túneles
  wails_shell.go       Ventana Wails y puente Go ↔ frontend
  frontend/            UI de producción en TypeScript
    src/main.ts         Controlador de interfaz
    index.html          Estructura visual
    style.css           Estilos
    public/static/      xterm.js
    dist/               Frontend compilado y embebido
  terminal.go          Terminal SSH sobre WebSocket
  ventana_windows.go   Diálogo nativo Guardar como… de Windows
  ventana_otros.go     Diálogo Guardar como… de Linux/macOS
  copia.go             Exportar / importar configuración cifrada
  historial.go         Historial de comandos del terminal, por servidor
  claves.go            Carga y diagnóstico de claves SSH
  archivos.go          Gestor de archivos SFTP y explorador local
  monitoring.go        Prometheus, servidores y WireGuard peers
  wails.json           Configuración de build de Wails
  icono.ico            Icono e identidad del ejecutable
herramientas/          Scripts de apoyo para trabajar con los repos
```

---

## Versionado

`MAYOR.menor.parche` — SemVer:

- **parche** (1.0.**1**): correcciones
- **menor** (1.**1**.0): funcionalidad nueva compatible
- **MAYOR** (**2**.0.0): cambio estructural o que rompe compatibilidad

TunnelForge reinició la numeración en **1.0.0** al relanzarse con nombre y
repositorio nuevos; viene de la **v3.7.0** del proyecto anterior (Gateway WISP
Access / Conectar Gateway). El historial `v2.x`/`v3.x` sigue en
[CHANGELOG.md](CHANGELOG.md) — no fue una regresión de funcionalidad.

Publicar una versión: al subir un tag `vX.Y.Z`, GitHub Actions compila y adjunta
los binarios al Release automáticamente.

---

## Licencia

Copyright (c) 2026 Gsus — Licencia MIT (ver [LICENSE](LICENSE)).


### Crear e instalar una Key SSH desde la app

En **Agregar / editar servidor**, completa nombre, host, usuario y la contraseña SSH actual y pulsa **Crear e instalar Key**. TunnelForge genera una ED25519, instala solo la clave pública en `~/.ssh/authorized_keys`, guarda la privada localmente y **comprueba una conexión nueva usando esa key** antes de actualizar el perfil.

Cuando la comprobación termina, TunnelForge pregunta si quieres **asegurar SSH**. Si aceptas, desactiva la autenticación por contraseña e interactiva, mantiene el acceso por claves y deja `root` en modo **solo key**. No usa `PermitRootLogin no` porque eso bloquearía un perfil que necesite administrar el servidor como root.

En cada **servidor conectado** hay además un botón discreto de seguridad SSH. Desde ahí puedes endurecer otra vez el servidor o volver a permitir `PasswordAuthentication` para usuarios normales. Al reabrir contraseña, `root` permanece deliberadamente en modo **solo key** (`PermitRootLogin prohibit-password`). TunnelForge normaliza las directivas globales conflictivas de `/etc/ssh/sshd_config`, deja intactos los bloques `Match`, valida la configuración y conserva rollback antes de confirmar el cambio.


### Terminal

La terminal integrada permite copiar y pegar con botones o con `Ctrl+Shift+C` / `Ctrl+Shift+V`.
