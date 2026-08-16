# Conectar Gateway

Cliente SSH de escritorio para administrar gateways: abre los túneles a los
paneles del servidor de un clic y trae terminal SSH integrado.

Un solo ejecutable, **sin dependencias**: trae su propio motor SSH y su propia
interfaz. No necesita PuTTY, ni el cliente OpenSSH del sistema, ni instalación.

Pensado para los gateways de [`gateway-wisp-wireguard`](https://github.com/gsus67/gateway-wisp-wireguard),
pero sirve para **cualquier servidor SSH**: los túneles son configurables.

Consulta el historial acumulado de versiones en **[CHANGELOG.md](CHANGELOG.md)**.

---

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
  sube y baja archivos, crea carpetas, renombra y borra
- **Copia de seguridad** cifrada: exporta e importa toda tu configuración
- **Verifica la identidad del servidor**: si su huella cambia, se niega a conectar
- **Avisa si una conexión se cae** sola (sin que la hayas cerrado tú)
- Atajos: `Esc` cierra modales y terminal, `Ctrl+Enter` guarda el formulario
  o confirma la contraseña
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

4. **Terminal** — el botón `>_` de cada servidor conectado
   abre una shell interactiva completa (colores, `htop`, `nano`,
   autocompletado, Ctrl+C), con un panel de **historial** al costado: los
   últimos comandos enviados a ese servidor, clicables para reenviar. Es
   historial propio de la app, no reemplaza el de la shell remota (las
   flechas ↑↓ siguen siendo las del `bash` del servidor).

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

### Archivos

El botón **Archivos** de cada servidor conectado abre un explorador de dos paneles
sobre la conexión SSH que ya tienes (no abre una segunda sesión): el servidor a la izquierda y
tu equipo a la derecha. Botón **⬆ Subir** en un archivo local para enviarlo a
la carpeta remota abierta, **⬇ Bajar** en uno remoto para traerlo. También
crea carpetas, renombra y borra en el servidor.

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

Puedes conectar a más de un servidor en paralelo. Cada perfil tiene ahora
**sus propios túneles**, pero dos conexiones no pueden reservar el mismo puerto
local al mismo tiempo. Si dos perfiles usan, por ejemplo, el puerto local 8888,
el segundo no podrá abrir ese túnel mientras el primero lo tenga ocupado.

Si quieres tener paneles de varios servidores abiertos simultáneamente,
configura puertos locales distintos en cada perfil. La Terminal y SFTP siguen
funcionando aunque un túnel concreto no pueda reservar su puerto.

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
- **Endurecimiento SSH opcional**: después de generar e instalar una key, Gateway
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
- **Importaciones validadas**: las claves SSH restauradas no pueden escapar de
  `keys/` mediante rutas manipuladas, y los túneles importados pasan las mismas
  validaciones de puertos y duplicados que los creados desde la interfaz.

### Actualizaciones

El panel aparece plegado y muestra un semáforo de estado: verde (al día), amarillo (pendiente/no comprobado) y rojo (actualización disponible). de la app

Gateway puede actualizarse desde las **Releases privadas** del repositorio sin
incluir credenciales personales dentro del ejecutable. La primera vez configura
un **fine-grained personal access token** de GitHub con acceso solamente a
`gsus67/gateway-wisp-access` y permiso de repositorio **Contents: read**. En
Windows el token se guarda protegido con **DPAPI**, ligado a tu cuenta de Windows.

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
un actualizador auxiliar, cierra Gateway, reemplaza el `.exe` y vuelve a abrirlo.
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
  historial.go         Historial de comandos del terminal, por servidor
  claves.go            Carga y diagnóstico de claves SSH
  archivos.go          Gestor de archivos SFTP y explorador local
  version.go           Info de versión para el botón de actualizaciones
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


### Crear e instalar una Key SSH desde la app

En **Agregar / editar servidor**, completa nombre, host, usuario y la contraseña SSH actual y pulsa **Crear e instalar Key**. Gateway genera una ED25519, instala solo la clave pública en `~/.ssh/authorized_keys`, guarda la privada localmente y **comprueba una conexión nueva usando esa key** antes de actualizar el perfil.

Cuando la comprobación termina, Gateway pregunta si quieres **asegurar SSH**. Si aceptas, desactiva la autenticación por contraseña e interactiva, mantiene el acceso por claves y deja `root` en modo **solo key**. No usa `PermitRootLogin no` porque eso bloquearía un perfil que necesite administrar el servidor como root.

En cada **servidor conectado** hay además un botón discreto de seguridad SSH. Desde ahí puedes endurecer otra vez el servidor o volver a permitir `PasswordAuthentication` para usuarios normales. Al reabrir contraseña, `root` permanece deliberadamente en modo **solo key** (`PermitRootLogin prohibit-password`). Gateway normaliza las directivas globales conflictivas de `/etc/ssh/sshd_config`, deja intactos los bloques `Match`, valida la configuración y conserva rollback antes de confirmar el cambio.
