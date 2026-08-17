## v3.2.3

### Monitoreo simplificado y WireGuard peers

- Eliminada la dependencia funcional de Grafana: la app ya no lo instala, configura ni embebe.
- Prometheus permanece como motor de métricas e historial; la visualización diaria se hace con la interfaz nativa de Gateway WISP Access.
- Preparación del monitor reducida a cuatro fases: preflight, paquetes, configuración segura y verificación de Prometheus.
- Corregido el contrato JSON de WireGuard peers (`nombre`, `servidor`, `interfaz`, `allowedIps`, `rxMbit`, `txMbit`, `handshakeAge`). Este error hacía que la interfaz mostrara “Peer WireGuard”, `wg` y 0.00 Mbit/s aunque el backend tuviera métricas.
- Se mantiene la resolución de nombres desde WGDashboard/configuración WireGuard y el fallback a AllowedIPs/clave corta.
- Backups de Monitoreo ya no guardan credenciales de Grafana. Backups antiguos siguen siendo importables; los campos legacy se ignoran.
- Una instalación previa de Grafana no se desinstala automáticamente al actualizar, para no borrar software potencialmente reutilizado por el usuario.
- Metadata de Windows sincronizada completamente a 3.2.3.

## v3.2.2

- Corregida la publicación de GitHub Releases para reemplazar assets existentes de forma determinista con GitHub CLI y evitar conflictos de borradores duplicados.

### Monitoreo

- Preparación del servidor monitor dividida en 6 fases verificables con progreso y errores más claros.
- Espera segura de bloqueos apt/dpkg y reintentos de red para reducir fallos en la primera instalación.
- La app solo marca el monitor como preparado después de comprobar Prometheus y Grafana por HTTP local.
- Nuevo Resumen nativo y responsive con servidores online, CPU, RAM, disco y tráfico RX/TX en Mbit/s.
- Grafana pasa a una pestaña independiente para evitar que su layout interno controle toda la vista al redimensionar la app.
- Peers WireGuard compactos y actualización en tiempo real.
- Resolución de nombres de peers mejorada: WGDashboard SQLite cuando está disponible, comentarios Name/Nombre/Client/Cliente/Peer y formato WGP como fallback.

### Arquitectura

- La migración Wails/TypeScript permanece aislada hasta validar esta corrección de Monitoreo; no se reemplaza todavía la UI estable.

## v3.2.1

### Monitoreo · pulido y diagnóstico

- El apartado se muestra simplemente como **Monitoreo**, sin distintivo de versión en la interfaz.
- Progreso visible con etapa, porcentaje y registro resumido durante preparación y aplicación de targets.
- Vista compacta nativa de peers WireGuard con nombre amigable, RX/TX en Mbit/s y handshake.
- Buscador de peers y orden por nombre, descarga, subida o actividad.
- Diagnóstico por servidor monitorizado: comprueba SSH, node_exporter, túnel SSH y visibilidad desde Prometheus sin modificar la configuración.
- Base aislada `frontend-next/` para la futura migración Go + Wails + TypeScript; todavía no forma parte del build estable.
- README, Info, CHANGELOG y documentación de terceros mantenidos al día.

## v3.2.0

### Monitoreo / Grafana

- Nuevo apartado global **Monitoreo** sin modificar el flujo existente de servidores y Herramientas.
- Selección de los servidores que se desean monitorizar.
- Preparación guiada de un servidor central con **Prometheus + Grafana OSS**.
- Grafana se visualiza embebida dentro de Gateway WISP Access mediante el enlace SSH existente; no se abre un navegador externo.
- `node_exporter` escucha únicamente en `127.0.0.1:9100` en los servidores gestionados.
- Túneles SSH persistentes desde el servidor Prometheus a los targets, con asignación automática de puertos en un rango configurable (19100-19999 por defecto).
- Dashboard de infraestructura con CPU, RAM y tráfico de red en Mbit/s.
- Dashboard dedicado de **WireGuard peers** con RX/TX por peer en Mbit/s y último handshake.
- Los contadores de WireGuard se publican mediante un collector propio hacia el textfile collector de node_exporter, sin añadir un exporter de terceros adicional.
- Configuración de Monitoreo y credenciales de Grafana cifradas localmente con la clave privada de Gateway WISP Access.
- Los backups `.cgw` pueden incluir toda la configuración de Monitoreo/Grafana junto con servidores, túneles y claves SSH.
- Atribuciones y licencias actualizadas para Grafana OSS (AGPL-3.0-only), Prometheus/node_exporter (Apache-2.0) y WireGuard tools (GPLv2).
- Eliminado el distintivo visual `3.2` del menú: el apartado se llama simplemente **Monitoreo**.
- Preparación y aplicación de targets muestran progreso, etapa actual y registro resumido mientras trabajan.
- Nueva vista compacta nativa de peers WireGuard: un peer por fila con nombre amigable, servidor, RX/TX en Mbit/s y antigüedad del handshake.
- El collector intenta recuperar el nombre asignado al peer desde comentarios de la configuración WireGuard (`Name`, `Nombre`, `Client` o `Cliente`) y mantiene IP/clave corta como fallback.
- Añadida base aislada `frontend-next/` para avanzar la futura migración a Go + Wails + TypeScript sin reemplazar la UI estable.

## v3.1.14

### Integración Gateway WISP y SSH

- Gateway WISP modular 1.5.0 queda embebido dentro de la aplicación y se transfiere al servidor desde la ventana dedicada de Herramientas.
- Ventana Gateway WISP con descripción, estado, instalación/desinstalación, administración por componentes y terminal xterm interactiva para responder preguntas del instalador.
- Flujo SSH Key revisado: permite crear una ED25519 o cargar una key privada existente, instala solo la pública y verifica una segunda conexión antes de asignarla al perfil.
- Cambio de puerto SSH en dos fases: prepara el nuevo puerto manteniendo el anterior, prueba automáticamente una segunda conexión interna y solo después permite aplicar definitivamente el cambio.
- Metadata de versión de Windows sincronizada completamente a 3.1.14.

## v3.1.13

### Herramientas SSH

- Ventana dedicada de administración SSH por servidor conectado.
- **Crear e instalar ED25519** genera la privada solo en el equipo local, instala únicamente la pública y abre una segunda conexión SSH real antes de guardar el perfil.
- **Usar key existente** permite elegir una privada local como en Editar servidor; instala su pública si falta, prueba una segunda conexión y solo después la asigna al perfil.
- **Cambio seguro de puerto SSH en dos fases**: prepara puerto actual+nuevo, valida `sshd -t`, abre firewall, prueba automáticamente una segunda conexión interna y habilita Aplicar solo tras el éxito.
- La sesión actual permanece abierta. En systemd se programa además un rollback de seguridad de 5 minutos si el flujo se abandona antes de confirmar.
- Soporte para `ssh.socket`; un nftables personalizado no gestionado se rechaza antes de cambiar SSH para evitar un puerto no persistente.

### Gateway WISP modular

- Nueva ventana propia **Gateway WISP** con descripción, estado, componentes y terminal xterm interactiva en la misma vista.
- El paquete embebido se transfiere y verifica en segundo plano; los botones no dependen de escribir la extracción a ciegas en la terminal.
- Instalación completa modular y administración individual de: Sistema base, WireGuard, Firewall/NAT, QoS CAKE, DNS, WGDashboard, CrowdSec, Netdata, Panel WISP y Backups.
- Instalación completa orquestada por módulos con preguntas interactivas en la terminal integrada.
- Desinstalación conservadora con backup: retira integración WISP sin purgar automáticamente paquetes ni datos de terceros.
- Operaciones automáticas del paquete limitadas a Debian/Ubuntu.
- Firewall persistente usa el puerto SSH real, valida nftables antes de reemplazar reglas y reserva un directorio de reglas administradas.
- Corregida la clasificación QoS para que una prioridad alta no sea sobrescrita después por una clase inferior.

- Conserva Firewall, Speed Test, scripts, tráfico real en Mbit/s y selector de localhost de versiones anteriores.

## v3.1.12

### Herramientas y servidor

- El tráfico real de cada servidor conectado se expresa en **Mbit/s**.
- Nueva herramienta **Firewall** por servidor conectado.
- Detección de **UFW**, **firewalld** y **nftables** sin depender directamente de la distribución Linux.
- UFW y firewalld permiten abrir/cerrar puertos TCP o UDP cuando hay permisos root o sudo sin contraseña.
- nftables se trata de forma conservadora: Gateway solo modifica reglas creadas por la propia app y no reescribe rulesets personalizados.
- El puerto SSH usado por el perfil está protegido contra cierre accidental.
- Se crea una copia de seguridad del firewall antes de cada cambio y se comprueba que el puerto SSH siga accesible; si falla, se intenta rollback automático.

### Copias de seguridad

- **Exportar** abre ahora un diálogo **Guardar como…** para elegir la carpeta y el nombre del archivo `.cgw`, igual que Importar permite elegir el archivo de origen.
- En Windows se usa el selector nativo del sistema; Linux usa Zenity/KDialog cuando están disponibles.

## v3.1.11

- Pestaña Info reorganizada con resumen de la instalación, estadísticas, funciones, seguridad, herramientas y atajos.

- Corregido el orden estable de los servidores conectados: ya no cambian de posición en cada refresco del Dashboard.
- El tráfico de cada servidor conectado muestra ahora RX/TX real de su interfaz de red principal, muestreado de forma ligera por SSH y expresado en Mbit/s.
- Nuevo selector discreto por servidor para decidir cuál responde en `localhost:puerto` cuando varios conectados comparten los mismos túneles.
- Los puertos locales se reasignan al servidor seleccionado sin necesidad de desconectar/reconectar.

### Cambios

- El test de velocidad ya no imprime el comando/script completo en la terminal; muestra solo el resultado.
- El test se prepara como script temporal remoto y se ejecuta de forma silenciosa en la terminal integrada.
- Descarga ajustada a 75 MB para evitar respuestas vacías del endpoint en algunas rutas/edges.
- Se mantiene la prueba de subida de 50 MB y la medición de latencia HTTP.

## v3.1.10

### Herramientas

- La descripción de seguridad de Herramientas pasa a un footer real, fijo al pie de esa ventana.
- Nueva herramienta **Test de velocidad** por servidor conectado.
- La prueba abre la terminal integrada y muestra latencia HTTP, descarga y subida en vivo.
- El test usa endpoints de Cloudflare y no instala paquetes; requiere `curl` en el servidor remoto.

## v3.1.9

### Cambios

- Nuevo icono **Herramientas** junto a Terminal y Archivos en cada servidor conectado.
- Nueva ventana de herramientas preparada para incorporar utilidades por servidor.
- Primera herramienta: **Cargar y ejecutar script** desde el equipo local.
- El script se transfiere por SFTP a `/tmp/gateway-wisp-access/scripts`, con permisos privados, y se ejecuta en la terminal integrada para ver toda la salida en vivo.
- Soporte directo para scripts `.sh`/`.bash` con Bash y `.py` con Python 3; otros scripts se ejecutan por su shebang/permisos.

## v3.1.8

### Corrección del Dashboard

- Reconstruido sobre la base estable v3.1.5, descartando el layout problemático de v3.1.6.
- Actualizaciones movidas a un footer real de 38 px en el borde inferior del Dashboard.
- Servidores guardados vuelven a mostrarse correctamente y usan una cuadrícula compacta de dos columnas para aumentar la densidad.
- Restaurada la desconexión individual de cada servidor conectado, manteniendo también "Desconectar todo".
- Terminal y Archivos usan botones compactos con iconos SVG.
- Los puertos/túneles permanecen ocultos por defecto y se muestran solo al pulsar "Puertos N".
- Ajustado el layout de Terminal y Archivos para aprovechar correctamente el tamaño completo de la ventana WebView.
- Corregido el estiramiento vertical de tarjetas guardadas y conexiones: las filas conservan su altura natural y se apilan arriba.
- El texto legal/licencias deja de vivir dentro de Info y pasa a un footer real, compacto y permanente al borde inferior de la app.
- El estado de updates comparte el footer y se muestra de forma compacta únicamente en Dashboard.

## v3.1.5

### Cambios

- Iconos rehechos con SVG inline visibles y consistentes en sidebar, dashboard y acciones rápidas.
- Logo lateral corregido con un diseño más limpio y funcional.
- Vista de servidores guardados más densa y compacta para manejar decenas de perfiles.
- Tarjetas de servidores conectados compactadas para aprovechar mejor la altura de la ventana.
- La vista por defecto del listado de servidores pasa a modo compacto de una sola columna.

## v3.1.4

### Cambios

- Eliminado el marco gris exterior: la interfaz ahora ocupa completamente la ventana de la app.
- Eliminado padding exterior, borde principal y sombra del contenedor raíz para adaptarlo mejor a WebView/HTML UI.
- Fondo exterior unificado con el fondo interno para evitar que el diseño se "rompa" visualmente.

## v3.1.3

### Cambios

- Reajuste del dashboard general a un estilo más cuadrado para no romper la composición visual.
- Reducción de radios en contenedor principal, paneles, tarjetas y botones.
- Conservados únicamente radios redondos donde sí aportan: indicadores, franjas y puntos de estado.

## v3.1.2

### Cambios

- Corrección visual de bordes fríos para evitar el aspecto gris marcado de la interfaz.
- Logo lateral rediseñado con un estilo más limpio y cercano al mockup aprobado.
- Iconografía del sidebar y dashboard rehecha con un lenguaje visual más consistente.
- Ajustes de contraste y bordes en paneles, tarjetas y botones para un acabado más premium.

## v3.1.1

### Cambios

- Reajuste visual del dashboard para acercarlo más al mockup 16:9 aprobado.
- Sidebar más compacto y limpio, con iconografía más discreta.
- Botonera superior con accesos rápidos a importar servidor y crear nuevo servidor.
- Tarjetas de servidores guardados y conectados más compactas y mejor alineadas.
- Nuevo resumen visual de actualizaciones dentro del dashboard.
- Tamaño inicial de ventana ajustado a 16:9 (1440x810) en Windows.

## v3.1.0

### Interfaz por vistas

- El Dashboard queda dedicado únicamente a servidores guardados y conexiones activas.
- Perfiles, Copias, Actualizaciones e Info pasan a ser vistas independientes controladas desde el sidebar.
- Eliminados botones y paneles duplicados del Dashboard.
- Eliminado el elemento redundante Servidores del sidebar; los servidores ya viven en Dashboard.
- El estado de actualizaciones se muestra directamente en el botón Updates del sidebar.
- La ventana nativa de Windows abre a 1320×860 para conservar el layout de dos columnas y acercarse al mockup aprobado.
- Editar un servidor cambia automáticamente a la vista Perfil SSH sin hacer scroll extraño.

## v3.0.1

### Corrección del rediseño de interfaz

- La interfaz ahora ocupa toda la ventana nativa y elimina el marco gris/espacio exterior del primer rediseño.
- Sidebar reducido y dashboard compacto para el tamaño real de la ventana de Gateway.
- Tarjetas de servidores reajustadas para evitar nombres cortados por la etiqueta del método SSH.
- Scroll movido al área de contenido para evitar que toda la ventana se vea como una página web larga.
- Los botones del sidebar ahora son funcionales: Servidores, Perfiles, Copias, Updates e Info navegan y despliegan la sección correspondiente.
- Los botones superiores “Nuevo servidor” y “Actualizaciones” ahora abren realmente sus paneles.
- Fondo con algoritmos SSH algo más visible, manteniéndolo detrás del contenido.
- Se conserva sin cambios la lógica de conexión SSH, Terminal, Archivos, túneles, updater y hardening SSH.
- Eliminado el workflow antiguo duplicado de GitHub Actions para dejar un solo build/release oficial.

## v3.0.0

### Cambios

- Rediseño completo de la interfaz principal con layout tipo dashboard.
- Nuevo sidebar lateral y encabezado visual más moderno.
- Fondo sutil con referencias a algoritmos SSH y elementos de seguridad.
- Tarjetas renovadas para servidores guardados y conexiones activas.
- Mantiene la lógica existente de Terminal, Archivos, túneles, actualizaciones y seguridad SSH.
- Conserva menús plegables y el estado visual de actualizaciones.

# Historial de cambios

Este archivo concentra los cambios de cada versión de **Conectar Gateway / Gateway WISP Access**.  
A partir de ahora, cada nueva versión se añade al inicio de este mismo archivo en lugar de crear un `RELEASE_NOTES_vX.X.X.md` nuevo.

## v2.9.4

### Normalización de `sshd_config`

- Al asegurar SSH, Gateway ya no se limita a anteponer su bloque: comenta las directivas globales conflictivas preexistentes de `PubkeyAuthentication`, `PasswordAuthentication`, `KbdInteractiveAuthentication`, `ChallengeResponseAuthentication` y `PermitRootLogin`.
- Las líneas anteriores quedan visibles como `# Gateway WISP previous: ...`, por lo que el archivo sigue siendo auditable y no se pierde la configuración original.
- Gateway deja intacto todo lo que aparezca desde el primer bloque `Match`, evitando modificar reglas condicionales por usuario, grupo, red u otras condiciones.
- La misma normalización se aplica al volver a permitir contraseña, manteniendo un único bloque administrado por Gateway y `root` en modo solo-key.
- Se mantienen los backups transaccionales, `sshd -t`, verificación efectiva, recarga, prueba de key y prueba real de autenticación por contraseña.
- Sincronizada la versión de aplicación y metadatos de Windows a **2.9.4**.

## v2.9.3

### Corrección del panel de actualizaciones

- Corregido el panel **Actualizaciones de la app** para que realmente permanezca plegado por defecto.
- Corregida la prioridad CSS que hacía que `.updapp { display:flex }` anulase el estado oculto de `.plegable`.
- El encabezado sigue mostrando el indicador de estado y el resumen aunque el contenido esté cerrado.
- Al hacer clic en el encabezado, el panel ahora alterna correctamente entre abierto y cerrado.
- Sincronizada la versión de aplicación y metadatos de Windows a **2.9.3**.

## v2.9.2

### Control reversible de seguridad SSH

- Añadido un botón discreto en cada servidor conectado para consultar y cambiar la política SSH administrada por Gateway.
- Cuando el servidor está endurecido, el botón muestra **SSH seguro** y permite volver a habilitar `PasswordAuthentication` para usuarios normales.
- Cuando Gateway tiene habilitado acceso por contraseña, el botón muestra **SSH password** y permite volver a endurecer el servidor.
- Al volver a permitir contraseña se mantiene `PermitRootLogin prohibit-password`: root continúa entrando únicamente por key.
- Cada cambio valida `sshd -t`, comprueba los valores efectivos, recarga `ssh`/`sshd` y confirma que la key continúa funcionando.
- Para usuarios no-root, cuando se proporciona la contraseña, Gateway verifica además una conexión real por password antes de confirmar que el acceso quedó reabierto.
- El hardening ahora elimina también cualquier bloque previo de “password access” administrado por Gateway antes de aplicar la política segura.
- Los rollbacks ahora usan un backup transaccional de la configuración inmediatamente anterior, evitando restaurar por accidente un estado demasiado antiguo después de alternar varias veces.
- Se conserva además un backup original de referencia antes del primer endurecimiento.
- Sincronizada la versión de aplicación y metadatos de Windows a **2.9.2**.

## v2.9.1

### Estado de actualizaciones

- **Actualizaciones de la app** aparece plegado por defecto, igual que los demás menús secundarios.
- Añadido un indicador circular visible desde el encabezado: verde = al día, amarillo = pendiente/no comprobado, rojo = hay una actualización disponible.
- El encabezado muestra también un resumen corto del estado sin necesidad de desplegar el menú.

### Seguridad SSH

- Corregido el endurecimiento SSH en servidores donde la prioridad de `sshd_config`/`Include` hacía que un drop-in no desactivara realmente la contraseña.
- Gateway ahora conserva `/etc/ssh/sshd_config.gateway-wisp.bak` y coloca un bloque gestionado al principio de `/etc/ssh/sshd_config`, evitando que una directiva anterior gane por precedencia.
- Se mantiene `PubkeyAuthentication yes`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no` y `PermitRootLogin prohibit-password`.
- Antes de confirmar el cambio se valida con `sshd -t`, se comprueba la configuración efectiva y se recarga `ssh`/`sshd`.
- Después de la recarga se verifica que la key todavía abre una conexión independiente.
- Añadida una prueba negativa real: Gateway intenta una conexión nueva usando solo contraseña/keyboard-interactive y **solo informa éxito si el servidor la rechaza**.
- Si la key deja de funcionar, la contraseña todavía funciona o no se puede verificar de forma fiable, Gateway restaura el backup y recarga SSH.
- Sincronizada la versión de aplicación y metadatos de Windows a **2.9.1**.

## v2.9.0

### Actualizaciones automáticas seguras

- Añadido actualizador integrado para Releases de un repositorio privado de GitHub.
- La credencial de GitHub la proporciona el usuario; no existe ningún token personal embebido en el ejecutable.
- En Windows el token se protege con **DPAPI**, ligado a la cuenta de Windows que lo guardó.
- Compatible con un **fine-grained personal access token** limitado a este repositorio y `Contents: read`.
- Las Releases deben incluir `update-manifest.json` y `update-manifest.sig`; la app verifica una firma **Ed25519** con una clave pública embebida antes de confiar en la versión o en sus hashes.
- El ejecutable descargado se valida además por **SHA-256** y tamaño contra el manifest firmado.
- El workflow genera y firma automáticamente el manifest al publicar un tag `v*`; la clave privada vive únicamente en el secret `UPDATE_SIGNING_PRIVATE_KEY_PEM` de GitHub Actions.
- La app rechaza downgrades automáticos y solo ofrece instalar una versión superior.
- En Windows la actualización usa un proceso auxiliar temporal para reemplazar el `.exe`, conserva brevemente el anterior como rollback y vuelve a abrir la app.
- Añadida opción para buscar actualizaciones al iniciar, mostrar las notas de la Release, borrar el token y actualizar con un clic.
- Sincronizada la versión de aplicación y metadatos de Windows a **2.9.0**.

## v2.8.1

### Terminal SSH

- Corregido un fallo que impedía escribir en la Terminal integrada: `ui.html` cargaba `xterm.css`, pero no estaba cargando los scripts locales `xterm.js` y `addon-fit.js`.
- La Terminal ahora valida que xterm.js y FitAddon estén disponibles antes de abrirse y muestra un aviso claro si falta algún recurso.
- Reforzado el foco del teclado al abrir la Terminal, al establecer el WebSocket y al hacer click dentro del área del terminal.
- Se limpia correctamente el contenedor de xterm al cerrar/reabrir una sesión para evitar restos de instancias anteriores.
- Añadido un mensaje visible si falla el WebSocket de la Terminal.
- Sincronizada la versión de aplicación y los metadatos de Windows a **2.8.1**.

## v2.8.0

### Asistente de seguridad SSH

- Después de **Crear e instalar Key**, Gateway comprueba que la ED25519 nueva puede abrir una conexión SSH independiente antes de cambiar el perfil.
- Tras verificar la key, la aplicación pregunta **¿Asegurar SSH ahora?**.
- La opción de endurecimiento mantiene `PubkeyAuthentication yes`, desactiva `PasswordAuthentication` y `KbdInteractiveAuthentication`, y configura `PermitRootLogin prohibit-password`.
- `root` no se desactiva por completo: queda permitido únicamente mediante key, evitando bloquear perfiles que administran el servidor directamente como root.
- Antes de tocar `sshd`, Gateway vuelve a comprobar la key; valida la configuración con `sshd -t`, verifica los valores efectivos con `sshd -T` y recarga `ssh`/`sshd`.
- Después de la recarga se prueba una tercera conexión mediante key. Si esa comprobación falla, Gateway intenta retirar el endurecimiento y recargar SSH mientras la sesión original sigue disponible.
- Para usuarios no-root se utiliza `sudo` con la contraseña que se acaba de usar para instalar la key.
- La instalación en `authorized_keys` evita añadir duplicados exactos en reintentos.

### Interfaz y túneles

- **Túneles de este servidor** aparece plegado por defecto dentro de Agregar / editar servidor, igual que el resto de menús desplegables.
- El encabezado plegado muestra cuántos túneles tiene configurado el perfil.
- El contador se actualiza al agregar o quitar túneles.

## v2.7.2

### Build y Releases

- Se mantiene la corrección de los túneles predeterminados usando campos nombrados, evitando `too few values in struct literal`.
- El workflow ahora compila también cada `push` a `main` y puede ejecutarse manualmente con `workflow_dispatch`.
- La publicación en GitHub Release se ejecuta únicamente cuando el build corresponde a un tag `v*`.
- Esto permite detectar errores de compilación antes de crear una versión/tag y evita confundir un re-run de un tag viejo con el código actual de `main`.
- Sincronizada la versión de aplicación y los metadatos de Windows a **2.7.2**.

## v2.7.1

### Correcciones

- Corregida la compilación después de añadir `AbrirWeb` al modelo de túneles.
- Los túneles predeterminados ahora usan campos nombrados (`Puerto`, `Nombre`, `Ruta`) para evitar que futuros campos nuevos rompan el build.
- Corregido el error `too few values in struct literal` en `main.go`.
- Sincronizada la metadata de Windows a **2.7.1** (`Patch: 1`).

## v2.7.0

### Claves SSH

- Añadido el asistente **Crear e instalar Key**.
- Genera una clave **ED25519** localmente desde la aplicación.
- Usa la contraseña actual una sola vez para instalar la clave pública en `~/.ssh/authorized_keys`.
- Mantiene la comprobación TOFU de la huella SSH durante la instalación.
- Después de instalar y comprobar la key, el perfil cambia automáticamente a autenticación por clave.
- La clave privada nunca se copia al servidor; permanece local y se guarda con permisos restrictivos dentro de `keys/`.

### Túneles por servidor

- Cada perfil guarda su propia lista de túneles, puertos, nombres y rutas web.
- Añadida la opción **Auto web** por túnel.
- Al conectar, solo se abre automáticamente el navegador para los túneles marcados que hayan podido iniciarse correctamente.
- Los backups conservan los túneles de cada servidor y los validan al importar.
- Un servidor puede tener cero túneles sin que vuelvan automáticamente los predeterminados.

### Aplicación

- Eliminado el botón **Cerrar aplicación**.
- En Windows, cerrar la ventana nativa termina la aplicación y cierra conexiones SSH, SFTP, túneles y el servidor HTTP local.

## v2.6.2

### Terminal y Archivos

- **Archivos** pasa a abrirse como una vista completa, siguiendo el mismo patrón visual que la Terminal.
- Añadido un botón compacto de Archivos junto al botón de Terminal en cada servidor conectado.
- Terminal y Archivos se muestran donde son funcionalmente útiles: en **Servidores conectados**.
- Eliminado Terminal de **Servidores guardados**; los perfiles guardados quedan para Conectar, Editar y Borrar.
- Eliminada la antigua sección desplegable global de Archivos del dashboard.
- `Esc` cierra tanto el explorador de Archivos como la Terminal.
- El explorador mantiene los paneles **Servidor remoto** y **Tu equipo**, con subir, bajar, renombrar, borrar y crear carpetas mediante SFTP.
- **Buscar…** para seleccionar una clave SSH sigue usando el explorador local aunque no haya un servidor conectado.

## v2.6.1

### Seguridad

- Eliminado el uso de `innerHTML` para datos dinámicos; los datos no confiables se insertan mediante DOM y `textContent` para mitigar XSS dentro del WebView.
- Protegida la importación de claves SSH contra **path traversal**.
- Los nombres de claves importadas se validan y se comprueba que el destino permanezca dentro de `keys/`.
- Los túneles importados pasan la misma validación que los creados desde la interfaz: puertos válidos, sin duplicados y con límites de nombre/ruta.
- Añadida validación del formato interno de los paquetes `.cgw` y del modo de importación.

### Concurrencia y estabilidad

- `ssh.Dial` deja de mantener bloqueado el mutex global mientras espera al servidor.
- SFTP utiliza un mutex por conexión en lugar del mutex global.
- La huella SSH aceptada se guarda de forma sincronizada después de establecer la conexión correctamente.

### Interfaz

- La ventana nativa de Windows se centra automáticamente al abrirse.
- Reorganizadas las acciones de las tarjetas de servidores.
- Corregida la `✕` de borrar perfil para que permanezca dentro del borde de la tarjeta.
- Mejor adaptación de los botones en ventanas estrechas.
