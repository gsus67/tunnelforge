# Historial de cambios

Este archivo concentra los cambios de cada versión de **Conectar Gateway / Gateway WISP Access**.  
A partir de ahora, cada nueva versión se añade al inicio de este mismo archivo en lugar de crear un `RELEASE_NOTES_vX.X.X.md` nuevo.

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
