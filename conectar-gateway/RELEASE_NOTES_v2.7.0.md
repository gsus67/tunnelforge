# Conectar Gateway v2.7.0

## Novedades

- **Asistente de Key SSH:** botón `Crear e instalar Key` que genera una ED25519 local, usa la contraseña actual una sola vez para instalar la pública en `~/.ssh/authorized_keys`, verifica la huella SSH y cambia el perfil automáticamente a autenticación por clave.
- **Túneles por servidor:** cada perfil guarda su propia lista de puertos, nombres y rutas web. Ya no hace falta compartir una sola configuración de túneles entre todos los gateways.
- **Auto web por túnel:** cada puerto tiene una casilla `Auto web`; al conectar, la app abre automáticamente en el navegador solo los paneles marcados cuyo túnel pudo abrirse correctamente.
- **Cierre simplificado:** eliminado el botón `Cerrar aplicación`. En Windows, cerrar la ventana nativa cierra conexiones SSH, listeners/túneles, SFTP y el servidor HTTP local.
- Los backups conservan los túneles individuales de cada servidor y los validan al importar.

## Seguridad

- La clave privada generada nunca se copia al servidor; solo se instala la pública.
- La primera instalación de una key mantiene la verificación TOFU de la huella del host SSH.
- Las claves ED25519 generadas se guardan con permisos restrictivos dentro de la carpeta `keys` de Gateway.
- Continúan vigentes las correcciones de XSS, path traversal y validaciones de importación introducidas en 2.6.x.
