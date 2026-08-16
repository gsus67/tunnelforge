# v2.7.0 — SSH keys y túneles por servidor

Esta versión simplifica la administración diaria de gateways WISP. Ahora Gateway puede crear e instalar una clave SSH ED25519 directamente desde la interfaz: introduces la contraseña actual una sola vez, confirmas la huella del servidor y la aplicación instala únicamente la clave pública en `authorized_keys`. La privada permanece local y el perfil queda configurado para usarla automáticamente.

Los túneles pasan a configurarse por servidor. Cada perfil puede tener sus propios puertos, nombres y rutas, además de una casilla **Auto web** para abrir automáticamente el panel correspondiente cuando la conexión se establece y el puerto local quedó disponible.

También se elimina el botón **Cerrar aplicación**. En Windows basta cerrar la ventana de Gateway para terminar las conexiones, los túneles y el servidor local.

### Cambios principales
- Generación ED25519 integrada.
- Instalación automática de la clave pública por SSH.
- Confirmación de huella del host durante la instalación.
- Túneles independientes por servidor.
- Apertura web automática opcional por túnel.
- Validación de túneles por perfil al guardar/importar.
- Eliminación del botón redundante de salida.
- Mantiene las mejoras de seguridad de 2.6.x.
