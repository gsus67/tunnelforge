# v3.5.0 — Acceso web local

Añade una vista **Web local** para iniciar, desde Gateway WISP Access, un servidor LAN opcional y abrir la misma interfaz desde un teléfono, tablet u otra PC de la red.

## Seguridad

- Apagado por defecto y detenido automáticamente al cerrar la app.
- Código aleatorio de 6 dígitos con bloqueo temporal tras intentos fallidos.
- Sesión mediante cookie HttpOnly ligada a la IP del cliente.
- El navegador remoto nunca recibe el token maestro de la API.
- Rechazo de clientes con IP pública; no se configura UPnP ni port-forwarding.
- Los controles para iniciar/detener/cambiar el código solo están disponibles desde la app de escritorio.

## Interfaz

- La misma compilación TypeScript funciona en Wails y en navegador.
- Nuevo layout responsive para pantallas pequeñas.
- Puerto LAN configurable, por defecto `8788`, con direcciones locales mostradas en la propia app.

Los paneles que existen únicamente detrás de túneles `localhost` no se publican en la LAN; desde el navegador remoto se abren en la PC que ejecuta Gateway.
