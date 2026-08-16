# Conectar Gateway v2.6.1 — seguridad y ajustes de interfaz

Esta versión endurece la aplicación frente a contenido no confiable y corrige varios detalles visuales y de concurrencia.

## Seguridad

- Eliminado el uso de `innerHTML` para datos dinámicos en la interfaz. Nombres de servidores, túneles, archivos, mensajes de error y datos de copias se crean ahora con nodos DOM y `textContent`, mitigando XSS dentro del WebView.
- Protegida la importación de claves SSH contra path traversal. Los nombres importados se validan, se normalizan y se comprueba que el destino permanezca dentro de la carpeta `keys/`.
- Los túneles importados usan la misma validación que los túneles creados desde la interfaz: puertos entre 1 y 65535, sin duplicados y con límites razonables para nombre y ruta.
- Se valida también el formato interno del paquete `.cgw` y el modo de importación.

## Estabilidad y concurrencia

- La conexión SSH ya no mantiene el mutex global durante `ssh.Dial`, evitando bloquear el resto de la API mientras un servidor tarda en responder.
- La apertura perezosa del canal SFTP usa un mutex por conexión en lugar del mutex global, reduciendo congelamientos cuando SFTP tarda o falla.
- La huella SSH aceptada se persiste de forma sincronizada después de establecer correctamente la conexión.

## Interfaz

- La ventana nativa de Windows se centra automáticamente al abrirse.
- Reorganizada la tarjeta de cada perfil/servidor para que los botones de acciones permanezcan dentro del borde.
- La `✕` de borrar perfil ya no queda fuera de la línea y las acciones se adaptan mejor a ventanas estrechas.

## Versión

- Actualizada la aplicación a **v2.6.1** y sincronizados los metadatos de versión de Windows.
