# v2.6.1 — Security hardening + UI fixes

Esta actualización corrige vulnerabilidades detectadas durante la revisión de seguridad y mejora varios detalles de la interfaz de Conectar Gateway WISP.

## Cambios de seguridad

- Eliminado el uso de `innerHTML` con datos dinámicos para evitar XSS dentro del WebView.
- Los nombres de servidores, archivos, túneles, errores y datos importados ahora se insertan usando nodos DOM y `textContent`.
- Corregido un posible path traversal al importar claves SSH desde copias `.cgw` manipuladas.
- Las claves importadas se validan y se comprueba que siempre queden dentro de la carpeta `keys/`.
- Los túneles importados pasan la misma validación que los túneles creados desde la interfaz: puertos válidos, sin duplicados y límites de longitud.
- Se valida el formato interno de la copia `.cgw` y el modo de importación.

## Concurrencia y estabilidad

- `ssh.Dial` ya no mantiene bloqueado el mutex global mientras espera al servidor.
- La creación del cliente SFTP utiliza ahora un mutex por conexión en lugar del mutex global.
- Se evita iniciar dos conexiones simultáneas al mismo perfil.
- La huella SSH aceptada se guarda de forma sincronizada después de establecer correctamente la conexión.

## Interfaz

- La ventana nativa de Windows se centra automáticamente al abrirse.
- Reorganizada la tarjeta de perfiles/servidores para mantener todos los botones dentro del borde.
- Corregida la posición del botón `✕` de borrar perfil.
- Las acciones se adaptan mejor cuando la ventana es estrecha.

## Versión

- Versión actualizada a **2.6.1**.
- Metadatos de versión de Windows actualizados a **2.6.1**.
