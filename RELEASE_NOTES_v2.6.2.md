# Conectar Gateway v2.6.2 — flujo de Terminal y Archivos

Esta versión reorganiza la interfaz para que las acciones operativas aparezcan donde realmente son útiles: en los servidores conectados.

## Cambios de interfaz

- **Archivos ahora se abre a pantalla completa**, con el mismo patrón visual que la Terminal integrada.
- Se agregó un **botón compacto de Archivos** al lado del botón de Terminal en cada servidor conectado.
- **Terminal se eliminó de “Servidores guardados”**. Un perfil guardado ahora muestra solo las acciones de administración: Conectar, Editar y Borrar.
- La antigua sección desplegable global de **Archivos** fue eliminada de la página principal para reducir ruido visual.
- La barra superior del explorador muestra claramente el servidor activo y permite cambiar entre conexiones activas.
- **Esc** cierra tanto el explorador de Archivos como la Terminal, manteniendo un comportamiento consistente.

## Explorador de archivos

- Mantiene la vista de dos paneles: **Servidor remoto** y **Tu equipo**.
- Sigue permitiendo subir, bajar, renombrar, borrar y crear carpetas mediante SFTP.
- La selección de claves SSH desde **Buscar…** sigue funcionando: abre el mismo explorador a pantalla completa en modo local aunque no haya un servidor conectado.
- Al seleccionar una clave SSH, el explorador se cierra y se vuelve automáticamente al formulario del perfil.

## Base de seguridad

Incluye todas las correcciones de v2.6.1: eliminación de `innerHTML` dinámico/XSS, protección contra path traversal al importar claves, validación de túneles importados y mejoras de concurrencia SSH/SFTP.
