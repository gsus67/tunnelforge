# v3.5.1 — Copiar y pegar en terminal

La terminal SSH integrada ahora permite copiar la selección y pegar desde el portapapeles con botones visibles y con los atajos estándar `Ctrl+Shift+C` / `Ctrl+Shift+V`. Se mantiene intacto `Ctrl+C` para interrumpir procesos remotos. La terminal del instalador Gateway WISP recibe el mismo comportamiento.

El acceso al portapapeles usa la API del navegador/WebView cuando está disponible; si la lectura está bloqueada, el botón Pegar ofrece un cuadro manual para introducir el contenido sin romper la sesión.
