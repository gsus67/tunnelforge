# v1.0.1 — Actualizaciones sin token

Se saca por completo la UI y el soporte de personal access token del panel de
Actualizaciones. Como el repositorio de Releases es público, buscar e instalar
una actualización no necesita ninguna credencial: el panel queda en un solo
paso, comprobar e instalar.

El resto del mecanismo no cambia: cada Release lleva un `update-manifest.json`
firmado con Ed25519, la app valida la firma con su clave pública embebida y
comprueba SHA-256 y tamaño del ejecutable contra ese manifest antes de
instalarlo.
