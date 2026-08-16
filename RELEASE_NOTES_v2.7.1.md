# Conectar Gateway v2.7.1

## Corrección de compilación

- Corregidos los literales de `Tunel` que todavía usaban 3 valores después de añadir el campo `AbrirWeb`.
- Los túneles predeterminados ahora usan campos nombrados (`Puerto`, `Nombre`, `Ruta`) para evitar que futuros campos nuevos vuelvan a romper el build.
- Sincronizada la versión de Windows a 2.7.1 (`Patch: 1`).

El fallo corregido era: `too few values in struct literal` en `main.go` líneas 58-62.
