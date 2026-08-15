# gateway-wisp-access

Herramientas de acceso y operación para los gateways WISP
(compañero de [`gateway-wisp-wireguard`](https://github.com/gsus67/gateway-wisp-wireguard)).

## conectar-gateway — túneles SSH con motor propio

Aplicación de un solo ejecutable, **sin dependencias**: trae embebido su
propio cliente SSH ([`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh),
la librería oficial del proyecto Go). No usa PuTTY ni el OpenSSH del sistema.

**Qué hace:** guarda tus servidores, abre los túneles a los paneles del
gateway (8888 panel, 10086 WGDashboard, 19999 Netdata, 6060/60601 métricas)
y lanza el navegador en `http://localhost:8888`.

**Seguridad:**
- Verificación de huella del servidor (TOFU): la primera conexión la
  confirmas tú; después, si la huella cambia, la app se niega a conectar
  (protección contra suplantación/MITM).
- Las contraseñas se piden al conectar y **nunca se guardan**.
- Tus servidores quedan en `conexiones.json` junto al ejecutable —
  ese archivo está en `.gitignore` y jamás se sube.

### Descargar
Baja el ejecutable de la pestaña **Releases** →
`Conectar-Gateway.exe` (Windows) o `conectar-gateway-linux`.
Ponlo en cualquier carpeta y ábrelo. Nada que instalar.

### Compilarlo tú mismo
```bash
cd conectar-gateway
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o Conectar-Gateway.exe .
```
Solo necesitas Go 1.22+. El binario resultante es idéntico al de Releases.

### Publicar una versión nueva
```bash
git tag v1.0.1 && git push origin v1.0.1
```
GitHub Actions compila y adjunta los binarios al Release automáticamente
(`.github/workflows/release.yml`).

## herramientas/
- `subir-cambios.cmd` / `.sh` — botón de "commit + push" para los repos
  (se coloca junto a la carpeta del repo y pide solo el mensaje).
