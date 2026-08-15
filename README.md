# gateway-wisp-access

Herramientas de acceso y operación para los gateways WISP
(compañero de [`gateway-wisp-wireguard`](https://github.com/gsus67/gateway-wisp-wireguard)).

## conectar-gateway — túneles SSH con interfaz gráfica

Aplicación de un solo ejecutable, **sin dependencias**: motor SSH embebido
([`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh),
la librería oficial del proyecto Go) e interfaz gráfica propia que se abre
sola en el navegador. No usa PuTTY ni el OpenSSH del sistema.

**Qué hace:**
- Guarda tus servidores con **key SSH o contraseña** (la contraseña se
  cifra con AES-256-GCM; la llave vive en `secreto.bin` junto al ejecutable)
- Un clic en *Conectar* abre los túneles a los paneles del gateway
  (8888 panel, 10086 WGDashboard, 19999 Netdata, 6060/60601 métricas)
  y muestra accesos directos a cada uno
- Verificación de huella del servidor (TOFU) con confirmación visual:
  si la huella cambia un día, se niega a conectar (anti-suplantación)
- La interfaz solo escucha en 127.0.0.1 con token de sesión aleatorio

**Archivos que crea junto al ejecutable** (ninguno se sube al repo):
`conexiones.json` (servidores y huellas), `secreto.bin` (llave de cifrado).

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
