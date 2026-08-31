# Firma Authenticode del ejecutable de Windows

Sin firma, Windows (SmartScreen, Acceso a carpetas controlado de Defender,
antivirus de terceros) trata a `TunnelForge.exe` como desconocido y el
**autoupdate rebota**: descarga la versión nueva, verifica firma Ed25519 y
SHA‑256 del updater propio, reemplaza el `.exe`… pero al intentar lanzar el
nuevo, Windows lo bloquea y el asistente restaura la versión anterior.

El workflow `build-release.yml` ya trae el paso de firma con **SignPath.io**
(plan gratuito para proyectos open source). Se **activa solo** cuando existen
estos valores en el repo — mientras tanto el build sale sin firmar como hasta
ahora:

| Tipo | Nombre | De dónde sale |
|---|---|---|
| Secret | `SIGNPATH_API_TOKEN` | SignPath → *User settings* → *API tokens* |
| Variable | `SIGNPATH_ORG_ID` | SignPath → *Organization* → GUID de la organización |
| Variable | `SIGNPATH_PROJECT_SLUG` | slug del proyecto que crees en SignPath |
| Variable | `SIGNPATH_POLICY_SLUG` | slug de la *signing policy* (ej. `release-signing`) |

## Pasos (una sola vez)

1. Crear cuenta en <https://signpath.io> y solicitar el **plan OSS gratuito**
   para `github.com/gsus67/tunnelforge` (revisión manual de SignPath, suele
   tardar unos días; ellos emiten el certificado).
2. En SignPath: crear un **Project** (`tunnelforge`), dentro un
   **Artifact configuration** con slug `exe` (tipo *Portable Executable*), y
   una **Signing policy** (ej. `release-signing`) que apunte al certificado
   del plan OSS.
3. Conectar el repo de GitHub como *trusted build system* (GitHub Actions) en
   la config del proyecto de SignPath, autorizando este workflow.
4. En GitHub → repo → *Settings* → *Secrets and variables* → *Actions*:
   - **Secret**: `SIGNPATH_API_TOKEN`
   - **Variables**: `SIGNPATH_ORG_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`
5. Subir un tag `vX.Y.Z` nuevo. El job de Windows detecta los valores, sube el
   `.exe` sin firmar como artefacto, lo manda a firmar a SignPath, baja el
   firmado y lo publica en la Release. `signtool verify /pa` confirma la firma
   en el log.

## Alternativas si no se usa SignPath

- **Azure Trusted Signing** (~10 USD/mes): certificado real, verificación de
  identidad (para persona física pide historial verificable de 3+ años).
  Se firmaría con `Azure.CodeSigning` en vez del paso de SignPath.
- **Certificado OV/EV de Sectigo/DigiCert** (~200–600 USD/año): con EV,
  SmartScreen confía al instante; con OV la reputación se gana con descargas.

Hasta que exista un certificado, el binario de Windows sale **sin firmar** y
el autoupdate puede requerir aprobar el archivo a mano en Windows Security, o
reemplazar el `.exe` manualmente desde la página de Releases.
