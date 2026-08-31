# Firma Authenticode del ejecutable de Windows (Azure Trusted Signing)

Sin firma, Windows (SmartScreen, Acceso a carpetas controlado de Defender,
antivirus de terceros) trata a `TunnelForge.exe` como desconocido y el
**autoupdate rebota**: descarga la versión nueva, verifica firma Ed25519 y
SHA‑256 del updater propio, reemplaza el `.exe`… pero al intentar lanzar el
nuevo, Windows lo bloquea y el asistente restaura la versión anterior.

El workflow `build-release.yml` ya trae el paso de firma con **Azure Trusted
Signing**. Se **activa solo** cuando existan los valores de abajo; mientras
tanto el build sale sin firmar como hasta ahora.

| Tipo | Nombre | Qué es |
|---|---|---|
| Secret | `AZURE_CLIENT_SECRET` | secret del app registration (service principal) |
| Variable | `AZURE_TENANT_ID` | GUID del tenant de Entra ID |
| Variable | `AZURE_CLIENT_ID` | GUID (app id) del service principal |
| Variable | `TRUSTED_SIGNING_ENDPOINT` | URL regional, ej. `https://eus.codesigning.azure.net/` |
| Variable | `TRUSTED_SIGNING_ACCOUNT` | nombre de la Trusted Signing account |
| Variable | `TRUSTED_SIGNING_PROFILE` | nombre del Certificate Profile (tipo *Public Trust*) |

## Pasos (una sola vez)

1. **Suscripción de Azure.** El servicio cuesta ~2 USD/mes por identidad + un
   monto ínfimo por operación de firma.
2. **Registrar el recurso.** En el portal, *Subscriptions → Resource
   providers* → registrar `Microsoft.CodeSigning`.
3. **Crear la Trusted Signing account** (*Trusted Signing Accounts → Create*).
   Anotá la **región** — de ahí sale `TRUSTED_SIGNING_ENDPOINT`
   (`https://<region-abrev>.codesigning.azure.net/`, p.ej. `eus`, `wus2`).
4. **Validación de identidad.** *Identity validations → New*:
   - **Individual**: requiere historial verificable de 3+ años (documento +
     verificación). Puede tardar días.
   - **Organización**: número D‑U‑N‑S y datos de la empresa.
   Sin una identidad *Completed* no se puede crear un Certificate Profile
   público.
5. **Certificate Profile.** *Certificate Profiles → Create* → tipo
   **Public Trust** → asociarlo a la identidad validada. Su nombre es
   `TRUSTED_SIGNING_PROFILE`.
6. **Service principal para el CI.** En Entra ID, *App registrations → New*.
   Crear un **client secret** (guardá el *value*). Anotá *Application (client)
   ID* y *Directory (tenant) ID*.
7. **Permisos.** En la Trusted Signing account → *Access control (IAM)* →
   asignar al service principal el rol **Trusted Signing Certificate Profile
   Signer**.
8. **GitHub** → repo → *Settings → Secrets and variables → Actions*:
   - **Secret**: `AZURE_CLIENT_SECRET`
   - **Variables**: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
     `TRUSTED_SIGNING_ENDPOINT`, `TRUSTED_SIGNING_ACCOUNT`,
     `TRUSTED_SIGNING_PROFILE`
9. Subir un tag `vX.Y.Z`. El job de Windows detecta los valores, firma
   `TunnelForge.exe` con `azure/trusted-signing-action`, lo timestampea contra
   `timestamp.acs.microsoft.com` y verifica con `signtool verify /pa`. El
   binario firmado es el que se publica en la Release.

## Nota sobre reputación de SmartScreen

Trusted Signing emite certificados de validez corta que rotan solos; la
reputación de SmartScreen se acumula por **identidad**, no por certificado, así
que no se pierde en cada rotación. Aun así, las primeras descargas de una
identidad nueva pueden mostrar el aviso de SmartScreen hasta que junta
reputación.

## Mientras no haya firma

El binario de Windows sale **sin firmar** y el autoupdate puede requerir
aprobar el archivo a mano en Windows Security (Historial de protección /
Acceso a carpetas controlado), o reemplazar el `.exe` manualmente desde la
página de Releases. Desde v1.1.5 el panel *Updates* informa en qué paso falló
el último intento.
