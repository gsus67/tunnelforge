# frontend-next

Base **experimental y no conectada al build estable** para migrar gradualmente Gateway WISP Access a **Go + Wails + TypeScript**.

Objetivos:

- mantener Go como backend para SSH, SFTP, túneles, cifrado y monitoreo;
- reemplazar JavaScript global por contratos TypeScript tipados;
- conservar la misma experiencia en Windows y Linux;
- migrar vista por vista, empezando por Monitoreo, sin reescribir funciones estables de una sola vez.

Mientras esta carpeta sea experimental, `conectar-gateway/ui.html` sigue siendo la UI de producción.
