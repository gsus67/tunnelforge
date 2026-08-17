# Migración Go + Wails + TypeScript

1. Mantener el backend Go actual y extraer contratos pequeños.
2. Migrar primero **Monitoreo**, porque ya tiene límites claros de API y modelos de estado.
3. Mantener WebView actual disponible hasta que la nueva vista tenga paridad funcional.
4. Añadir build Wails para Windows y Linux solamente cuando la UI TypeScript sea estable.
5. Después migrar Copias, Perfiles, Dashboard y finalmente Terminal/Archivos.

No se deben duplicar implementaciones Go versionadas (`v313.go`, `v314.go`, etc.). Los módulos futuros usarán nombres funcionales estables.
