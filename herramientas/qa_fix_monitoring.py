from pathlib import Path

path = Path("conectar-gateway/monitoring.go")
text = path.read_text(encoding="utf-8")
old = '''\ttype srv struct {\n\t\tNombre                          string  `json:"nombre"`\n\t\tOnline                          bool    `json:"online"`\n\t\tCPU, RAM, Disco, RX, TX, Uptime float64 `json:"cpu"`\n\t}'''
new = '''\ttype srv struct {\n\t\tNombre string  `json:"nombre"`\n\t\tOnline bool    `json:"online"`\n\t\tCPU    float64 `json:"cpu"`\n\t\tRAM    float64 `json:"ram"`\n\t\tDisco  float64 `json:"disco"`\n\t\tRX     float64 `json:"rx"`\n\t\tTX     float64 `json:"tx"`\n\t\tUptime float64 `json:"uptime"`\n\t}'''

if old in text:
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
    print("monitoring.go corregido")
elif new in text:
    print("monitoring.go ya estaba corregido")
else:
    raise SystemExit("No encontré el bloque esperado; no se modifica nada")
