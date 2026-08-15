#!/bin/bash
# ============================================================================
#  subir-cambios.sh - Sube los cambios del repo gateway-wisp a GitHub
#  Colocar JUNTO a la carpeta gateway-wisp (no dentro).
#  Uso: bash subir-cambios.sh   (o ./subir-cambios.sh si le das chmod +x)
# ============================================================================

set -u
cd "$(dirname "$0")"

if [ ! -d "gateway-wisp/.git" ]; then
    echo ""
    echo "  ERROR: no encuentro la carpeta gateway-wisp con su .git aqui mismo."
    echo "  Este archivo debe estar JUNTO a la carpeta gateway-wisp."
    echo ""
    exit 1
fi

cd gateway-wisp

echo "=============================================="
echo " Repositorio: gateway-wisp"
echo "=============================================="
echo ""
echo "--- Cambios detectados: ----------------------"
git status --short
echo "----------------------------------------------"
echo ""

N=$(git status --porcelain | wc -l)

if [ "$N" -eq 0 ]; then
    echo "  No hay cambios nuevos que subir. Todo esta al dia."
    echo ""
    exit 0
fi

echo "Hay $N archivo(s) con cambios."
echo ""
echo "Escribe un mensaje CORTO para este cambio. Ejemplos:"
echo "   fix: corrige panel    feat: nueva metrica    docs: readme"
echo ""
read -rp "Mensaje: " MSG

if [ -z "$MSG" ]; then
    echo ""
    echo "  Cancelado: no escribiste mensaje."
    echo ""
    exit 1
fi

echo ""
echo "--- Subiendo a GitHub... ---------------------"
git add -A
git commit -m "$MSG"

if git push; then
    echo ""
    echo "=============================================="
    echo " LISTO. Cambios subidos a GitHub."
    echo "=============================================="
else
    echo ""
    echo "  ATENCION: el push devolvio un error. Revisa arriba."
    echo "  Causas comunes: sin internet o credenciales expiradas."
fi
echo ""
