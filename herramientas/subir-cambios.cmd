@echo off
setlocal EnableExtensions
REM ============================================================================
REM  subir-cambios.cmd - Sube los cambios del repo gateway-wisp a GitHub
REM  Colocar JUNTO a la carpeta gateway-wisp (no dentro). Doble clic y listo.
REM ============================================================================

pushd "%~dp0"

if not exist "gateway-wisp\.git" (
    echo.
    echo  ERROR: no encuentro la carpeta gateway-wisp con su .git aqui mismo.
    echo  Este archivo debe estar JUNTO a la carpeta gateway-wisp.
    echo.
    pause
    popd
    exit /b 1
)

cd gateway-wisp

echo ==============================================
echo  Repositorio: gateway-wisp
echo ==============================================
echo.
echo --- Cambios detectados: ----------------------
git status --short
echo ----------------------------------------------
echo.

set "N=0"
for /f %%i in ('git status --porcelain ^| find /c /v ""') do set "N=%%i"

if "%N%"=="0" (
    echo  No hay cambios nuevos que subir. Todo esta al dia.
    echo.
    pause
    popd
    exit /b 0
)

echo Hay %N% archivo^(s^) con cambios.
echo.
echo Escribe un mensaje CORTO para este cambio. Ejemplos:
echo    fix: corrige panel    feat: nueva metrica    docs: readme
echo.
set "MSG="
set /p MSG="Mensaje: "

if "%MSG%"=="" (
    echo.
    echo  Cancelado: no escribiste mensaje.
    echo.
    pause
    popd
    exit /b 1
)

echo.
echo --- Subiendo a GitHub... ---------------------
git add -A
git commit -m "%MSG%"
git push

if errorlevel 1 (
    echo.
    echo  ATENCION: el push devolvio un error. Revisa arriba.
    echo  Causas comunes: sin internet o sesion de GitHub expirada.
) else (
    echo.
    echo ==============================================
    echo  LISTO. Cambios subidos a GitHub.
    echo ==============================================
)

echo.
pause
popd
