param(
    [string]$WorkDir = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $repoRoot ".wireguard-upstream"
}

$wgCommit = "378990476748b5038df433f73712bfde859f4d65" # WireGuard for Windows v1.1
$dest = Join-Path $repoRoot "conectar-gateway\wireguard-assets\windows\amd64"
$hostSource = Join-Path $repoRoot "herramientas\wg-service-host.c"

if (Test-Path $WorkDir) {
    Remove-Item -Recurse -Force $WorkDir
}

# Construimos tunnel.dll desde el tag fijado del repositorio oficial.
git clone --depth 1 --branch v1.1 https://git.zx2c4.com/wireguard-windows $WorkDir
Push-Location $WorkDir
try {
    $actual = (git rev-parse HEAD).Trim()
    if ($actual -ne $wgCommit) {
        throw "WireGuard v1.1 no coincide con el commit fijado: $actual"
    }
    cmd /c embeddable-dll-service\build.bat
    if ($LASTEXITCODE -ne 0) {
        throw "Falló la compilación oficial de embeddable-dll-service"
    }
} finally {
    Pop-Location
}

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item (Join-Path $WorkDir "embeddable-dll-service\amd64\tunnel.dll") (Join-Path $dest "tunnel.dll") -Force
Copy-Item (Join-Path $WorkDir ".deps\wireguard-nt\bin\amd64\wireguard.dll") (Join-Path $dest "wireguard.dll") -Force

# tunnel.dll es una librería Go c-shared. Para no cargar un segundo runtime Go
# dentro del proceso Wails, la ejecutamos desde un host nativo mínimo siguiendo
# el patrón documentado por WireGuard para WireGuardTunnelService.
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "No encontré vswhere.exe para compilar el host nativo WireGuard"
}
$vsPath = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if ([string]::IsNullOrWhiteSpace($vsPath)) {
    throw "No encontré Visual C++ x64 en el runner"
}
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    throw "No encontré vcvars64.bat: $vcvars"
}
$hostOut = Join-Path $dest "wg-service-host.exe"
$compileCmd = 'call "{0}" >nul && cl.exe /nologo /O2 /W4 /utf-8 /MT /Fe:"{1}" "{2}" /link /SUBSYSTEM:CONSOLE' -f $vcvars, $hostOut, $hostSource
cmd.exe /d /s /c $compileCmd
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $hostOut)) {
    throw "Falló la compilación de wg-service-host.exe"
}

Write-Host "Motor WireGuard embebible preparado:"
Get-FileHash (Join-Path $dest "wg-service-host.exe"), (Join-Path $dest "tunnel.dll"), (Join-Path $dest "wireguard.dll") -Algorithm SHA256
