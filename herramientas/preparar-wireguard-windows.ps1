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

if (Test-Path $WorkDir) {
    Remove-Item -Recurse -Force $WorkDir
}

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

Write-Host "Motor WireGuard embebible preparado:"
Get-FileHash (Join-Path $dest "tunnel.dll"), (Join-Path $dest "wireguard.dll") -Algorithm SHA256
