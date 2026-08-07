param(
    [Parameter(Mandatory = $true)][string]$BaselineInstaller,
    [Parameter(Mandatory = $true)][string]$CurrentInstaller
)

$ErrorActionPreference = 'Stop'
$BaselineInstaller = (Resolve-Path -LiteralPath $BaselineInstaller).Path
$CurrentInstaller = (Resolve-Path -LiteralPath $CurrentInstaller).Path
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$LifecycleRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("basilisk-installer-lifecycle-" + [guid]::NewGuid().ToString('N'))
$InstallRoot = Join-Path $LifecycleRoot 'app'
$SmokeScript = Join-Path $RepoRoot 'desktop\tests\packaged-smoke.js'

function Invoke-Installer([string]$Installer) {
    New-Item -ItemType Directory -Path $LifecycleRoot -Force | Out-Null
    $process = Start-Process -FilePath $Installer -ArgumentList @('/S', "/D=$InstallRoot") -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Installer failed with exit code $($process.ExitCode): $Installer"
    }
}

function Get-InstalledExecutable {
    $preferred = Join-Path $InstallRoot 'Basilisk.exe'
    if (Test-Path -LiteralPath $preferred) { return $preferred }
    $candidate = Get-ChildItem -LiteralPath $InstallRoot -Filter '*.exe' -File -Recurse |
        Where-Object { $_.Name -notlike 'Uninstall*' } |
        Select-Object -First 1
    if (-not $candidate) { throw "Basilisk executable was not installed under $InstallRoot" }
    return $candidate.FullName
}

function Invoke-PackagedSmoke([string]$Executable) {
    & node $SmokeScript $Executable
    if ($LASTEXITCODE -ne 0) { throw "Packaged smoke failed for $Executable" }
}

function Invoke-Uninstall {
    $uninstaller = Get-ChildItem -LiteralPath $InstallRoot -Filter 'Uninstall*.exe' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $uninstaller) { throw "Uninstaller was not found under $InstallRoot" }
    $process = Start-Process -FilePath $uninstaller.FullName -ArgumentList '/S' -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Uninstaller failed with exit code $($process.ExitCode)" }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ((Test-Path -LiteralPath (Join-Path $InstallRoot 'Basilisk.exe')) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-Path -LiteralPath (Join-Path $InstallRoot 'Basilisk.exe')) {
        throw 'Basilisk executable remained after uninstall'
    }
}

try {
    Invoke-Installer $BaselineInstaller
    $baselineExecutable = Get-InstalledExecutable
    $baselineVersion = (Get-Item -LiteralPath $baselineExecutable).VersionInfo.ProductVersion
    Invoke-PackagedSmoke $baselineExecutable

    Invoke-Installer $CurrentInstaller
    $currentExecutable = Get-InstalledExecutable
    $currentVersion = (Get-Item -LiteralPath $currentExecutable).VersionInfo.ProductVersion
    if ($baselineVersion -eq $currentVersion) {
        throw "Upgrade did not change product version ($currentVersion)"
    }
    Invoke-PackagedSmoke $currentExecutable
    Invoke-Uninstall
    Write-Output "Windows install/launch/upgrade/uninstall passed: $baselineVersion -> $currentVersion"
} finally {
    if (Test-Path -LiteralPath $InstallRoot) {
        $uninstaller = Get-ChildItem -LiteralPath $InstallRoot -Filter 'Uninstall*.exe' -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($uninstaller) {
            Start-Process -FilePath $uninstaller.FullName -ArgumentList '/S' -Wait | Out-Null
        }
    }
    $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $resolvedLifecycle = [System.IO.Path]::GetFullPath($LifecycleRoot)
    if ($resolvedLifecycle.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedLifecycle) -like 'basilisk-installer-lifecycle-*') {
        Remove-Item -LiteralPath $resolvedLifecycle -Recurse -Force -ErrorAction SilentlyContinue
    }
}
