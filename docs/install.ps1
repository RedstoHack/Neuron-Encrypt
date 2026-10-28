#Requires -Version 5.1
<#
.SYNOPSIS
    One-line installer for neuron-encrypt-cli on Windows.
.DESCRIPTION
    Downloads the latest (or pinned) neuron-encrypt-cli binary from GitLab
    Generic Package Registry, verifies its SHA-256 hash, installs it to
    %LOCALAPPDATA%\Programs\NeuronEncrypt\bin (or $HOME\.neuron-encrypt\bin),
    and adds it to the User PATH environment variable if not already present.
.EXAMPLE
    irm https://theredhacker0345.gitlab.io/neuron-encrypt/install.ps1 | iex
.EXAMPLE
    # Pin a specific version:
    $env:NEURON_VERSION = "2.2.0"; irm .../install.ps1 | iex
.EXAMPLE
    # Custom install directory:
    $env:NEURON_INSTALL_DIR = "C:\Tools\bin"; irm .../install.ps1 | iex
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── constants ──────────────────────────────────────────────────────────────────
$GitLabProjectId = "84892701"
$PackageName     = "neuron-encrypt-cli"
$BinaryName      = "neuron-encrypt-cli.exe"
$PagesBase       = "https://theredhacker0345.gitlab.io/neuron-encrypt"
$RegistryBase    = "https://gitlab.com/api/v4/projects/$GitLabProjectId/packages/generic/$PackageName"

# ── color helpers ──────────────────────────────────────────────────────────────
function Write-Step  { Write-Host "==> $args" -ForegroundColor Green  }
function Write-Warn  { Write-Host "WARN: $args" -ForegroundColor Yellow }
function Write-Fatal { Write-Host "ERROR: $args" -ForegroundColor Red; exit 1 }

# ── resolve version ────────────────────────────────────────────────────────────
function Get-NeuronVersion {
    $pinned = [System.Environment]::GetEnvironmentVariable("NEURON_VERSION")
    if ($pinned) {
        Write-Step "Using pinned version: $pinned"
        return $pinned
    }

    Write-Step "Resolving latest version..."
    $latestUrl = "$PagesBase/latest-version.txt"
    try {
        $resp = Invoke-WebRequest -Uri $latestUrl -UseBasicParsing -TimeoutSec 10
        $version = $resp.Content.Trim()
        if ($version -match '^\d+\.\d+\.\d+$') {
            Write-Step "Latest version: $version"
            return $version
        }
    } catch {
        Write-Warn "Could not fetch latest-version.txt: $_"
    }
    # Hardcoded fallback
    $fallback = "2.2.0"
    Write-Warn "Falling back to version $fallback."
    return $fallback
}

# ── pick install directory ─────────────────────────────────────────────────────
function Get-InstallDir {
    $customDir = [System.Environment]::GetEnvironmentVariable("NEURON_INSTALL_DIR")
    if ($customDir) {
        New-Item -ItemType Directory -Force -Path $customDir | Out-Null
        return $customDir
    }

    # Prefer LocalAppData so we never need elevation
    $dir = Join-Path $env:LOCALAPPDATA "Programs\NeuronEncrypt\bin"
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    return $dir
}

# ── ensure on PATH ─────────────────────────────────────────────────────────────
function Add-ToUserPath([string]$Dir) {
    # Read the *unexpanded* registry value and write it back as REG_EXPAND_SZ.
    #
    # `SetEnvironmentVariable("PATH", ..., "User")` writes REG_SZ, which turns
    # every %VAR% in the user's PATH into a literal string, and an empty user
    # PATH produced a leading ";" — on Windows an empty PATH entry means
    # "current directory", so the user's own folder would end up on PATH.
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
    if ($null -eq $key) {
        Write-Warn "Could not open HKCU\Environment to update PATH — add '$Dir' to your PATH manually."
        return
    }
    try {
        $raw = $key.GetValue("PATH", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $entries = @()
        if ($raw) {
            # Split, drop empty segments, and de-duplicate while keeping order.
            $entries = @($raw -split ";" | Where-Object { $_ -ne "" } | Select-Object -Unique)
        }
        if ($entries -notcontains $Dir) {
            $newPath = (@($entries) + $Dir) -join ";"
            $key.SetValue("PATH", $newPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            # Also update the current-session PATH so the binary is immediately usable
            $env:PATH = "$env:PATH;$Dir"
            Write-Step "Added to User PATH: $Dir"
            Write-Warn "Restart your terminal (or run 'refreshenv') for PATH changes to take full effect."
        }
    } finally {
        $key.Close()
    }
}

# ── download file ──────────────────────────────────────────────────────────────
function Get-RemoteFile([string]$Url, [string]$Dest) {
    Write-Host "    $Url" -ForegroundColor DarkGray
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing `
            -Headers @{ "Accept" = "application/octet-stream" }
    } catch {
        Write-Fatal "Download failed: $_"
    }
}

# ── verify SHA-256 ─────────────────────────────────────────────────────────────
function Assert-Sha256([string]$FilePath, [string]$ChecksumsPath) {
    Write-Step "Verifying SHA-256..."

    $checksumsContent = Get-Content $ChecksumsPath -Raw
    $fileName         = [System.IO.Path]::GetFileName($FilePath)

    # Find matching line: "<hash>  <filename>" or "<hash> *<filename>"
    $line = ($checksumsContent -split "`n") | Where-Object {
        $_ -match ([System.Text.RegularExpressions.Regex]::Escape($fileName))
    } | Select-Object -First 1

    if (-not $line) {
        Write-Fatal "Could not find checksum for '$fileName' in SHA256SUMS file."
    }

    $expectedHash = ($line -split '\s+')[0].ToUpper()

    $actualHash = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToUpper()

    if ($actualHash -ne $expectedHash) {
        Write-Fatal "SHA-256 mismatch!`n  Expected: $expectedHash`n  Got:      $actualHash`nDo NOT run this binary — the download may be corrupt or tampered with."
    }

    Write-Step "Checksum OK."
}

# ── create alias cmd wrapper ───────────────────────────────────────────────────
function New-CmdAlias([string]$InstallDir, [string]$ExePath, [string]$AliasName) {
    $cmdFile = Join-Path $InstallDir "$AliasName.cmd"
    # Simple CMD wrapper that forwards all args to the real binary
    $content = "@echo off`r`n`"$ExePath`" %*`r`n"
    [System.IO.File]::WriteAllText($cmdFile, $content)
}

# ── main ───────────────────────────────────────────────────────────────────────
function Install-NeuronEncryptCli {
    Write-Step "neuron-encrypt-cli Windows installer"
    Write-Host ""

    $version    = Get-NeuronVersion
    $installDir = Get-InstallDir

    $versionedName  = "neuron-encrypt-cli-$version-windows-x86_64.exe"
    $checksumName   = "SHA256SUMS-cli-windows.txt"
    $binUrl         = "$RegistryBase/$version/$versionedName"
    $checksumUrl    = "$RegistryBase/$version/$checksumName"

    $tmpDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "neuron-install-$([System.Guid]::NewGuid().ToString('N'))")
    New-Item -ItemType Directory -Path $tmpDir | Out-Null

    try {
        Write-Step "Downloading binary..."
        Get-RemoteFile $binUrl (Join-Path $tmpDir $versionedName)

        Write-Step "Downloading checksums..."
        Get-RemoteFile $checksumUrl (Join-Path $tmpDir $checksumName)

        Assert-Sha256 (Join-Path $tmpDir $versionedName) (Join-Path $tmpDir $checksumName)

        $destExe = Join-Path $installDir $BinaryName
        Copy-Item (Join-Path $tmpDir $versionedName) $destExe -Force

        # Create short "neuron.cmd" alias for convenience
        New-CmdAlias $installDir $destExe "neuron"

        Add-ToUserPath $installDir

        Write-Host ""
        Write-Step "Installed → $destExe"
        Write-Step "Alias     → $(Join-Path $installDir 'neuron.cmd')"
        Write-Host ""
        Write-Host "Run: neuron-encrypt-cli --help" -ForegroundColor Cyan
        Write-Host "  or: neuron --help" -ForegroundColor Cyan

    } finally {
        Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    }
}

Install-NeuronEncryptCli
