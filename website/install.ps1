# Install the latest verified Code Buster binary on x86-64 Windows.
$ErrorActionPreference = 'Stop'

$repository = 'https://github.com/tool-bunker/code-buster'
$version = if ($env:CODE_BUSTER_VERSION) { $env:CODE_BUSTER_VERSION } else { 'latest' }
$prefix = if ($env:PREFIX) { $env:PREFIX } else { Join-Path $HOME '.local' }
$binDirectory = Join-Path $prefix 'bin'
$archive = 'code-buster-windows-x64.zip'

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($architecture -ne [System.Runtime.InteropServices.Architecture]::X64) {
  throw "Unsupported Windows architecture: $architecture. Code Buster currently supports x86-64 Windows."
}

$release = if ($version -eq 'latest') {
  "$repository/releases/latest/download"
} else {
  "$repository/releases/download/v$version"
}

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("code-buster-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporary | Out-Null

try {
  $archivePath = Join-Path $temporary $archive
  $checksumsPath = Join-Path $temporary 'SHA256SUMS'
  Write-Host "Downloading Code Buster $version for Windows x86-64..."
  Invoke-WebRequest -Uri "$release/$archive" -OutFile $archivePath
  Invoke-WebRequest -Uri "$release/SHA256SUMS" -OutFile $checksumsPath

  $checksumLine = Get-Content $checksumsPath | Where-Object { $_ -match "\s$([regex]::Escape($archive))$" } | Select-Object -First 1
  if (-not $checksumLine) {
    throw "Checksum for $archive is missing."
  }
  $expected = ($checksumLine -split '\s+')[0].ToLowerInvariant()
  $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "Checksum mismatch for $archive."
  }

  $expanded = Join-Path $temporary 'expanded'
  Expand-Archive -Path $archivePath -DestinationPath $expanded
  New-Item -ItemType Directory -Force -Path $binDirectory | Out-Null
  $executable = Join-Path $binDirectory 'cb.exe'
  Copy-Item -Force (Join-Path $expanded 'cb.exe') $executable

  Write-Host "Installed Code Buster to $executable"
  if (($env:PATH -split ';') -notcontains $binDirectory) {
    Write-Host "Add $binDirectory to PATH to run cb from any directory."
  }
  & $executable version
} finally {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $temporary
}
