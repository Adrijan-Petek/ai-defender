param(
  [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$installerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $installerDir
$sourceDir = Join-Path $installerDir "build"

function Require-Command {
  param([string]$Name, [string]$InstallHint)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Missing required tool '$Name'. $InstallHint"
  }
}

Require-Command "cargo" "Install Rust stable toolchain: https://rustup.rs/"
Require-Command "dotnet" "Install .NET SDK 8+: https://dotnet.microsoft.com/download"
Require-Command "wix" "Install WiX v4 CLI: dotnet tool install --global wix"

New-Item -ItemType Directory -Force -Path $sourceDir | Out-Null

Write-Host "Building Rust binaries..."
Push-Location $repoRoot
try {
  cargo build -p agent-core --release
  cargo build -p scanner --release
}
finally {
  Pop-Location
}

Write-Host "Publishing tray UI..."
$uiProject = Join-Path $repoRoot "ui/AI.Defender.Tray/AI.Defender.Tray.csproj"
$uiPublishDir = Join-Path $sourceDir "ui-publish"
if (Test-Path $uiPublishDir) {
  Remove-Item -Recurse -Force $uiPublishDir
}
dotnet publish $uiProject -c $Configuration -r win-x64 --self-contained false -o $uiPublishDir

Write-Host "Copying installer SourceDir payload..."
foreach ($name in @("agent-core.exe", "scanner.exe", "AI.Defender.Tray.exe", "VERSION", "PRODUCT.toml", "config.default.toml")) {
  $dst = Join-Path $sourceDir $name
  if (Test-Path $dst) {
    Remove-Item -Force $dst
  }
}

$agentExe = Join-Path $repoRoot "target/release/agent-core.exe"
$scannerExe = Join-Path $repoRoot "target/release/scanner.exe"
$trayExe = Join-Path $uiPublishDir "AI.Defender.Tray.exe"
$versionFile = Join-Path $repoRoot "VERSION"
$productToml = Join-Path $repoRoot "PRODUCT.toml"
$defaultConfig = Join-Path $installerDir "wix/config.default.toml"

foreach ($required in @($agentExe, $scannerExe, $trayExe, $versionFile, $productToml, $defaultConfig)) {
  if (-not (Test-Path $required)) {
    throw "Missing expected build artifact: $required"
  }
}

Copy-Item $agentExe (Join-Path $sourceDir "agent-core.exe") -Force
Copy-Item $scannerExe (Join-Path $sourceDir "scanner.exe") -Force
Copy-Item $trayExe (Join-Path $sourceDir "AI.Defender.Tray.exe") -Force
Copy-Item $versionFile (Join-Path $sourceDir "VERSION") -Force
Copy-Item $productToml (Join-Path $sourceDir "PRODUCT.toml") -Force
Copy-Item $defaultConfig (Join-Path $sourceDir "config.default.toml") -Force

$rawVersion = (Get-Content -Path $versionFile -Raw).Trim()
if ($rawVersion -match "^(\d+)\.(\d+)\.(\d+)") {
  $productVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
} else {
  throw "VERSION file '$rawVersion' is not in expected semver format (e.g., 0.1.1-alpha)."
}

$wxsPath = Join-Path $installerDir "wix/AI.Defender.wxs"
$msiPath = Join-Path $sourceDir "AI-Defender-$productVersion.msi"

Write-Host "Building MSI with WiX..."
wix build $wxsPath -o $msiPath -d SourceDir=$sourceDir -d ProductVersion=$productVersion

if (-not (Test-Path $msiPath)) {
  Write-Host "WiX build completed but expected MSI was not found at: $msiPath"
  Write-Host "Installer build directory contents:"
  Get-ChildItem -Path $sourceDir -Recurse | ForEach-Object { Write-Host " - $($_.FullName)" }
  throw "MSI output missing after WiX build."
}

Write-Host "Done. MSI: $msiPath"
