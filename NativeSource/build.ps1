# SPDX-FileCopyrightText: 2026 cfm-miku-en
# SPDX-License-Identifier: Apache-2.0

# Builds libarpnative.so for Quest (arm64-v8a) and drops it where Unity expects it.
#
#   .\build.ps1
#   .\build.ps1 -NdkPath "C:\Android\ndk\27.0.12077973"
#
# Needs the Android NDK and CMake. Both ship with Unity's Android module - see
# SETUP.md if you would rather point at Unity's copy than install your own.

param(
    [string]$NdkPath = $env:ANDROID_NDK_HOME,
    [string]$AndroidPlatform = "android-32"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    Write-Error "No NDK path. Pass -NdkPath, or set ANDROID_NDK_HOME. See SETUP.md."
}

if (-not (Test-Path $NdkPath)) {
    Write-Error "NDK path does not exist: $NdkPath"
}

$toolchain = Join-Path $NdkPath "build\cmake\android.toolchain.cmake"
if (-not (Test-Path $toolchain)) {
    Write-Error "No android.toolchain.cmake under $NdkPath. Is that really an NDK root?"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $scriptDir "build\arm64-v8a"

# Quest is arm64-v8a only, so there is exactly one ABI to build.
Write-Host "Configuring (arm64-v8a, $AndroidPlatform)..." -ForegroundColor Cyan
cmake -S $scriptDir -B $buildDir `
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" `
    -DANDROID_ABI=arm64-v8a `
    -DANDROID_PLATFORM=$AndroidPlatform `
    -DCMAKE_BUILD_TYPE=MinSizeRel

if ($LASTEXITCODE -ne 0) { Write-Error "CMake configure failed." }

Write-Host "Building..." -ForegroundColor Cyan
cmake --build $buildDir --config MinSizeRel
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed." }

$built = Join-Path $buildDir "libarpnative.so"
if (-not (Test-Path $built)) {
    Write-Error "Build reported success but libarpnative.so is not at $built"
}

$destDir = Join-Path (Split-Path -Parent $scriptDir) "Runtime\Plugins\Android\arm64-v8a"
New-Item -ItemType Directory -Force -Path $destDir | Out-Null

$dest = Join-Path $destDir "libarpnative.so"
Copy-Item -Path $built -Destination $dest -Force

$size = [math]::Round((Get-Item $dest).Length / 1KB, 1)
Write-Host ""
Write-Host "Done. libarpnative.so ($size KB) -> $dest" -ForegroundColor Green
Write-Host ""
Write-Host "Next: in Unity, select the .so and confirm the import settings are" -ForegroundColor Yellow
Write-Host "Android + ARM64. Unity will silently exclude it otherwise, and ARP will" -ForegroundColor Yellow
Write-Host "fall back to the managed path. See SETUP.md." -ForegroundColor Yellow
