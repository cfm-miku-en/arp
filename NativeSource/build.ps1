# SPDX-FileCopyrightText: 2026 cfm-miku-en
# SPDX-License-Identifier: Apache-2.0

# Builds libarpnative.so for Quest (arm64-v8a) and drops it where Unity expects it.
#
#   .\build.ps1
#   .\build.ps1 -NdkPath "C:\Program Files\Unity\Hub\Editor\<ver>\Editor\Data\PlaybackEngines\AndroidPlayer\NDK"
#
# Needs the Android NDK, CMake and Ninja. All three ship with Unity's Android Build
# Support module - point -NdkPath at Unity's NDK and the script finds the rest.
# See SETUP.md.

param(
    [string]$NdkPath = $env:ANDROID_NDK_HOME,
    [string]$AndroidPlatform = "android-32",
    [string]$CMakePath = "",
    [string]$NinjaPath = ""
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

# Unity keeps CMake and Ninja beside the NDK, under SDK\cmake\<version>\bin.
#
# Both matter. CMake on Windows defaults to the Visual Studio generator, which cannot
# cross-compile for Android and fails while probing VCTargetsPath - so a single-config
# generator is required, and Ninja is the one Unity ships. Unity's CMake is also
# pinned to a version the NDK toolchain is tested against, which avoids the
# cmake_minimum_required deprecation errors newer CMake raises against it.
function Find-UnityTool([string]$ndk, [string]$exeName) {
    $androidPlayer = Split-Path -Parent $ndk
    $cmakeRoot = Join-Path $androidPlayer "SDK\cmake"
    if (-not (Test-Path $cmakeRoot)) { return $null }

    $found = Get-ChildItem -Path $cmakeRoot -Filter $exeName -Recurse -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

if ([string]::IsNullOrWhiteSpace($NinjaPath)) {
    $NinjaPath = Find-UnityTool $NdkPath "ninja.exe"
}
if ([string]::IsNullOrWhiteSpace($NinjaPath)) {
    $onPath = Get-Command ninja -ErrorAction SilentlyContinue
    if ($onPath) { $NinjaPath = $onPath.Source }
}
if ([string]::IsNullOrWhiteSpace($NinjaPath)) {
    Write-Error @"
Ninja not found.

CMake defaults to the Visual Studio generator on Windows, which cannot build for
Android. Ninja ships with Unity's Android module at:

  <Editor>\Data\PlaybackEngines\AndroidPlayer\SDK\cmake\<version>\bin\ninja.exe

Pass it with -NinjaPath, or install Ninja and put it on PATH.
"@
}

if ([string]::IsNullOrWhiteSpace($CMakePath)) {
    $CMakePath = Find-UnityTool $NdkPath "cmake.exe"
}
if ([string]::IsNullOrWhiteSpace($CMakePath)) {
    $onPath = Get-Command cmake -ErrorAction SilentlyContinue
    if ($onPath) { $CMakePath = $onPath.Source }
}
if ([string]::IsNullOrWhiteSpace($CMakePath)) {
    Write-Error "CMake not found. Pass -CMakePath, or install CMake and put it on PATH."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $scriptDir "build\arm64-v8a"

Write-Host "CMake : $CMakePath" -ForegroundColor DarkGray
Write-Host "Ninja : $NinjaPath" -ForegroundColor DarkGray
Write-Host ""

# Quest is arm64-v8a only, so there is exactly one ABI to build.
Write-Host "Configuring (arm64-v8a, $AndroidPlatform)..." -ForegroundColor Cyan
& $CMakePath -S $scriptDir -B $buildDir `
    -G Ninja `
    -DCMAKE_MAKE_PROGRAM="$NinjaPath" `
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" `
    -DANDROID_ABI=arm64-v8a `
    "-DANDROID_PLATFORM=$AndroidPlatform" `
    -DCMAKE_BUILD_TYPE=MinSizeRel

if ($LASTEXITCODE -ne 0) { Write-Error "CMake configure failed." }

Write-Host "Building..." -ForegroundColor Cyan
& $CMakePath --build $buildDir
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
