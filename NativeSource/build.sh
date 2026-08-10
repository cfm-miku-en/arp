#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 cfm-miku-en
# SPDX-License-Identifier: Apache-2.0

# Builds libarpnative.so for Quest (arm64-v8a) and drops it where Unity expects it.
#
#   ./build.sh
#   ANDROID_NDK_HOME=/path/to/ndk ./build.sh
#
# Needs the Android NDK and CMake. Both ship with Unity's Android module - see
# SETUP.md if you would rather point at Unity's copy than install your own.

set -euo pipefail

NDK_PATH="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
ANDROID_PLATFORM="${ANDROID_PLATFORM:-android-32}"

if [ -z "$NDK_PATH" ]; then
    echo "error: no NDK path. Set ANDROID_NDK_HOME. See SETUP.md." >&2
    exit 1
fi

TOOLCHAIN="$NDK_PATH/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN" ]; then
    echo "error: no android.toolchain.cmake under $NDK_PATH. Is that really an NDK root?" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/arm64-v8a"

# Unity keeps CMake and Ninja beside the NDK under SDK/cmake/<version>/bin.
#
# Both matter. The default generator cannot cross-compile for Android - on Windows it
# picks Visual Studio and dies probing VCTargetsPath - so a single-config generator is
# required, and Ninja is the one Unity ships. Unity's CMake is also pinned to a
# version the NDK toolchain is tested against, which avoids the deprecation errors
# newer CMake raises against it.
ANDROID_PLAYER="$(dirname "$NDK_PATH")"
find_unity_tool() {
    find "$ANDROID_PLAYER/SDK/cmake" -name "$1" -type f 2>/dev/null | head -1
}

CMAKE_BIN="${CMAKE_BIN:-$(find_unity_tool cmake)}"
[ -z "$CMAKE_BIN" ] && CMAKE_BIN="$(command -v cmake || true)"
if [ -z "$CMAKE_BIN" ]; then
    echo "error: cmake not found. Set CMAKE_BIN, or install CMake." >&2
    exit 1
fi

NINJA_BIN="${NINJA_BIN:-$(find_unity_tool ninja)}"
[ -z "$NINJA_BIN" ] && NINJA_BIN="$(command -v ninja || true)"
if [ -z "$NINJA_BIN" ]; then
    echo "error: ninja not found. It ships with Unity's Android module at" >&2
    echo "  <Editor>/.../AndroidPlayer/SDK/cmake/<version>/bin/ninja" >&2
    echo "Set NINJA_BIN, or install Ninja." >&2
    exit 1
fi

echo "CMake : $CMAKE_BIN"
echo "Ninja : $NINJA_BIN"
echo

# Quest is arm64-v8a only, so there is exactly one ABI to build.
echo "Configuring (arm64-v8a, $ANDROID_PLATFORM)..."
"$CMAKE_BIN" -S "$SCRIPT_DIR" -B "$BUILD_DIR" \
    -G Ninja \
    -DCMAKE_MAKE_PROGRAM="$NINJA_BIN" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM="$ANDROID_PLATFORM" \
    -DCMAKE_BUILD_TYPE=MinSizeRel

echo "Building..."
"$CMAKE_BIN" --build "$BUILD_DIR"

BUILT="$BUILD_DIR/libarpnative.so"
if [ ! -f "$BUILT" ]; then
    echo "error: build reported success but libarpnative.so is not at $BUILT" >&2
    exit 1
fi

DEST_DIR="$(dirname "$SCRIPT_DIR")/Runtime/Plugins/Android/arm64-v8a"
mkdir -p "$DEST_DIR"
cp -f "$BUILT" "$DEST_DIR/libarpnative.so"

echo
echo "Done. libarpnative.so -> $DEST_DIR/libarpnative.so"
echo
echo "Next: in Unity, select the .so and confirm the import settings are Android +"
echo "ARM64. Unity will silently exclude it otherwise, and ARP will fall back to the"
echo "managed path. See SETUP.md."
