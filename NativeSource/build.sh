#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 cfm-miku-en
# SPDX-License-Identifier: Apache-2.0

# Builds libarpnative.so for Quest (arm64-v8a) and drops it where Unity expects it.
#
#   ./build.sh
#   ANDROID_NDK_HOME=/path/to/ndk ./build.sh
#
# Needs the Android NDK and CMake. Both ship with Unity's Android module — see
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

# Quest is arm64-v8a only, so there is exactly one ABI to build.
echo "Configuring (arm64-v8a, $ANDROID_PLATFORM)..."
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM="$ANDROID_PLATFORM" \
    -DCMAKE_BUILD_TYPE=MinSizeRel

echo "Building..."
cmake --build "$BUILD_DIR"

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
