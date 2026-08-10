# ARP - building and wiring up `libarpnative.so`

This covers the native library only. Backend setup lives in the Unity editor:
**Tools → ARP → PlayFab Tutorial**.

---

## What the library is for, and what you lose without it

`ARPRootDetector` asks two questions through native code:

1. **Is SELinux enforcing?** (`/sys/fs/selinux/enforce`) - the highest-value root
   check on Quest, because the CVE-2025-21479 chain used to root Quest 3/3S
   disables SELinux outright, and a stock headset is always enforcing.
2. **Do the native and Java layers agree?** The same file-existence probes run
   through both raw syscalls and `java.io.File`, and the answers are compared.
   Frida and LSPosed bypass modules usually hook one layer and not the other, so a
   disagreement is itself evidence of instrumentation - often stronger than either
   answer alone, since a hider produces the signal in the act of hiding.

**ARP works without it.** `[DllImport]` failures are caught, `NativeAvailable`
goes false, and the SELinux check falls back to a managed `File.ReadAllText`.

What you actually give up:

| | With the `.so` | Without |
|---|---|---|
| SELinux check | Raw syscall, hard to hook | Managed read, easy to hook |
| Layer disagreement | Runs | **Never runs** - reports inconclusive |
| Path probes | Raw `faccessat` | `File.Exists` |

So it is optional in the sense that nothing breaks, and not optional in the sense
that one of the two strongest device checks simply does not execute. Build it.

---

## Prerequisites

You need the **Android NDK** and **CMake**. If you already build Android from
Unity, you have both - no separate install needed.

### Using Unity's bundled NDK (easiest)

Unity ships the NDK with the Android Build Support module. Find it at:

- **Windows** - `C:\Program Files\Unity\Hub\Editor\<version>\Editor\Data\PlaybackEngines\AndroidPlayer\NDK`
- **macOS** - `/Applications/Unity/Hub/Editor/<version>/PlaybackEngines/AndroidPlayer/NDK`

Or ask Unity directly: **Edit → Preferences → External Tools**, under Android.
The NDK path is listed there.

CMake is next to it, under `.../AndroidPlayer/Tools/CMake/bin`. Add that to `PATH`
for the build if you do not have CMake installed globally.

### Or install standalone

[NDK r27 or newer](https://developer.android.com/ndk/downloads) plus
[CMake 3.18+](https://cmake.org/download/).

---

## Build it

From `NativeSource/`:

```bash
cd NativeSource
```

**Windows (PowerShell):**

```bash
.\build.ps1 -NdkPath "C:\Program Files\Unity\Hub\Editor\6000.0.30f1\Editor\Data\PlaybackEngines\AndroidPlayer\NDK"
```

Or set it once and just run the script:

```bash
$env:ANDROID_NDK_HOME = "C:\Program Files\Unity\Hub\Editor\6000.0.30f1\Editor\Data\PlaybackEngines\AndroidPlayer\NDK"; .\build.ps1
```

**macOS / Linux:**

```bash
ANDROID_NDK_HOME=/path/to/ndk ./build.sh
```

Only `arm64-v8a` is built. Every Quest is arm64 - there is no second ABI worth
carrying.

The script copies the result to:

```
Runtime/Plugins/Android/arm64-v8a/libarpnative.so
```

Expect something around 5-10 KB. It links no NDK libraries and exports two
symbols.

---

## Wire it up in Unity

**This step is the one people skip, and the failure is silent.**

1. Let Unity import the `.so`. It should appear at
   `Runtime/Plugins/Android/arm64-v8a/libarpnative.so`.
2. Select it and check the Inspector:

   | Setting | Value |
   |---|---|
   | Select platforms for plugin | **Android** only |
   | CPU | **ARM64** |

   Unity usually infers both from the `Plugins/Android/arm64-v8a/` path. Confirm
   it anyway - if the platform is unticked, Unity excludes the library from the
   APK without warning, and the only symptom is `NativeAvailable` quietly
   returning false on device.
3. Hit **Apply**.
4. In **Player Settings → Other Settings**, confirm **Target Architectures** has
   **ARM64** ticked. If your build excludes ARM64 you have bigger problems, but
   it is worth a glance.

---

## Verify it loaded

The library is only probed on device - in the editor `NativeAvailable` is always
false, by design, because there is nothing meaningful to probe.

Add this to a scene script and check logcat on the headset:

```csharp
Debug.Log($"[ARP] native available: {ARP.ARPRootDetector.NativeAvailable}");
```

```bash
adb logcat -s Unity:V | findstr ARP
```

`native available: True` means you are done. False means work through the
troubleshooting below.

The Inspector on `ARPManager` also shows native availability once you have run a
build, so you do not have to keep a debug line around permanently.

---

## Troubleshooting

**`DllNotFoundException: arpnative`**

The library is not in the APK. Almost always the plugin import settings from step
2. Confirm by unzipping your build:

```bash
unzip -l yourgame.apk | findstr arpnative
```

You should see `lib/arm64-v8a/libarpnative.so`. Nothing means Unity excluded it.

**`EntryPointNotFoundException`**

The library loaded but a symbol is missing. Usually a stale `.so` from before an
edit to `arpnative.c`. Delete `NativeSource/build/` and rebuild - CMake caches
aggressively and will happily relink an old object file.

**Builds fine, still false on device**

Check the ABI actually matches:

```bash
adb shell getprop ro.product.cpu.abi
```

Should be `arm64-v8a`. If you built for a different ABI the library is present
but unloadable.

**`android.toolchain.cmake` not found**

You pointed at the wrong directory. The NDK root is the folder *containing*
`build/`, `toolchains/` and `sources/` - not `build/cmake/`, and not the
`AndroidPlayer` folder above it.

**Loads on your test headset, not on a retail one**

Check 16 KB page alignment. `CMakeLists.txt` already passes
`-Wl,-z,max-page-size=16384`, but if you built with your own flags on an NDK older
than r27 the library may be aligned for 4 KB pages and will refuse to load on
Android 15.

---

## When you change `arpnative.c`

Rebuild and re-copy - the script does both. There is no version handshake between
the C and the C# beyond the two entry point names, so if you rename or add an
export, update the `[DllImport]` declarations in
[ARPRootDetector.cs](Runtime/ARPRootDetector.cs) to match. A mismatch surfaces as
`EntryPointNotFoundException` at runtime rather than as a compile error.

---

## What this library deliberately does not do

- **No logging.** Nothing goes to logcat. Telling an attacker which check fired,
  in a log they can read on their own device, would undo most of the point.
- **No JNI.** No `JNI_OnLoad`, no `env` pointer, no Java callbacks. Two plain C
  functions, called straight from C#.
- **No obfuscation.** Symbol visibility is restricted and the binary is stripped,
  which raises the effort a little. It is not a packer and does not pretend to be.
  Someone determined will find these two functions; the goal is to be more work
  than patching a C# method, not to be unbreakable.

Same honesty as everywhere else in ARP: this runs inside a process the attacker
controls, so it can be defeated. The one check that cannot be forged is the Meta
attestation token, because it is signed by Meta's server rather than by anything
on the headset.
