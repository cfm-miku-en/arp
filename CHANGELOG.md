# Changelog

All notable changes to AndroidRootProtector. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2026-08-10

First build. **Nothing here has been tested beyond compiling.** The native library
builds and the C# compiles; no check has run on a headset, no CloudScript function has
been deployed, and no detection has been verified against real rooted or modded
hardware. Treat every threshold as unvalidated and run `enforcementMode` as
`FlagForReview`.

### Added

- Meta Platform Integrity Attestation, verified server-side against
  `graph.oculus.com`, with server-issued single-use nonces
- Build checksums: signing certificate SHA-256 and a zip central-directory content
  hash covering `lib/`, `classes*.dex`, `AndroidManifest.xml` and `assets/bin/Data/`
- Expected-library reference set, so an added cheat `.so` is caught even when no mod
  loader is involved
- In-memory code integrity: executable-page dirty check plus comparison of executing
  code against the APK it was loaded from
- Loaded-library enumeration from `/proc/self/maps`, catching runtime injection that
  never touches the APK
- Local device checks led by SELinux enforcement, with native-vs-Java layer
  disagreement detection
- Continuous monitoring with tiered scan intervals and report-on-change
- Heartbeat watchdog with fail-closed network severing
- Three independent ban targets: PlayFab account, IP address, and a device blocklist
- Six CloudScript functions plus a PlayStream login-capture action
- Editor tooling: PlayFab tutorial with per-script copy, post-build checksum window,
  help window, and generated Android `<queries>` manifest
- `libarpnative.so` source, CMake project and build scripts for Windows and Unix

### Known limitations

- Attestation cannot be forged but can be bypassed by relay from a clean device
- Every other layer runs in-process and can be patched out
- `Private_Dirty` and `/proc/self/attr/prev` thresholds need baselining on a stock
  Quest before they are allowed to enforce
- PlayFab bans are per-account; the device blocklist is a pseudo-HWID that a factory
  reset clears
