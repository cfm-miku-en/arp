# AndroidRootProtector (ARP)

Server-authoritative tamper and root detection for Quest/Android games on PlayFab.

The client never bans itself. It gathers evidence and reports; every decision and
every ban happens in CloudScript.

## Quick start

1. **Tools → ARP → PlayFab Tutorial** - walks through the whole backend setup and
   has copy buttons for every CloudScript file.
2. **Tools → ARP → Add ARP Manager to Scene**, then wire the four events.
   For the ban message, add an **ARP Ban Display** component and point it at a
   `TMP_Text` — or bind `OnBanConfirmed` to your own UI directly.
3. Build the native library - see [SETUP.md](SETUP.md).
4. Add the manifest `<queries>` block below.

## Three layers

| Layer | Catches | Forgeable? |
|---|---|---|
| Meta attestation | Repacked APKs, compromised headsets | Not forgeable, but see below |
| Build checksums | Repacked APKs | Yes |
| Local device checks | Rooted headsets | Yes |

The attestation token is signed by Meta's server, so it cannot be forged. It can
still be bypassed: a client can omit it (ARP now treats that as a signal), or relay
a nonce to a clean device and pass back a genuine token. Treat it as much harder
and more expensive to defeat, not impossible. The other two layers
raise the cost from "repack the APK" to "repack the APK, then find and patch ARP
inside it" - a real bar for the population that actually cheats on Quest, and no
bar at all for someone determined.

## Package visibility - handled for you

Package visibility filtering (API 30+, and every Horizon app must target API 34 from
1 March 2026) means an installed-but-undeclared package is indistinguishable from an
absent one. Without `<queries>` entries the root-package check silently finds nothing.

ARP ships those entries as an `.androidlib`, so Android's manifest merger folds them
into your app automatically. **No manual step.**

The list is generated from `ARPRootDetector.RootPackages` so the manifest and the
runtime check cannot drift. If you edit that array, run:

**Tools → ARP → Regenerate Android Queries Manifest**

A pre-build check warns if the two have diverged.

Note the list is fixed at build time and readable by anyone who unzips your APK.
`QUERY_ALL_PACKAGES` would avoid both limits, and while it is restricted on Google
Play, that policy does not govern the Horizon Store - check Meta's current submission
requirements if you want it.

## Layout

```
Runtime/        detection, attestation, heartbeat, orchestration
Editor/         tutorial window, checksum window, build hook, Inspector
CloudScript/    six PlayFab functions - edit arpConfig.js only
NativeSource/   libarpnative.so source and build scripts
```

## Optional dependencies

Neither is required to compile.

- **Meta Platform SDK v55+** → defines `ARP_META_PLATFORM`, enables attestation.
- **PlayFab Unity SDK** → defines `ARP_PLAYFAB`, enables the default transport.

Both defines come from asmdef `versionDefines` when installed via UPM. Both SDKs
are commonly shipped as `.unitypackage` instead, which UPM cannot see - add the
define manually in that case. The tutorial window has a button for `ARP_PLAYFAB`.

Without a transport, ARP logs an error and does nothing. Implement
`IARPTransport` to use a different backend.

## Known limits

- **Ban evasion is cheap.** PlayFab bans are per-account and a new Meta account
  costs nothing. The device blocklist is a hashed `ANDROID_ID` - a factory reset
  clears it and a rooted device can spoof it.
- **IP bans need a PlayStream rule** and hit everyone behind the address.
- **The heartbeat cannot detect its own death in real time.** Silence produces no
  request. ARP judges the previous session when the next one starts.
- **Everything except attestation runs inside the process being checked.**
- **Attestation is bypassable by relay** - a genuine token from a clean device,
  replayed through a modified one. Architectural, not an ARP bug; Play Integrity
  has the same weakness.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Free for commercial use, including in closed-source games. Keep the copyright
notice and the NOTICE file with any redistribution, and mark any files you
modify as changed.

