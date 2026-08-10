# AndroidRootProtector (ARP)

Server-authoritative tamper and root detection for Quest/Android games on PlayFab.

The client never bans itself. It gathers evidence and reports; every decision and
every ban happens in CloudScript.

## Quick start

1. **Tools → ARP → PlayFab Tutorial** — walks through the whole backend setup and
   has copy buttons for every CloudScript file.
2. **Tools → ARP → Add ARP Manager to Scene**, then wire the four events.
3. Build the native library — see [SETUP.md](SETUP.md).
4. Add the manifest `<queries>` block below.

## Three layers

| Layer | Catches | Forgeable? |
|---|---|---|
| Meta attestation | Repacked APKs, compromised headsets | **No** — signed by Meta's server |
| Build checksums | Repacked APKs | Yes |
| Local device checks | Rooted headsets | Yes |

Attestation is the only layer a competent attacker cannot defeat. The other two
raise the cost from "run QuestPatcher" to "run QuestPatcher, then find and patch
ARP inside libil2cpp.so" — a real bar for the population that actually cheats on
Quest, and no bar at all for someone determined.

## Required manifest entries

Package visibility filtering (API 30+, and every Horizon app must target API 34
from 1 March 2026) means an installed-but-undeclared package is indistinguishable
from an absent one. Without this block, the root-package check silently finds
nothing.

Add to `Assets/Plugins/Android/AndroidManifest.xml`:

```xml
<queries>
    <package android:name="com.topjohnwu.magisk" />
    <package android:name="io.github.huskydg.magisk" />
    <package android:name="me.weishu.kernelsu" />
    <package android:name="me.bmax.apatch" />
    <package android:name="eu.chainfire.supersu" />
    <package android:name="com.noshufou.android.su" />
    <package android:name="com.koushikdutta.superuser" />
    <package android:name="com.thirdparty.superuser" />
    <package android:name="com.yellowes.su" />
    <package android:name="com.kingroot.kinguser" />
    <package android:name="com.kingo.root" />
    <package android:name="com.zachspong.temprootremovejb" />
    <package android:name="de.robv.android.xposed.installer" />
    <package android:name="org.lsposed.manager" />
    <package android:name="com.saurik.substrate" />
    <package android:name="com.devadvance.rootcloak" />
    <package android:name="com.devadvance.rootcloakplus" />
    <package android:name="com.formyhm.hideroot" />
    <package android:name="com.amphoras.hidemyroot" />
</queries>
```

This list is fixed at build time and readable by anyone who unzips your APK.
`QUERY_ALL_PACKAGES` would avoid that but it is a restricted permission for
launchers, antivirus and device management, and does not apply here.

Keep it in step with `RootPackages` in
[ARPRootDetector.cs](Runtime/ARPRootDetector.cs).

## Layout

```
Runtime/        detection, attestation, heartbeat, orchestration
Editor/         tutorial window, checksum window, build hook, Inspector
CloudScript/    six PlayFab functions — edit arpConfig.js only
NativeSource/   libarpnative.so source and build scripts
```

## Optional dependencies

Neither is required to compile.

- **Meta Platform SDK v55+** → defines `ARP_META_PLATFORM`, enables attestation.
- **PlayFab Unity SDK** → defines `ARP_PLAYFAB`, enables the default transport.

Both defines come from asmdef `versionDefines` when installed via UPM. Both SDKs
are commonly shipped as `.unitypackage` instead, which UPM cannot see — add the
define manually in that case. The tutorial window has a button for `ARP_PLAYFAB`.

Without a transport, ARP logs an error and does nothing. Implement
`IARPTransport` to use a different backend.

## Known limits

- **Ban evasion is cheap.** PlayFab bans are per-account and a new Meta account
  costs nothing. The device blocklist is a hashed `ANDROID_ID` — a factory reset
  clears it and a rooted device can spoof it.
- **IP bans need a PlayStream rule** and hit everyone behind the address.
- **The heartbeat cannot detect its own death in real time.** Silence produces no
  request. ARP judges the previous session when the next one starts.
- **Everything except attestation runs inside the process being checked.**

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Free for commercial use, including in closed-source games. Keep the copyright
notice and the NOTICE file with any redistribution, and mark any files you
modify as changed.

