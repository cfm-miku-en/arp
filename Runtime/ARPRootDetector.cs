// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
#if UNITY_ANDROID && !UNITY_EDITOR
using UnityEngine;
#endif

namespace ARP
{
    public static class ARPRootDetector
    {
        private static readonly string[] SuPaths =
        {
            "/system/bin/su", "/system/xbin/su", "/system/sbin/su", "/sbin/su",
            "/su/bin/su", "/vendor/bin/su", "/data/local/bin/su",
            "/data/local/xbin/su", "/system/bin/failsafe/su",
        };

        private static readonly string[] MagiskPaths =
        {
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
            "/cache/magisk.log", "/data/adb/magisk.db", "/data/adb/magisk_simple",
        };

        private static readonly string[] KernelSuPaths = { "/data/adb/ksu", "/data/adb/ksud" };

        private static readonly string[] APatchPaths = { "/data/adb/ap", "/data/adb/apd" };

        // Public because the editor generates the manifest <queries> block from this
        // exact array. Two hand-maintained copies of the same list would drift, and the
        // failure is silent: an undeclared package reports "not installed" identically
        // to one that genuinely is not there.
        public static readonly string[] RootPackages =
        {
            "com.topjohnwu.magisk", "io.github.huskydg.magisk", "me.weishu.kernelsu",
            "me.bmax.apatch", "eu.chainfire.supersu", "com.noshufou.android.su",
            "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su",
            "com.kingroot.kinguser", "com.kingo.root", "com.zachspong.temprootremovejb",
            "de.robv.android.xposed.installer", "org.lsposed.manager",
            "com.saurik.substrate", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "com.formyhm.hideroot", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "io.github.vvb2060.magisk",
            "org.meowcat.edxposed.manager",
        };

        // On-device cheat tooling: mod-loader installers and standalone mod menus.
        // Separate from RootPackages because a mod menu means the app is compromised,
        // not the headset, and reporting it under a device: id would mis-tier it.
        //
        // Ships empty on purpose. Package ids here have to be real - a guessed one is a
        // check that silently never fires while looking like coverage. Get them with
        // "adb shell pm list packages" on a device that has the tool, add them here, then
        // run Tools > ARP > Regenerate Android Queries Manifest.
        public static readonly string[] CheatToolPackages =
        {
        };

        private static readonly string[] LayerProbePaths =
        {
            "/system/bin/su",
            "/data/adb/magisk",
            "/system/bin/sh",
            "/proc/self/maps",
        };

        private const string NativeLib = "arpnative";

        [DllImport(NativeLib, EntryPoint = "arp_path_exists")]
        private static extern int NativePathExists([MarshalAs(UnmanagedType.LPStr)] string path);

        [DllImport(NativeLib, EntryPoint = "arp_selinux_enforcing")]
        private static extern int NativeSelinuxEnforcing();

        private static bool _nativeProbed;
        private static bool _nativeAvailable;

        public static bool NativeAvailable
        {
            get
            {
                ProbeNative();
                return _nativeAvailable;
            }
        }

        private static void ProbeNative()
        {
            if (_nativeProbed) return;
            _nativeProbed = true;

#if UNITY_ANDROID && !UNITY_EDITOR
            try
            {
                NativePathExists("/system/bin/sh");
                _nativeAvailable = true;
            }
            catch (DllNotFoundException) { _nativeAvailable = false; }
            catch (EntryPointNotFoundException) { _nativeAvailable = false; }
#else
            _nativeAvailable = false;
#endif
        }

        public static ARPScanResult Scan(ARPScanDepth depth = ARPScanDepth.Full)
        {
            var result = new ARPScanResult();
            foreach (var _ in ScanIncremental(result, depth)) { }
            return result;
        }

        // Quick covers everything that is a file read or a proc parse, so it is cheap
        // enough to repeat every few seconds. Full adds the two that are not: spawning
        // a process for the su probe, and walking the package list over JNI.
        public static IEnumerable<string> ScanIncremental(
            ARPScanResult result, ARPScanDepth depth = ARPScanDepth.Full)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));

#if UNITY_ANDROID && !UNITY_EDITOR
            ProbeNative();

            CheckSelinux(result);
            yield return "selinux";

            CheckRootManagerArtifacts(result);
            yield return "artifacts";

            CheckMounts(result);
            yield return "mounts";

            CheckLayerConsistency(result);
            yield return "layers";

            CheckSuBinaries(result);
            yield return "su_paths";

            if (depth == ARPScanDepth.Full)
            {
                CheckSuExecutable(result);
                yield return "su_exec";

                CheckRootPackages(result);
                yield return "packages";

                CheckBuildTags(result);
                yield return "build_tags";
            }
#else
            result.Inconclusive("device:not_android");
            yield return "skipped";
#endif
        }

#if UNITY_ANDROID && !UNITY_EDITOR

        private static void CheckSelinux(ARPScanResult result)
        {
            if (NativeAvailable)
            {
                try
                {
                    var native = NativeSelinuxEnforcing();
                    if (native == 0) { result.Trigger(ARPCheckIds.DeviceSelinuxPermissive); return; }
                    if (native == 1) return;
                }
                catch (Exception) {  }
            }

            try
            {
                const string path = "/sys/fs/selinux/enforce";
                if (!File.Exists(path))
                {
                    result.Inconclusive(ARPCheckIds.DeviceSelinuxPermissive);
                    return;
                }

                var raw = File.ReadAllText(path).Trim();
                if (raw == "0") result.Trigger(ARPCheckIds.DeviceSelinuxPermissive);
                else if (raw != "1") result.Inconclusive(ARPCheckIds.DeviceSelinuxPermissive);
            }
            catch (UnauthorizedAccessException) { result.Inconclusive(ARPCheckIds.DeviceSelinuxPermissive); }
            catch (IOException) { result.Inconclusive(ARPCheckIds.DeviceSelinuxPermissive); }
        }

        private static void CheckRootManagerArtifacts(ARPScanResult result)
        {
            if (AnyPathExists(MagiskPaths)) result.Trigger(ARPCheckIds.DeviceMagiskArtifact);
            if (AnyPathExists(KernelSuPaths)) result.Trigger(ARPCheckIds.DeviceKernelSuArtifact);
            if (AnyPathExists(APatchPaths)) result.Trigger(ARPCheckIds.DeviceAPatchArtifact);
        }

        private static void CheckMounts(ARPScanResult result)
        {
            try
            {
                var mounts = File.ReadAllText("/proc/self/mountinfo");
                if (mounts.IndexOf("magisk", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    mounts.IndexOf("/data/adb", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    result.Trigger(ARPCheckIds.DeviceSuspiciousMount);
                }
            }
            catch (Exception) { result.Inconclusive(ARPCheckIds.DeviceSuspiciousMount); }

            try
            {
                var prev = File.ReadAllText("/proc/self/attr/prev").Trim('\0', ' ', '\n');

                if (prev.Length > 0 && prev.IndexOf("zygote", StringComparison.OrdinalIgnoreCase) < 0)
                    result.Inconclusive(ARPCheckIds.DeviceZygiskContext);
            }
            catch (Exception) { result.Inconclusive(ARPCheckIds.DeviceZygiskContext); }
        }

        private static void CheckLayerConsistency(ARPScanResult result)
        {
            if (!NativeAvailable)
            {
                result.Inconclusive(ARPCheckIds.DeviceLayerDisagreement);
                return;
            }

            foreach (var path in LayerProbePaths)
            {
                bool nativeSays;
                bool javaSays;

                try
                {
                    nativeSays = NativePathExists(path) != 0;
                    javaSays = File.Exists(path) || Directory.Exists(path);
                }
                catch (Exception)
                {
                    result.Inconclusive(ARPCheckIds.DeviceLayerDisagreement);
                    continue;
                }

                if (nativeSays != javaSays)
                {
                    result.Trigger(ARPCheckIds.DeviceLayerDisagreement);
                    return;
                }
            }
        }

        private static void CheckSuBinaries(ARPScanResult result)
        {
            if (AnyPathExists(SuPaths)) result.Trigger(ARPCheckIds.DeviceSuBinaryPresent);
        }

        private static void CheckSuExecutable(ARPScanResult result)
        {
            AndroidJavaObject process = null;
            try
            {
                using (var runtimeClass = new AndroidJavaClass("java.lang.Runtime"))
                using (var runtime = runtimeClass.CallStatic<AndroidJavaObject>("getRuntime"))
                {
                    process = runtime.Call<AndroidJavaObject>("exec", (object)new[] { "which", "su" });
                    var exitCode = process.Call<int>("waitFor");
                    if (exitCode == 0) result.Trigger(ARPCheckIds.DeviceSuExecutable);
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                if (process != null)
                {
                    try { process.Call("destroy"); } catch (Exception) { }
                    process.Dispose();
                }
            }
        }

        private static void CheckRootPackages(ARPScanResult result)
        {
            try
            {
                using (var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                using (var activity = player.GetStatic<AndroidJavaObject>("currentActivity"))
                using (var pm = activity.Call<AndroidJavaObject>("getPackageManager"))
                {
                    foreach (var package in RootPackages)
                    {
                        if (IsInstalled(pm, package))
                        {
                            result.Trigger(ARPCheckIds.DeviceRootPackageInstalled);
                            break;
                        }
                    }

                    foreach (var package in CheatToolPackages)
                    {
                        if (IsInstalled(pm, package))
                        {
                            result.Trigger(ARPCheckIds.AppCheatToolInstalled);
                            break;
                        }
                    }
                }
            }
            catch (Exception) { result.Inconclusive(ARPCheckIds.DeviceRootPackageInstalled); }
        }

        private static void CheckBuildTags(ARPScanResult result)
        {
            try
            {
                using (var build = new AndroidJavaClass("android.os.Build"))
                {
                    var tags = build.GetStatic<string>("TAGS");
                    if (!string.IsNullOrEmpty(tags) &&
                        tags.IndexOf("test-keys", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        result.Trigger(ARPCheckIds.DeviceTestKeys);
                    }
                }
            }
            catch (Exception) { result.Inconclusive(ARPCheckIds.DeviceTestKeys); }
        }

        private static bool IsInstalled(AndroidJavaObject packageManager, string package)
        {
            try
            {
                using (packageManager.Call<AndroidJavaObject>("getPackageInfo", package, 0))
                {
                    return true;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool AnyPathExists(string[] paths)
        {
            foreach (var path in paths)
            {
                if (NativeAvailable)
                {
                    try { if (NativePathExists(path) != 0) return true; continue; }
                    catch (Exception) {  }
                }

                try { if (File.Exists(path) || Directory.Exists(path)) return true; }
                catch (Exception) { }
            }
            return false;
        }
#endif
    }
}
