
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
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/vendor/bin/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/bin/failsafe/su",
            "/debug_ramdisk/su"
        };

        private static readonly string[] MagiskPaths =
        {
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/cache/magisk.log",
            "/data/adb/magisk.db",
            "/data/adb/magisk_simple"
        };

        private static readonly string[] KernelSuPaths =
        {
            "/data/adb/ksu",
            "/data/adb/ksud"
        };

        private static readonly string[] APatchPaths =
        {
            "/data/adb/ap",
            "/data/adb/apd"
        };

        public static readonly string[] RootPackages =
        {
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",
            "me.weishu.kernelsu",
            "me.bmax.apatch",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.zachspong.temprootremovejb",
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "com.saurik.substrate",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "com.formyhm.hideroot",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "io.github.vvb2060.magisk",
            "org.meowcat.edxposed.manager"
        };

        public static readonly string[] CheatToolPackages = { };

        private static readonly string[] LayerProbePaths =
        {
            "/system/bin/su",
            "/data/adb/magisk",
            "/system/bin/sh",
            "/proc/self/maps"
        };

        private const string NativeLib = "arpnative";

        [DllImport(NativeLib, EntryPoint = "arp_path_exists")]
        private static extern int NativePathExists(
            [MarshalAs(UnmanagedType.LPStr)] string path);

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
            if (_nativeProbed)
                return;

            _nativeProbed = true;

#if UNITY_ANDROID && !UNITY_EDITOR
            try
            {
                NativePathExists("/system/bin/sh");
                _nativeAvailable = true;
            }
            catch (DllNotFoundException)
            {
                _nativeAvailable = false;
            }
            catch (EntryPointNotFoundException)
            {
                _nativeAvailable = false;
            }
            catch (BadImageFormatException)
            {
                _nativeAvailable = false;
            }
#else
            _nativeAvailable = false;
#endif
        }

        public static ARPScanResult Scan(
            ARPScanDepth depth = ARPScanDepth.Full)
        {
            var result = new ARPScanResult();

            foreach (var stage in ScanIncremental(result, depth))
            {
            }

            return result;
        }

        public static IEnumerable<string> ScanIncremental(
            ARPScanResult result,
            ARPScanDepth depth = ARPScanDepth.Full)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

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
                    int state = NativeSelinuxEnforcing();

                    if (state == 0)
                    {
                        result.Trigger(ARPCheckIds.DeviceSelinuxPermissive);
                        return;
                    }

                    if (state == 1)
                        return;
                }
                catch (Exception)
                {
                }
            }

            try
            {
                const string path = "/sys/fs/selinux/enforce";

                if (!File.Exists(path))
                {
                    result.Inconclusive(
                        ARPCheckIds.DeviceSelinuxPermissive);
                    return;
                }

                string value = File.ReadAllText(path).Trim();

                if (value == "0")
                    result.Trigger(ARPCheckIds.DeviceSelinuxPermissive);
                else if (value != "1")
                    result.Inconclusive(
                        ARPCheckIds.DeviceSelinuxPermissive);
            }
            catch (Exception)
            {
                result.Inconclusive(
                    ARPCheckIds.DeviceSelinuxPermissive);
            }
        }

        private static void CheckRootManagerArtifacts(
            ARPScanResult result)
        {
            if (AnyPathExists(MagiskPaths))
                result.Trigger(ARPCheckIds.DeviceMagiskArtifact);

            if (AnyPathExists(KernelSuPaths))
                result.Trigger(ARPCheckIds.DeviceKernelSuArtifact);

            if (AnyPathExists(APatchPaths))
                result.Trigger(ARPCheckIds.DeviceAPatchArtifact);
        }

        private static void CheckMounts(ARPScanResult result)
        {
            try
            {
                string[] lines =
                    File.ReadAllLines("/proc/self/mountinfo");

                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    string normalized = line.ToLowerInvariant();

                    if (normalized.Contains("magisk") ||
                        normalized.Contains("/data/adb"))
                    {
                        result.Trigger(
                            ARPCheckIds.DeviceSuspiciousMount);
                        break;
                    }
                }
            }
            catch (Exception)
            {
                result.Inconclusive(
                    ARPCheckIds.DeviceSuspiciousMount);
            }

            try
            {
                string context = File.ReadAllText(
                    "/proc/self/attr/prev").Trim('\0', ' ', '\n', '\r');

                if (context.Length > 0 &&
                    context.IndexOf(
                        "zygote",
                        StringComparison.OrdinalIgnoreCase) < 0)
                {
                    result.Inconclusive(
                        ARPCheckIds.DeviceZygiskContext);
                }
            }
            catch (Exception)
            {
                result.Inconclusive(
                    ARPCheckIds.DeviceZygiskContext);
            }
        }

        private static void CheckLayerConsistency(
            ARPScanResult result)
        {
            if (!NativeAvailable)
            {
                result.Inconclusive(
                    ARPCheckIds.DeviceLayerDisagreement);
                return;
            }

            foreach (string path in LayerProbePaths)
            {
                bool nativeExists;
                bool managedExists;

                try
                {
                    nativeExists = NativePathExists(path) != 0;
                    managedExists =
                        File.Exists(path) || Directory.Exists(path);
                }
                catch (Exception)
                {
                    result.Inconclusive(
                        ARPCheckIds.DeviceLayerDisagreement);
                    continue;
                }

                if (nativeExists != managedExists)
                {
                    result.Trigger(
                        ARPCheckIds.DeviceLayerDisagreement);
                    return;
                }
            }
        }

        private static void CheckSuBinaries(ARPScanResult result)
        {
            if (AnyPathExists(SuPaths))
                result.Trigger(ARPCheckIds.DeviceSuBinaryPresent);
        }

        private static void CheckSuExecutable(ARPScanResult result)
        {
            AndroidJavaObject process = null;
            AndroidJavaObject timeUnit = null;

            try
            {
                using (var runtimeClass =
                       new AndroidJavaClass("java.lang.Runtime"))
                using (var runtime =
                       runtimeClass.CallStatic<AndroidJavaObject>(
                           "getRuntime"))
                using (var timeUnitClass =
                       new AndroidJavaClass(
                           "java.util.concurrent.TimeUnit"))
                {
                    timeUnit =
                        timeUnitClass.GetStatic<AndroidJavaObject>(
                            "MILLISECONDS");

                    process = runtime.Call<AndroidJavaObject>(
                        "exec",
                        (object)new[] { "which", "su" });

                    bool completed = process.Call<bool>(
                        "waitFor",
                        1500L,
                        timeUnit);

                    if (!completed)
                    {
                        process.Call("destroy");
                        result.Inconclusive(
                            ARPCheckIds.DeviceSuExecutable);
                        return;
                    }

                    int exitCode = process.Call<int>("exitValue");

                    if (exitCode == 0)
                        result.Trigger(
                            ARPCheckIds.DeviceSuExecutable);
                }
            }
            catch (Exception)
            {
                result.Inconclusive(
                    ARPCheckIds.DeviceSuExecutable);
            }
            finally
            {
                if (process != null)
                {
                    try
                    {
                        process.Call("destroy");
                    }
                    catch (Exception)
                    {
                    }

                    process.Dispose();
                }

                if (timeUnit != null)
                    timeUnit.Dispose();
            }
        }

        private static void CheckRootPackages(ARPScanResult result)
        {
            try
            {
                using (var player =
                       new AndroidJavaClass(
                           "com.unity3d.player.UnityPlayer"))
                using (var activity =
                       player.GetStatic<AndroidJavaObject>(
                           "currentActivity"))
                using (var packageManager =
                       activity.Call<AndroidJavaObject>(
                           "getPackageManager"))
                {
                    foreach (string package in RootPackages)
                    {
                        if (!IsInstalled(packageManager, package))
                            continue;

                        result.Trigger(
                            ARPCheckIds.DeviceRootPackageInstalled);
                        break;
                    }

                    foreach (string package in CheatToolPackages)
                    {
                        if (!IsInstalled(packageManager, package))
                            continue;

                        result.Trigger(
                            ARPCheckIds.AppCheatToolInstalled);
                        break;
                    }
                }
            }
            catch (Exception)
            {
                result.Inconclusive(
                    ARPCheckIds.DeviceRootPackageInstalled);
            }
        }

        private static void CheckBuildTags(ARPScanResult result)
        {
            try
            {
                using (var build =
                       new AndroidJavaClass("android.os.Build"))
                {
                    string tags = build.GetStatic<string>("TAGS");

                    if (!string.IsNullOrEmpty(tags) &&
                        tags.IndexOf(
                            "test-keys",
                            StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        result.Trigger(ARPCheckIds.DeviceTestKeys);
                    }
                }
            }
            catch (Exception)
            {
                result.Inconclusive(ARPCheckIds.DeviceTestKeys);
            }
        }

        private static bool IsInstalled(
            AndroidJavaObject packageManager,
            string package)
        {
            try
            {
                using (packageManager.Call<AndroidJavaObject>(
                           "getPackageInfo", package, 0))
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
            foreach (string path in paths)
            {
                if (NativeAvailable)
                {
                    try
                    {
                        if (NativePathExists(path) != 0)
                            return true;

                        continue;
                    }
                    catch (Exception)
                    {
                    }
                }

                try
                {
                    if (File.Exists(path) || Directory.Exists(path))
                        return true;
                }
                catch (Exception)
                {
                }
            }

            return false;
        }

#endif
    }
}
