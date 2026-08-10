// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
#if UNITY_ANDROID && !UNITY_EDITOR
using UnityEngine;
#endif

namespace ARP
{
    public static class ARPIntegrityChecker
    {
        private const int GetSigningCertificates = 0x08000000;

        // Populated while the content hash walks the zip, so the library check costs no
        // second enumeration. Populate() runs the hash before the check for that reason.
        public static readonly HashSet<string> ApkLibraryNames = new HashSet<string>(StringComparer.Ordinal);

        [DllImport("arpnative", EntryPoint = "arp_list_app_libraries")]
        private static extern int NativeListAppLibraries(byte[] buffer, int size);

        private static readonly string[] SideloadInstallers =
        {
            "com.android.shell", "com.google.android.packageinstaller",
            "com.android.packageinstaller",
        };

        private static readonly string[] ModLoaderLibraries =
        {
            "libmelonloader.so", "libsl2.so", "libmodloader.so", "libmain_modded.so",
        };

        private static readonly string[] ModDirectories =
        {
            "Mods", "MelonLoader", "mods", "sl2", "il2cpp_modding",
        };

        public static void Populate(ARPIntegrityReport report, ARPDistribution distribution)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));

#if UNITY_ANDROID && !UNITY_EDITOR
            report.SigningCertSha256 = GetSigningCertSha256(report.Signals);
            report.BuildContentHash = GetBuildContentHash(report.Signals);
            report.InstallSourcePackage = GetInstallSourcePackage(report.Signals);
            report.DeviceFingerprint = GetDeviceFingerprint();

            CheckInstallSource(report, distribution);
            CheckModLoaderArtifacts(report.Signals);
            CheckLoadedLibraries(report.Signals);

            report.ApkLibraries.Clear();
            report.ApkLibraries.AddRange(ApkLibraryNames);
#else
            report.Signals.Inconclusive("app:not_android");
#endif
        }

        // Re-runnable on its own so the monitor loop can repeat it. Injection after
        // startup is the case this check exists for, and a one-shot at launch would miss
        // exactly that. Requires Populate to have run first, since the expected set comes
        // from the zip walk.
        public static void ScanLoadedLibraries(ARPScanResult signals)
        {
            if (signals == null) throw new ArgumentNullException(nameof(signals));

#if UNITY_ANDROID && !UNITY_EDITOR
            CheckLoadedLibraries(signals);
#else
            signals.Inconclusive(ARPCheckIds.AppUnexpectedNativeLibrary);
#endif
        }

#if UNITY_ANDROID && !UNITY_EDITOR

        public static string GetSigningCertSha256(ARPScanResult signals)
        {
            try
            {
                using (var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                using (var activity = player.GetStatic<AndroidJavaObject>("currentActivity"))
                using (var pm = activity.Call<AndroidJavaObject>("getPackageManager"))
                {
                    var packageName = activity.Call<string>("getPackageName");

                    using (var info = pm.Call<AndroidJavaObject>("getPackageInfo", packageName, GetSigningCertificates))
                    using (var signingInfo = info.Get<AndroidJavaObject>("signingInfo"))
                    {
                        if (signingInfo == null)
                        {
                            signals?.Inconclusive(ARPCheckIds.AppSigningCertMismatch);
                            return null;
                        }

                        var signers = signingInfo.Call<AndroidJavaObject[]>("getApkContentsSigners");
                        if (signers == null || signers.Length == 0)
                        {
                            signals?.Inconclusive(ARPCheckIds.AppSigningCertMismatch);
                            return null;
                        }

                        var certBytes = signers[0].Call<byte[]>("toByteArray");
                        foreach (var s in signers) s.Dispose();

                        return ARPHashSpec.Sha256Hex(certBytes);
                    }
                }
            }
            catch (Exception)
            {
                signals?.Inconclusive(ARPCheckIds.AppSigningCertMismatch);
                return null;
            }
        }

        public static string GetBuildContentHash(ARPScanResult signals)
        {
            AndroidJavaObject zipFile = null;
            try
            {
                using (var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                using (var activity = player.GetStatic<AndroidJavaObject>("currentActivity"))
                using (var appInfo = activity.Call<AndroidJavaObject>("getApplicationInfo"))
                {
                    var sourceDir = appInfo.Get<string>("sourceDir");
                    if (string.IsNullOrEmpty(sourceDir))
                    {
                        signals?.Inconclusive(ARPCheckIds.AppContentHashMismatch);
                        return null;
                    }

                    zipFile = new AndroidJavaObject("java.util.zip.ZipFile", sourceDir);
                    var entries = new List<ARPZipEntry>();

                    using (var enumeration = zipFile.Call<AndroidJavaObject>("entries"))
                    {
                        while (enumeration.Call<bool>("hasMoreElements"))
                        {
                            using (var entry = enumeration.Call<AndroidJavaObject>("nextElement"))
                            {
                                var name = entry.Call<string>("getName");

                                if (!ARPHashSpec.IsHashedEntry(name)) continue;

                                if (name.StartsWith("lib/", StringComparison.Ordinal))
                                {
                                    var slash = name.LastIndexOf('/');
                                    ApkLibraryNames.Add(slash >= 0 ? name.Substring(slash + 1) : name);
                                }

                                entries.Add(new ARPZipEntry(
                                    name,
                                    entry.Call<long>("getSize"),
                                    entry.Call<long>("getCrc")));
                            }
                        }
                    }

                    return entries.Count == 0 ? null : ARPHashSpec.Fold(entries);
                }
            }
            catch (Exception)
            {
                signals?.Inconclusive(ARPCheckIds.AppContentHashMismatch);
                return null;
            }
            finally
            {
                if (zipFile != null)
                {
                    try { zipFile.Call("close"); } catch (Exception) { }
                    zipFile.Dispose();
                }
            }
        }

        public static string GetInstallSourcePackage(ARPScanResult signals)
        {
            try
            {
                using (var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                using (var activity = player.GetStatic<AndroidJavaObject>("currentActivity"))
                using (var pm = activity.Call<AndroidJavaObject>("getPackageManager"))
                {
                    var packageName = activity.Call<string>("getPackageName");
                    using (var sourceInfo = pm.Call<AndroidJavaObject>("getInstallSourceInfo", packageName))
                    {
                        return sourceInfo?.Call<string>("getInstallingPackageName");
                    }
                }
            }
            catch (Exception)
            {
                signals?.Inconclusive(ARPCheckIds.AppUnexpectedInstallSource);
                return null;
            }
        }

        private static void CheckInstallSource(ARPIntegrityReport report, ARPDistribution distribution)
        {
            if (distribution != ARPDistribution.MetaStoreOrAppLab) return;

            var installer = report.InstallSourcePackage;

            if (string.IsNullOrEmpty(installer))
            {
                report.Signals.Inconclusive(ARPCheckIds.AppUnexpectedInstallSource);
                return;
            }

            foreach (var sideload in SideloadInstallers)
            {
                if (string.Equals(installer, sideload, StringComparison.OrdinalIgnoreCase))
                {
                    report.Signals.Trigger(ARPCheckIds.AppUnexpectedInstallSource);
                    return;
                }
            }
        }

        private static void CheckModLoaderArtifacts(ARPScanResult signals)
        {
            try
            {
                using (var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                using (var activity = player.GetStatic<AndroidJavaObject>("currentActivity"))
                using (var appInfo = activity.Call<AndroidJavaObject>("getApplicationInfo"))
                {
                    var nativeLibDir = appInfo.Get<string>("nativeLibraryDir");
                    if (!string.IsNullOrEmpty(nativeLibDir) && System.IO.Directory.Exists(nativeLibDir))
                    {
                        foreach (var file in System.IO.Directory.GetFiles(nativeLibDir))
                        {
                            var name = System.IO.Path.GetFileName(file).ToLowerInvariant();
                            foreach (var loader in ModLoaderLibraries)
                            {
                                if (name != loader) continue;
                                signals.Trigger(LoaderCheckId(loader));
                            }
                        }
                    }

                    using (var filesDir = activity.Call<AndroidJavaObject>("getFilesDir"))
                    {
                        var basePath = filesDir?.Call<string>("getAbsolutePath");
                        if (string.IsNullOrEmpty(basePath)) return;

                        var parent = System.IO.Directory.GetParent(basePath)?.FullName ?? basePath;
                        foreach (var dir in ModDirectories)
                        {
                            if (System.IO.Directory.Exists(System.IO.Path.Combine(parent, dir)))
                            {
                                signals.Trigger(ARPCheckIds.AppModsDirectoryPresent);
                                return;
                            }
                        }
                    }
                }
            }
            catch (Exception) { signals.Inconclusive(ARPCheckIds.AppModsDirectoryPresent); }
        }

        // Every hardcoded artifact list shares one flaw: it only finds libraries someone
        // already named. An injected loader called anything else walks straight past it.
        //
        // This inverts the question. Instead of asking whether a known-bad library is
        // present, it asks whether anything is executing that the APK does not ship -
        // which catches arbitrary names, and catches runtime injection that never touched
        // the APK at all and so leaves the content hash intact.
        private static void CheckLoadedLibraries(ARPScanResult signals)
        {
            if (!ARPRootDetector.NativeAvailable || ApkLibraryNames.Count == 0)
            {
                signals.Inconclusive(ARPCheckIds.AppUnexpectedNativeLibrary);
                return;
            }

            var buffer = new byte[8192];
            int count;

            try
            {
                count = NativeListAppLibraries(buffer, buffer.Length);
            }
            catch (Exception)
            {
                signals.Inconclusive(ARPCheckIds.AppUnexpectedNativeLibrary);
                return;
            }

            if (count <= 0)
            {
                signals.Inconclusive(ARPCheckIds.AppUnexpectedNativeLibrary);
                return;
            }

            foreach (var loaded in SplitNulTerminated(buffer))
            {
                if (ApkLibraryNames.Contains(loaded)) continue;

                signals.Trigger(ARPCheckIds.AppUnexpectedNativeLibrary);
                return;
            }
        }

        private static IEnumerable<string> SplitNulTerminated(byte[] buffer)
        {
            var start = 0;
            for (var i = 0; i < buffer.Length; i++)
            {
                if (buffer[i] != 0) continue;
                if (i == start) yield break;

                yield return Encoding.UTF8.GetString(buffer, start, i - start);
                start = i + 1;
            }
        }

        private static string LoaderCheckId(string library)
        {
            switch (library)
            {
                case "libmelonloader.so": return ARPCheckIds.AppModLoaderMelon;
                case "libsl2.so": return ARPCheckIds.AppModLoaderScotland2;
                case "libmodloader.so": return ARPCheckIds.AppModLoaderQuestLoader;
                default: return ARPCheckIds.AppUnexpectedNativeLibrary;
            }
        }

        public static string GetDeviceFingerprint()
        {
            try
            {
                using (var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                using (var activity = player.GetStatic<AndroidJavaObject>("currentActivity"))
                using (var resolver = activity.Call<AndroidJavaObject>("getContentResolver"))
                using (var secure = new AndroidJavaClass("android.provider.Settings$Secure"))
                {
                    var androidId = secure.CallStatic<string>("getString", resolver, "android_id");
                    if (string.IsNullOrEmpty(androidId)) return null;

                    var packageName = activity.Call<string>("getPackageName");
                    var salted = "arp-hwid/v1|" + packageName + "|" + androidId;
                    return ARPHashSpec.Sha256Hex(Encoding.UTF8.GetBytes(salted));
                }
            }
            catch (Exception) { return null; }
        }
#endif
    }
}
