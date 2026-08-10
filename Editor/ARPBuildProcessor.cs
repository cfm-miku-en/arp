// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using ARP;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;
using Debug = UnityEngine.Debug;

namespace ARP.Editor
{
    public sealed class ARPBuildProcessor : IPostprocessBuildWithReport
    {
        public int callbackOrder => 4000;

        public void OnPostprocessBuild(BuildReport report)
        {
            if (report == null) return;
            if (report.summary.platform != BuildTarget.Android) return;
            if ((report.summary.options & BuildOptions.Development) != 0) return;
            if (report.summary.result == BuildResult.Failed ||
                report.summary.result == BuildResult.Cancelled) return;

            var outputPath = report.summary.outputPath;
            var previous = ARPChecksumRecord.Load();

            var record = new ARPChecksumRecord
            {
                OutputPath = outputPath,
                ProductName = PlayerSettings.productName,
                BuiltAtUtc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                PreviousSigningCertSha256 = previous?.SigningCertSha256,
            };

            record.BuildContentHash = ComputeContentHash(outputPath);
            record.SigningCertSha256 = ComputeCertificateHash(out var note);
            record.CertificateNote = note;
            record.Save();

            Debug.LogWarning(
                "[ARP] UPDATE YOUR CLOUDSCRIPT BEFORE PUBLISHING.\n" +
                "Build content hash: " + (record.HasContentHash ? record.BuildContentHash : "unavailable") + "\n" +
                "Written to " + ARPChecksumRecord.TextPath);

            ARPChecksumWindow.Show(record);
        }

        private static string ComputeContentHash(string outputPath)
        {
            if (string.IsNullOrEmpty(outputPath)) return null;

            if (outputPath.EndsWith(".aab", StringComparison.OrdinalIgnoreCase))
            {
                Debug.LogWarning(
                    "[ARP] This build is an .aab. The content hash is computed over the APK a " +
                    "player actually installs, and an app bundle is repackaged before it gets " +
                    "there, so a hash taken from the .aab would never match on device. Build an " +
                    "APK — Meta Horizon accepts APKs — or disable the content hash check and " +
                    "rely on the signing certificate instead.");
                return null;
            }

            if (!File.Exists(outputPath))
            {
                if (Directory.Exists(outputPath))
                {
                    Debug.LogWarning(
                        "[ARP] This looks like an exported Gradle project rather than a built APK. " +
                        "Build the APK, then reopen Tools > ARP > Show Last Build Checksums.");
                }
                return null;
            }

            try
            {
                var entries = ARPZipCentralDirectory.Read(outputPath);
                if (entries.Count == 0)
                {
                    Debug.LogWarning("[ARP] No hashable entries found in the APK.");
                    return null;
                }

                return ARPHashSpec.Fold(entries);
            }
            catch (Exception e)
            {
                Debug.LogError("[ARP] Could not read the APK central directory: " + e.Message);
                return null;
            }
        }

        private static string ComputeCertificateHash(out string note)
        {
            note = null;

            var keystore = PlayerSettings.Android.keystoreName;
            var alias = PlayerSettings.Android.keyaliasName;
            var storePass = PlayerSettings.Android.keystorePass;

            if (string.IsNullOrEmpty(keystore) || !File.Exists(keystore))
            {
                note = "no keystore configured in Player Settings";
                return null;
            }

            if (string.IsNullOrEmpty(alias))
            {
                note = "no key alias configured in Player Settings";
                return null;
            }

            if (string.IsNullOrEmpty(storePass))
            {
                note = "Unity is not holding the keystore password this session; " +
                       "run the keytool command shown in the window";
                return null;
            }

            var keytool = FindKeytool();
            if (keytool == null)
            {
                note = "keytool not found";
                return null;
            }

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = keytool,
                    Arguments = "-list -v -keystore \"" + keystore + "\" -alias \"" + alias +
                                "\" -storepass \"" + storePass + "\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };

                using (var process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        note = "keytool failed to start";
                        return null;
                    }

                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(20000);

                    var match = Regex.Match(output, @"SHA256:\s*([0-9A-Fa-f:]+)");
                    if (!match.Success)
                    {
                        note = "keytool produced no SHA256 fingerprint";
                        return null;
                    }

                    return match.Groups[1].Value.Replace(":", string.Empty).ToLowerInvariant();
                }
            }
            catch (Exception e)
            {
                note = "keytool failed: " + e.Message;
                return null;
            }
        }

        private static string FindKeytool()
        {
            var extension = Application.platform == RuntimePlatform.WindowsEditor ? ".exe" : string.Empty;

            var bundled = Path.Combine(
                EditorApplication.applicationContentsPath,
                "PlaybackEngines", "AndroidPlayer", "OpenJDK", "bin", "keytool" + extension);

            if (File.Exists(bundled)) return bundled;

            var javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
            if (!string.IsNullOrEmpty(javaHome))
            {
                var fromJavaHome = Path.Combine(javaHome, "bin", "keytool" + extension);
                if (File.Exists(fromJavaHome)) return fromJavaHome;
            }

            return "keytool";
        }

        public static string KeytoolCommandFor(string keystore, string alias)
        {
            var ks = string.IsNullOrEmpty(keystore) ? "<path-to-your.keystore>" : keystore;
            var al = string.IsNullOrEmpty(alias) ? "<your-alias>" : alias;
            return "keytool -list -v -keystore \"" + ks + "\" -alias \"" + al + "\"";
        }
    }
}
