// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.IO;
using System.Text;
using ARP;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

namespace ARP.Editor
{
    // Package visibility filtering (API 30+, mandatory from targetSdk 34) means an
    // undeclared package reports "not installed" identically to one that genuinely is
    // not installed. The root-package check finds nothing at all without these entries.
    //
    // Generated from ARPRootDetector.RootPackages so the manifest and the runtime check
    // cannot drift apart, and shipped as an .androidlib so Android's manifest merger
    // folds it into the app automatically. No manual step.
    public static class ARPManifestGenerator
    {
        private const string LibraryFolder = "ARPQueries.androidlib";
        private const string ManifestName = "AndroidManifest.xml";
        private const string GeneratedMarker = "ARP-GENERATED";

        [MenuItem("Tools/ARP/Regenerate Android Queries Manifest", false, 62)]
        public static void Regenerate()
        {
            var path = ManifestPath();
            if (path == null)
            {
                Debug.LogError("[ARP] Could not locate " + LibraryFolder + " in the package.");
                return;
            }

            File.WriteAllText(path, BuildManifest());
            AssetDatabase.Refresh();

            Debug.Log($"[ARP] Wrote {ARPRootDetector.RootPackages.Length + ARPRootDetector.CheatToolPackages.Length}" +
                     $" <queries> entries to {path}");
        }

        public static bool IsUpToDate(out int declared, out int expected)
        {
            declared = 0;
            expected = ARPRootDetector.RootPackages.Length + ARPRootDetector.CheatToolPackages.Length;

            var path = ManifestPath();
            if (path == null || !File.Exists(path)) return false;

            var current = File.ReadAllText(path);
            foreach (var package in ARPRootDetector.RootPackages)
            {
                if (current.Contains("\"" + package + "\"")) declared++;
            }

            foreach (var package in ARPRootDetector.CheatToolPackages)
            {
                if (current.Contains("\"" + package + "\"")) declared++;
            }

            return declared == expected;
        }

        public static string BuildManifest()
        {
            var sb = new StringBuilder();

            sb.Append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
            sb.Append("<!-- ").Append(GeneratedMarker).Append(": do not edit by hand. ");
            sb.Append("Regenerate with Tools > ARP > Regenerate Android Queries Manifest. -->\n");
            sb.Append("<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n");
            sb.Append("    package=\"com.arp.queries\">\n\n");
            sb.Append("    <queries>\n");

            foreach (var package in ARPRootDetector.RootPackages)
            {
                sb.Append("        <package android:name=\"").Append(package).Append("\" />\n");
            }

            foreach (var package in ARPRootDetector.CheatToolPackages)
            {
                sb.Append("        <package android:name=\"").Append(package).Append("\" />\n");
            }

            sb.Append("    </queries>\n");
            sb.Append("</manifest>\n");

            return sb.ToString();
        }

        private static string ManifestPath()
        {
            var package = UnityEditor.PackageManager.PackageInfo.FindForAssembly(
                typeof(ARPManifestGenerator).Assembly);

            if (package != null && !string.IsNullOrEmpty(package.resolvedPath))
            {
                var candidate = Path.Combine(
                    package.resolvedPath, "Runtime", "Plugins", "Android", LibraryFolder, ManifestName);

                if (Directory.Exists(Path.GetDirectoryName(candidate) ?? string.Empty)) return candidate;
            }

            var projectRoot = Path.GetDirectoryName(Application.dataPath);
            foreach (var root in new[] { Application.dataPath, projectRoot })
            {
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;

                var found = Directory.GetDirectories(root, LibraryFolder, SearchOption.AllDirectories);
                if (found.Length > 0) return Path.Combine(found[0], ManifestName);
            }

            return null;
        }
    }

    public sealed class ARPManifestValidator : IPreprocessBuildWithReport
    {
        public int callbackOrder => 0;

        public void OnPreprocessBuild(BuildReport report)
        {
            if (report == null || report.summary.platform != BuildTarget.Android) return;

            if (ARPManifestGenerator.IsUpToDate(out var declared, out var expected)) return;

            Debug.LogWarning(
                $"[ARP] The Android queries manifest declares {declared} of {expected} " +
                "packages. Until it matches, the package check silently finds nothing for the " +
                "missing entries. Run Tools > ARP > Regenerate Android Queries Manifest.");
        }
    }
}
