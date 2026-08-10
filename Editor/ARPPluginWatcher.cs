// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using UnityEditor;
using UnityEngine;

namespace ARP.Editor
{
    // ARP_EXPECTED_LIBRARIES is the reference set for "did someone add a cheat .so to
    // the APK". Add a Unity plugin and forget to repaste it, and the check turns on
    // your own players instead - which is worse than not having it, because the
    // failure looks like a detection.
    //
    // Nothing here can write to CloudScript, so this cannot silently fix itself. What
    // it can do is guarantee you never ship a stale list without being told, loudly and
    // more than once.
    public sealed class ARPPluginWatcher : AssetPostprocessor
    {
        private static readonly string[] WatchedExtensions = { ".so", ".aar" };

        private static string StaleKey =>
            "ARP.LibrariesStale." + Application.dataPath.GetHashCode().ToString("x8");

        private static string StaleDetailKey => StaleKey + ".detail";

        public static bool LibrariesStale
        {
            get => EditorPrefs.GetBool(StaleKey, false);
            private set => EditorPrefs.SetBool(StaleKey, value);
        }

        public static string StaleDetail => EditorPrefs.GetString(StaleDetailKey, string.Empty);

        public static void ClearStale()
        {
            EditorPrefs.DeleteKey(StaleKey);
            EditorPrefs.DeleteKey(StaleDetailKey);
        }

        private static void OnPostprocessAllAssets(
            string[] imported, string[] deleted, string[] moved, string[] movedFrom)
        {
            var touched = new List<string>();

            Collect(imported, "added", touched);
            Collect(deleted, "removed", touched);
            Collect(moved, "moved", touched);

            if (touched.Count == 0) return;

            EditorPrefs.SetBool(StaleKey, true);
            EditorPrefs.SetString(StaleDetailKey, string.Join("\n", touched));

            Debug.LogWarning(
                "[ARP] Native plugins changed:\n" + string.Join("\n", touched) +
                "\n\nARP_EXPECTED_LIBRARIES in your CloudScript is now out of date. Make a " +
                "release build and repaste it from Tools > ARP > Show Last Build Checksums, " +
                "or clear the constant to disable the library check until you do.");
        }

        private static void Collect(string[] paths, string verb, List<string> into)
        {
            if (paths == null) return;

            foreach (var path in paths)
            {
                if (string.IsNullOrEmpty(path)) continue;

                foreach (var extension in WatchedExtensions)
                {
                    if (!path.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) continue;

                    // Our own library is expected and would otherwise mark itself stale
                    // every time the package is reimported.
                    if (path.EndsWith("libarpnative.so", StringComparison.OrdinalIgnoreCase)) break;

                    into.Add("  " + verb + ": " + path);
                    break;
                }
            }
        }
    }
}
