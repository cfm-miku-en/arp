// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System.IO;
using UnityEditor;
using UnityEngine;

namespace ARP.Editor
{
    public static class ARPMenu
    {
        [MenuItem("Tools/ARP/Add ARP Manager to Scene", false, 40)]
        public static void AddManagerToScene()
        {
            var existing = Object.FindObjectOfType<ARPManager>();
            if (existing != null)
            {
                EditorGUIUtility.PingObject(existing.gameObject);
                Selection.activeGameObject = existing.gameObject;
                Debug.Log("[ARP] Scene already has an ARPManager.");
                return;
            }

            var go = new GameObject("ARP Manager");
            go.AddComponent<ARPManager>();
            Undo.RegisterCreatedObjectUndo(go, "Add ARP Manager");
            Selection.activeGameObject = go;
        }

        [MenuItem("Tools/ARP/Open Setup Guide (native library)", false, 60)]
        public static void OpenSetupGuide()
        {
            var path = FindPackageFile("SETUP.md");
            if (path == null)
            {
                Debug.LogError("[ARP] Could not locate SETUP.md.");
                return;
            }

            EditorUtility.RevealInFinder(path);
        }

        [MenuItem("Tools/ARP/Reveal CloudScript Folder", false, 61)]
        public static void RevealCloudScript()
        {
            var path = FindPackageFile(Path.Combine("CloudScript", "arpConfig.js"));
            if (path == null)
            {
                Debug.LogError("[ARP] Could not locate the CloudScript folder.");
                return;
            }

            EditorUtility.RevealInFinder(path);
        }

        private static string FindPackageFile(string relativePath)
        {
            var package = UnityEditor.PackageManager.PackageInfo.FindForAssembly(typeof(ARPMenu).Assembly);
            if (package != null && !string.IsNullOrEmpty(package.resolvedPath))
            {
                var candidate = Path.Combine(package.resolvedPath, relativePath);
                if (File.Exists(candidate)) return candidate;
            }

            var fileName = Path.GetFileName(relativePath);
            var projectRoot = Path.GetDirectoryName(Application.dataPath);

            foreach (var root in new[] { Application.dataPath, projectRoot })
            {
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;

                var found = Directory.GetFiles(root, fileName, SearchOption.AllDirectories);
                if (found.Length > 0) return found[0];
            }

            return null;
        }
    }
}
