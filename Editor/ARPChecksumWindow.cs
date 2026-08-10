// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using UnityEditor;
using UnityEngine;

namespace ARP.Editor
{
    public sealed class ARPChecksumWindow : EditorWindow
    {
        private ARPChecksumRecord _record;
        private Vector2 _scroll;

        private static GUIStyle _headline;
        private static GUIStyle _hashField;

        public static void Show(ARPChecksumRecord record)
        {
            var window = GetWindow<ARPChecksumWindow>(true, "ARP — Build Checksums", true);
            window._record = record ?? ARPChecksumRecord.Load();
            window.minSize = new Vector2(620, 520);
            window.Focus();
        }

        [MenuItem("Tools/ARP/Show Last Build Checksums", false, 20)]
        public static void ShowLast()
        {
            var record = ARPChecksumRecord.Load();
            if (record == null)
            {
                EditorUtility.DisplayDialog(
                    "ARP",
                    "No checksums recorded yet. Make a non-development Android build and this " +
                    "window will open automatically.",
                    "OK");
                return;
            }

            Show(record);
        }

        private void OnGUI()
        {
            BuildStyles();

            if (_record == null)
            {
                EditorGUILayout.HelpBox("No checksum record loaded.", MessageType.Info);
                return;
            }

            _scroll = EditorGUILayout.BeginScrollView(_scroll);

            GUILayout.Space(6);
            EditorGUILayout.LabelField("UPDATE YOUR CLOUDSCRIPT BEFORE PUBLISHING!", _headline);
            GUILayout.Space(2);
            EditorGUILayout.LabelField("PUT THIS CHECKSUM IN THE SCRIPT:", EditorStyles.boldLabel);
            GUILayout.Space(8);

            if (_record.CertificateChanged) DrawCertificateChangedWarning();

            DrawHashBlock(
                "Build content hash",
                "Changes every build. Update this before every release.",
                _record.BuildContentHash,
                "ARP_EXPECTED_CONTENT_HASH");

            GUILayout.Space(10);

            DrawHashBlock(
                "Signing certificate SHA-256",
                "Set once. Meta never re-signs your uploads, so this is fixed for the life " +
                "of the title and you will not need to touch it again.",
                _record.SigningCertSha256,
                "ARP_EXPECTED_SIGNING_CERT_SHA256");

            if (!_record.HasCertificate) DrawKeytoolFallback();

            GUILayout.Space(14);
            DrawSnippetBlock();
            GUILayout.Space(14);
            DrawBuildInfo();

            EditorGUILayout.EndScrollView();
        }

        private void DrawCertificateChangedWarning()
        {
            EditorGUILayout.HelpBox(
                "The signing certificate changed since your last build.\n\n" +
                "Previous: " + _record.PreviousSigningCertSha256 + "\n" +
                "Current:  " + _record.SigningCertSha256 + "\n\n" +
                "If that was not deliberate, stop and check which keystore you are building " +
                "with. Meta requires every update to be signed with the original certificate, " +
                "and a published title signed with a new one cannot be updated at all.",
                MessageType.Error);
            GUILayout.Space(8);
        }

        private void DrawHashBlock(string title, string subtitle, string value, string constantName)
        {
            EditorGUILayout.BeginVertical(EditorStyles.helpBox);

            EditorGUILayout.LabelField(title, EditorStyles.boldLabel);
            EditorGUILayout.LabelField(subtitle, EditorStyles.wordWrappedMiniLabel);
            GUILayout.Space(4);

            if (string.IsNullOrEmpty(value))
            {
                EditorGUILayout.HelpBox("Not available for this build.", MessageType.Warning);
            }
            else
            {
                EditorGUILayout.SelectableLabel(value, _hashField, GUILayout.Height(36));

                EditorGUILayout.BeginHorizontal();
                if (GUILayout.Button("Copy", GUILayout.Width(90))) CopyToClipboard(value);
                if (GUILayout.Button("Copy as " + constantName, GUILayout.Width(280)))
                {
                    CopyToClipboard("var " + constantName + " = \"" + value + "\";");
                }
                EditorGUILayout.EndHorizontal();
            }

            EditorGUILayout.EndVertical();
        }

        private void DrawKeytoolFallback()
        {
            GUILayout.Space(6);
            EditorGUILayout.HelpBox(
                "ARP could not read the certificate automatically" +
                (string.IsNullOrEmpty(_record.CertificateNote) ? "." : ": " + _record.CertificateNote + ".") +
                "\n\nRun the command below and copy the SHA256 line, removing the colons and " +
                "lowercasing it.",
                MessageType.Info);

            var command = ARPBuildProcessor.KeytoolCommandFor(
                PlayerSettings.Android.keystoreName,
                PlayerSettings.Android.keyaliasName);

            EditorGUILayout.SelectableLabel(command, _hashField, GUILayout.Height(34));
            if (GUILayout.Button("Copy command", GUILayout.Width(140))) CopyToClipboard(command);
        }

        private void DrawSnippetBlock()
        {
            EditorGUILayout.BeginVertical(EditorStyles.helpBox);
            EditorGUILayout.LabelField("Ready to paste into CloudScript/arpConfig.js", EditorStyles.boldLabel);
            GUILayout.Space(4);

            var snippet = _record.ToCloudScriptSnippet();
            EditorGUILayout.SelectableLabel(snippet, _hashField, GUILayout.Height(52));

            EditorGUILayout.BeginHorizontal();
            if (GUILayout.Button("Copy CloudScript snippet", GUILayout.Width(220))) CopyToClipboard(snippet);
            if (GUILayout.Button("Open PlayFab Tutorial", GUILayout.Width(180))) ARPTutorialWindow.Open();
            EditorGUILayout.EndHorizontal();

            EditorGUILayout.EndVertical();
        }

        private void DrawBuildInfo()
        {
            EditorGUILayout.LabelField("Build", EditorStyles.boldLabel);
            EditorGUILayout.LabelField("Product", _record.ProductName ?? "-");
            EditorGUILayout.LabelField("Output", _record.OutputPath ?? "-");
            EditorGUILayout.LabelField("Built at", (_record.BuiltAtUtc ?? "-") + " UTC");

            GUILayout.Space(6);
            EditorGUILayout.LabelField(
                "Also written to " + ARPChecksumRecord.TextPath,
                EditorStyles.wordWrappedMiniLabel);

            if (GUILayout.Button("Reveal file", GUILayout.Width(120)))
            {
                EditorUtility.RevealInFinder(ARPChecksumRecord.TextPath);
            }
        }

        private static void CopyToClipboard(string value)
        {
            EditorGUIUtility.systemCopyBuffer = value;
            Debug.Log("[ARP] Copied to clipboard.");
        }

        private static void BuildStyles()
        {
            if (_headline == null)
            {
                _headline = new GUIStyle(EditorStyles.boldLabel)
                {
                    fontSize = 16,
                    wordWrap = true,
                };
                _headline.normal.textColor = new Color(0.92f, 0.36f, 0.24f);
            }

            if (_hashField == null)
            {
                _hashField = new GUIStyle(EditorStyles.textArea)
                {
                    font = EditorStyles.miniFont,
                    wordWrap = true,
                    richText = false,
                };
            }
        }
    }
}
