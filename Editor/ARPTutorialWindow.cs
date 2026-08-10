// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UnityEditor;
using UnityEngine;

namespace ARP.Editor
{
    public sealed class ARPTutorialWindow : EditorWindow
    {
        private static readonly string[] ScriptOrder =
        {
            "arpConfig.js",
            "arpGetNonce.js",
            "arpVerifyIntegrity.js",
            "banRootedDevice.js",
            "arpHeartbeat.js",
            "arpRecordLoginContext.js",
        };

        private static readonly Dictionary<string, string> ScriptSummaries = new Dictionary<string, string>
        {
            { "arpConfig.js", "The only file you edit. Checksums, Meta credentials, thresholds, shared helpers." },
            { "arpGetNonce.js", "Issues the single-use attestation nonce." },
            { "arpVerifyIntegrity.js", "The decision point. Verifies the Meta token, compares checksums, decides." },
            { "banRootedDevice.js", "Applies the ban across account, IP and device targets." },
            { "arpHeartbeat.js", "Records the watchdog pulse and judges the silences." },
            { "arpRecordLoginContext.js", "PlayStream action. Only needed if you want IP bans." },
        };

        private Vector2 _scroll;
        private string _cloudScriptDirectory;
        private readonly Dictionary<string, bool> _foldouts = new Dictionary<string, bool>();

        private static GUIStyle _stepHeader;
        private static GUIStyle _body;
        private static GUIStyle _code;

        [MenuItem("Tools/ARP/PlayFab Tutorial", false, 1)]
        public static void Open()
        {
            var window = GetWindow<ARPTutorialWindow>(false, "ARP — PlayFab Tutorial", true);
            window.minSize = new Vector2(680, 600);
            window._cloudScriptDirectory = null;
            window.Focus();
        }

        private void OnGUI()
        {
            BuildStyles();
            _scroll = EditorGUILayout.BeginScrollView(_scroll);

            GUILayout.Space(8);
            EditorGUILayout.LabelField("Setting up ARP with PlayFab", _stepHeader);
            EditorGUILayout.LabelField(
                "Work top to bottom. Steps 1-5 are required. Steps 6 and 7 are optional but " +
                "step 6 is the only part of ARP a modder cannot forge, so skip it only if you " +
                "genuinely cannot use it.",
                _body);

            GUILayout.Space(10);
            DrawStep1();
            DrawStep2();
            DrawStep3();
            DrawStep4();
            DrawStep5();
            DrawStep6();
            DrawStep7();
            DrawStep8();

            GUILayout.Space(20);
            EditorGUILayout.EndScrollView();
        }

        private void DrawStep1()
        {
            Step("1. Create a PlayFab title");
            Body(
                "Sign in at developer.playfab.com and create a title if you do not have one. " +
                "Copy its Title ID from Settings > API Features — it is a short alphanumeric " +
                "code like A1B2C.");

            EditorGUILayout.BeginHorizontal();
            if (GUILayout.Button("Open PlayFab Game Manager", GUILayout.Width(240)))
                Application.OpenURL("https://developer.playfab.com/");
            EditorGUILayout.EndHorizontal();

            Note(
                "Heads up on pricing: PlayFab replaced Development Mode with Foundation Mode on " +
                "11 March 2026. Dev Mode is now capped at 1,000 lifetime accounts, and Foundation " +
                "Mode is free only if you ship on Xbox. Worth checking what a Quest-only title " +
                "costs you before building on this.");

            EndStep();
        }

        private void DrawStep2()
        {
            Step("2. Install the PlayFab Unity SDK");
            Body(
                "Import the PlayFab Unity SDK, then set your Title ID in the PlayFab editor " +
                "extensions panel. Log the player in before ARP runs — ARP waits for an " +
                "authenticated session and gives up after 30 seconds, because detection with " +
                "nowhere to report is worth nothing.");

            EditorGUILayout.BeginHorizontal();
            if (GUILayout.Button("PlayFab Unity SDK releases", GUILayout.Width(240)))
                Application.OpenURL("https://github.com/PlayFab/UnitySDK/releases");
            EditorGUILayout.EndHorizontal();

            EndStep();
        }

        private void DrawStep3()
        {
            Step("3. Define ARP_PLAYFAB");

            var defined = IsDefineSet("ARP_PLAYFAB");

            if (defined)
            {
                EditorGUILayout.HelpBox("ARP_PLAYFAB is defined. Nothing to do here.", MessageType.Info);
            }
            else
            {
                Body(
                    "ARP's PlayFab transport compiles only when ARP_PLAYFAB is defined. If you " +
                    "installed PlayFab as a UPM package that happens automatically. The SDK is " +
                    "more often shipped as a .unitypackage, which UPM cannot see — in that case " +
                    "add the define yourself.");

                if (GUILayout.Button("Add ARP_PLAYFAB to Android scripting defines", GUILayout.Width(340)))
                {
                    AddDefine("ARP_PLAYFAB");
                }
            }

            EndStep();
        }

        private void DrawStep4()
        {
            Step("4. Upload the CloudScript");
            Body(
                "In Game Manager go to Automation > Revisions > Upload New Revision.\n\n" +
                "Legacy CloudScript stores one file per revision, so for a manual upload you " +
                "want everything concatenated into a single file. Use the button below and " +
                "paste it into one .js file. If you bind the title to GitHub instead, commit " +
                "the six files separately and PlayFab concatenates them for you.\n\n" +
                "After uploading, click DEPLOY REVISION TO LIVE. An uploaded revision that has " +
                "not been deployed does nothing.");

            GUILayout.Space(4);

            var missing = ResolveCloudScriptDirectory() == null;
            if (missing)
            {
                EditorGUILayout.HelpBox(
                    "Could not locate the CloudScript folder in the ARP package. Copy the files " +
                    "from CloudScript/ manually.",
                    MessageType.Warning);
                EndStep();
                return;
            }

            using (new EditorGUILayout.HorizontalScope())
            {
                var wide = new GUIStyle(GUI.skin.button) { fontStyle = FontStyle.Bold };
                if (GUILayout.Button("Copy ALL scripts as one file", wide, GUILayout.Height(30)))
                {
                    CopyConcatenated();
                }

                if (GUILayout.Button("Reveal folder", GUILayout.Width(120), GUILayout.Height(30)))
                {
                    EditorUtility.RevealInFinder(ResolveCloudScriptDirectory());
                }
            }

            GUILayout.Space(8);
            EditorGUILayout.LabelField("Or copy them one at a time:", EditorStyles.miniBoldLabel);
            GUILayout.Space(2);

            foreach (var fileName in ScriptOrder) DrawScriptRow(fileName);

            EndStep();
        }

        private void DrawScriptRow(string fileName)
        {
            EditorGUILayout.BeginVertical(EditorStyles.helpBox);
            EditorGUILayout.BeginHorizontal();

            if (!_foldouts.ContainsKey(fileName)) _foldouts[fileName] = false;

            _foldouts[fileName] = EditorGUILayout.Foldout(_foldouts[fileName], fileName, true);

            if (GUILayout.Button("Copy", GUILayout.Width(70)))
            {
                var contents = LoadScript(fileName);
                if (contents != null)
                {
                    EditorGUIUtility.systemCopyBuffer = contents;
                    Debug.Log("[ARP] Copied " + fileName + " to clipboard.");
                }
                else
                {
                    Debug.LogError("[ARP] Could not read " + fileName + ".");
                }
            }

            EditorGUILayout.EndHorizontal();

            if (ScriptSummaries.TryGetValue(fileName, out var summary))
            {
                EditorGUILayout.LabelField(summary, EditorStyles.wordWrappedMiniLabel);
            }

            if (_foldouts[fileName])
            {
                var contents = LoadScript(fileName);
                if (contents != null)
                {
                    var preview = contents.Length > 4000 ? contents.Substring(0, 4000) + "\n..." : contents;
                    EditorGUILayout.SelectableLabel(preview, _code, GUILayout.Height(220));
                }
            }

            EditorGUILayout.EndVertical();
        }

        private void DrawStep5()
        {
            Step("5. Paste your checksums into arpConfig.js");
            Body(
                "Make a non-development Android build. ARP opens a window with two values.\n\n" +
                "The signing certificate hash is set once and never changes — Meta does not " +
                "re-sign uploads, so your certificate is fixed for the life of the title.\n\n" +
                "The build content hash changes every build. Update it before every release, or " +
                "your own players will look tampered.\n\n" +
                "Leaving either at its placeholder SKIPS that comparison rather than failing it, " +
                "so a half-finished setup will not flag your whole playerbase.");

            EditorGUILayout.BeginHorizontal();
            if (GUILayout.Button("Show Last Build Checksums", GUILayout.Width(240)))
                ARPChecksumWindow.ShowLast();
            EditorGUILayout.EndHorizontal();

            EndStep();
        }

        private void DrawStep6()
        {
            Step("6. Meta attestation (strongly recommended)");
            Body(
                "This is the only check in ARP a modder cannot forge, because the token is " +
                "signed by Meta's server rather than by anything on the headset. It is also the " +
                "only thing that reliably catches a repacked APK, which is how Quest games are " +
                "actually cheated — the headset stays completely stock, so no root check sees it.\n\n" +
                "You need a Meta developer app. Store and App Lab both work. Copy the App ID and " +
                "App Secret into ARP_META_APP_ID and ARP_META_APP_SECRET in arpConfig.js.\n\n" +
                "The secret goes in CloudScript and nowhere else. Never in the client, never in " +
                "an Inspector field, never in a serialized asset.\n\n" +
                "You also need the Meta Platform SDK v55 or newer in the project, and " +
                "attestationEnabled ticked on the ARPManager component.");

            EditorGUILayout.BeginHorizontal();
            if (GUILayout.Button("Meta developer dashboard", GUILayout.Width(240)))
                Application.OpenURL("https://developers.meta.com/horizon/manage/");
            if (GUILayout.Button("Attestation API docs", GUILayout.Width(200)))
                Application.OpenURL("https://developers.meta.com/horizon/documentation/unity/ps-attestation-api/");
            EditorGUILayout.EndHorizontal();

            Note(
                "Meta caps attestation at 100 requests per hour and 200 per day per device, and " +
                "tokens last 24 hours. ARP fetches one per session and caches it. Do not try to " +
                "attest on every heartbeat — at a 30 second interval that is 2,880 calls a day " +
                "and it will hard-fail.");

            EndStep();
        }

        private void DrawStep7()
        {
            Step("7. IP bans (optional)");
            Body(
                "Only needed if you tick 'Ban IP address' on ARPManager.\n\n" +
                "CloudScript cannot see the caller's IP address — the context object exposes the " +
                "PlayStream event, the player profile and the triggering task, and none of them " +
                "carry an address. The login PlayStream event does, so ARP captures it there.\n\n" +
                "In Game Manager: Automation > Rules > New Rule.\n" +
                "  Event type:  player_logged_in\n" +
                "  Action:      Execute CloudScript > arpRecordLoginContext\n\n" +
                "Without this rule there is no IP on record and the target reports itself as " +
                "skipped rather than silently doing nothing.");

            Note(
                "IP bans hit everyone behind the address. Household members share it, and under " +
                "CGNAT so do strangers. This is off by default for that reason.");

            EndStep();
        }

        private void DrawStep8()
        {
            Step("8. Add ARPManager to your scene");
            Body(
                "Drop the Android Root Protector component onto a GameObject that survives scene " +
                "loads, then wire the events:\n\n" +
                "  OnBanConfirmed        — show the ban message and close out the session\n" +
                "  OnBanReportFailed     — your call, but do not let the player carry on by default\n" +
                "  OnHeartbeatFailed     — sever your own network connections here\n" +
                "  OnIntegrityCheckFailed — the binary is wrong rather than the headset\n\n" +
                "Then read the recommendation at the top of the component's Inspector. It matters " +
                "more than any single setting on it.");

            EndStep();
        }

        private void CopyConcatenated()
        {
            var builder = new StringBuilder();
            var failed = new List<string>();

            builder.Append("// ARP CloudScript — concatenated for a single PlayFab revision.\n");
            builder.Append("// Generated from the ARP package on ")
                   .Append(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"))
                   .Append(" UTC.\n\n");

            foreach (var fileName in ScriptOrder)
            {
                var contents = LoadScript(fileName);
                if (contents == null)
                {
                    failed.Add(fileName);
                    continue;
                }

                builder.Append("// ---- ").Append(fileName).Append(" ")
                       .Append(new string('-', Math.Max(4, 60 - fileName.Length))).Append('\n');
                builder.Append(contents.TrimEnd()).Append("\n\n");
            }

            if (failed.Count > 0)
            {
                Debug.LogError("[ARP] Could not read: " + string.Join(", ", failed));
                return;
            }

            EditorGUIUtility.systemCopyBuffer = builder.ToString();
            Debug.Log("[ARP] Copied all " + ScriptOrder.Length + " CloudScript files to clipboard.");
        }

        private string LoadScript(string fileName)
        {
            var directory = ResolveCloudScriptDirectory();
            if (directory == null) return null;

            var path = Path.Combine(directory, fileName);
            if (!File.Exists(path)) return null;

            try { return File.ReadAllText(path); }
            catch (Exception) { return null; }
        }

        private string ResolveCloudScriptDirectory()
        {
            if (_cloudScriptDirectory != null && Directory.Exists(_cloudScriptDirectory))
                return _cloudScriptDirectory;

            var package = UnityEditor.PackageManager.PackageInfo.FindForAssembly(GetType().Assembly);
            if (package != null && !string.IsNullOrEmpty(package.resolvedPath))
            {
                var candidate = Path.Combine(package.resolvedPath, "CloudScript");
                if (Directory.Exists(candidate))
                {
                    _cloudScriptDirectory = candidate;
                    return _cloudScriptDirectory;
                }
            }

            var projectRoot = Path.GetDirectoryName(Application.dataPath);
            foreach (var searchRoot in new[] { Application.dataPath, projectRoot })
            {
                if (string.IsNullOrEmpty(searchRoot) || !Directory.Exists(searchRoot)) continue;

                try
                {
                    var found = Directory.GetFiles(searchRoot, "arpConfig.js", SearchOption.AllDirectories);
                    if (found.Length > 0)
                    {
                        _cloudScriptDirectory = Path.GetDirectoryName(found[0]);
                        return _cloudScriptDirectory;
                    }
                }
                catch (Exception) { }
            }

            return null;
        }

        private static bool IsDefineSet(string define)
        {
            var group = BuildTargetGroup.Android;
#if UNITY_2021_2_OR_NEWER
            var target = UnityEditor.Build.NamedBuildTarget.Android;
            var defines = PlayerSettings.GetScriptingDefineSymbols(target);
#else
            var defines = PlayerSettings.GetScriptingDefineSymbolsForGroup(group);
#endif
            return defines != null && defines.Split(';').Length > 0 &&
                   Array.IndexOf(defines.Split(';'), define) >= 0;
        }

        private static void AddDefine(string define)
        {
#if UNITY_2021_2_OR_NEWER
            var target = UnityEditor.Build.NamedBuildTarget.Android;
            var defines = PlayerSettings.GetScriptingDefineSymbols(target);
            if (Array.IndexOf(defines.Split(';'), define) >= 0) return;
            PlayerSettings.SetScriptingDefineSymbols(
                target, string.IsNullOrEmpty(defines) ? define : defines + ";" + define);
#else
            var group = BuildTargetGroup.Android;
            var defines = PlayerSettings.GetScriptingDefineSymbolsForGroup(group);
            if (Array.IndexOf(defines.Split(';'), define) >= 0) return;
            PlayerSettings.SetScriptingDefineSymbolsForGroup(
                group, string.IsNullOrEmpty(defines) ? define : defines + ";" + define);
#endif
            Debug.Log("[ARP] Added " + define + " to Android scripting defines.");
        }

        private static void Step(string title)
        {
            GUILayout.Space(12);
            EditorGUILayout.BeginVertical(EditorStyles.helpBox);
            EditorGUILayout.LabelField(title, _stepHeader);
            GUILayout.Space(4);
        }

        private static void EndStep()
        {
            EditorGUILayout.EndVertical();
        }

        private static void Body(string text)
        {
            EditorGUILayout.LabelField(text, _body);
            GUILayout.Space(4);
        }

        private static void Note(string text)
        {
            GUILayout.Space(4);
            EditorGUILayout.HelpBox(text, MessageType.Info);
        }

        private static void BuildStyles()
        {
            if (_stepHeader == null)
            {
                _stepHeader = new GUIStyle(EditorStyles.boldLabel) { fontSize = 13, wordWrap = true };
            }

            if (_body == null)
            {
                _body = new GUIStyle(EditorStyles.label) { wordWrap = true, richText = false };
            }

            if (_code == null)
            {
                _code = new GUIStyle(EditorStyles.textArea) { font = EditorStyles.miniFont, wordWrap = false };
            }
        }
    }
}
