// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using UnityEditor;
using UnityEngine;

namespace ARP.Editor
{
    [CustomEditor(typeof(ARPManager))]
    [CanEditMultipleObjects]
    public sealed class ARPManagerEditor : UnityEditor.Editor
    {
        private const string CoreGameRecommendation =
            "We would recommend putting a CloudScript connection in the core game to ensure " +
            "cheaters cannot be saved by deleting the ARP heartbeat files.";

        private SerializedProperty _attestationEnabled;
        private SerializedProperty _distribution;
        private SerializedProperty _deviceIntegrityThreshold;

        private SerializedProperty _appIntegrityChecksEnabled;
        private SerializedProperty _deviceChecksEnabled;
        private SerializedProperty _scanDelaySeconds;
        private SerializedProperty _continuousMonitoring;
        private SerializedProperty _quickScanInterval;
        private SerializedProperty _fullScanInterval;
        private SerializedProperty _memoryIntegrityEnabled;
        private SerializedProperty _instrumentationChecksEnabled;
        private SerializedProperty _fridaPortProbeEnabled;
        private SerializedProperty _lockOutOnDisguisedLibFolder;
        private SerializedProperty _disguisedLibFolderMessage;

        private SerializedProperty _banMode;
        private SerializedProperty _timedDuration;
        private SerializedProperty _timedUnit;
        private SerializedProperty _internalBanReason;
        private SerializedProperty _timedMessageTemplate;
        private SerializedProperty _permanentMessage;

        private SerializedProperty _banAccount;
        private SerializedProperty _banIpAddress;
        private SerializedProperty _banHardware;
        private SerializedProperty _enforcementMode;

        private SerializedProperty _heartbeatEnabled;
        private SerializedProperty _heartbeatInterval;
        private SerializedProperty _heartbeatRetries;
        private SerializedProperty _heartbeatRetryBackoff;

        private SerializedProperty _onBanConfirmed;
        private SerializedProperty _onBanReportFailed;
        private SerializedProperty _onHeartbeatFailed;
        private SerializedProperty _onIntegrityCheckFailed;

        private static GUIStyle _banner;

        private void OnEnable()
        {
            _attestationEnabled = serializedObject.FindProperty("attestationEnabled");
            _distribution = serializedObject.FindProperty("distribution");
            _deviceIntegrityThreshold = serializedObject.FindProperty("deviceIntegrityThreshold");

            _appIntegrityChecksEnabled = serializedObject.FindProperty("appIntegrityChecksEnabled");
            _deviceChecksEnabled = serializedObject.FindProperty("deviceChecksEnabled");
            _scanDelaySeconds = serializedObject.FindProperty("scanDelaySeconds");
            _continuousMonitoring = serializedObject.FindProperty("continuousMonitoring");
            _quickScanInterval = serializedObject.FindProperty("quickScanInterval");
            _fullScanInterval = serializedObject.FindProperty("fullScanInterval");
            _memoryIntegrityEnabled = serializedObject.FindProperty("memoryIntegrityEnabled");
            _instrumentationChecksEnabled = serializedObject.FindProperty("instrumentationChecksEnabled");
            _fridaPortProbeEnabled = serializedObject.FindProperty("fridaPortProbeEnabled");
            _lockOutOnDisguisedLibFolder = serializedObject.FindProperty("lockOutOnDisguisedLibFolder");
            _disguisedLibFolderMessage = serializedObject.FindProperty("disguisedLibFolderMessage");

            _banMode = serializedObject.FindProperty("banMode");
            _timedDuration = serializedObject.FindProperty("timedDuration");
            _timedUnit = serializedObject.FindProperty("timedUnit");
            _internalBanReason = serializedObject.FindProperty("internalBanReason");
            _timedMessageTemplate = serializedObject.FindProperty("timedMessageTemplate");
            _permanentMessage = serializedObject.FindProperty("permanentMessage");

            _banAccount = serializedObject.FindProperty("banAccount");
            _banIpAddress = serializedObject.FindProperty("banIpAddress");
            _banHardware = serializedObject.FindProperty("banHardware");
            _enforcementMode = serializedObject.FindProperty("enforcementMode");

            _heartbeatEnabled = serializedObject.FindProperty("heartbeatEnabled");
            _heartbeatInterval = serializedObject.FindProperty("heartbeatInterval");
            _heartbeatRetries = serializedObject.FindProperty("heartbeatRetries");
            _heartbeatRetryBackoff = serializedObject.FindProperty("heartbeatRetryBackoff");

            _onBanConfirmed = serializedObject.FindProperty("OnBanConfirmed");
            _onBanReportFailed = serializedObject.FindProperty("OnBanReportFailed");
            _onHeartbeatFailed = serializedObject.FindProperty("OnHeartbeatFailed");
            _onIntegrityCheckFailed = serializedObject.FindProperty("OnIntegrityCheckFailed");
        }

        public override void OnInspectorGUI()
        {
            BuildStyles();
            serializedObject.Update();

            DrawRecommendationBanner();
            DrawAttestation();
            DrawLocalChecks();
            DrawBanPolicy();
            DrawBanTargets();
            DrawHeartbeat();
            DrawEvents();

            serializedObject.ApplyModifiedProperties();
        }

        private void DrawRecommendationBanner()
        {
            GUILayout.Space(6);
            EditorGUILayout.LabelField(CoreGameRecommendation, _banner);
            GUILayout.Space(4);

            EditorGUILayout.HelpBox(
                "ARP is one component on one GameObject. Anyone who can modify your APK can " +
                "delete it. If the only integrity check in your game lives in here, removing " +
                "ARP removes the check - so put an independent CloudScript call directly in " +
                "your netcode, not routed through this component.",
                MessageType.Warning);

            GUILayout.Space(4);
            EditorGUILayout.BeginHorizontal();
            if (GUILayout.Button("Open PlayFab Tutorial")) ARPTutorialWindow.Open();
            if (GUILayout.Button("Help")) ARPHelpWindow.Open();
            EditorGUILayout.EndHorizontal();
            GUILayout.Space(8);
        }

        private void DrawAttestation()
        {
            Section("Attestation (Meta)");

            Field(_attestationEnabled, "Attestation Enabled");

            if (!_attestationEnabled.boolValue)
            {
                EditorGUILayout.HelpBox(
                    "Attestation is off, so ARP is running on forgeable client-side signals only.\n\n" +
                    "Everything else in this component is computed inside the process an attacker " +
                    "controls and can be patched out. The attestation token is signed by Meta's " +
                    "server, which is the one thing a modded client cannot fake. It is also the " +
                    "only reliable way to catch a repacked APK - which is how Quest games are " +
                    "actually cheated, with the headset left completely stock.",
                    MessageType.Warning);
            }
            else if (!ARPAttestation.PlatformSdkPresent)
            {
                EditorGUILayout.HelpBox(
                    "Attestation is enabled but the Meta Platform SDK was not detected. You need " +
                    "v55 or newer. If you imported it as a .unitypackage rather than a UPM " +
                    "package, add ARP_META_PLATFORM to your scripting defines.",
                    MessageType.Error);
            }

            Field(_distribution, "Distribution");
            Field(_deviceIntegrityThreshold, "Device Integrity Threshold");

            if (_deviceIntegrityThreshold.enumValueIndex == (int)ARPDeviceIntegrityThreshold.BasicOrWorse)
            {
                EditorGUILayout.HelpBox(
                    "'Basic' means the bootloader is locked and the OS valid, but some integrity " +
                    "check failed. It is suggestive of rooting, not proof of it. Treating it as a " +
                    "violation will catch more cheaters and also more innocent players.",
                    MessageType.Warning);
            }

            EndSection();
        }

        private void DrawLocalChecks()
        {
            Section("Local checks");

            Field(_appIntegrityChecksEnabled, "App Integrity Checks");
            Field(_deviceChecksEnabled, "Device Checks");
            Field(_scanDelaySeconds, "Scan Delay (seconds)");

            GUILayout.Space(6);
            Field(_instrumentationChecksEnabled, "Instrumentation Checks");

            if (_instrumentationChecksEnabled.boolValue)
            {
                EditorGUI.indentLevel++;
                Field(_fridaPortProbeEnabled, "Frida Port Probe (experimental)");
                EditorGUI.indentLevel--;

                if (_fridaPortProbeEnabled.boolValue)
                {
                    EditorGUILayout.HelpBox(
                        "Experimental. This is the only check in ARP that opens a socket - to " +
                        "loopback only, completing Frida's handshake so a hit means " +
                        "frida-server rather than merely an open port.\n\n" +
                        "Nothing on a stock Quest binds those ports, so a confirmed hit is " +
                        "close to conclusive there. Baseline it on your own devices before " +
                        "letting it contribute to a ban.",
                        MessageType.Info);
                }
            }

            GUILayout.Space(6);
            Field(_lockOutOnDisguisedLibFolder, "Lock Out On Disguised Lib Folder");

            if (_lockOutOnDisguisedLibFolder.boolValue)
            {
                EditorGUI.indentLevel++;
                Field(_disguisedLibFolderMessage, "Lockout Log Message");
                EditorGUI.indentLevel--;

                EditorGUILayout.HelpBox(
                    "The detection is solid - Android loads natives from lib/ and nowhere " +
                    "else. The shutdown is not: whoever rearranged the APK can remove this " +
                    "code just as easily, so it stops nobody who matters.\n\n" +
                    "The server is told either way, and that is the part that holds.",
                    MessageType.Warning);
            }

            DrawAddressablesRecommendation();

            GUILayout.Space(6);
            Field(_continuousMonitoring, "Continuous Monitoring");

            if (_continuousMonitoring.boolValue)
            {
                EditorGUI.indentLevel++;
                Field(_quickScanInterval, "Quick Scan (seconds)");
                Field(_fullScanInterval, "Full Scan (seconds)");
                EditorGUI.indentLevel--;

                if (_fullScanInterval.floatValue < _quickScanInterval.floatValue)
                {
                    EditorGUILayout.HelpBox(
                        "Full scan interval is shorter than the quick one, so every pass will be " +
                        "a full scan. That spawns a process and walks the package list every " +
                        "time - measure the frame cost before shipping it.",
                        MessageType.Warning);
                }
            }
            else
            {
                EditorGUILayout.HelpBox(
                    "With monitoring off, ARP checks once at startup and never again. Anyone who " +
                    "roots or attaches to the process after launch stays invisible for the rest " +
                    "of the session, and the heartbeat just resends the startup result.",
                    MessageType.Warning);
            }

            GUILayout.Space(6);
            Field(_memoryIntegrityEnabled, "Memory Integrity");

            if (_memoryIntegrityEnabled.boolValue)
            {
                EditorGUILayout.HelpBox(
                    "Compares executing code against the APK it was loaded from. This is the " +
                    "only check that sees in-memory patching, which with root leaves the signing " +
                    "certificate, the content hash and Meta's app claim all valid.\n\n" +
                    "Requires libarpnative.so - see SETUP.md. Without it this reports " +
                    "inconclusive rather than clean.",
                    MessageType.Info);
            }

            EndSection();
        }

        // Hidden once Addressables is in the project, via the ARP_ADDRESSABLES version
        // define on this assembly. Advice a dev has already taken is just noise.
        private static void DrawAddressablesRecommendation()
        {
#if !ARP_ADDRESSABLES
            GUILayout.Space(6);
            EditorGUILayout.HelpBox(
                "We would recommend installing Addressables and setting it up with a custom " +
                "configuration to defend against UABEA.\n\n" +
                "Addressables on its own does not help - bundles are what that tool reads " +
                "best. The protection comes from pairing it with a custom AssetBundleProvider " +
                "that decrypts the stream before Unity loads it.\n\n" +
                "Note the decryption key ships inside your client, so this raises the cost of " +
                "pulling your assets apart rather than preventing it. It also does not cover " +
                "your code or IL2CPP metadata.",
                MessageType.Info);

            if (GUILayout.Button("Addressables documentation", GUILayout.Width(240)))
            {
                Application.OpenURL(
                    "https://docs.unity3d.com/Packages/com.unity.addressables@latest");
            }
#endif
        }

        private void DrawBanPolicy()
        {
            Section("Ban policy");

            Field(_banMode, "Ban Mode");

            if (_banMode.enumValueIndex == (int)ARPBanMode.Timed)
            {
                EditorGUI.indentLevel++;
                Field(_timedDuration, "Duration");
                Field(_timedUnit, "Unit");
                EditorGUI.indentLevel--;

                Field(_timedMessageTemplate, "Timed Message");

                var preview = ARPDurationFormatter.Apply(
                    _timedMessageTemplate.stringValue,
                    _timedDuration.floatValue,
                    (ARPTimeUnit)_timedUnit.enumValueIndex);

                EditorGUILayout.LabelField("Preview", preview, EditorStyles.wordWrappedMiniLabel);
            }
            else
            {
                Field(_permanentMessage, "Permanent Message");
            }

            Field(_internalBanReason, "Internal Reason");

            var reasonLength = (_internalBanReason.stringValue ?? string.Empty).Length;
            if (reasonLength > 140)
            {
                EditorGUILayout.HelpBox(
                    "PlayFab caps the ban reason at 140 characters. Yours is " + reasonLength +
                    " and will be truncated.",
                    MessageType.Warning);
            }

            EndSection();
        }

        private void DrawBanTargets()
        {
            Section("Ban targets");

            EditorGUILayout.LabelField(
                "Tick any combination. These are three different mechanisms server-side, not " +
                "three fields on one call.",
                EditorStyles.wordWrappedMiniLabel);
            GUILayout.Space(4);

            Field(_banAccount, "Ban Account");
            Field(_banIpAddress, "Ban IP Address");
            Field(_banHardware, "Ban Hardware");

            if (!_banAccount.boolValue && !_banIpAddress.boolValue && !_banHardware.boolValue)
            {
                EditorGUILayout.HelpBox(
                    "No ban targets selected. ARP will detect and report, but nothing will ever " +
                    "be banned.",
                    MessageType.Error);
            }

            if (_banIpAddress.boolValue)
            {
                EditorGUILayout.HelpBox(
                    "IP bans need the arpRecordLoginContext PlayStream rule wired to " +
                    "player_logged_in - CloudScript cannot see the caller's IP, so without that " +
                    "rule there is nothing on record and this target is skipped.\n\n" +
                    "They also hit everyone behind the address: household members share it, and " +
                    "under CGNAT so do strangers.",
                    MessageType.Warning);
            }

            if (_banHardware.boolValue)
            {
                EditorGUILayout.HelpBox(
                    "PlayFab has no hardware ban, so ARP keeps its own blocklist keyed on a " +
                    "hashed ANDROID_ID.\n\n" +
                    "This is a pseudo-HWID, not a console-style hardware ban. A factory reset " +
                    "clears it, and a rooted device - exactly the population you are targeting - " +
                    "can spoof it. It raises the cost of ban evasion; it does not end it.",
                    MessageType.Info);
            }

            if (_banIpAddress.boolValue || _banHardware.boolValue)
            {
                GUILayout.Space(2);
                if (GUILayout.Button("Read this before testing bans on yourself"))
                {
                    ARPHelpWindow.OpenAt("Testing Bans");
                }
            }

            GUILayout.Space(4);
            Field(_enforcementMode, "Enforcement Mode");

            if (_enforcementMode.enumValueIndex == (int)ARPEnforcementMode.AutoBan)
            {
                EditorGUILayout.HelpBox(
                    "AutoBan lets the corroborating local checks ban on their own. Those all run " +
                    "inside the process an attacker controls, and they produce false positives.\n\n" +
                    "A false positive here costs a real player their account, which is a worse " +
                    "outcome than missing a cheater. Run FlagForReview first and read what you " +
                    "actually catch before turning this on.",
                    MessageType.Warning);
            }

            EndSection();
        }

        private void DrawHeartbeat()
        {
            Section("Heartbeat");

            Field(_heartbeatEnabled, "Heartbeat Enabled");

            if (_heartbeatEnabled.boolValue)
            {
                Field(_heartbeatInterval, "Interval (seconds)");
                Field(_heartbeatRetries, "Retries");
                Field(_heartbeatRetryBackoff, "Retry Backoff");

                EditorGUILayout.HelpBox(
                    "When retries run out ARP fails closed and raises OnHeartbeatFailed. Your " +
                    "netcode must sever its own connections there.\n\n" +
                    "This is not a ban. A dropped Wi-Fi packet and a killed watchdog are " +
                    "indistinguishable from inside the process, so both stop network play and " +
                    "neither takes anyone's account.",
                    MessageType.Info);
            }
            else
            {
                EditorGUILayout.HelpBox(
                    "With the heartbeat off, a one-shot check at startup is all you have - and " +
                    "anyone who can disable this component skips it entirely.",
                    MessageType.Warning);
            }

            EndSection();
        }

        private void DrawEvents()
        {
            Section("Events");

            EditorGUILayout.PropertyField(_onBanConfirmed);
            EditorGUILayout.PropertyField(_onBanReportFailed);
            EditorGUILayout.PropertyField(_onHeartbeatFailed);
            EditorGUILayout.PropertyField(_onIntegrityCheckFailed);

            EndSection();
        }

        // Unity attaches the [Tooltip] automatically only when it builds the label
        // itself. Passing a bare `new GUIContent("Label")` silently replaced the whole
        // label, tooltip included - which is how every tooltip on this component went
        // missing. SerializedProperty.tooltip carries the attribute text, so put it back.
        private static void Field(SerializedProperty property, string label)
        {
            EditorGUILayout.PropertyField(
                property, new GUIContent(label, property.tooltip), true);
        }

        private static void Section(string title)
        {
            GUILayout.Space(8);
            EditorGUILayout.BeginVertical(EditorStyles.helpBox);
            EditorGUILayout.LabelField(title, EditorStyles.boldLabel);
            GUILayout.Space(2);
        }

        private static void EndSection()
        {
            EditorGUILayout.EndVertical();
        }

        private static void BuildStyles()
        {
            if (_banner != null) return;

            _banner = new GUIStyle(EditorStyles.boldLabel)
            {
                wordWrap = true,
                fontSize = 12,
            };
            _banner.normal.textColor = new Color(0.95f, 0.75f, 0.2f);
        }
    }
}
