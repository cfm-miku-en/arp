// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using UnityEditor;
using UnityEngine;

namespace ARP.Editor
{
    [CustomEditor(typeof(ARPManager))]
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
                "ARP removes the check — so put an independent CloudScript call directly in " +
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

            EditorGUILayout.PropertyField(_attestationEnabled, new GUIContent("Attestation Enabled"));

            if (!_attestationEnabled.boolValue)
            {
                EditorGUILayout.HelpBox(
                    "Attestation is off, so ARP is running on forgeable client-side signals only.\n\n" +
                    "Everything else in this component is computed inside the process an attacker " +
                    "controls and can be patched out. The attestation token is signed by Meta's " +
                    "server, which is the one thing a modded client cannot fake. It is also the " +
                    "only reliable way to catch a repacked APK — which is how Quest games are " +
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

            EditorGUILayout.PropertyField(_distribution, new GUIContent("Distribution"));
            EditorGUILayout.PropertyField(_deviceIntegrityThreshold, new GUIContent("Device Integrity Threshold"));

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

            EditorGUILayout.PropertyField(_appIntegrityChecksEnabled, new GUIContent("App Integrity Checks"));
            EditorGUILayout.PropertyField(_deviceChecksEnabled, new GUIContent("Device Checks"));
            EditorGUILayout.PropertyField(_scanDelaySeconds, new GUIContent("Scan Delay (seconds)"));

            EndSection();
        }

        private void DrawBanPolicy()
        {
            Section("Ban policy");

            EditorGUILayout.PropertyField(_banMode, new GUIContent("Ban Mode"));

            if (_banMode.enumValueIndex == (int)ARPBanMode.Timed)
            {
                EditorGUI.indentLevel++;
                EditorGUILayout.PropertyField(_timedDuration, new GUIContent("Duration"));
                EditorGUILayout.PropertyField(_timedUnit, new GUIContent("Unit"));
                EditorGUI.indentLevel--;

                EditorGUILayout.PropertyField(_timedMessageTemplate, new GUIContent("Timed Message"));

                var preview = ARPDurationFormatter.Apply(
                    _timedMessageTemplate.stringValue,
                    _timedDuration.floatValue,
                    (ARPTimeUnit)_timedUnit.enumValueIndex);

                EditorGUILayout.LabelField("Preview", preview, EditorStyles.wordWrappedMiniLabel);
            }
            else
            {
                EditorGUILayout.PropertyField(_permanentMessage, new GUIContent("Permanent Message"));
            }

            EditorGUILayout.PropertyField(_internalBanReason, new GUIContent("Internal Reason"));

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

            EditorGUILayout.PropertyField(_banAccount, new GUIContent("Ban Account"));
            EditorGUILayout.PropertyField(_banIpAddress, new GUIContent("Ban IP Address"));
            EditorGUILayout.PropertyField(_banHardware, new GUIContent("Ban Hardware"));

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
                    "player_logged_in — CloudScript cannot see the caller's IP, so without that " +
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
                    "clears it, and a rooted device — exactly the population you are targeting — " +
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
            EditorGUILayout.PropertyField(_enforcementMode, new GUIContent("Enforcement Mode"));

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

            EditorGUILayout.PropertyField(_heartbeatEnabled, new GUIContent("Heartbeat Enabled"));

            if (_heartbeatEnabled.boolValue)
            {
                EditorGUILayout.PropertyField(_heartbeatInterval, new GUIContent("Interval (seconds)"));
                EditorGUILayout.PropertyField(_heartbeatRetries, new GUIContent("Retries"));
                EditorGUILayout.PropertyField(_heartbeatRetryBackoff, new GUIContent("Retry Backoff"));

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
                    "With the heartbeat off, a one-shot check at startup is all you have — and " +
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
