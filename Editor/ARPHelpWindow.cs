// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using UnityEditor;
using UnityEngine;

namespace ARP.Editor
{
    public sealed class ARPHelpWindow : EditorWindow
    {
        private static readonly string[] Tabs =
        {
            "Testing Bans",
            "Troubleshooting",
            "Check Reference",
            "Limitations",
        };

        private int _tab;
        private Vector2 _scroll;

        private static GUIStyle _heading;
        private static GUIStyle _body;

        [MenuItem("Tools/ARP/Help", false, 2)]
        public static void Open()
        {
            var window = GetWindow<ARPHelpWindow>(false, "ARP — Help", true);
            window.minSize = new Vector2(640, 560);
            window.Focus();
        }

        public static void OpenAt(string tabName)
        {
            Open();
            var window = GetWindow<ARPHelpWindow>();
            for (var i = 0; i < Tabs.Length; i++)
            {
                if (Tabs[i] == tabName) window._tab = i;
            }
        }

        private void OnGUI()
        {
            BuildStyles();

            GUILayout.Space(6);
            _tab = GUILayout.Toolbar(_tab, Tabs, GUILayout.Height(26));
            GUILayout.Space(8);

            _scroll = EditorGUILayout.BeginScrollView(_scroll);

            switch (_tab)
            {
                case 0: DrawTestingBans(); break;
                case 1: DrawTroubleshooting(); break;
                case 2: DrawCheckReference(); break;
                case 3: DrawLimitations(); break;
            }

            GUILayout.Space(20);
            EditorGUILayout.EndScrollView();
        }

        private void DrawTestingBans()
        {
            Heading("Do not ban yourself out of your own game");

            EditorGUILayout.HelpBox(
                "If you are testing with a modded APK or a rooted device to see whether ARP " +
                "catches it, ARP will do exactly what you built it to do. Read this first.",
                MessageType.Warning);

            GUILayout.Space(6);
            Heading("1. Always use a throwaway PlayFab account");
            Body(
                "Never test against the account you use for anything else. A permanent ban is " +
                "tedious to reverse and a timed one sits there until it expires.\n\n" +
                "Easier still: set Enforcement Mode to FlagForReview and read the results in " +
                "PlayStream instead of actually banning anyone. You can verify every detection " +
                "path that way without a single ban being issued.");

            GUILayout.Space(6);
            Heading("2. If Ban Hardware is ticked — use a throwaway headset");
            Body(
                "The device blocklist is keyed on a hash of your headset's ANDROID_ID, and it " +
                "follows the hardware rather than the account. Banning yourself means a fresh " +
                "PlayFab account on that same headset is still banned.\n\n" +
                "A factory reset regenerates ANDROID_ID and clears it, but that is a heavy price " +
                "for a test. Either use a spare headset, or leave Ban Hardware off until the rest " +
                "of the ban path is verified.\n\n" +
                "To undo one manually: the entry lives in PlayFab Title Internal Data under the " +
                "key ARP_DeviceBan_ plus the first two characters of the fingerprint. Delete your " +
                "fingerprint's entry from that JSON blob.");

            GUILayout.Space(6);
            Heading("3. If Ban IP Address is ticked — use a VPN");
            Body(
                "Otherwise you are banning your own home connection.\n\n" +
                "That does not just lock out the account you were testing with. It locks out " +
                "everyone behind that address: everyone else in the house, every other test " +
                "account you own, and you, from your own game. If your ISP uses CGNAT it can " +
                "reach strangers who share the address too.\n\n" +
                "Connect through a VPN before triggering the ban, and confirm the recorded IP is " +
                "the VPN's before you pull the trigger.");

            GUILayout.Space(6);
            Heading("Suggested order");
            Body(
                "Account ban first, on a throwaway account. Then IP, behind a VPN. Hardware last, " +
                "on a spare headset. Each one is harder to undo than the one before it.");

            GUILayout.Space(6);
            Heading("Undoing a ban");
            Body(
                "Account and IP bans: Game Manager > Players > select the player > Bans > revoke. " +
                "IP bans appear in the same list.\n\n" +
                "Hardware bans are not PlayFab bans and will not appear there — PlayFab has no " +
                "hardware ban, so ARP keeps its own list. See above.");

            GUILayout.Space(8);
            if (GUILayout.Button("Open PlayFab Game Manager", GUILayout.Width(240)))
            {
                Application.OpenURL("https://developer.playfab.com/");
            }
        }

        private void DrawTroubleshooting()
        {
            Heading("Every player is suddenly flagged");
            Body(
                "Almost always a checksum that no longer matches. The build content hash changes " +
                "with every build — if you shipped a new APK without updating arpConfig.js, every " +
                "legitimate player now mismatches.\n\n" +
                "Clear ARP_EXPECTED_CONTENT_HASH back to its placeholder to disable that check " +
                "immediately, then repaste from Tools > ARP > Show Last Build Checksums.");

            GUILayout.Space(6);
            Heading("Nothing is ever detected");
            Body(
                "Check in this order: is a transport wired (the console logs if not), is the " +
                "player logged in before ARP runs, are the checksum constants still placeholders, " +
                "and is Enforcement Mode set to FlagForReview.\n\n" +
                "Flagged results go to PlayStream as arp_integrity_flagged, not to the ban list.");

            GUILayout.Space(6);
            Heading("DllNotFoundException: arpnative");
            Body(
                "The native library is not in the APK. Select the .so and confirm the import " +
                "settings say Android and ARM64 — Unity excludes it silently otherwise. " +
                "See SETUP.md.");

            GUILayout.Space(6);
            Heading("Attestation always fails");
            Body(
                "Confirm the Meta Platform SDK is v55 or newer and initialised before ARP runs, " +
                "that ARP_META_APP_ID and ARP_META_APP_SECRET are set in arpConfig.js, and that " +
                "the headset has Wi-Fi. Attestation needs a network; the entitlement check does " +
                "not.\n\n" +
                "Also check you are not exceeding 100 requests per hour or 200 per day per " +
                "device. Repeatedly reinstalling during a testing session can hit that.");

            GUILayout.Space(6);
            Heading("IP bans never apply");
            Body(
                "The arpRecordLoginContext PlayStream rule is missing. CloudScript cannot see the " +
                "caller's IP, so without that rule there is nothing on record. The ban result " +
                "will say so in skippedTargets.");

            GUILayout.Space(8);
            if (GUILayout.Button("Open PlayFab Tutorial", GUILayout.Width(240))) ARPTutorialWindow.Open();
        }

        private void DrawCheckReference()
        {
            Body(
                "Check ids as they appear in PlayStream events. The prefix is the tier: app: " +
                "means the binary is modified, device: means the headset is compromised, beat: " +
                "means a heartbeat pattern.");

            GUILayout.Space(8);
            Heading("app: — the binary is modified");
            Mono(
                "attestation_not_recognized   Meta says this is not a Store binary\n" +
                "signing_cert_mismatch        signed with a different key — repacked\n" +
                "content_hash_mismatch        APK contents differ from the build you shipped\n" +
                "unexpected_install_source    installed by adb or a raw installer\n" +
                "modloader_melonloader        libmelonloader.so present\n" +
                "modloader_scotland2          libsl2.so present\n" +
                "modloader_questloader        libmodloader.so present\n" +
                "mods_directory_present       a Mods/ or MelonLoader/ directory exists\n" +
                "unexpected_native_library    an .so that was not in your build");

            GUILayout.Space(8);
            Heading("device: — the headset is compromised");
            Mono(
                "selinux_permissive           SELinux is not enforcing — strongest signal\n" +
                "attestation_not_trusted      unlocked bootloader or invalid OS image\n" +
                "attestation_basic            locked and valid, some integrity checks failed\n" +
                "magisk_artifact              Magisk files on disk\n" +
                "kernelsu_artifact            KernelSU files on disk\n" +
                "apatch_artifact              APatch files on disk\n" +
                "suspicious_mount             magisk or /data/adb in the mount table\n" +
                "zygisk_context               unexpected SELinux context — possible injection\n" +
                "layer_disagreement           native and Java disagree — something is hooked\n" +
                "su_binary_present            an su binary exists\n" +
                "su_executable                su actually ran\n" +
                "root_package_installed       a root manager is installed\n" +
                "test_keys                    custom ROM build tags (never fires on Quest)\n" +
                "blocklisted_hardware         this device is on ARP's own blocklist");

            GUILayout.Space(8);
            Heading("beat: — heartbeat patterns");
            Mono(
                "missed_threshold             too many consecutive intervals missed\n" +
                "sequence_regression          sequence number did not advance — replay\n" +
                "no_session_end               session stopped mid-flow with no clean close");

            GUILayout.Space(8);
            EditorGUILayout.HelpBox(
                "These strings are a public contract. They end up in PlayStream history and in " +
                "any dashboard queries you build on top of it, so renaming one breaks your own " +
                "historical data.",
                MessageType.Info);
        }

        private void DrawLimitations()
        {
            Heading("What ARP cannot do");

            Body(
                "Everything except the Meta attestation token is computed inside the process an " +
                "attacker controls, which means all of it can be patched out. The checksums, " +
                "every root check, the mod-loader scan — a modder who finds the comparison inside " +
                "libil2cpp.so can send back whatever ARP expects to see.\n\n" +
                "What that buys you is cost. The job goes from \"run QuestPatcher\" to \"run " +
                "QuestPatcher, then locate and patch ARP\". That is a real barrier for the " +
                "population that actually cheats on Quest, and no barrier at all for someone " +
                "determined.\n\n" +
                "The attestation token is different because Meta's server signs it. A modified " +
                "client cannot produce a valid one. If you can use attestation, it is worth more " +
                "than everything else here combined.");

            GUILayout.Space(6);
            Heading("Ban evasion is cheap");
            Body(
                "PlayFab bans are per-account and a new Meta account costs nothing. The device " +
                "blocklist is a hashed ANDROID_ID: a factory reset clears it, and a rooted device " +
                "can spoof it. IP bans are evaded with any VPN.\n\n" +
                "None of this is a reason not to ban. It is a reason not to treat a ban as final.");

            GUILayout.Space(6);
            Heading("The heartbeat cannot see its own death");
            Body(
                "When the beats stop, nothing calls the server to report it — silence produces no " +
                "request. ARP judges the previous session when the next one begins, so a killed " +
                "watchdog is caught on the player's next launch rather than in the moment.");

            GUILayout.Space(6);
            Heading("ARP is one component and can be deleted");
            Body(
                "Which is why the Inspector recommends putting an independent CloudScript check " +
                "directly in your netcode. If the only integrity check in your game lives in ARP, " +
                "removing ARP removes the check.");

            GUILayout.Space(6);
            Heading("False positives cost real players their accounts");
            Body(
                "Which is worse than missing a cheater. Run FlagForReview, read what you actually " +
                "catch, and only then decide what deserves an automatic ban.");
        }

        private static void Heading(string text)
        {
            EditorGUILayout.LabelField(text, _heading);
            GUILayout.Space(2);
        }

        private static void Body(string text)
        {
            EditorGUILayout.LabelField(text, _body);
            GUILayout.Space(4);
        }

        private static void Mono(string text)
        {
            EditorGUILayout.SelectableLabel(
                text,
                new GUIStyle(EditorStyles.textArea) { font = EditorStyles.miniFont, wordWrap = false },
                GUILayout.Height(18 * (text.Split('\n').Length + 1)));
        }

        private static void BuildStyles()
        {
            if (_heading == null)
            {
                _heading = new GUIStyle(EditorStyles.boldLabel) { fontSize = 13, wordWrap = true };
            }

            if (_body == null)
            {
                _body = new GUIStyle(EditorStyles.label) { wordWrap = true };
            }
        }
    }
}
