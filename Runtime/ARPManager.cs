// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Events;

namespace ARP
{
    [AddComponentMenu("ARP/Android Root Protector")]
    [DisallowMultipleComponent]
    public sealed class ARPManager : MonoBehaviour
    {
        [Header("Attestation (Meta)")]
        [Tooltip("Use the Meta Platform Integrity Attestation API. The only check in ARP whose " +
                 "result cannot be forged, since Meta signs it. Still bypassable by relay " +
                 "from a clean device. Needs a Meta developer app (App ID and App Secret) " +
                 "and Platform SDK v55+. Works for Horizon Store and App Lab.")]
        [SerializeField] private bool attestationEnabled = false;

        [Tooltip("How this build reaches players. Drives how the attestation app-integrity " +
                 "claim is read: a sideloaded build is legitimately 'NotRecognized', so " +
                 "enforcing on it would flag every one of your own testers.")]
        [SerializeField] private ARPDistribution distribution = ARPDistribution.MetaStoreOrAppLab;

        [Tooltip("Which device_integrity_state values count as a violation. 'Basic' means " +
                 "the bootloader is locked and the OS valid but some integrity checks " +
                 "failed - suggestive of rooting, not proof of it.")]
        [SerializeField] private ARPDeviceIntegrityThreshold deviceIntegrityThreshold =
            ARPDeviceIntegrityThreshold.NotTrustedOnly;

        [Header("Local checks")]
        [Tooltip("Run the Tier 1 app-tamper checks: signing certificate, build content " +
                 "hash, install source, mod-loader artifacts.")]
        [SerializeField] private bool appIntegrityChecksEnabled = true;

        [Tooltip("Run the Tier 2 device checks: SELinux, Magisk artifacts, mounts, su.")]
        [SerializeField] private bool deviceChecksEnabled = true;

        [Tooltip("Seconds to wait after startup before scanning. Keeps the scan off the " +
                 "first frames while the headset is still loading the scene.")]
        [SerializeField, Range(0f, 30f)] private float scanDelaySeconds = 3f;

        [Tooltip("Keep scanning for the whole session instead of only at startup.\n\n" +
                 "Root on Quest is non-persistent - the exploit is re-run per boot - and " +
                 "nothing stops a player rooting or attaching to the process after the game " +
                 "is already running. A one-shot check at startup misses all of that.")]
        [SerializeField] private bool continuousMonitoring = true;

        [Tooltip("Seconds between cheap re-scans: SELinux, root artifacts, mounts, layer " +
                 "consistency, executable page integrity. All file reads, so this is safe " +
                 "to run often.")]
        [SerializeField, Range(2f, 60f)] private float quickScanInterval = 5f;

        [Tooltip("Seconds between full re-scans, which add the two expensive checks: " +
                 "spawning a process for the su probe, and walking the package list over JNI.")]
        [SerializeField, Range(15f, 600f)] private float fullScanInterval = 60f;

        [Tooltip("Compare executing code against the APK it was loaded from.\n\n" +
                 "With root you can patch a running process without touching the file, which " +
                 "leaves the signing certificate, the content hash and Meta's app claim all " +
                 "valid while the game runs modified. Every other check in ARP looks at disk; " +
                 "this is the only one that looks at what is actually executing.\n\n" +
                 "Requires the native library.")]
        [SerializeField] private bool memoryIntegrityEnabled = true;

        [Tooltip("Look for a debugger or injected code: an attached tracer, and large " +
                 "writable-executable memory that no file backs.\n\n" +
                 "Both are behavioural rather than name-based, so they do not care which " +
                 "tool is doing it. Requires the native library.")]
        [SerializeField] private bool instrumentationChecksEnabled = true;

        [Tooltip("EXPERIMENTAL. Also probe Frida's default ports on loopback and complete " +
                 "its handshake, so a hit means frida-server specifically rather than " +
                 "just an open port.\n\n" +
                 "Off by default because it is the only check in ARP that opens a socket. " +
                 "Nothing on a stock Quest binds those ports, so a confirmed hit is close " +
                 "to conclusive there - but baseline it on your own devices first.")]
        [SerializeField] private bool fridaPortProbeEnabled = false;

        [Tooltip("Shut the app down locally if a native library is found outside lib/.\n\n" +
                 "Android loads natives from lib/ and nowhere else, so this is a strong " +
                 "signal - but the shutdown is cosmetic. Anyone who rearranged the APK can " +
                 "delete this code in the same sitting, and the server has already been " +
                 "told regardless.\n\n" +
                 "Off by default because a false positive here is an instant close for a " +
                 "real player, and because manufactured shutdowns pollute your own crash " +
                 "and retention numbers.")]
        [SerializeField] private bool lockOutOnDisguisedLibFolder = false;

        [Tooltip("Logged when the lockout fires. Yours to change.")]
        [SerializeField] private string disguisedLibFolderMessage =
            "Turn off your headset, the person that appears in the lenses is a clown.";

        [Tooltip("Survive scene loads, and destroy any duplicate that appears later.\n\n" +
                 "Leave on for anything with more than one scene. Without it ARP dies on the " +
                 "first load, the heartbeat stops, and the server reads that silence as a " +
                 "killed watchdog.")]
        [SerializeField] private bool persistAcrossScenes = true;

        [Header("Ban policy")]
        [SerializeField] private ARPBanMode banMode = ARPBanMode.Permanent;
        [SerializeField] private float timedDuration = 3f;
        [SerializeField] private ARPTimeUnit timedUnit = ARPTimeUnit.Days;

        [Tooltip("Sent to PlayFab and shown in the Game Manager dashboard. Never shown to " +
                 "the player. PlayFab caps this at 140 characters.")]
        [SerializeField] private string internalBanReason = "ARP: client integrity violation";

        [Tooltip("Player-facing text for a timed ban. {{long}} is replaced with a formatted " +
                 "duration, e.g. \"3 days\" or \"12 hours\".")]
        [TextArea(2, 4)]
        [SerializeField] private string timedMessageTemplate =
            "Your account has been suspended for {{long}} for using a modified game client.";

        [Tooltip("Player-facing text for a permanent ban. Used instead of the template.")]
        [TextArea(2, 4)]
        [SerializeField] private string permanentMessage =
            "Your account has been permanently suspended for using a modified game client.";

        [Header("Ban targets - any combination")]
        [Tooltip("Ban the PlayFab account. Native PlayFab. Cheap for a cheater to evade: a " +
                 "new Meta account costs nothing.")]
        [SerializeField] private bool banAccount = true;

        [Tooltip("Ban the IP address. Requires the arpRecordLoginContext PlayStream rule, " +
                 "because CloudScript cannot see the caller's IP - without that rule there " +
                 "is no IP on record and this target is skipped.\n\n" +
                 "High collateral damage: everyone in the household shares the IP, and " +
                 "CGNAT means strangers may too.")]
        [SerializeField] private bool banIpAddress = false;

        [Tooltip("Ban the device. Not native to PlayFab - ARP keeps its own blocklist, " +
                 "keyed on a hashed ANDROID_ID.\n\n" +
                 "This is a pseudo-HWID, not a console-style hardware ban: a factory reset " +
                 "clears it, and a rooted device - exactly the population this targets - " +
                 "can spoof it. It raises the cost of ban evasion; it does not end it.")]
        [SerializeField] private bool banHardware = false;

        [Tooltip("What happens on soft signals - heartbeat misses, 'Basic' device " +
                 "integrity, corroborating local checks. Hard signals (failed attestation " +
                 "on a Store build, signing-certificate mismatch) always report.\n\n" +
                 "False positives here cost real players their accounts, which is worse " +
                 "than missing a cheater.")]
        [SerializeField] private ARPEnforcementMode enforcementMode = ARPEnforcementMode.FlagForReview;

        [Header("Heartbeat")]
        [SerializeField] private bool heartbeatEnabled = true;

        [Tooltip("Seconds between heartbeats. Do not set this low expecting more security: " +
                 "the server's miss threshold is what catches a killed watchdog, and Meta " +
                 "caps attestation at 200 requests per device per day regardless.")]
        [SerializeField, Range(15f, 300f)] private float heartbeatInterval = 45f;

        [Tooltip("Retries before failing closed. Enough to survive one dropped packet on " +
                 "Quest Wi-Fi; not enough to give a modder a comfortable window.")]
        [SerializeField, Range(0, 5)] private int heartbeatRetries = 2;

        [SerializeField, Range(0.5f, 10f)] private float heartbeatRetryBackoff = 2f;

        [Header("Events")]
        [Tooltip("Fires with the final formatted message once the SERVER confirms the ban. " +
                 "Never fires on client suspicion alone.")]
        public UnityEvent<string> OnBanConfirmed = new UnityEvent<string>();

        [Tooltip("Fires if the report call itself fails, e.g. offline. ARP does not decide " +
                 "your fallback - but do not let the player continue by default.")]
        public UnityEvent<string> OnBanReportFailed = new UnityEvent<string>();

        [Tooltip("Fires when heartbeat retries are exhausted. Your netcode should sever its " +
                 "own connections here. This is NOT a ban - a dropped packet and a killed " +
                 "watchdog are indistinguishable from inside the process, so both stop " +
                 "network play and neither bans.")]
        public UnityEvent OnHeartbeatFailed = new UnityEvent();

        [Tooltip("Fires when attestation or a checksum comparison fails server-side. " +
                 "Distinct from a root detection: the binary is wrong, not the headset.")]
        public UnityEvent<string> OnIntegrityCheckFailed = new UnityEvent<string>();

        private IARPTransport _transport;
        private ARPHeartbeat _heartbeat;
        private ARPIntegrityReport _report;
        private readonly List<string> _lastSignals = new List<string>();

        public IARPTransport Transport => _transport;
        public ARPHeartbeat Heartbeat => _heartbeat;

        /// Survives a scene load, unlike a UnityEvent listener. A common ban flow is to
        /// send the player to a dedicated scene, by which point the object that raised
        /// OnBanConfirmed is gone and the message with it.
        public static string LastBanMessage { get; private set; }

        public static bool WasBanned => !string.IsNullOrEmpty(LastBanMessage);

        public void SetTransport(IARPTransport transport) => _transport = transport;

        private static ARPManager _instance;

        // A multi-scene game destroys this on the first load otherwise: the heartbeat
        // stops, the server sees silence, and fail-closed kicks a legitimate player.
        // Returning to an earlier scene would then spawn a second manager, doubling
        // every report and running two heartbeats against one session.
        private void Awake()
        {
            if (persistAcrossScenes)
            {
                if (_instance != null && _instance != this)
                {
                    Destroy(gameObject);
                    return;
                }

                _instance = this;
                transform.SetParent(null);
                DontDestroyOnLoad(gameObject);
            }
        }

        private void OnDestroy()
        {
            if (_instance == this) _instance = null;
        }

        private void Start() => StartCoroutine(RunStartupCheck());

        private IEnumerator RunStartupCheck()
        {
            if (scanDelaySeconds > 0f) yield return new WaitForSeconds(scanDelaySeconds);

            if (_transport == null) _transport = CreateDefaultTransport();

            if (_transport == null)
            {
                Debug.LogError("[ARP] No transport available. ARP is inert: nothing is being " +
                               "verified and no ban can be issued. Install the PlayFab Unity " +
                               "SDK, or call SetTransport() with your own IARPTransport.");
                yield break;
            }

            var waited = 0f;
            while (!_transport.IsReady && waited < 30f)
            {
                waited += Time.unscaledDeltaTime;
                yield return null;
            }

            if (!_transport.IsReady)
            {
                OnBanReportFailed?.Invoke("Backend not ready; integrity was never verified.");
                yield break;
            }

            var report = new ARPIntegrityReport();

            if (attestationEnabled) yield return CollectAttestation(report);
            if (appIntegrityChecksEnabled) ARPIntegrityChecker.Populate(report, distribution);

            if (deviceChecksEnabled)
            {
                foreach (var _ in ARPRootDetector.ScanIncremental(report.Signals)) yield return null;
            }

            if (instrumentationChecksEnabled)
            {
                ARPInstrumentationDetector.ProbeFridaPorts = fridaPortProbeEnabled;
                ARPInstrumentationDetector.Scan(report.Signals);
            }

            if (memoryIntegrityEnabled && ARPMemoryIntegrity.QuickCheck(report.Signals))
            {
                yield return ARPMemoryIntegrity.DeepVerify(report.Signals);
            }

            // Reported first, then locked out. The server has to hear about it even if
            // the app is about to close, because the report is the part that matters.
            if (lockOutOnDisguisedLibFolder &&
                report.Signals.TriggeredChecks.Contains(ARPCheckIds.AppDisguisedLibFolder))
            {
                yield return SubmitReport(report);
                Debug.LogError("[ARP] " + disguisedLibFolderMessage);
                Application.Quit();
                yield break;
            }

            _report = report;
            _lastSignals.Clear();
            _lastSignals.AddRange(report.Signals.TriggeredChecks);

            yield return SubmitReport(report);

            if (heartbeatEnabled) StartHeartbeat(report);
            if (continuousMonitoring) StartCoroutine(MonitorLoop());
        }

        private IEnumerator CollectAttestation(ARPIntegrityReport report)
        {
            if (!ARPAttestation.PlatformSdkPresent)
            {
                report.AttestationError = "meta_platform_sdk_missing";
                Debug.LogWarning("[ARP] Attestation is enabled but the Meta Platform SDK was not " +
                                 "detected. Falling back to forgeable client-side signals only.");
                yield break;
            }

            string nonce = null;
            string nonceError = null;
            var nonceDone = false;

            _transport.GetNonce((n, e) => { nonce = n; nonceError = e; nonceDone = true; });
            while (!nonceDone) yield return null;

            if (string.IsNullOrEmpty(nonce))
            {
                report.AttestationError = "nonce_unavailable: " + nonceError;
                Debug.LogWarning($"[ARP] Could not obtain an attestation nonce: {nonceError}");
                yield break;
            }

            var attestDone = false;
            ARPAttestationResult attestation = null;

            ARPAttestation.RequestToken(nonce, r => { attestation = r; attestDone = true; });
            while (!attestDone) yield return null;

            if (attestation != null && attestation.Succeeded)
            {
                report.AttestationToken = attestation.Token;
                report.AttestationNonce = attestation.Nonce;
            }
            else
            {
                report.AttestationError = attestation?.Error ?? "unknown";
                Debug.LogWarning($"[ARP] Attestation failed: {attestation?.Error}");
            }
        }

        private IEnumerator SubmitReport(ARPIntegrityReport report)
        {
            var policy = BuildPolicy();
            ARPServerVerdict verdict = null;
            var done = false;

            _transport.ReportIntegrity(report, policy, v => { verdict = v; done = true; });
            while (!done) yield return null;

            if (verdict == null || verdict.IsError)
            {
                OnBanReportFailed?.Invoke(verdict?.Error ?? "Integrity report failed with no detail.");
                yield break;
            }

            if (verdict.Banned)
            {
                LastBanMessage = verdict.PlayerMessage ?? BuildPlayerMessage();
                OnBanConfirmed?.Invoke(verdict.PlayerMessage ?? BuildPlayerMessage());
            }
            else if (verdict.Flagged)
            {
                OnIntegrityCheckFailed?.Invoke(verdict.PlayerMessage ?? "Integrity check failed.");
            }
        }

        private void StartHeartbeat(ARPIntegrityReport report)
        {
            _heartbeat = new ARPHeartbeat(_transport, Guid.NewGuid().ToString("N"))
            {
                IntervalSeconds = heartbeatInterval,
                MaxRetries = heartbeatRetries,
                RetryBackoffSeconds = heartbeatRetryBackoff,
                LastKnownSignals = new List<string>(_lastSignals),
                AttestationRef = report.AttestationNonce,
            };

            _heartbeat.OnHeartbeatFailed += () => OnHeartbeatFailed?.Invoke();
            StartCoroutine(_heartbeat.Run());
        }

        private ARPBanPolicy BuildPolicy()
        {
            var policy = new ARPBanPolicy
            {
                BanMode = banMode.ToString(),
                DurationHours = banMode == ARPBanMode.Timed
                    ? ARPDurationFormatter.ToHours(timedDuration, timedUnit)
                    : 0,
                InternalReason = TruncateReason(internalBanReason),
                PlayerMessage = BuildPlayerMessage(),
                EnforcementMode = enforcementMode.ToString(),
                Distribution = distribution.ToString(),
                DeviceIntegrityThreshold = deviceIntegrityThreshold.ToString(),
            };

            if (banAccount) policy.Targets.Add(ARPBanTargets.Account.ToString());
            if (banIpAddress) policy.Targets.Add(ARPBanTargets.IpAddress.ToString());
            if (banHardware) policy.Targets.Add(ARPBanTargets.Hardware.ToString());

            return policy;
        }

        private static string TruncateReason(string reason)
        {
            if (string.IsNullOrEmpty(reason)) return "ARP: client integrity violation";
            return reason.Length <= 140 ? reason : reason.Substring(0, 140);
        }

        public string BuildPlayerMessage() =>
            banMode == ARPBanMode.Permanent
                ? permanentMessage
                : ARPDurationFormatter.Apply(timedMessageTemplate, timedDuration, timedUnit);

        private static IARPTransport CreateDefaultTransport()
        {
#if ARP_PLAYFAB
            return new ARPPlayFabTransport();
#else
            return null;
#endif
        }

        // The heartbeat used to resend the startup scan verbatim for the whole session,
        // so anything that changed after launch was invisible. This is what actually
        // keeps it current.
        private IEnumerator MonitorLoop()
        {
            var sinceFullScan = 0f;

            while (true)
            {
                yield return new WaitForSecondsRealtime(quickScanInterval);

                sinceFullScan += quickScanInterval;

                var depth = ARPScanDepth.Quick;
                if (sinceFullScan >= fullScanInterval)
                {
                    depth = ARPScanDepth.Full;
                    sinceFullScan = 0f;
                }

                var pass = new ARPScanResult();

                if (deviceChecksEnabled)
                {
                    foreach (var _ in ARPRootDetector.ScanIncremental(pass, depth)) yield return null;
                }

                if (appIntegrityChecksEnabled) ARPIntegrityChecker.ScanLoadedLibraries(pass);
                if (instrumentationChecksEnabled) ARPInstrumentationDetector.Scan(pass);

                if (memoryIntegrityEnabled && ARPMemoryIntegrity.QuickCheck(pass))
                {
                    yield return ARPMemoryIntegrity.DeepVerify(pass);
                }

                yield return HandleNewSignals(pass);
            }
        }

        private IEnumerator HandleNewSignals(ARPScanResult pass)
        {
            var fresh = new List<string>();
            foreach (var signal in pass.TriggeredChecks)
            {
                if (!_lastSignals.Contains(signal)) fresh.Add(signal);
            }

            if (fresh.Count == 0) yield break;

            _lastSignals.AddRange(fresh);

            if (_heartbeat != null)
            {
                _heartbeat.LastKnownSignals = new List<string>(_lastSignals);
            }

            // Report the moment something changes rather than waiting for the next beat.
            // A mid-session root is exactly the case the heartbeat interval would delay.
            if (_report != null)
            {
                _report.Signals.Absorb(pass);
                yield return SubmitReport(_report);
            }
        }

        private void OnApplicationQuit() => _heartbeat?.SendSessionEnd();

    }
}
