// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

#if ARP_PLAYFAB
using System;
using System.Collections.Generic;
using PlayFab;
using PlayFab.ClientModels;
using UnityEngine;

namespace ARP
{
    public sealed class ARPPlayFabTransport : IARPTransport
    {
        public const string FnGetNonce = "arpGetNonce";
        public const string FnVerifyIntegrity = "arpVerifyIntegrity";
        public const string FnHeartbeat = "arpHeartbeat";

        public bool IsReady => PlayFabClientAPI.IsClientLoggedIn();

        public void GetNonce(Action<string, string> callback)
        {
            Execute(FnGetNonce, new Dictionary<string, object>(),
                json =>
                {
                    var nonce = ReadString(json, "nonce");
                    if (string.IsNullOrEmpty(nonce)) callback(null, "CloudScript returned no nonce.");
                    else callback(nonce, null);
                },
                error => callback(null, error));
        }

        public void ReportIntegrity(ARPIntegrityReport report, ARPBanPolicy policy, Action<ARPServerVerdict> callback)
        {
            var args = new Dictionary<string, object>
            {
                { "attestationToken", report.AttestationToken },
                { "attestationNonce", report.AttestationNonce },
                { "attestationError", report.AttestationError },
                { "signingCertSha256", report.SigningCertSha256 },
                { "buildContentHash", report.BuildContentHash },
                { "installSource", report.InstallSourcePackage },
                { "deviceFingerprint", report.DeviceFingerprint },
                { "triggeredChecks", report.Signals.TriggeredChecks },
                { "inconclusiveChecks", report.Signals.InconclusiveChecks },
                { "policy", PolicyToDictionary(policy) },
            };

            Execute(FnVerifyIntegrity, args,
                json =>
                {
                    var verdict = new ARPServerVerdict
                    {
                        Banned = ReadBool(json, "banned"),
                        Flagged = ReadBool(json, "flagged"),
                        PlayerMessage = ReadString(json, "playerMessage"),
                    };

                    ReadInto(json, "appliedTargets", verdict.AppliedTargets);
                    ReadInto(json, "skippedTargets", verdict.SkippedTargets);
                    callback(verdict);
                },
                error => callback(new ARPServerVerdict { Error = error }));
        }

        public void SendHeartbeat(ARPHeartbeatPayload payload, Action<bool, string> callback)
        {
            var args = new Dictionary<string, object>
            {
                { "sessionId", payload.SessionId },
                { "sequence", payload.Sequence },
                { "unixTimeMs", payload.UnixTimeMs },
                { "sessionEnd", payload.SessionEnd },
                { "lastKnownSignals", payload.LastKnownSignals },
                { "attestationRef", payload.AttestationRef },
            };

            Execute(FnHeartbeat, args,
                json =>
                {
                    callback(ReadBool(json, "ack"), null);
                },
                error => callback(false, error));
        }

        private static void Execute(
            string functionName,
            Dictionary<string, object> args,
            Action<Dictionary<string, object>> onSuccess,
            Action<string> onError)
        {
            var request = new ExecuteCloudScriptRequest
            {
                FunctionName = functionName,
                FunctionParameter = args,
                GeneratePlayStreamEvent = true,
            };

            PlayFabClientAPI.ExecuteCloudScript(request,
                result =>
                {
                    if (result.Error != null)
                    {
                        onError($"CloudScript error in {functionName}: {result.Error.Message}");
                        return;
                    }

                    if (result.FunctionResult == null)
                    {
                        onError($"CloudScript {functionName} returned no result.");
                        return;
                    }

                    try
                    {
                        var json = PlayFab.Json.PlayFabSimpleJson
                            .DeserializeObject<Dictionary<string, object>>(result.FunctionResult.ToString());
                        onSuccess(json);
                    }
                    catch (Exception e)
                    {
                        onError($"Could not parse {functionName} response: {e.Message}");
                    }
                },
                error => onError(error.GenerateErrorReport()));
        }

        private static Dictionary<string, object> PolicyToDictionary(ARPBanPolicy policy) =>
            new Dictionary<string, object>
            {
                { "banMode", policy.BanMode },
                { "durationHours", policy.DurationHours },
                { "internalReason", policy.InternalReason },
                { "playerMessage", policy.PlayerMessage },
                { "targets", policy.Targets },
                { "enforcementMode", policy.EnforcementMode },
                { "distribution", policy.Distribution },
                { "deviceIntegrityThreshold", policy.DeviceIntegrityThreshold },
            };

        private static string ReadString(IReadOnlyDictionary<string, object> json, string key) =>
            json != null && json.TryGetValue(key, out var value) ? value?.ToString() : null;

        private static bool ReadBool(IReadOnlyDictionary<string, object> json, string key)
        {
            if (json == null || !json.TryGetValue(key, out var value) || value == null) return false;
            if (value is bool b) return b;
            return bool.TryParse(value.ToString(), out var parsed) && parsed;
        }

        private static void ReadInto(IReadOnlyDictionary<string, object> json, string key, List<string> target)
        {
            if (json == null || !json.TryGetValue(key, out var value)) return;
            if (!(value is IEnumerable<object> list)) return;

            foreach (var item in list)
            {
                if (item != null) target.Add(item.ToString());
            }
        }
    }
}
#endif
