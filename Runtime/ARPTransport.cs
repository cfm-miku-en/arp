// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace ARP
{
    [Serializable]
    public sealed class ARPBanPolicy
    {
        public string BanMode;
        public double DurationHours;
        public string InternalReason;
        public string PlayerMessage;
        public List<string> Targets = new List<string>();
        public string EnforcementMode;
        public string Distribution;
        public string DeviceIntegrityThreshold;
    }

    public sealed class ARPServerVerdict
    {
        public bool Banned;
        public bool Flagged;

        public string PlayerMessage;

        public readonly List<string> AppliedTargets = new List<string>();

        public readonly List<string> SkippedTargets = new List<string>();

        public string Error;
        public bool IsError => !string.IsNullOrEmpty(Error);
    }

    [Serializable]
    public sealed class ARPHeartbeatPayload
    {
        public string SessionId;
        public long Sequence;
        public long UnixTimeMs;
        public bool SessionEnd;

        public List<string> LastKnownSignals = new List<string>();

        public string AttestationRef;
    }

    public interface IARPTransport
    {
        bool IsReady { get; }

        void GetNonce(Action<string, string> callback);

        void ReportIntegrity(ARPIntegrityReport report, ARPBanPolicy policy, Action<ARPServerVerdict> callback);

        void SendHeartbeat(ARPHeartbeatPayload payload, Action<bool, string> callback);
    }
}
