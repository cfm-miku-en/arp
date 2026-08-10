// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace ARP
{
    public enum ARPBanMode
    {
        Permanent = 0,
        Timed = 1,
    }

    public enum ARPTimeUnit
    {
        Minutes = 0,
        Hours = 1,
        Days = 2,
    }

    public enum ARPEnforcementMode
    {
        FlagForReview = 0,
        AutoBan = 1,
    }

    public enum ARPDistribution
    {
        MetaStoreOrAppLab = 0,

        ReleaseChannel = 1,

        Sideloaded = 2,
    }

    public enum ARPDeviceIntegrityThreshold
    {
        NotTrustedOnly = 0,
        BasicOrWorse = 1,
    }

    public enum ARPDeviceIntegrityState
    {
        Unknown = 0,
        Advanced = 1,
        Basic = 2,
        NotTrusted = 3,
    }

    public enum ARPAppIntegrityState
    {
        Unknown = 0,
        StoreRecognized = 1,
        NotRecognized = 2,
        NotEvaluated = 3,
    }

    [Flags]
    public enum ARPBanTargets
    {
        None = 0,

        Account = 1 << 0,

        IpAddress = 1 << 1,

        Hardware = 1 << 2,
    }

    public enum ARPSignalTier
    {
        AppTamper = 0,

        DeviceRoot = 1,

        HeartbeatPattern = 2,
    }

    public sealed class ARPScanResult
    {
        public readonly List<string> TriggeredChecks = new List<string>();

        public readonly List<string> InconclusiveChecks = new List<string>();

        public bool AnyTriggered => TriggeredChecks.Count > 0;

        public void Trigger(string checkId)
        {
            if (!string.IsNullOrEmpty(checkId) && !TriggeredChecks.Contains(checkId))
                TriggeredChecks.Add(checkId);
        }

        public void Inconclusive(string checkId)
        {
            if (!string.IsNullOrEmpty(checkId) && !InconclusiveChecks.Contains(checkId))
                InconclusiveChecks.Add(checkId);
        }

        public void Absorb(ARPScanResult other)
        {
            if (other == null) return;
            foreach (var c in other.TriggeredChecks) Trigger(c);
            foreach (var c in other.InconclusiveChecks) Inconclusive(c);
        }
    }

    public sealed class ARPIntegrityReport
    {
        public string AttestationToken;
        public string AttestationNonce;

        public string SigningCertSha256;
        public string BuildContentHash;
        public string InstallSourcePackage;
        public string DeviceFingerprint;

        public readonly ARPScanResult Signals = new ARPScanResult();
    }
}
