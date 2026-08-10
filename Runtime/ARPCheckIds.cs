// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

namespace ARP
{
    public static class ARPCheckIds
    {
        public const string AppAttestationNotRecognized = "app:attestation_not_recognized";
        public const string AppAttestationMissing = "app:attestation_missing";
        public const string AppCodePagesDirty = "app:code_pages_dirty";
        public const string AppCodePatched = "app:code_patched";
        public const string AppSigningCertMismatch = "app:signing_cert_mismatch";
        public const string AppContentHashMismatch = "app:content_hash_mismatch";
        public const string AppUnexpectedInstallSource = "app:unexpected_install_source";
        public const string AppModLoaderMelon = "app:modloader_melonloader";
        public const string AppModLoaderScotland2 = "app:modloader_scotland2";
        public const string AppModLoaderQuestLoader = "app:modloader_questloader";
        public const string AppModsDirectoryPresent = "app:mods_directory_present";
        public const string AppUnexpectedNativeLibrary = "app:unexpected_native_library";
        public const string AppCheatToolInstalled = "app:cheat_tool_installed";

        public const string DeviceSelinuxPermissive = "device:selinux_permissive";
        public const string DeviceAttestationNotTrusted = "device:attestation_not_trusted";
        public const string DeviceAttestationBasic = "device:attestation_basic";
        public const string DeviceMagiskArtifact = "device:magisk_artifact";
        public const string DeviceKernelSuArtifact = "device:kernelsu_artifact";
        public const string DeviceAPatchArtifact = "device:apatch_artifact";
        public const string DeviceSuspiciousMount = "device:suspicious_mount";
        public const string DeviceZygiskContext = "device:zygisk_context";

        public const string DeviceLayerDisagreement = "device:layer_disagreement";
        public const string DeviceSuBinaryPresent = "device:su_binary_present";
        public const string DeviceSuExecutable = "device:su_executable";
        public const string DeviceRootPackageInstalled = "device:root_package_installed";
        public const string DeviceTestKeys = "device:test_keys";
        public const string DeviceVerificationObstructed = "device:verification_obstructed";

        public const string BeatMissedThreshold = "beat:missed_threshold";
        public const string BeatSequenceRegression = "beat:sequence_regression";
        public const string BeatNoSessionEnd = "beat:no_session_end";

        public static ARPSignalTier TierOf(string checkId)
        {
            if (string.IsNullOrEmpty(checkId)) return ARPSignalTier.AppTamper;
            if (checkId.StartsWith("device:")) return ARPSignalTier.DeviceRoot;
            if (checkId.StartsWith("beat:")) return ARPSignalTier.HeartbeatPattern;
            return ARPSignalTier.AppTamper;
        }
    }
}
