// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;

namespace ARP
{
    public sealed class ARPAttestationResult
    {
        public bool Available;
        public bool Succeeded;
        public string Token;
        public string Nonce;
        public string Error;

        public static ARPAttestationResult Unavailable(string reason) =>
            new ARPAttestationResult { Available = false, Succeeded = false, Error = reason };
    }

    public static class ARPAttestation
    {
        public const int TokenValidityHours = 24;

        private static string _cachedToken;
        private static string _cachedNonce;
        private static DateTime _cachedAtUtc;

#if ARP_META_PLATFORM
        public static bool PlatformSdkPresent => true;
#else
        public static bool PlatformSdkPresent => false;
#endif

        public static bool HasValidCachedToken =>
            !string.IsNullOrEmpty(_cachedToken) &&
            (DateTime.UtcNow - _cachedAtUtc).TotalHours < TokenValidityHours;

        public static string CachedToken => HasValidCachedToken ? _cachedToken : null;
        public static string CachedNonce => HasValidCachedToken ? _cachedNonce : null;

        public static void InvalidateCache()
        {
            _cachedToken = null;
            _cachedNonce = null;
            _cachedAtUtc = default;
        }

        public static void RequestToken(string serverNonce, Action<ARPAttestationResult> callback)
        {
            if (callback == null) throw new ArgumentNullException(nameof(callback));

            if (string.IsNullOrEmpty(serverNonce))
            {
                callback(ARPAttestationResult.Unavailable("No server nonce supplied."));
                return;
            }

            if (serverNonce.Length < 22 || serverNonce.Length > 172)
            {
                callback(ARPAttestationResult.Unavailable(
                    $"Nonce length {serverNonce.Length} is outside Meta's required 22-172 characters."));
                return;
            }

            if (HasValidCachedToken && _cachedNonce == serverNonce)
            {
                callback(new ARPAttestationResult
                {
                    Available = true,
                    Succeeded = true,
                    Token = _cachedToken,
                    Nonce = _cachedNonce,
                });
                return;
            }

#if !ARP_META_PLATFORM
            callback(ARPAttestationResult.Unavailable(
                "Meta Platform SDK not detected. Install it, or define ARP_META_PLATFORM manually " +
                "if the SDK was imported as a .unitypackage rather than a UPM package."));
#else
            try
            {
                Oculus.Platform.DeviceApplicationIntegrity
                    .GetIntegrityToken(serverNonce)
                    .OnComplete(message =>
                    {
                        if (message.IsError)
                        {
                            var error = message.GetError();
                            callback(new ARPAttestationResult
                            {
                                Available = true,
                                Succeeded = false,
                                Nonce = serverNonce,
                                Error = error != null ? error.Message : "Unknown attestation error.",
                            });
                            return;
                        }

                        _cachedToken = message.Data;
                        _cachedNonce = serverNonce;
                        _cachedAtUtc = DateTime.UtcNow;

                        callback(new ARPAttestationResult
                        {
                            Available = true,
                            Succeeded = true,
                            Token = _cachedToken,
                            Nonce = serverNonce,
                        });
                    });
            }
            catch (Exception e)
            {
                callback(new ARPAttestationResult
                {
                    Available = true,
                    Succeeded = false,
                    Nonce = serverNonce,
                    Error = e.Message,
                });
            }
#endif
        }
    }
}
