// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

handlers.arpVerifyIntegrity = function (args, context) {
    var response = {
        banned: false,
        flagged: false,
        playerMessage: null,
        appliedTargets: [],
        skippedTargets: []
    };

    var attestationToken = arpString(args, "attestationToken", 8192);
    var attestationNonce = arpString(args, "attestationNonce", 256);
    var signingCert = arpString(args, "signingCertSha256", 128);
    var contentHash = arpString(args, "buildContentHash", 128);
    var deviceFingerprint = arpString(args, "deviceFingerprint", 128);
    var installSource = arpString(args, "installSource", 128);
    var apkLibraries = arpStringArray(args, "apkLibraries", 128, 128);
    var loadedLibraries = arpStringArray(args, "loadedLibraries", 128, 128);
    var disguisedPaths = arpStringArray(args, "disguisedLibraryPaths", 32, 256);
    var clientChecks = arpStringArray(args, "triggeredChecks", 64, 128);
    var inconclusive = arpStringArray(args, "inconclusiveChecks", 64, 128);

    var policy = arpNormalizePolicy(args ? args.policy : null);

    var hardSignals = [];
    var softSignals = [];

    // Everything the client scanned is soft by construction: it was produced inside a
    // process the attacker controls. Only the signed attestation claims and the
    // server-held checksums are allowed to be hard.
    for (var i = 0; i < clientChecks.length; i++) {
        softSignals.push(clientChecks[i]);
    }

    // A root hider does not make a device look clean, it makes it unreadable - and
    // treating "could not determine" as "fine" is how hiders win. Enough silence is
    // itself the signal.
    if (inconclusive.length >= ARP_INCONCLUSIVE_THRESHOLD) {
        softSignals.push("device:verification_obstructed");
        log.info("ARP: " + inconclusive.length + " checks were indeterminate: " +
                 inconclusive.join(", "));
    }

    if (deviceFingerprint && arpIsDeviceBanned(deviceFingerprint)) {
        hardSignals.push("device:blocklisted_hardware");
    }

    if (arpAttestationConfigured() && !attestationToken) {
        // A client that simply omits the token used to skip this whole block, which
        // made the strongest layer optional from the client's side. Never silent
        // again. Kept soft because no-Wi-Fi, an uninitialised SDK and Meta's
        // 200/day cap all produce a legitimately absent token.
        softSignals.push("app:attestation_missing");
        log.info("ARP: no attestation token. Client reported: " +
                 (arpString(args, "attestationError", 256) || "no reason given"));
    }

    if (attestationToken && arpAttestationConfigured()) {
        var attestation = arpVerifyAttestationToken(attestationToken, attestationNonce);

        if (attestation.verified) {
            if (attestation.appState === "NotRecognized" &&
                policy.distribution === "MetaStoreOrAppLab") {
                hardSignals.push("app:attestation_not_recognized");
            }

            if (attestation.deviceState === "NotTrusted") {
                hardSignals.push("device:attestation_not_trusted");
            } else if (attestation.deviceState === "Basic") {
                if (policy.deviceIntegrityThreshold === "BasicOrWorse") {
                    hardSignals.push("device:attestation_basic");
                } else {
                    softSignals.push("device:attestation_basic");
                }
            }
        } else if (attestation.replayed) {
            hardSignals.push("app:attestation_replayed");
        } else {
            log.info("ARP: attestation could not be verified: " + attestation.error);
        }
    }

    if (arpCertConfigured()) {
        if (!signingCert) {
            log.info("ARP: client reported no signing certificate hash.");
        } else if (!arpSecureEquals(signingCert, ARP_EXPECTED_SIGNING_CERT_SHA256)) {
            hardSignals.push("app:signing_cert_mismatch");
        }
    } else {
        log.info("ARP: ARP_EXPECTED_SIGNING_CERT_SHA256 is unset - certificate check skipped.");
    }

    if (arpContentHashConfigured()) {
        if (!contentHash) {
            log.info("ARP: client reported no build content hash.");
        } else if (!arpSecureEquals(contentHash, ARP_EXPECTED_CONTENT_HASH)) {
            hardSignals.push("app:content_hash_mismatch");
        }
    } else {
        log.info("ARP: ARP_EXPECTED_CONTENT_HASH is unset - content hash check skipped. " +
                 "Update it from Unity: Tools > ARP > Show Last Build Checksums.");
    }

    if (disguisedPaths.length > 0) {
        // Android loads native libraries from lib/ and nowhere else, so a .so parked
        // anywhere else in the APK has no legitimate reason to exist. Renaming the
        // folder is aimed at checks that look up a path by name.
        hardSignals.push("app:disguised_lib_folder");
        log.info("ARP: native libraries outside lib/: " + disguisedPaths.join(", "));
    }

    if (arpLibrariesConfigured()) {
        // Compare against what is actually mapped into the process where we can. That
        // view does not care what the APK folder was renamed to, what the file was
        // renamed to, or whether the library was ever in the APK - all of which are
        // published ways around a name-based check.
        var reported = loadedLibraries.length > 0 ? loadedLibraries : apkLibraries;

        if (reported.length === 0) {
            // Silence is not a pass. An empty list is what a renamed lib/ folder
            // produces, and it used to sail through the loop below without a signal.
            hardSignals.push("app:libraries_missing");
            log.info("ARP: client reported no libraries at all.");
        } else {
            for (var l = 0; l < reported.length; l++) {
                if (arpContains(ARP_EXPECTED_LIBRARIES, reported[l])) continue;

                hardSignals.push("app:unexpected_native_library");
                log.info("ARP: library not in this build: " + reported[l]);
                break;
            }

            // The other direction. Everything the build shipped has to still be there;
            // a library going missing means the layout was rearranged under us.
            for (var x = 0; x < ARP_EXPECTED_LIBRARIES.length; x++) {
                if (arpContains(reported, ARP_EXPECTED_LIBRARIES[x])) continue;

                hardSignals.push("app:libraries_missing");
                log.info("ARP: expected library absent: " + ARP_EXPECTED_LIBRARIES[x]);
                break;
            }
        }
    } else {
        log.info("ARP: ARP_EXPECTED_LIBRARIES is unset - library check skipped.");
    }

    // Only meaningful when the distribution channel is controlled. A sideloaded or
    // itch.io build can legitimately be installed by any file manager on the headset,
    // so the installing package carries no signal at all there.
    if (policy.distribution === "MetaStoreOrAppLab" &&
        ARP_EXPECTED_INSTALLER.length > 0 && installSource &&
        installSource !== ARP_EXPECTED_INSTALLER) {
        softSignals.push("app:unexpected_install_source");
        log.info("ARP: installed by " + installSource + ", expected " + ARP_EXPECTED_INSTALLER);
    }

    var allSignals = hardSignals.concat(softSignals);

    if (hardSignals.length === 0 && softSignals.length === 0) {
        return response;
    }

    var shouldBan = hardSignals.length > 0 ||
                    (policy.enforcementMode === "AutoBan" && softSignals.length > 0);

    if (shouldBan) {
        var banResult = arpApplyBan(policy, allSignals, deviceFingerprint);
        response.banned = banResult.banned;
        response.playerMessage = banResult.playerMessage;
        response.appliedTargets = banResult.appliedTargets;
        response.skippedTargets = banResult.skippedTargets;

        if (!banResult.banned) {
            response.flagged = true;
            arpRecordFlag(allSignals, "ban requested but no target applied");
        }
    } else {
        response.flagged = true;
        arpRecordFlag(allSignals, "soft signals under FlagForReview");
    }

    return response;
};

function arpVerifyAttestationToken(token, clientNonce) {
    var outcome = {
        verified: false,
        replayed: false,
        appState: null,
        deviceState: null,
        error: null
    };

    var stored = arpReadInternal(ARP_KEY_NONCE);
    arpDeleteInternal(ARP_KEY_NONCE);

    if (!stored || !stored.nonce) {
        outcome.error = "no outstanding nonce for this player";
        return outcome;
    }

    if (stored.expiresAt && stored.expiresAt < (new Date()).getTime()) {
        outcome.error = "nonce expired";
        return outcome;
    }

    if (!arpSecureEquals(stored.nonce, clientNonce || "")) {
        outcome.replayed = true;
        outcome.error = "nonce mismatch";
        return outcome;
    }

    var accessToken = "OC|" + ARP_META_APP_ID + "|" + ARP_META_APP_SECRET;
    var url = "https://graph.oculus.com/platform_integrity/verify" +
              "?token=" + encodeURIComponent(token) +
              "&access_token=" + encodeURIComponent(accessToken);

    var body;
    try {
        body = http.request(url, "post", "", "application/json", null);
    } catch (e) {
        outcome.error = "graph.oculus.com request failed: " + e;
        return outcome;
    }

    var parsed;
    try {
        parsed = JSON.parse(body);
    } catch (e2) {
        outcome.error = "attestation response was not JSON";
        return outcome;
    }

    if (!parsed || !parsed.data || !parsed.data[0]) {
        outcome.error = "attestation response had no data";
        return outcome;
    }

    var entry = parsed.data[0];
    if (entry.message !== "success" || !entry.claims) {
        outcome.error = "attestation rejected: " + (entry.message || "unknown");
        return outcome;
    }

    var claims = arpParseClaims(entry.claims);
    if (!claims) {
        outcome.error = "claims did not decode";
        return outcome;
    }

    var claimNonce = claims.nonce || claims.challenge_nonce || null;
    if (!claimNonce) {
        outcome.error = "signed claims carried no nonce field - cannot rule out replay";
        return outcome;
    }

    if (!arpSecureEquals(claimNonce, stored.nonce)) {
        outcome.replayed = true;
        outcome.error = "claim nonce does not match the issued challenge";
        return outcome;
    }

    outcome.verified = true;
    outcome.appState = claims.app_integrity_state || null;
    outcome.deviceState = claims.device_integrity_state || null;
    return outcome;
}

function arpNormalizePolicy(raw) {
    var policy = {
        banMode: "Permanent",
        durationHours: null,
        internalReason: "ARP: client integrity violation",
        playerMessage: "Your account has been suspended.",
        targets: ["Account"],
        enforcementMode: "FlagForReview",
        distribution: "MetaStoreOrAppLab",
        deviceIntegrityThreshold: "NotTrustedOnly"
    };

    if (!raw || typeof raw !== "object") return policy;

    if (raw.banMode === "Timed") policy.banMode = "Timed";
    if (typeof raw.durationHours === "number" && raw.durationHours > 0) {
        policy.durationHours = raw.durationHours;
    }
    if (typeof raw.internalReason === "string" && raw.internalReason.length > 0) {
        policy.internalReason = raw.internalReason.substring(0, 140);
    }
    if (typeof raw.playerMessage === "string" && raw.playerMessage.length > 0) {
        policy.playerMessage = raw.playerMessage.substring(0, 512);
    }
    if (raw.enforcementMode === "AutoBan") policy.enforcementMode = "AutoBan";
    if (raw.deviceIntegrityThreshold === "BasicOrWorse") {
        policy.deviceIntegrityThreshold = "BasicOrWorse";
    }
    if (typeof raw.distribution === "string") {
        policy.distribution = raw.distribution.substring(0, 32);
    }

    var targets = arpStringArray({ t: raw.targets }, "t", 3, 16);
    if (targets.length > 0) policy.targets = targets;

    return policy;
}

function arpRecordFlag(signals, note) {
    var existing = arpReadInternal(ARP_KEY_FLAGS) || { flags: [] };
    if (!existing.flags) existing.flags = [];

    existing.flags.push({
        at: (new Date()).getTime(),
        signals: signals,
        note: note,
        revision: script.revision
    });

    if (existing.flags.length > 20) {
        existing.flags = existing.flags.slice(existing.flags.length - 20);
    }

    arpWriteInternal(ARP_KEY_FLAGS, existing);

    try {
        server.WritePlayerEvent({
            PlayFabId: currentPlayerId,
            EventName: "arp_integrity_flagged",
            Body: { signals: signals, note: note, revision: script.revision }
        });
    } catch (e) {
        log.error("ARP: could not write arp_integrity_flagged: " + e);
    }
}
