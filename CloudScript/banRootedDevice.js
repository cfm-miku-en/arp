// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

function arpApplyBan(policy, triggeredChecks, deviceFingerprint) {
    var result = {
        banned: false,
        appliedTargets: [],
        skippedTargets: [],
        playerMessage: policy.playerMessage || "Your account has been suspended."
    };

    var permanent = policy.banMode !== "Timed";
    var durationHours = permanent ? null : policy.durationHours;

    var reason = (policy.internalReason || "ARP: client integrity violation").substring(0, 140);

    var wantsAccount = arpTargetEnabled(policy, "Account");
    var wantsIp = arpTargetEnabled(policy, "IpAddress");
    var wantsHardware = arpTargetEnabled(policy, "Hardware");

    if (!wantsAccount && !wantsIp && !wantsHardware) {
        result.skippedTargets.push("none:no ban targets enabled in the Inspector");
        return result;
    }

    var bans = [];

    if (wantsAccount) {
        var accountBan = {
            PlayFabId: currentPlayerId,
            Reason: reason
        };

        if (!permanent) accountBan.DurationInHours = durationHours;
        bans.push(accountBan);
    }

    if (wantsIp) {
        var loginContext = arpReadInternal(ARP_KEY_LOGIN_IP);
        if (loginContext && loginContext.ip) {
            var ipBan = {
                PlayFabId: currentPlayerId,
                IPAddress: loginContext.ip,
                Reason: reason
            };
            if (!permanent) ipBan.DurationInHours = durationHours;
            bans.push(ipBan);
        } else {
            result.skippedTargets.push(
                "IpAddress:no IP on record - wire the arpRecordLoginContext PlayStream " +
                "rule to player_logged_in");
        }
    }

    if (bans.length > 0) {
        try {
            server.BanUsers({ Bans: bans });
            if (wantsAccount) result.appliedTargets.push("Account");
            if (wantsIp && bans.length === (wantsAccount ? 2 : 1)) result.appliedTargets.push("IpAddress");
            result.banned = true;
        } catch (e) {
            log.error("ARP: server.BanUsers failed: " + e);
            result.skippedTargets.push("Account/IpAddress:BanUsers call failed");
        }
    }

    if (wantsHardware) {
        if (typeof deviceFingerprint === "string" && deviceFingerprint.length >= 16) {
            try {
                arpAddDeviceBan(deviceFingerprint, reason, durationHours);
                result.appliedTargets.push("Hardware");
                result.banned = true;
            } catch (e) {
                log.error("ARP: device blocklist write failed: " + e);
                result.skippedTargets.push("Hardware:blocklist write failed");
            }
        } else {
            result.skippedTargets.push("Hardware:no usable device fingerprint reported");
        }
    }

    try {
        server.WritePlayerEvent({
            PlayFabId: currentPlayerId,
            EventName: "arp_root_ban_issued",
            Body: {
                triggeredChecks: triggeredChecks || [],
                appliedTargets: result.appliedTargets,
                skippedTargets: result.skippedTargets,
                banMode: permanent ? "Permanent" : "Timed",
                durationHours: durationHours,
                internalReason: reason,
                enforcementMode: policy.enforcementMode,
                distribution: policy.distribution,
                scriptRevision: script.revision
            }
        });
    } catch (e) {
        log.error("ARP: could not write the arp_root_ban_issued PlayStream event: " + e);
    }

    return result;
}

function arpTargetEnabled(policy, name) {
    if (!policy || !policy.targets) return false;
    if (Object.prototype.toString.call(policy.targets) !== "[object Array]") return false;

    for (var i = 0; i < policy.targets.length; i++) {
        if (policy.targets[i] === name) return true;
    }
    return false;
}

handlers.banRootedDevice = function (args, context) {
    var durationHours = arpNumber(args, "durationHours", 0.0166, 87600);

    var policy = {
        banMode: durationHours === null ? "Permanent" : "Timed",
        durationHours: durationHours,
        internalReason: arpString(args, "reason", 140) || "ARP: client integrity violation",
        playerMessage: arpString(args, "playerMessage", 512),
        targets: arpStringArray(args, "targets", 3, 16),
        enforcementMode: arpString(args, "enforcementMode", 32),
        distribution: arpString(args, "distribution", 32)
    };

    if (policy.targets.length === 0) policy.targets = ["Account"];

    var triggeredChecks = arpStringArray(args, "triggeredChecks", 64, 128);
    var fingerprint = arpString(args, "deviceFingerprint", 128);

    return arpApplyBan(policy, triggeredChecks, fingerprint);
};
