// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

// The only file you edit. Paste from Unity: Tools > ARP > Show Last Build Checksums.
// A value left at its placeholder SKIPS that comparison rather than failing it.
// The Meta App Secret belongs here and nowhere else - never in the client.

var ARP_EXPECTED_SIGNING_CERT_SHA256 = "PASTE_SIGNING_CERT_SHA256_HERE";
var ARP_EXPECTED_CONTENT_HASH = "PASTE_BUILD_CONTENT_HASH_HERE";

var ARP_META_APP_ID = "";
var ARP_META_APP_SECRET = "";

var ARP_NONCE_TTL_SECONDS = 300;

// How many checks may come back "could not determine" before the silence is itself
// the signal. A root hider does not make a device look clean so much as make it
// unreadable, and treating unreadable as clean is how hiders win.
var ARP_INCONCLUSIVE_THRESHOLD = 5;

var ARP_HEARTBEAT_MISS_THRESHOLD = 4;

var ARP_HEARTBEAT_GRACE_SECONDS = 600;

var ARP_KEY_NONCE = "ARP_Nonce";
var ARP_KEY_HEARTBEAT = "ARP_Heartbeat";
var ARP_KEY_LOGIN_IP = "ARP_LoginIP";
var ARP_KEY_FLAGS = "ARP_Flags";

var ARP_DEVICEBAN_PREFIX = "ARP_DeviceBan_";

function arpIsConfigured(value, placeholder) {
    return typeof value === "string" && value.length > 0 && value !== placeholder;
}

function arpCertConfigured() {
    return arpIsConfigured(ARP_EXPECTED_SIGNING_CERT_SHA256, "PASTE_SIGNING_CERT_SHA256_HERE");
}

function arpContentHashConfigured() {
    return arpIsConfigured(ARP_EXPECTED_CONTENT_HASH, "PASTE_BUILD_CONTENT_HASH_HERE");
}

function arpAttestationConfigured() {
    return ARP_META_APP_ID.length > 0 && ARP_META_APP_SECRET.length > 0;
}

function arpString(args, key, maxLength) {
    if (!args || typeof args[key] !== "string") return null;
    var value = args[key];
    if (typeof maxLength === "number" && value.length > maxLength) {
        return value.substring(0, maxLength);
    }
    return value;
}

function arpNumber(args, key, min, max) {
    if (!args || typeof args[key] !== "number" || isNaN(args[key])) return null;
    var value = args[key];
    if (typeof min === "number" && value < min) return null;
    if (typeof max === "number" && value > max) return null;
    return value;
}

function arpBool(args, key) {
    return !!(args && args[key] === true);
}

function arpStringArray(args, key, maxItems, maxItemLength) {
    var out = [];
    if (!args || !args[key] || Object.prototype.toString.call(args[key]) !== "[object Array]") {
        return out;
    }

    var source = args[key];
    var limit = Math.min(source.length, maxItems || 64);

    for (var i = 0; i < limit; i++) {
        if (typeof source[i] !== "string") continue;
        out.push(source[i].substring(0, maxItemLength || 128));
    }
    return out;
}

function arpReadInternal(key) {
    var response = server.GetUserInternalData({
        PlayFabId: currentPlayerId,
        Keys: [key]
    });

    if (!response || !response.Data || !response.Data[key]) return null;

    try {
        return JSON.parse(response.Data[key].Value);
    } catch (e) {
        return null;
    }
}

function arpWriteInternal(key, value) {
    var data = {};
    data[key] = JSON.stringify(value);
    server.UpdateUserInternalData({
        PlayFabId: currentPlayerId,
        Data: data
    });
}

function arpDeleteInternal(key) {
    server.UpdateUserInternalData({
        PlayFabId: currentPlayerId,
        KeysToRemove: [key]
    });
}

var ARP_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function arpBase64UrlDecode(input) {
    if (typeof input !== "string" || input.length === 0) return null;

    var normalized = input.replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4 !== 0) normalized += "=";

    var output = "";
    var buffer = 0;
    var bits = 0;

    for (var i = 0; i < normalized.length; i++) {
        var ch = normalized.charAt(i);
        if (ch === "=") break;

        var index = ARP_B64_ALPHABET.indexOf(ch);
        if (index === -1) continue;

        buffer = (buffer << 6) | index;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            output += String.fromCharCode((buffer >> bits) & 0xFF);
        }
    }

    return output;
}

function arpParseClaims(claimsBase64Url) {
    var decoded = arpBase64UrlDecode(claimsBase64Url);
    if (!decoded) return null;

    try {
        return JSON.parse(decoded);
    } catch (e) {
        log.error("ARP: attestation claims did not parse as JSON.");
        return null;
    }
}

function arpGenerateNonce() {
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var seed = currentPlayerId + "|" + (new Date()).getTime();
    var nonce = "";

    for (var i = 0; i < 32; i++) {
        nonce += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
    }

    for (var j = 0; j < seed.length && nonce.length < 64; j++) {
        nonce += alphabet.charAt(seed.charCodeAt(j) % alphabet.length);
    }

    return nonce.substring(0, 64);
}

function arpSecureEquals(a, b) {
    if (typeof a !== "string" || typeof b !== "string") return false;
    if (a.length !== b.length) return false;

    var diff = 0;
    for (var i = 0; i < a.length; i++) {
        diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    }
    return diff === 0;
}

function arpDeviceBanShardKey(fingerprint) {
    if (typeof fingerprint !== "string" || fingerprint.length < 2) return null;
    return ARP_DEVICEBAN_PREFIX + fingerprint.substring(0, 2);
}

function arpReadDeviceBanShard(fingerprint) {
    var key = arpDeviceBanShardKey(fingerprint);
    if (!key) return null;

    var response = server.GetTitleInternalData({ Keys: [key] });
    if (!response || !response.Data || !response.Data[key]) return {};

    try {
        return JSON.parse(response.Data[key]);
    } catch (e) {
        return {};
    }
}

function arpIsDeviceBanned(fingerprint) {
    var shard = arpReadDeviceBanShard(fingerprint);
    if (!shard) return false;

    var record = shard[fingerprint];
    if (!record) return false;

    if (record.expiresAt && record.expiresAt < (new Date()).getTime()) return false;
    return true;
}

function arpAddDeviceBan(fingerprint, reason, durationHours) {
    var key = arpDeviceBanShardKey(fingerprint);
    if (!key) return false;

    var shard = arpReadDeviceBanShard(fingerprint) || {};
    var now = (new Date()).getTime();

    shard[fingerprint] = {
        bannedAt: now,
        expiresAt: durationHours ? now + (durationHours * 3600 * 1000) : null,
        reason: reason,
        playFabId: currentPlayerId
    };

    server.SetTitleInternalData({ Key: key, Value: JSON.stringify(shard) });
    return true;
}
