// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

// The gate the game's own code calls before letting a player into public play.
//
// Nothing in ARP calls this. That is the entire point: it is meant to be invoked from
// somewhere in the game that a modder cannot delete without breaking the game, so that
// removing ARP is not enough to remove the check.
//
// Deliberately lenient. It answers "has this player been caught, or did ARP fail to
// report", not "is this player clean" - the real detection happens in
// arpVerifyIntegrity. A gate that guesses would lock out legitimate players on a slow
// startup.

handlers.arpSessionGate = function (args, context) {
    var login = arpReadInternal(ARP_KEY_LOGIN_IP);
    var now = (new Date()).getTime();

    // No login record means the PlayStream rule is not wired. Fail open and say so -
    // a misconfigured server must not lock out a whole playerbase.
    if (!login || !login.loginAt) {
        log.info("ARP: session gate has no login record. Wire arpRecordLoginContext to " +
                 "player_logged_in, or this gate can never do anything.");
        return { ok: true, reason: "no login record" };
    }

    if (!login.reported) {
        var elapsed = now - login.loginAt;

        // Still inside the grace window: the client may simply be starting up.
        if (elapsed <= (ARP_REPORT_GRACE_SECONDS * 1000)) {
            return { ok: true, reason: "waiting for first report" };
        }

        return { ok: false, reason: "integrity never reported" };
    }

    var flags = arpReadInternal(ARP_KEY_FLAGS);
    if (flags && flags.flags && flags.flags.length > 0) {
        var latest = flags.flags[flags.flags.length - 1];
        return { ok: false, reason: "flagged", signals: latest.signals || [] };
    }

    return { ok: true };
};
