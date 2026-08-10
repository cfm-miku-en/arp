// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

// NOT client-callable. Wire it in Game Manager as a PlayStream action:
//   Automation > Rules > New Rule > player_logged_in > Execute CloudScript
// Without that rule there is no IP on record and IP bans are skipped.

handlers.arpRecordLoginContext = function (args, context) {
    if (!context || !context.playStreamEvent) {
        log.error("ARP: arpRecordLoginContext ran without a PlayStream event. It is a " +
                  "PlayStream action, not a client-callable function.");
        return { recorded: false };
    }

    var evt = context.playStreamEvent;

    var ip = evt.IPV4Address || evt.IPv4Address || evt.IPAddress || null;

    if (!ip || typeof ip !== "string") {
        log.info("ARP: no IP address on the login event; IP bans will be unavailable " +
                 "for this player.");
        return { recorded: false };
    }

    arpWriteInternal(ARP_KEY_LOGIN_IP, {
        ip: ip,
        recordedAt: (new Date()).getTime()
    });

    return { recorded: true };
};
