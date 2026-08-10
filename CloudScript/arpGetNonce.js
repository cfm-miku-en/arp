// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

handlers.arpGetNonce = function (args, context) {
    var nonce = arpGenerateNonce();
    var now = (new Date()).getTime();

    arpWriteInternal(ARP_KEY_NONCE, {
        nonce: nonce,
        issuedAt: now,
        expiresAt: now + (ARP_NONCE_TTL_SECONDS * 1000)
    });

    return {
        nonce: nonce,
        ttlSeconds: ARP_NONCE_TTL_SECONDS
    };
};
