// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

// Tier 3. Records one player's observation of another sending a value a stock
// client cannot produce.
//
// This is the only ARP function where the reported player is not the caller, and
// it is therefore the only one that must never ban. A witness report is an
// accusation from an untrusted party: the witness is running the same forgeable
// client as everyone else, and a modder who wants an innocent player banned would
// reach for exactly this function. Corroboration across distinct witnesses is what
// makes the signal worth anything, and even corroborated it only flags.
//
// Requires Photon to be authenticated through PlayFab, so the subject id comes from
// Photon's UserId rather than a client-chosen string. Without that there is no
// trustworthy subject identity and this whole path is a framing vector.

// Distinct witnesses required before a subject is flagged. Below 3 a single
// modified client plus one alt account is enough to manufacture a flag.
var ARP_WITNESS_THRESHOLD = 3;

// How long a report stays countable. Long enough to span a session, short enough
// that reports from unrelated sessions weeks apart do not accumulate into a flag.
var ARP_WITNESS_WINDOW_SECONDS = 3600;

// Reports one player may file per window. A player sitting far above this is
// either being griefed by a room full of cheaters or is fabricating accusations,
// and both are worth seeing.
var ARP_WITNESS_MAX_FILED = 30;

var ARP_KEY_WITNESS = "ARP_Witness";
var ARP_KEY_WITNESS_FILED = "ARP_WitnessFiled";

// Deliberately NOT ARP_KEY_FLAGS. arpSessionGate reads that key, so writing witness
// corroboration there would hand three colluding accounts the power to keep a
// stranger out of matchmaking. Witness signals are the least trustworthy input ARP
// has and must not reach the store that carries enforcement weight.
var ARP_KEY_WITNESS_FLAGS = "ARP_WitnessFlags";

var ARP_WITNESS_CHECK_IDS = [
    "net:name_illegal_characters",
    "net:name_change_flood",
    "net:name_impersonates_reserved",
    "net:rpc_unauthorized_source",
    "net:rpc_flood",
    "net:cosmetic_forced_on_peer",
    "net:property_out_of_range"
];

handlers.arpWitnessReport = function (args, context) {
    var checkId = arpString(args, "checkId", 64);
    var subject = arpString(args, "subjectPlayFabId", 64);
    var sessionName = arpString(args, "sessionName", 64);

    // Every rejection returns the same shape and says nothing about the subject's
    // standing. A client that can probe "did that land" can binary-search the
    // threshold and tune its accusations to sit just under it.
    var ok = { accepted: true };

    if (!arpContains(ARP_WITNESS_CHECK_IDS, checkId)) return ok;
    if (!arpLooksLikePlayFabId(subject)) return ok;
    if (!sessionName) return ok;

    // Not a witness report. Allowing it would let a client write into the flag
    // store directly, bypassing every check that produces a real signal.
    if (subject === currentPlayerId) return ok;

    if (!arpWitnessBudgetAvailable()) return ok;

    var now = (new Date()).getTime();
    var cutoff = now - (ARP_WITNESS_WINDOW_SECONDS * 1000);

    var record = arpReadInternalFor(subject, ARP_KEY_WITNESS) || { reports: [] };
    if (!record.reports) record.reports = [];

    var kept = [];
    var alreadyFiled = false;

    for (var i = 0; i < record.reports.length; i++) {
        var r = record.reports[i];
        if (!r || r.at < cutoff) continue;

        if (r.witness === currentPlayerId && r.checkId === checkId && r.session === sessionName) {
            alreadyFiled = true;
        }

        kept.push(r);
    }

    if (alreadyFiled) {
        record.reports = kept;
        arpWriteInternalFor(subject, ARP_KEY_WITNESS, record);
        return ok;
    }

    kept.push({
        at: now,
        witness: currentPlayerId,
        checkId: checkId,
        session: sessionName
    });

    // One report per witness per check per session is all that counts, so this
    // only grows with genuinely distinct observations.
    if (kept.length > 200) kept = kept.slice(kept.length - 200);

    record.reports = kept;
    arpWriteInternalFor(subject, ARP_KEY_WITNESS, record);

    arpChargeWitnessBudget();

    var witnesses = arpDistinctWitnesses(kept, checkId, cutoff);
    if (witnesses.length >= ARP_WITNESS_THRESHOLD) {
        arpFlagWitnessedSubject(subject, checkId, witnesses, sessionName);
    }

    return ok;
};

// Distinct accounts, not distinct reports. Counting reports would allow one witness
// in one session to reach the threshold alone by reconnecting.
function arpDistinctWitnesses(reports, checkId, cutoff) {
    var seen = [];

    for (var i = 0; i < reports.length; i++) {
        var r = reports[i];
        if (!r || r.checkId !== checkId || r.at < cutoff) continue;
        if (!arpContains(seen, r.witness)) seen.push(r.witness);
    }

    return seen;
}

function arpFlagWitnessedSubject(subject, checkId, witnesses, sessionName) {
    var note = witnesses.length + " independent witnesses reported " + checkId +
               " in session " + sessionName;

    var existing = arpReadInternalFor(subject, ARP_KEY_WITNESS_FLAGS) || { flags: [] };
    if (!existing.flags) existing.flags = [];

    existing.flags.push({
        at: (new Date()).getTime(),
        signals: [checkId],
        note: note,
        revision: script.revision
    });

    if (existing.flags.length > 20) {
        existing.flags = existing.flags.slice(existing.flags.length - 20);
    }

    arpWriteInternalFor(subject, ARP_KEY_WITNESS_FLAGS, existing);

    try {
        server.WritePlayerEvent({
            PlayFabId: subject,
            EventName: "arp_witness_corroborated",
            Body: {
                signals: [checkId],
                note: note,
                witnesses: witnesses,
                session: sessionName,
                revision: script.revision
            }
        });
    } catch (e) {
        log.error("ARP: could not write arp_witness_corroborated: " + e);
    }
}

function arpWitnessBudgetAvailable() {
    var now = (new Date()).getTime();
    var filed = arpReadInternal(ARP_KEY_WITNESS_FILED);

    if (!filed || (now - (filed.windowStart || 0)) > (ARP_WITNESS_WINDOW_SECONDS * 1000)) {
        return true;
    }

    return (filed.count || 0) < ARP_WITNESS_MAX_FILED;
}

function arpChargeWitnessBudget() {
    var now = (new Date()).getTime();
    var filed = arpReadInternal(ARP_KEY_WITNESS_FILED);

    if (!filed || (now - (filed.windowStart || 0)) > (ARP_WITNESS_WINDOW_SECONDS * 1000)) {
        filed = { windowStart: now, count: 0 };
    }

    filed.count = (filed.count || 0) + 1;
    arpWriteInternal(ARP_KEY_WITNESS_FILED, filed);
}

function arpLooksLikePlayFabId(value) {
    if (typeof value !== "string") return false;
    if (value.length < 8 || value.length > 32) return false;
    return /^[0-9A-Fa-f]+$/.test(value);
}

// arpReadInternal and arpWriteInternal in arpConfig.js are hardcoded to
// currentPlayerId, which is the witness here, not the player being reported.
function arpReadInternalFor(playFabId, key) {
    var response = server.GetUserInternalData({
        PlayFabId: playFabId,
        Keys: [key]
    });

    if (!response || !response.Data || !response.Data[key]) return null;

    try {
        return JSON.parse(response.Data[key].Value);
    } catch (e) {
        return null;
    }
}

function arpWriteInternalFor(playFabId, key, value) {
    var data = {};
    data[key] = JSON.stringify(value);
    server.UpdateUserInternalData({
        PlayFabId: playFabId,
        Data: data
    });
}
