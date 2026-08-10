// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

handlers.arpHeartbeat = function (args, context) {
    var sessionId = arpString(args, "sessionId", 64);
    var sequence = arpNumber(args, "sequence", 0, 1e12);
    var unixTimeMs = arpNumber(args, "unixTimeMs", 0, 1e15);
    var sessionEnd = arpBool(args, "sessionEnd");
    var signals = arpStringArray(args, "lastKnownSignals", 64, 128);

    if (!sessionId || sequence === null) {
        return { ack: false, error: "malformed heartbeat" };
    }

    var now = (new Date()).getTime();
    var state = arpReadInternal(ARP_KEY_HEARTBEAT);
    var verdict = { ack: true };

    if (!state || state.sessionId !== sessionId) {
        if (state && !state.closedCleanly) {
            var gap = now - (state.lastBeatAt || now);
            if (gap > (ARP_HEARTBEAT_GRACE_SECONDS * 1000)) {
                arpFlagAbandonedSession(state, gap);
            }
        }

        state = {
            sessionId: sessionId,
            firstBeatAt: now,
            lastBeatAt: now,
            lastSequence: sequence,
            missedIntervals: 0,
            closedCleanly: false,
            signals: signals
        };

        arpWriteInternal(ARP_KEY_HEARTBEAT, state);
        return verdict;
    }

    if (sequence <= state.lastSequence) {
        arpRecordFlag([ARPCheckIdsBeatSequenceRegression()],
                      "heartbeat sequence did not advance: " + state.lastSequence + " -> " + sequence);
        verdict.ack = true;
    }

    var elapsedMs = now - (state.lastBeatAt || now);
    var expectedGapMs = 60 * 1000;
    var missed = Math.max(0, Math.floor(elapsedMs / expectedGapMs) - 1);

    state.missedIntervals = missed > 0 ? state.missedIntervals + missed : 0;
    state.lastBeatAt = now;
    state.lastSequence = sequence;
    state.signals = signals;

    if (sessionEnd) {
        state.closedCleanly = true;
        arpWriteInternal(ARP_KEY_HEARTBEAT, state);
        return verdict;
    }

    if (state.missedIntervals >= ARP_HEARTBEAT_MISS_THRESHOLD) {
        arpRecordFlag([ARPCheckIdsBeatMissedThreshold()],
                      "missed " + state.missedIntervals + " consecutive heartbeat intervals");
        state.missedIntervals = 0;
    }

    arpWriteInternal(ARP_KEY_HEARTBEAT, state);
    return verdict;
};

function arpFlagAbandonedSession(state, gapMs) {
    arpRecordFlag(
        [ARPCheckIdsBeatNoSessionEnd()],
        "previous session " + state.sessionId + " stopped beating " +
        Math.round(gapMs / 1000) + "s before the next session began, with no arpSessionEnd"
    );
}

function ARPCheckIdsBeatMissedThreshold() { return "beat:missed_threshold"; }
function ARPCheckIdsBeatSequenceRegression() { return "beat:sequence_regression"; }
function ARPCheckIdsBeatNoSessionEnd() { return "beat:no_session_end"; }
