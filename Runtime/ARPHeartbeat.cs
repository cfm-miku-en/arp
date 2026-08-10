// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace ARP
{
    public sealed class ARPHeartbeat
    {
        private readonly IARPTransport _transport;
        private readonly string _sessionId;

        private long _sequence;
        private bool _running;
        private bool _failed;

        public event Action OnHeartbeatFailed;

        public event Action<long> OnHeartbeatAcknowledged;

        public float IntervalSeconds { get; set; } = 45f;

        public int MaxRetries { get; set; } = 2;

        public float RetryBackoffSeconds { get; set; } = 2f;

        public List<string> LastKnownSignals { get; set; } = new List<string>();

        public string AttestationRef { get; set; }

        public bool HasFailed => _failed;
        public long Sequence => _sequence;
        public string SessionId => _sessionId;

        public ARPHeartbeat(IARPTransport transport, string sessionId)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _sessionId = string.IsNullOrEmpty(sessionId) ? Guid.NewGuid().ToString("N") : sessionId;
        }

        public IEnumerator Run()
        {
            _running = true;

            while (_running)
            {
                yield return new WaitForSecondsRealtime(IntervalSeconds);
                if (!_running) break;

                yield return SendBeat(false);
                if (_failed) break;
            }
        }

        public void Stop() => _running = false;

        public void SendSessionEnd()
        {
            _running = false;
            if (!_transport.IsReady) return;

            _sequence++;
            _transport.SendHeartbeat(BuildPayload(true), (_, __) => { });
        }

        private IEnumerator SendBeat(bool sessionEnd)
        {
            _sequence++;
            var payload = BuildPayload(sessionEnd);

            for (var attempt = 0; attempt <= MaxRetries; attempt++)
            {
                var done = false;
                var acknowledged = false;

                _transport.SendHeartbeat(payload, (ok, _) =>
                {
                    acknowledged = ok;
                    done = true;
                });

                while (!done) yield return null;

                if (acknowledged)
                {
                    OnHeartbeatAcknowledged?.Invoke(_sequence);
                    yield break;
                }

                if (attempt < MaxRetries)
                    yield return new WaitForSecondsRealtime(RetryBackoffSeconds * (attempt + 1));
            }

            _failed = true;
            _running = false;
            OnHeartbeatFailed?.Invoke();
        }

        private ARPHeartbeatPayload BuildPayload(bool sessionEnd) => new ARPHeartbeatPayload
        {
            SessionId = _sessionId,
            Sequence = _sequence,
            UnixTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            SessionEnd = sessionEnd,
            LastKnownSignals = new List<string>(LastKnownSignals ?? new List<string>()),
            AttestationRef = AttestationRef,
        };
    }
}
