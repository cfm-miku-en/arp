// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace ARP
{
    public static class ARPInstrumentationDetector
    {
        // Frida and friends. Two of these are generic - anything attaching a debugger
        // or injecting code trips them regardless of which tool it is - and the third
        // is deliberately Frida-specific, because a named tool on a known port is a
        // far more legible finding than "there is executable memory somewhere".

        private const int TracerAttached = 0x01;
        private const int AnonymousExecMemory = 0x02;
        private const int FridaPortOpen = 0x04;

        [DllImport("arpnative", EntryPoint = "arp_instrumentation_scan")]
        private static extern int NativeInstrumentationScan(int probePorts);

        /// Opens sockets to loopback, so the caller decides. Nothing on a stock Quest
        /// binds Frida's port, which makes a hit close to conclusive there.
        public static bool ProbeFridaPorts { get; set; }

        public static void Scan(ARPScanResult result)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));

            if (!ARPRootDetector.NativeAvailable)
            {
                result.Inconclusive(ARPCheckIds.DeviceDebuggerAttached);
                result.Inconclusive(ARPCheckIds.DeviceAnonymousExecMemory);
                return;
            }

            int flags;

            try
            {
                flags = NativeInstrumentationScan(ProbeFridaPorts ? 1 : 0);
            }
            catch (Exception)
            {
                result.Inconclusive(ARPCheckIds.DeviceDebuggerAttached);
                result.Inconclusive(ARPCheckIds.DeviceAnonymousExecMemory);
                return;
            }

            if ((flags & TracerAttached) != 0) result.Trigger(ARPCheckIds.DeviceDebuggerAttached);
            if ((flags & AnonymousExecMemory) != 0) result.Trigger(ARPCheckIds.DeviceAnonymousExecMemory);
            if ((flags & FridaPortOpen) != 0) result.Trigger(ARPCheckIds.DeviceFridaPortOpen);
        }
    }
}
