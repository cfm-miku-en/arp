// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections;
using System.Runtime.InteropServices;

namespace ARP
{
    public static class ARPMemoryIntegrity
    {
        // Everything else in ARP looks at the APK on disk. Nothing did until now looked
        // at what is actually executing, and with root you can patch a running process
        // without touching the file - leaving the signing certificate, the content hash
        // and Meta's app_integrity_state all perfectly valid while the game runs
        // modified. This closes that.

        public const string DefaultLibrary = "libil2cpp.so";

        private const long DeepChunkBytes = 4 * 1024 * 1024;

        private const string NativeLib = "arpnative";

        [DllImport(NativeLib, EntryPoint = "arp_code_dirty_kb")]
        private static extern long NativeCodeDirtyKb([MarshalAs(UnmanagedType.LPStr)] string soname);

        [DllImport(NativeLib, EntryPoint = "arp_code_exec_size")]
        private static extern long NativeCodeExecSize([MarshalAs(UnmanagedType.LPStr)] string soname);

        [DllImport(NativeLib, EntryPoint = "arp_code_compare")]
        private static extern int NativeCodeCompare(
            [MarshalAs(UnmanagedType.LPStr)] string soname, long start, long length);

        public static string Library { get; set; } = DefaultLibrary;

        public static long LastDirtyKb { get; private set; } = -1;

        public static bool Available => ARPRootDetector.NativeAvailable;

        /// Cheap. Safe to call every few seconds.
        public static bool QuickCheck(ARPScanResult result)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));

            if (!Available)
            {
                result.Inconclusive(ARPCheckIds.AppCodePagesDirty);
                return false;
            }

            try
            {
                LastDirtyKb = NativeCodeDirtyKb(Library);
            }
            catch (Exception)
            {
                result.Inconclusive(ARPCheckIds.AppCodePagesDirty);
                return false;
            }

            if (LastDirtyKb < 0)
            {
                result.Inconclusive(ARPCheckIds.AppCodePagesDirty);
                return false;
            }

            return LastDirtyKb > 0;
        }

        /// Expensive, chunked across frames. Only worth running when QuickCheck said yes.
        public static IEnumerator DeepVerify(ARPScanResult result)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));

            if (!Available)
            {
                result.Inconclusive(ARPCheckIds.AppCodePatched);
                yield break;
            }

            long size = -1;
            var probeFailed = false;

            try { size = NativeCodeExecSize(Library); }
            catch (Exception) { probeFailed = true; }

            if (probeFailed || size <= 0)
            {
                result.Inconclusive(ARPCheckIds.AppCodePatched);
                yield break;
            }

            long offset = 0;
            var inconclusive = false;

            while (offset < size)
            {
                var length = Math.Min(DeepChunkBytes, size - offset);
                int verdict;

                try
                {
                    verdict = NativeCodeCompare(Library, offset, length);
                }
                catch (Exception)
                {
                    inconclusive = true;
                    break;
                }

                if (verdict == 1)
                {
                    result.Trigger(ARPCheckIds.AppCodePatched);
                    yield break;
                }

                if (verdict < 0)
                {
                    inconclusive = true;
                    break;
                }

                offset += length;
                yield return null;
            }

            // Dirty pages we could not explain are still worth reporting: the
            // comparison failing to complete is not the same as the code being clean.
            if (inconclusive) result.Inconclusive(ARPCheckIds.AppCodePatched);
            else if (LastDirtyKb > 0) result.Trigger(ARPCheckIds.AppCodePagesDirty);
        }
    }
}
