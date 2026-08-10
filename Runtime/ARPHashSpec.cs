// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ARP
{
    public struct ARPZipEntry
    {
        public string Name;
        public long UncompressedSize;
        public long Crc32;

        public ARPZipEntry(string name, long uncompressedSize, long crc32)
        {
            Name = name;
            UncompressedSize = uncompressedSize;
            Crc32 = crc32;
        }
    }

    public static class ARPHashSpec
    {
        public const int FormatVersion = 2;

        public static bool IsHashedEntry(string entryName)
        {
            if (string.IsNullOrEmpty(entryName)) return false;

            if (entryName.StartsWith("lib/", StringComparison.Ordinal)) return true;
            if (entryName.Equals("AndroidManifest.xml", StringComparison.Ordinal)) return true;

            // The whole Unity data directory, not just code. Most on-device Quest modding
            // goes through UABEA, which edits resources.assets, sharedassets*, level* and
            // data.unity3d - none of which are code, all of which change the game. A
            // filter tuned only for mod loaders calls that clean.
            //
            // Cheap despite the breadth: this directory is a few dozen entries even on a
            // large title, and only names, sizes and stored CRCs are read.
            if (entryName.StartsWith("assets/bin/Data/", StringComparison.Ordinal)) return true;

            if (entryName.StartsWith("classes", StringComparison.Ordinal) &&
                entryName.EndsWith(".dex", StringComparison.Ordinal) &&
                entryName.IndexOf('/') < 0)
            {
                return true;
            }

            return false;
        }

        public static string Fold(IEnumerable<ARPZipEntry> entries)
        {
            if (entries == null) throw new ArgumentNullException(nameof(entries));

            var filtered = new List<ARPZipEntry>();
            foreach (var e in entries)
            {
                if (IsHashedEntry(e.Name)) filtered.Add(e);
            }

            filtered.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));

            var sb = new StringBuilder();
            sb.Append("arp-content-hash/v").Append(FormatVersion).Append('\n');

            foreach (var e in filtered)
            {
                sb.Append(e.Name).Append('\0')
                  .Append(e.UncompressedSize.ToString(CultureInfo.InvariantCulture)).Append('\0')
                  .Append(e.Crc32.ToString(CultureInfo.InvariantCulture)).Append('\n');
            }

            using (var sha = SHA256.Create())
            {
                return ToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString())));
            }
        }

        public static string Sha256Hex(byte[] data)
        {
            if (data == null) return null;
            using (var sha = SHA256.Create())
            {
                return ToHex(sha.ComputeHash(data));
            }
        }

        public static string ToHex(byte[] bytes)
        {
            if (bytes == null) return null;
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        public static bool ConstantTimeEquals(string a, string b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;

            var diff = 0;
            for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
