// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using UnityEngine;

namespace ARP.Editor
{
    [Serializable]
    public sealed class ARPChecksumRecord
    {
        public string SigningCertSha256;
        public string BuildContentHash;
        public string PreviousSigningCertSha256;
        public string OutputPath;
        public string ProductName;
        public string BuiltAtUtc;
        public string CertificateNote;
        public List<string> ExpectedLibraries = new List<string>();
        public List<string> PreviousLibraries = new List<string>();

        public bool CertificateChanged =>
            !string.IsNullOrEmpty(PreviousSigningCertSha256) &&
            !string.IsNullOrEmpty(SigningCertSha256) &&
            PreviousSigningCertSha256 != SigningCertSha256;

        public bool LibrariesChanged
        {
            get
            {
                if (PreviousLibraries == null || PreviousLibraries.Count == 0) return false;
                if (ExpectedLibraries == null) return true;
                if (PreviousLibraries.Count != ExpectedLibraries.Count) return true;

                foreach (var name in PreviousLibraries)
                {
                    if (!ExpectedLibraries.Contains(name)) return true;
                }
                return false;
            }
        }

        public List<string> AddedLibraries()
        {
            var added = new List<string>();
            if (ExpectedLibraries == null) return added;

            foreach (var name in ExpectedLibraries)
            {
                if (PreviousLibraries == null || !PreviousLibraries.Contains(name)) added.Add(name);
            }
            return added;
        }

        public bool HasCertificate => !string.IsNullOrEmpty(SigningCertSha256);
        public bool HasContentHash => !string.IsNullOrEmpty(BuildContentHash);

        public static string Directory =>
            Path.Combine(Path.GetDirectoryName(Application.dataPath) ?? ".", "ARP");

        public static string JsonPath => Path.Combine(Directory, "last-build-checksums.json");
        public static string TextPath => Path.Combine(Directory, "last-build-checksums.txt");

        public static ARPChecksumRecord Load()
        {
            try
            {
                if (!File.Exists(JsonPath)) return null;
                return JsonUtility.FromJson<ARPChecksumRecord>(File.ReadAllText(JsonPath));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public void Save()
        {
            System.IO.Directory.CreateDirectory(Directory);
            File.WriteAllText(JsonPath, JsonUtility.ToJson(this, true));
            File.WriteAllText(TextPath, ToReadableText());
        }

        public string ToCloudScriptSnippet()
        {
            var cert = HasCertificate ? SigningCertSha256 : "PASTE_SIGNING_CERT_SHA256_HERE";
            var content = HasContentHash ? BuildContentHash : "PASTE_BUILD_CONTENT_HASH_HERE";

            return
                "var ARP_EXPECTED_SIGNING_CERT_SHA256 = \"" + cert + "\";\n" +
                "var ARP_EXPECTED_CONTENT_HASH = \"" + content + "\";";
        }

        public string ToReadableText()
        {
            return
                "ARP build checksums\n" +
                "===================\n\n" +
                "Product   : " + ProductName + "\n" +
                "Build     : " + OutputPath + "\n" +
                "Built at  : " + BuiltAtUtc + " UTC\n\n" +
                "Signing certificate SHA-256 (set once, does not change between builds)\n" +
                "  " + (HasCertificate ? SigningCertSha256 : "<unavailable - " + CertificateNote + ">") + "\n\n" +
                "Build content hash (changes every build - update before every release)\n" +
                "  " + (HasContentHash ? BuildContentHash : "<unavailable>") + "\n\n" +
                "Paste into CloudScript/arpConfig.js:\n\n" +
                ToCloudScriptSnippet() + "\n";
        }
    }
}
