// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using ARP;

namespace ARP.Editor
{
    public static class ARPZipCentralDirectory
    {
        private const uint EocdSignature = 0x06054b50;
        private const uint Eocd64LocatorSignature = 0x07064b50;
        private const uint Eocd64Signature = 0x06064b50;
        private const uint CentralFileSignature = 0x02014b50;
        private const int MaxCommentLength = 0xFFFF;

        public static List<ARPZipEntry> Read(string archivePath)
        {
            if (string.IsNullOrEmpty(archivePath)) throw new ArgumentNullException(nameof(archivePath));
            if (!File.Exists(archivePath)) throw new FileNotFoundException("Archive not found.", archivePath);

            using (var stream = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var reader = new BinaryReader(stream))
            {
                var eocdOffset = FindEocd(stream, reader);
                if (eocdOffset < 0) throw new InvalidDataException("No end-of-central-directory record; not a zip.");

                stream.Seek(eocdOffset + 10, SeekOrigin.Begin);
                long entryCount = reader.ReadUInt16();
                stream.Seek(eocdOffset + 16, SeekOrigin.Begin);
                long directoryOffset = reader.ReadUInt32();

                if (directoryOffset == 0xFFFFFFFF || entryCount == 0xFFFF)
                {
                    ReadZip64(stream, reader, eocdOffset, ref entryCount, ref directoryOffset);
                }

                return ReadEntries(stream, reader, directoryOffset, entryCount);
            }
        }

        private static long FindEocd(Stream stream, BinaryReader reader)
        {
            var searchLength = (int)Math.Min(stream.Length, MaxCommentLength + 22);
            var start = stream.Length - searchLength;

            stream.Seek(start, SeekOrigin.Begin);
            var buffer = reader.ReadBytes(searchLength);

            for (var i = buffer.Length - 22; i >= 0; i--)
            {
                if (buffer[i] != 0x50 || buffer[i + 1] != 0x4b ||
                    buffer[i + 2] != 0x05 || buffer[i + 3] != 0x06) continue;

                return start + i;
            }

            return -1;
        }

        private static void ReadZip64(
            Stream stream, BinaryReader reader, long eocdOffset,
            ref long entryCount, ref long directoryOffset)
        {
            var locatorOffset = eocdOffset - 20;
            if (locatorOffset < 0) return;

            stream.Seek(locatorOffset, SeekOrigin.Begin);
            if (reader.ReadUInt32() != Eocd64LocatorSignature) return;

            stream.Seek(locatorOffset + 8, SeekOrigin.Begin);
            var eocd64Offset = (long)reader.ReadUInt64();
            if (eocd64Offset < 0 || eocd64Offset >= stream.Length) return;

            stream.Seek(eocd64Offset, SeekOrigin.Begin);
            if (reader.ReadUInt32() != Eocd64Signature) return;

            stream.Seek(eocd64Offset + 32, SeekOrigin.Begin);
            entryCount = (long)reader.ReadUInt64();
            stream.Seek(eocd64Offset + 48, SeekOrigin.Begin);
            directoryOffset = (long)reader.ReadUInt64();
        }

        private static List<ARPZipEntry> ReadEntries(
            Stream stream, BinaryReader reader, long directoryOffset, long entryCount)
        {
            var entries = new List<ARPZipEntry>();
            stream.Seek(directoryOffset, SeekOrigin.Begin);

            for (long i = 0; i < entryCount; i++)
            {
                if (stream.Position + 46 > stream.Length) break;
                if (reader.ReadUInt32() != CentralFileSignature) break;

                var recordStart = stream.Position - 4;

                stream.Seek(recordStart + 16, SeekOrigin.Begin);
                long crc = reader.ReadUInt32();
                reader.ReadUInt32();
                long uncompressedSize = reader.ReadUInt32();

                stream.Seek(recordStart + 28, SeekOrigin.Begin);
                int nameLength = reader.ReadUInt16();
                int extraLength = reader.ReadUInt16();
                int commentLength = reader.ReadUInt16();

                stream.Seek(recordStart + 46, SeekOrigin.Begin);
                var nameBytes = reader.ReadBytes(nameLength);
                var name = System.Text.Encoding.UTF8.GetString(nameBytes);

                var extra = extraLength > 0 ? reader.ReadBytes(extraLength) : Array.Empty<byte>();
                if (uncompressedSize == 0xFFFFFFFF)
                {
                    uncompressedSize = ReadZip64Size(extra) ?? uncompressedSize;
                }

                if (commentLength > 0) stream.Seek(commentLength, SeekOrigin.Current);

                if (ARPHashSpec.IsHashedEntry(name))
                {
                    entries.Add(new ARPZipEntry(name, uncompressedSize, crc));
                }
            }

            return entries;
        }

        private static long? ReadZip64Size(byte[] extra)
        {
            var offset = 0;
            while (offset + 4 <= extra.Length)
            {
                var headerId = BitConverter.ToUInt16(extra, offset);
                var dataSize = BitConverter.ToUInt16(extra, offset + 2);
                offset += 4;

                if (headerId == 0x0001 && offset + 8 <= extra.Length)
                {
                    return (long)BitConverter.ToUInt64(extra, offset);
                }

                offset += dataSize;
            }

            return null;
        }
    }
}
