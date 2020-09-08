// SPDX-License-Identifier: BSD-3-Clause
// Copyright © 2020 Xpl0itR

using LibHac;
using LibHac.Common;
using LibHac.Crypto;
using LibHac.Fs.Fsa;
using LibHac.Fs;
using LibHac.FsSystem;
using LibHac.FsSystem.NcaUtils;
using LibHac.Spl;
using Mono.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using ZRA.NET.Streaming;

namespace ZcaTool
{
    public static class Program
    {
        public static Keyset KeySet;
        public static string OutDirectoryPath;
        public static string TempPath;
        public static string ProdKeyPath;
        public static string TitleKeyPath;
        public static bool   ShowHelp;
        public static bool   IsDev;
        public static byte   CompressionLevel = 9;
        public static uint   FrameSize        = 131072;

        public static void Main(string[] cmdArgs)
        {
            OptionSet optionSet = new OptionSet
            {
                { "h|help",       "Show this message and exit",                                          _ => ShowHelp         = true          },
                { "v|dev=",       "Load production keys as development keys\n(optional)",                _ => IsDev            = true          },
                { "p|prodkeys=",  "Path to a file containing switch production keys.\n(optional)",       s => ProdKeyPath      = s             },
                { "k|titlekeys=", "Path to a file containing switch title keys.\n(optional)",            s => TitleKeyPath     = s             },
                { "l|level=",     "zStd compression level used to compress the file.",                   s => CompressionLevel = byte.Parse(s) },
                { "f|framesize=", "Size of a frame used to split a file.",                               s => FrameSize        = uint.Parse(s) },
                { "t|temp=",      "The directory to use for storing temp files.\n(Defaults to OS temp)", s => TempPath         = s             },
                { "o|output=",    "The directory to output the compressed file.\n(Defaults to the same dir as input file)", s => OutDirectoryPath = s }
            };

            List<string> args = optionSet.Parse(cmdArgs);

            if (ShowHelp)
            {
                Console.WriteLine("ZcaTool - Copyright (c) 2020 Xpl0itR");
                Console.WriteLine("Usage: ZcaTool(.exe) [options] <path>");
                Console.WriteLine("Options:");
                optionSet.WriteOptionDescriptions(Console.Out);
                return;
            }

            if (args.Count < 1 || !File.Exists(args[0]))
                throw new Exception("Input file does not exist!");

            if (CompressionLevel < 1 || CompressionLevel > 22)
                throw new Exception("You must enter a valid compression level!");

            KeySet = LoadKeySet();
            OutDirectoryPath ??= Path.GetDirectoryName(args[0]);

            using (IStorage inStorage = new LocalStorage(args[0], FileAccess.Read))
            {
                string fileName = Path.GetFileNameWithoutExtension(args[0]);
                inStorage.GetSize(out long inSize);
                IStorage outStorage = null;

                Stopwatch stopwatch = Stopwatch.StartNew();
                switch (Path.GetExtension(args[0]).ToLower())
                {
                    case ".nca":
                        Console.WriteLine($"Compressing {Path.GetFileName(args[0])} [{PrettyFileSize(inSize)}] with ZStandard compression level: {CompressionLevel} and frame size: {FrameSize}");
                        fileName += ".zca";
                        break;
                    case ".zca":
                        Console.WriteLine($"Decompressing {Path.GetFileName(args[0])} [{PrettyFileSize(inSize)}]");
                        outStorage = new Nca(KeySet, new ZraDecompressionStream(inStorage.AsStream()).AsStorage()).OpenEncryptedNca();
                        fileName += ".nca";
                        break;
                    case ".nsp":
                        Console.WriteLine($"Compressing {Path.GetFileName(args[0])} [{PrettyFileSize(inSize)}] with ZStandard compression level: {CompressionLevel} and frame size: {FrameSize}");
                        outStorage = ProcessPartitionFileSystem(new PartitionFileSystem(inStorage), PartitionFileSystemType.Standard, true);
                        fileName += ".zsp";
                        break;
                    case ".zsp":
                        Console.WriteLine($"Decompressing {Path.GetFileName(args[0])} [{PrettyFileSize(inSize)}]");
                        outStorage = ProcessPartitionFileSystem(new PartitionFileSystem(inStorage), PartitionFileSystemType.Standard, false);
                        fileName += ".nsp";
                        break;
                    case ".xci":
                        Console.WriteLine($"Compressing {Path.GetFileName(args[0])} [{PrettyFileSize(inSize)}] with ZStandard compression level: {CompressionLevel} and frame size: {FrameSize}");
                        outStorage = ProcessXci(inStorage, true);
                        fileName += ".zci";
                        break;
                    case ".zci":
                        Console.WriteLine($"Decompressing {Path.GetFileName(args[0])} [{PrettyFileSize(inSize)}]");
                        outStorage = ProcessXci(inStorage, false);
                        fileName += ".xci";
                        break;
                    default:
                        throw new Exception("Input file was not of a valid format!");
                }

                long outSize;
                string filePath = Path.Join(OutDirectoryPath, fileName);
                using (FileStream outStream = File.OpenWrite(filePath))
                {
                    if (Path.GetExtension(args[0]).ToLower() == ".nca")
                    {
                        (IStorage processedNca, byte[] metaBuffer) = ProcessNca(inStorage);
                        processedNca.GetSize(out long ncaLength);

                        using (ZraCompressionStream compressionStream = new ZraCompressionStream(outStream, (ulong) ncaLength, CompressionLevel, FrameSize, metaBuffer, true))
                        {
                            processedNca.CopyToStream(compressionStream, (int)FrameSize);
                        }
                    }
                    else
                    {
                        outStorage.CopyToStream(outStream);
                        outStorage?.Dispose();
                    }

                    outSize = outStream.Length;
                }
                stopwatch.Stop();

                Console.WriteLine($"Out file: {filePath} [{PrettyFileSize(outSize)}]");
                Console.WriteLine($"Time taken: {decimal.Round((decimal)stopwatch.ElapsedMilliseconds / 1000, 2)}s ({stopwatch.ElapsedMilliseconds}ms)");
                Console.WriteLine($"Size Reduction: {decimal.Truncate(100 - (decimal)outSize / inSize * 100)}%");
            }

            Console.WriteLine("Cleaning temp files...");
            ZraCompressionStorageHack.CleanTempFiles();
            Console.WriteLine("Done!");
        }

        public static IStorage ProcessXci(IStorage xciStorage, bool compress)
        {
            Xci xci = new Xci(KeySet, xciStorage);
            IStorage xciHeaderStorage = new MemoryStorage(new byte[0x200]);
            xciStorage.CopyTo(xciHeaderStorage);

            XciPartition securePartition          = xci.OpenPartition(XciPartitionType.Secure);
            IStorage     processedSecurePartition = ProcessPartitionFileSystem(securePartition, PartitionFileSystemType.Hashed, compress);

            PartitionFileSystemBuilder rootPartitionBuilder = new PartitionFileSystemBuilder();
            rootPartitionBuilder.AddFile("secure", processedSecurePartition.AsFile(OpenMode.Read));
            IStorage rootPartitionStorage = rootPartitionBuilder.Build(PartitionFileSystemType.Hashed);

            using (BinaryReader reader = new BinaryReader(rootPartitionStorage.AsStream()))
            {
                PartitionFileSystemHeader pfsHeader = new PartitionFileSystemHeader(reader);
                Span<byte> pfsHeaderBytes = stackalloc byte[pfsHeader.HeaderSize];
                Span<byte> pfsHeaderHash  = stackalloc byte[0x20];
                rootPartitionStorage.Read(0, pfsHeaderBytes);
                Sha256.GenerateSha256Hash(pfsHeaderBytes, pfsHeaderHash);

                xciHeaderStorage.Write(0x138, BitConverter.GetBytes(pfsHeader.HeaderSize));
                xciHeaderStorage.Write(0x140, pfsHeaderHash);
            }

            return new ConcatenationStorage(new[]
            {
                xciHeaderStorage,
                new MemoryStorage(new byte[xci.Header.RootPartitionOffset - 0x200]), // Cert and padding
                rootPartitionStorage
            }, false);
        }

        public static IStorage ProcessPartitionFileSystem(PartitionFileSystem pfs, PartitionFileSystemType pfsType, bool compress)
        {
            PartitionFileSystemBuilder pfsBuilder = new PartitionFileSystemBuilder();

            foreach (DirectoryEntryEx ticketEntry in pfs.EnumerateEntries("/", "*.tik"))
            {
                Result result = pfs.OpenFile(out IFile ticketFile, ticketEntry.FullPath.ToU8Span(), OpenMode.Read);

                if (result.IsSuccess())
                {
                    Ticket ticket = new Ticket(ticketFile.AsStream());

                    KeySet.ExternalKeySet.Add(new RightsId(ticket.RightsId), new AccessKey(ticket.GetTitleKey(KeySet)));
                }
            }

            foreach (DirectoryEntryEx fileEntry in pfs.EnumerateEntries())
            {
                pfs.OpenFile(out IFile file, fileEntry.FullPath.ToU8Span(), OpenMode.Read).ThrowIfFailure();

                if (compress && Path.GetExtension(fileEntry.Name).ToLower() == ".nca")
                {
                    (IStorage processedNca, byte[] metaBuffer) = ProcessNca(file.AsStorage());
                    IFile zcaFile = new ZraCompressionStorageHack(processedNca, CompressionLevel, FrameSize, metaBuffer, TempPath).AsFile(OpenMode.Read);

                    pfsBuilder.AddFile($"{Path.GetFileNameWithoutExtension(fileEntry.Name)}.zca", zcaFile);
                }
                else if (!compress && Path.GetExtension(fileEntry.Name).ToLower() == ".zca")
                {
                    IStorage ncaStorage = new ZraDecompressionStream(file.AsStream()).AsStorage();
                    IFile ncaFile = new Nca(KeySet, ncaStorage).OpenEncryptedNca().AsFile(OpenMode.Read);

                    pfsBuilder.AddFile($"{Path.GetFileNameWithoutExtension(fileEntry.Name)}.nca", ncaFile);
                }
                else
                {
                    pfsBuilder.AddFile(fileEntry.Name, file);
                }
            }

            return pfsBuilder.Build(pfsType);
        }

        public static (IStorage processedNca, byte[] metaBuffer) ProcessNca(IStorage ncaStorage)
        {
            Nca nca = new Nca(KeySet, ncaStorage);

            MemoryStream memoryStream = new MemoryStream();
            memoryStream.Write(stackalloc byte[] { (byte)'Z', (byte)'C', (byte)'A', (byte)'0' });
            memoryStream.Seek(1, SeekOrigin.Current);

            byte sectionCount = 0;
            for (int i = 0; i < 4; i++)
            {
                if (nca.Header.IsSectionEnabled(i))
                {
                    sectionCount++;
                    NcaFsHeader fsHeader = nca.Header.GetFsHeader(i);

                    memoryStream.Write(BitConverter.GetBytes(nca.Header.GetSectionStartOffset(i)));
                    memoryStream.Write(BitConverter.GetBytes(nca.Header.GetSectionSize(i)));
                    memoryStream.WriteByte((byte)fsHeader.EncryptionType);
                    memoryStream.Write(BitConverter.GetBytes(fsHeader.Counter));
                }
            }

            memoryStream.Position = 4;
            memoryStream.WriteByte(sectionCount);

            return (nca.OpenDecryptedNca(), memoryStream.ToArray());
        }

        public static void ReadZcaHeader(byte[] zcaHeaderBytes)
        {
            using MemoryStream zcaHeaderStream = new MemoryStream(zcaHeaderBytes);
            using BinaryReader reader          = new BinaryReader(zcaHeaderStream);

            string magic = reader.ReadAscii(4);

            if (magic != "ZCA0")
                throw new Exception($"Invalid Magic. Expected Magic: ZCA0. Actual Magic: {magic}");

            byte sectionCount = reader.ReadByte();
            
            Span<long>  sectionOffsets  = stackalloc long[sectionCount];
            Span<long>  sectionSizes    = stackalloc long[sectionCount];
            Span<byte>  encryptionTypes = stackalloc byte[sectionCount];
            Span<ulong> aesCounters     = stackalloc ulong[sectionCount];

            for (int i = 0; i < sectionCount; i++)
            {
                sectionOffsets[i]  = reader.ReadInt64();
                sectionSizes[i]    = reader.ReadInt64();
                encryptionTypes[i] = reader.ReadByte();
                aesCounters[i]     = reader.ReadUInt64();
            }
        }

        public static Keyset LoadKeySet()
        {
            string prodKeyFile    = null;
            string titleKeyFile   = null;
            string consoleKeyFile = null;

            void LoadSetAtPath(string basePath)
            {
                string localKeyFile        = Path.Combine(basePath, "prod.keys");
                string localTitleKeyFile   = Path.Combine(basePath, "title.keys");
                string localConsoleKeyFile = Path.Combine(basePath, "console.keys");

                if (File.Exists(localKeyFile))
                {
                    prodKeyFile = localKeyFile;
                }

                if (File.Exists(localTitleKeyFile))
                {
                    titleKeyFile = localTitleKeyFile;
                }

                if (File.Exists(localConsoleKeyFile))
                {
                    consoleKeyFile = localConsoleKeyFile;
                }
            }

            LoadSetAtPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".switch"));
            LoadSetAtPath(AppDomain.CurrentDomain.BaseDirectory);

            if (File.Exists(ProdKeyPath))
            {
                prodKeyFile = ProdKeyPath;
            }

            if (File.Exists(TitleKeyPath))
            {
                titleKeyFile = TitleKeyPath;
            }

            return ExternalKeyReader.ReadKeyFile(prodKeyFile, titleKeyFile, consoleKeyFile, dev: IsDev);
        }

        public static string PrettyFileSize(double bytes, bool si = false)
        {
            int thresh = si ? 1000 : 1024;

            if (Math.Abs(bytes) < thresh)
                return $"{bytes}B";

            int i = -1;
            string[] units = si
                ? new[] { "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" }
                : new[] { "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };

            do
            {
                bytes /= thresh;
                ++i;
            } while (Math.Abs(bytes) > thresh && i < units.Length - 1);

            return $"{Math.Round(bytes, 2)}{units[i]}";
        }
    }
}