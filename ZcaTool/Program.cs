// SPDX-License-Identifier: BSD-3-Clause
// Copyright © 2020 Xpl0itR

using LibHac;
using LibHac.Common;
using LibHac.Fs.Fsa;
using LibHac.Fs;
using LibHac.FsSystem;
using LibHac.FsSystem.NcaUtils;
using LibHac.Crypto;
using Mono.Options;
using System;
using System.Collections.Generic;
using System.IO;
using LibHac.Spl;
using ZRA.NET.Streaming;

namespace ZcaTool
{
    public static class Program
    {
        public static Keyset KeySet;
        
        public static void Main(string[] cmdArgs)
        {
            string outDirectoryPath = null;
            string prodKeyPath      = null;
            string titleKeyPath     = null;
            bool   showHelp         = false;
            bool   isDev            = false;
            byte   compressionLevel = 9;
            uint   frameSize        = 131072;

            OptionSet optionSet = new OptionSet
            {
                { "h|help",       "Show this message and exit",                                    _ => showHelp         = true          },
                { "v|dev=",       "Load production keys as development keys\n(optional)",          _ => isDev            = true          },
                { "p|prodkeys=",  "Path to a file containing switch production keys.\n(optional)", s => prodKeyPath      = s             },
                { "t|titlekeys=", "Path to a file containing switch title keys.\n(optional)",      s => titleKeyPath     = s             },
                { "l|level=",     "zStd compression level used to compress the file.",             s => compressionLevel = byte.Parse(s) },
                { "f|framesize=", "Size of a frame used to split a file.",                         s => frameSize        = uint.Parse(s) },
                { "o|output=",    "The directory to output the compressed file.\n(Defaults to the same dir as input file)", s => outDirectoryPath = s }
            };

            List<string> args = optionSet.Parse(cmdArgs);

            if (showHelp)
            {
                Console.WriteLine("ZcaTool - Copyright (c) 2020 Xpl0itR");
                Console.WriteLine("Usage: ZcaTool(.exe) [options] <path>");
                Console.WriteLine("Options:");
                optionSet.WriteOptionDescriptions(Console.Out);
                return;
            }

            if (args.Count < 1 || !File.Exists(args[0]))
                throw new Exception("Input file does not exist!");

            if (compressionLevel < 1 || compressionLevel > 22)
                throw new Exception("You must enter a valid compression level!");

            KeySet = LoadKeySet(prodKeyPath, titleKeyPath, isDev);
            outDirectoryPath ??= Path.GetDirectoryName(args[0]);

            using (IStorage inStorage = new LocalStorage(args[0], FileAccess.Read))
            {
                string fileName = Path.GetFileNameWithoutExtension(args[0]);
                IStorage outStorage;

                switch (Path.GetExtension(args[0]).ToLower())
                {
                    case ".nca":
                        outStorage = new ZraCompressionStorageHack(new Nca(KeySet, inStorage).OpenDecryptedNca(), compressionLevel, frameSize);
                        fileName += ".zca";
                        break;
                    case ".zca":
                        outStorage = new Nca(KeySet, new ZraDecompressionStream(inStorage.AsStream()).AsStorage()).OpenEncryptedNca();
                        fileName += ".nca";
                        break;
                    case ".nsp":
                        outStorage = ProcessPartitionFileSystem(new PartitionFileSystem(inStorage), PartitionFileSystemType.Standard, true, compressionLevel, frameSize);
                        fileName += ".zsp";
                        break;
                    case ".zsp":
                        outStorage = ProcessPartitionFileSystem(new PartitionFileSystem(inStorage), PartitionFileSystemType.Standard, false, compressionLevel, frameSize);
                        fileName += ".nsp";
                        break;
                    case ".xci":
                        outStorage = ProcessXci(inStorage, true, compressionLevel, frameSize);
                        fileName += ".zci";
                        break;
                    case ".zci":
                        outStorage = ProcessXci(inStorage, false, compressionLevel, frameSize);
                        fileName += ".xci";
                        break;
                    default:
                        throw new Exception("Input file was not of a valid format");
                }

                string filePath = Path.Join(outDirectoryPath, fileName);

                using (FileStream outStream = File.OpenWrite(filePath))
                {
                    outStorage.CopyToStream(outStream);
                }
            }
        }

        public static IStorage ProcessXci(IStorage xciStorage, bool compress, byte compressionLevel = 0, uint frameSize = 0)
        {
            Xci xci = new Xci(KeySet, xciStorage);
            IStorage xciHeaderStorage = new MemoryStorage(new byte[0x200]);
            xciStorage.CopyTo(xciHeaderStorage);

            XciPartition securePartition          = xci.OpenPartition(XciPartitionType.Secure);
            IStorage     processedSecurePartition = ProcessPartitionFileSystem(securePartition, PartitionFileSystemType.Hashed, compress, compressionLevel, frameSize);

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

        public static IStorage ProcessPartitionFileSystem(PartitionFileSystem pfs, PartitionFileSystemType pfsType, bool compress, byte compressionLevel = 0, uint frameSize = 0)
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
                    IStorage decryptedNcaStorage = new Nca(KeySet, file.AsStorage()).OpenDecryptedNca();
                    IFile zcaFile = new ZraCompressionStorageHack(decryptedNcaStorage, compressionLevel, frameSize).AsFile(OpenMode.Read);

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

        public static Keyset LoadKeySet(string paramProdKeyFile, string paramTitleKeyFile, bool isDev)
        {
            string prodKeyFile    = null;
            string titleKeyFile   = null;
            string consoleKeyFile = null;

            LoadSetAtPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".switch"));
            LoadSetAtPath(AppDomain.CurrentDomain.BaseDirectory);

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

            if (File.Exists(paramProdKeyFile))
            {
                prodKeyFile = paramProdKeyFile;
            }

            if (File.Exists(paramTitleKeyFile))
            {
                titleKeyFile = paramTitleKeyFile;
            }

            return ExternalKeyReader.ReadKeyFile(prodKeyFile, titleKeyFile, consoleKeyFile, dev: isDev);
        }
    }
}