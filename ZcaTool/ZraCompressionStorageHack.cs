// SPDX-License-Identifier: BSD-3-Clause
// Copyright © 2020 Xpl0itR

using LibHac;
using LibHac.Fs;
using LibHac.FsSystem;
using System;
using System.Collections.Generic;
using System.IO;
using ZRA.NET.Streaming;

namespace ZcaTool
{
    public class ZraCompressionStorageHack : IStorage
    {
        private static readonly List<Action> DisposeList = new List<Action>();
        public static void CleanTempFiles()
        {
            foreach (Action dispose in DisposeList) dispose();
        }

        private readonly IStorage _baseStorage;
        private readonly bool _leaveOpen;

        public ZraCompressionStorageHack(IStorage inStorage, byte compressionLevel, uint frameSize, byte[] metaBuffer = null, string tempPath = null, bool leaveOpen = false)
        {
            _leaveOpen = leaveOpen;
            inStorage.GetSize(out long inSize);

            if (tempPath == null)
            {
                tempPath = Path.GetTempFileName();
            }
            else
            {
                Directory.CreateDirectory(tempPath);
                tempPath = Path.Combine(tempPath, $"temp{new Random().Next()}.tmp");
            }

            FileStream tempFile = new FileStream(tempPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.RandomAccess | FileOptions.DeleteOnClose);
            using (ZraCompressionStream compressionStream = new ZraCompressionStream(tempFile, (ulong)inSize, compressionLevel, frameSize, metaBuffer, true))
            {
                inStorage.CopyToStream(compressionStream, (int)frameSize);
            }

            if (!leaveOpen) inStorage.Dispose();

            _baseStorage = new StreamStorage(tempFile, leaveOpen);
            DisposeList.Add(tempFile.Dispose);
        }

        protected override Result DoRead(long offset, Span<byte> destination) => _baseStorage.Read(offset, destination);
        protected override Result DoGetSize(out long size) => _baseStorage.GetSize(out size);
        protected override Result DoWrite(long offset, ReadOnlySpan<byte> source) => _baseStorage.Write(offset, source);
        protected override Result DoFlush() => _baseStorage.Flush();
        protected override Result DoSetSize(long size) => _baseStorage.SetSize(size);

        protected override void Dispose(bool disposing)
        {
            if (!_leaveOpen)
                _baseStorage?.Dispose();

            base.Dispose(disposing);
        }
    }
}