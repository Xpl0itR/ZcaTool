// SPDX-License-Identifier: BSD-3-Clause
// Copyright © 2020 Xpl0itR

using LibHac;
using LibHac.Fs;
using LibHac.FsSystem;
using System;
using System.IO;
using ZRA.NET.Streaming;

namespace ZcaTool
{
    public class ZraCompressionStorageHack : IStorage
    {
        private readonly IStorage _baseStorage;
        private readonly bool _leaveOpen;

        public ZraCompressionStorageHack(IStorage inStorage, byte compressionLevel, uint frameSize, byte[] metaBuffer = null, bool leaveOpen = false)
        {
            _leaveOpen = leaveOpen;

            string path = Path.GetTempFileName();
            inStorage.GetSize(out long inSize);

            using (FileStream outStream = File.OpenWrite(path))
            using (ZraCompressionStream compressionStream = new ZraCompressionStream(outStream, (ulong)inSize, compressionLevel, frameSize, metaBuffer))
            {
                inStorage.CopyToStream(compressionStream, (int)frameSize);
                compressionStream.Flush();
            }

            if (!leaveOpen) inStorage.Dispose();

            _baseStorage = new StreamStorage(File.OpenRead(path), leaveOpen);
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