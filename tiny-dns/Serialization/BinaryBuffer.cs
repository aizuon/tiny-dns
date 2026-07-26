using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace TinyDNS.Serialization;

public class BinaryBuffer
{
    private const int DefaultCapacity = 64;
    private const int MaxDomainNameWireLength = 255;
    private const int MaxCompressionPointers = 128;

    private byte[] _buffer;
    private uint _readOffset;
    private uint _writeOffset;

    public BinaryBuffer()
    {
        _buffer = new byte[DefaultCapacity];
    }

    public BinaryBuffer(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        _buffer = bytes;
        _writeOffset = (uint)bytes.Length;
        Length = (uint)bytes.Length;
    }

    public ArraySegment<byte> Buffer => new(_buffer, 0, checked((int)Length));

    public uint Length { get; private set; }

    public uint Remaining => Length - _readOffset;

    public uint ReadOffset
    {
        get => _readOffset;
        set
        {
            if (value > Length)
                throw new ArgumentOutOfRangeException(nameof(value), "Read offset cannot exceed the buffer length.");

            _readOffset = value;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Write<T>(T value) where T : unmanaged, IBinaryNumber<T>
    {
        var length = (uint)Unsafe.SizeOf<T>();
        GrowIfNeeded(length);

        var bufferSpan = _buffer.AsSpan(checked((int)_writeOffset), checked((int)length));
        value = Mem.ToBigEndian(value);
        MemoryMarshal.Write(bufferSpan, in value);

        AdvanceWriteOffset(length);
    }

    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        var length = (uint)bytes.Length;
        GrowIfNeeded(length);
        bytes.CopyTo(_buffer.AsSpan(checked((int)_writeOffset), bytes.Length));
        AdvanceWriteOffset(length);
    }

    public void WriteDomainName(string domainName)
    {
        ArgumentNullException.ThrowIfNull(domainName);

        if (domainName.Length == 0 || domainName == ".")
        {
            Write((byte)0);
            return;
        }

        var span = domainName.AsSpan();
        if (span[^1] == '.')
            span = span[..^1];

        var wireLength = 1; // terminating root label
        var labelStart = 0;

        for (var i = 0; i <= span.Length; i++)
        {
            if (i != span.Length && span[i] != '.')
                continue;

            var label = span[labelStart..i];
            if (label.Length == 0)
                throw new ArgumentException("DNS names cannot contain empty labels.", nameof(domainName));

            if (label.Length > 63)
                throw new ArgumentException("A DNS label cannot exceed 63 bytes.", nameof(domainName));

            foreach (var character in label)
            {
                if (character > 0x7F)
                {
                    throw new ArgumentException(
                        "DNS wire names must be ASCII. Convert internationalized names to IDNA first.",
                        nameof(domainName));
                }
            }

            wireLength = checked(wireLength + 1 + label.Length);
            if (wireLength > MaxDomainNameWireLength)
                throw new ArgumentException("A DNS name cannot exceed 255 bytes on the wire.", nameof(domainName));

            Write((byte)label.Length);
            GrowIfNeeded((uint)label.Length);
            Encoding.ASCII.GetBytes(label, _buffer.AsSpan(checked((int)_writeOffset), label.Length));
            AdvanceWriteOffset((uint)label.Length);
            labelStart = i + 1;
        }

        Write((byte)0);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public T Read<T>() where T : unmanaged, IBinaryNumber<T>
    {
        var length = (uint)Unsafe.SizeOf<T>();
        EnsureReadable(_readOffset, length);

        var bufferSpan = _buffer.AsSpan(checked((int)_readOffset), checked((int)length));
        var value = MemoryMarshal.Read<T>(bufferSpan);
        _readOffset += length;
        return Mem.ToBigEndian(value);
    }

    public byte[] ReadBytes(uint count)
    {
        var span = ReadBytesSpan(count);
        return span.ToArray();
    }

    public ReadOnlySpan<byte> ReadBytesSpan(uint count)
    {
        EnsureReadable(_readOffset, count);

        var span = _buffer.AsSpan(checked((int)_readOffset), checked((int)count));
        _readOffset += count;
        return span;
    }

    public string ReadDomainName()
    {
        var builder = new StringBuilder(64);
        var position = _readOffset;
        uint? resumePosition = null;
        HashSet<uint>? visitedPointers = null;
        var expandedWireLength = 1;
        var pointerCount = 0;
        Span<char> labelChars = stackalloc char[63];

        while (true)
        {
            EnsureReadable(position, 1);
            var lengthOrPointer = _buffer[checked((int)position++)];

            if (lengthOrPointer == 0)
            {
                _readOffset = resumePosition ?? position;
                return builder.ToString();
            }

            if ((lengthOrPointer & 0xC0) == 0xC0)
            {
                if (++pointerCount > MaxCompressionPointers)
                    throw new InvalidDataException("DNS name contains too many compression pointers.");

                EnsureReadable(position, 1);
                var pointerOffset = (uint)(((lengthOrPointer & 0x3F) << 8) |
                                           _buffer[checked((int)position++)]);
                EnsureReadable(pointerOffset, 1);

                resumePosition ??= position;
                visitedPointers ??= [];
                if (!visitedPointers.Add(pointerOffset))
                    throw new InvalidDataException("DNS compression pointer loop detected.");

                position = pointerOffset;
                continue;
            }

            if ((lengthOrPointer & 0xC0) != 0)
                throw new InvalidDataException("DNS label uses a reserved length encoding.");

            if (lengthOrPointer > 63)
                throw new InvalidDataException($"DNS label length {lengthOrPointer} exceeds 63 bytes.");

            EnsureReadable(position, lengthOrPointer);
            expandedWireLength = checked(expandedWireLength + 1 + lengthOrPointer);
            if (expandedWireLength > MaxDomainNameWireLength)
                throw new InvalidDataException("Expanded DNS name exceeds 255 bytes.");

            if (builder.Length > 0)
                builder.Append('.');

            var label = labelChars[..lengthOrPointer];
            Encoding.ASCII.GetChars(
                _buffer.AsSpan(checked((int)position), lengthOrPointer),
                label);
            builder.Append(label);
            position += lengthOrPointer;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EnsureReadable(uint offset, uint count)
    {
        if (offset > Length || count > Length - offset)
            throw new InvalidDataException("DNS packet ended unexpectedly.");
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void GrowIfNeeded(uint writeLength)
    {
        var requiredLength = checked(_writeOffset + writeLength);
        if ((uint)_buffer.Length >= requiredLength)
            return;

        var doubledCapacity = Math.Max((uint)_buffer.Length * 2, DefaultCapacity);
        var newCapacity = Math.Max(doubledCapacity, requiredLength);
        if (newCapacity > int.MaxValue)
            throw new InvalidOperationException("Buffer exceeds the maximum supported size.");

        Array.Resize(ref _buffer, (int)newCapacity);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void AdvanceWriteOffset(uint count)
    {
        _writeOffset += count;
        Length = Math.Max(Length, _writeOffset);
    }
}
