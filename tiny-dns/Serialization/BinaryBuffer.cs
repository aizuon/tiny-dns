using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace TinyDNS.Serialization;

public class BinaryBuffer
{
    private const int DefaultCapacity = 64;

    private byte[] _buffer;

    private uint _readOffset;

    private uint _writeOffset;

    private uint _capacity;

    public BinaryBuffer()
    {
        _buffer = new byte[DefaultCapacity];
        _capacity = DefaultCapacity;
        Length = 0;
    }

    public BinaryBuffer(byte[] obj)
    {
        _buffer = obj;
        _writeOffset = (uint)obj.Length;
        _capacity = (uint)obj.Length;
        Length = (uint)obj.Length;
    }

    public ArraySegment<byte> Buffer => new ArraySegment<byte>(_buffer, 0, (int)Length);

    public uint Length { get; private set; }

    public uint ReadOffset
    {
        get => _readOffset;
        set
        {
            if (value > Length)
                throw new ArgumentOutOfRangeException();
            _readOffset = value;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Write<T>(T obj) where T : unmanaged, IBinaryNumber<T>
    {
        uint length = (uint)Unsafe.SizeOf<T>();
        GrowIfNeeded(length);

        var bufferSpan = _buffer.AsSpan((int)_writeOffset, (int)length);
        obj = Mem.ToBigEndian(obj);
        MemoryMarshal.Write(bufferSpan, in obj);

        _writeOffset += length;
        Length = Math.Max(Length, _writeOffset);
    }

    public void WriteBytes(ReadOnlySpan<byte> obj)
    {
        uint length = (uint)obj.Length;
        GrowIfNeeded(length);

        obj.CopyTo(_buffer.AsSpan((int)_writeOffset, (int)length));

        _writeOffset += length;
        Length = Math.Max(Length, _writeOffset);
    }

    public void WriteDomainName(string obj)
    {
        var span = obj.AsSpan();
        int start = 0;
        for (int i = 0; i <= span.Length; i++)
        {
            if (i == span.Length || span[i] == '.')
            {
                int labelLen = i - start;
                if (labelLen > 63)
                    throw new ArgumentException($"DNS label exceeds 63 bytes: '{obj}'");
                if (labelLen == 0)
                {
                    start = i + 1;
                    continue;
                }

                Write((byte)labelLen);
                GrowIfNeeded((uint)labelLen);
                Encoding.ASCII.GetBytes(span[start..i], _buffer.AsSpan((int)_writeOffset, labelLen));
                _writeOffset += (uint)labelLen;
                Length = Math.Max(Length, _writeOffset);
                start = i + 1;
            }
        }

        Write((byte)0);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public T Read<T>() where T : unmanaged, IBinaryNumber<T>
    {
        uint length = (uint)Unsafe.SizeOf<T>();

        if (_buffer.Length < _readOffset + length)
            throw new ArgumentOutOfRangeException();

        var bufferSpan = _buffer.AsSpan((int)_readOffset, (int)length);
        var value = MemoryMarshal.Read<T>(bufferSpan);
        value = Mem.ToBigEndian(value);

        _readOffset += length;

        return value;
    }

    public byte[] ReadBytes(uint count)
    {
        if (_buffer.Length - _readOffset < count)
            throw new ArgumentOutOfRangeException();

        var result = new byte[count];
        _buffer.AsSpan((int)_readOffset, (int)count).CopyTo(result);
        _readOffset += count;

        return result;
    }

    public ReadOnlySpan<byte> ReadBytesSpan(uint count)
    {
        if (_buffer.Length - _readOffset < count)
            throw new ArgumentOutOfRangeException();

        var span = _buffer.AsSpan((int)_readOffset, (int)count);
        _readOffset += count;

        return span;
    }

    public string ReadDomainName()
    {
        var sb = new StringBuilder(64);
        ReadDomainNameInto(sb, maxPointers: 16);
        return sb.ToString();
    }

    private void ReadDomainNameInto(StringBuilder sb, int maxPointers)
    {
        bool first = true;
        Span<char> chars = stackalloc char[63];

        while (true)
        {
            byte lengthOrPointer = Read<byte>();

            if (lengthOrPointer == 0)
            {
                break;
            }
            else if ((lengthOrPointer & 0xC0) == 0xC0)
            {
                if (maxPointers <= 0)
                    throw new InvalidDataException("DNS compression pointer loop detected");

                byte secondByte = Read<byte>();
                uint offset = (uint)(((lengthOrPointer & 0x3F) << 8) | secondByte);
                if (offset >= Length)
                    throw new InvalidDataException("DNS compression pointer points beyond packet");

                uint currentPosition = _readOffset;
                _readOffset = offset;

                if (!first)
                    sb.Append('.');
                ReadDomainNameInto(sb, maxPointers - 1);

                _readOffset = currentPosition;
                return;
            }
            else
            {
                if (lengthOrPointer > 63)
                    throw new InvalidDataException($"DNS label length {lengthOrPointer} exceeds maximum of 63");

                if (!first)
                    sb.Append('.');
                first = false;

                if (_buffer.Length < _readOffset + lengthOrPointer)
                    throw new ArgumentOutOfRangeException();

                var labelChars = chars[..lengthOrPointer];
                Encoding.ASCII.GetChars(_buffer.AsSpan((int)_readOffset, lengthOrPointer), labelChars);
                sb.Append(labelChars);
                _readOffset += lengthOrPointer;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void GrowIfNeeded(uint writeLength)
    {
        uint requiredLength = _writeOffset + writeLength;
        if (_capacity < requiredLength)
        {
            uint newCapacity = Math.Max(_capacity * 2, requiredLength);
            Array.Resize(ref _buffer, (int)newCapacity);
            Length = requiredLength;
            _capacity = newCapacity;
        }
    }
}
