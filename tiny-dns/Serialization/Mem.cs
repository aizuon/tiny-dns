using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace TinyDNS.Serialization;

public static class Mem
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static T ToBigEndian<T>(T obj) where T : unmanaged, IBinaryNumber<T>
    {
        if (!BitConverter.IsLittleEndian)
            return obj;

        uint size = (uint)Unsafe.SizeOf<T>();

        switch (size)
        {
            case 1:
                return obj;
            case 2:
            {
                ushort val = Unsafe.As<T, ushort>(ref obj);
                val = BinaryPrimitives.ReverseEndianness(val);
                return Unsafe.As<ushort, T>(ref val);
            }
            case 4:
            {
                uint val = Unsafe.As<T, uint>(ref obj);
                val = BinaryPrimitives.ReverseEndianness(val);
                return Unsafe.As<uint, T>(ref val);
            }
            case 8:
            {
                ulong val = Unsafe.As<T, ulong>(ref obj);
                val = BinaryPrimitives.ReverseEndianness(val);
                return Unsafe.As<ulong, T>(ref val);
            }
            default:
                throw new NotSupportedException($"ToBigEndian does not support size {size}");
        }
    }
}
