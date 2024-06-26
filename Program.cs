using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

// Force JIT to compile the methods
new DateTimeOffset(new DateTime(0, DateTimeKind.Utc) + TimeSpan.Zero).ToString();

// Go into the x64 instruction code, replacing DateTime.MaxValue.Ticks with long.MaxValue in various functions.
Replace(
   typeof(DateTime).GetConstructor(BindingFlags.Public | BindingFlags.Instance, types: [typeof(long), typeof(DateTimeKind)])!,
   BitConverter.GetBytes(DateTime.MaxValue.Ticks),
   BitConverter.GetBytes(long.MaxValue),
   100);

Replace(
   typeof(DateTime).GetMethod("op_Addition", BindingFlags.Public | BindingFlags.Static)!,
   BitConverter.GetBytes(DateTime.MaxValue.Ticks),
   BitConverter.GetBytes(long.MaxValue),
   100);

Replace(
   typeof(DateTimeOffset).GetMethod("ValidateDate", BindingFlags.NonPublic | BindingFlags.Static)!,
   BitConverter.GetBytes(DateTime.MaxValue.Ticks),
   BitConverter.GetBytes(long.MaxValue),
   100);

Replace(
   typeof(DateTimeOffset).GetMethod("get_ClockDateTime", BindingFlags.NonPublic | BindingFlags.Instance)!,
   BitConverter.GetBytes(DateTime.MaxValue.Ticks),
   BitConverter.GetBytes(long.MaxValue),
   100);

var dt = new DateTime((long)~(3UL << 62), DateTimeKind.Utc);
var dto = new DateTimeOffset(dt);

Console.WriteLine("DateTime: " + dt);
Console.WriteLine("DateTimeOffset: " + dto);

return;

[DllImport("kernel32.dll")]
static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

static unsafe void Replace(MethodBase method, ReadOnlySpan<byte> original, ReadOnlySpan<byte> replacement, int fnLen)
{
    if (original.Length != replacement.Length)
    {
        throw new ArgumentException("Original and replacement must have the same length");
    }

    var fptr = method.MethodHandle.GetFunctionPointer();
    byte* sitePtr = (byte*)fptr.ToPointer();
    sitePtr = ResolveActualFunctionPointer(sitePtr);

    var hProcess = Process.GetCurrentProcess().Handle;

    if (!VirtualProtectEx(
            hProcess: hProcess,
            lpAddress: (nint)sitePtr,
            dwSize: 16,
            flNewProtect: 0x40,
            out var oldProtect))
    {
        throw new Exception("Unable to change protection of virtual memory");
    }

    for (int i = 0; i < fnLen; i++)
    {
        var span = new Span<byte>(sitePtr + i, original.Length);
        if (span.SequenceEqual(original))
        {
            replacement.CopyTo(span);
        }
    }

    if (!VirtualProtectEx(
            hProcess: hProcess,
            lpAddress: (nint)sitePtr,
            dwSize: 16,
            flNewProtect: oldProtect,
            out _))
    {
        throw new Exception("Unable to change protection of virtual memory");
    }

    bool Equals(byte* ptr, ReadOnlySpan<byte> arr) => arr.SequenceEqual(new ReadOnlySpan<byte>(ptr, arr.Length));
}

static unsafe byte* ResolveActualFunctionPointer(byte* ptr)
{
    if(Equals(ptr, [0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x53, 0x56, 0x57, 0x48, 0x83]))
    {
        // Jit is dumping all registers i.e. the method hasn't been compiled
        throw new Exception("Method not compiled");
    }

    if (Equals(ptr, [0x55])
        || Equals(ptr, [0x53, 0x48, 0x83]) // push rbx | sub rsp, ?
        || Equals(ptr, [0x48, 0x83, 0xEC])) // sub rsp, ?
    {
        return ptr;
    }

    if (Equals(ptr, [0xFF, 0x25]))
    {
        // call (indirect)
        uint offset = *(uint*)(ptr + 0x2);
        // actual location is in ptr + 6 + offset
        ulong loc = *(ulong*)(ptr + 0x6 + offset);
        return ResolveActualFunctionPointer((byte*)loc);
    }

    if (Equals(ptr, [0x48, 0x8b, 0x05])
        && Equals(ptr + 0x07, [0x66, 0xFF, 0x08])
        && Equals(ptr + 0x0A, [0x74, 0x06])
        && Equals(ptr + 0x0C, [0xFF, 0x25])
        && Equals(ptr + 0x12, [0xFF, 0x25]))
    {
        // 0:  48 8b 05 f9 3f 00 00    mov    rax,QWORD PTR [rip+0x3ff9]        # 0x4000
        // 7:  66 ff 08                dec    WORD PTR [rax]
        // a:  74 06                   je     0x12
        // c:  ff 25 f6 3f 00 00       jmp    QWORD PTR [rip+0x3ff6]        # 0x4008
        // 12: ff 25 f8 3f 00 00       jmp    QWORD PTR [rip+0x3ff8]        # 0x4010

        var offset = *(uint*)(ptr + 0x3);
        ulong data = *(uint*)(ptr + 0x7 + offset);
        data--;
        if(data == 0)
        {
            var offsetInner = *(uint*)(ptr + 0x12 + 0x2);
            ulong locInner = *(ulong*)(ptr + 0x12 + 0x6 + offsetInner);
            return ResolveActualFunctionPointer((byte*)locInner);
        }
        else
        {
            var offsetInner = *(uint*)(ptr + 0x0C + 0x2);
            ulong locInner = *(ulong*)(ptr + 0x0C + 0x6 + offsetInner);
            return ResolveActualFunctionPointer((byte*)locInner);
        }
    }

    if (Equals(ptr, [0x4C, 0x8B, 0x15])
        && Equals(ptr + 0x07, [0xFF, 0x25]))
    {
        // 0:  4c 8b 15 fb 3f 00 00    mov    r10,QWORD PTR [rip+0x3ffb]        # 0x4002
        // 7:  ff 25 fd 3f 00 00       jmp    QWORD PTR [rip+0x3ffd]        # 0x400a
        // d:  90                      nop
        var offsetInner = *(uint*)(ptr + 0x07 + 0x2);
        ulong locInner = *(ulong*)(ptr + 0x07 + 0x06 + offsetInner);
        return ResolveActualFunctionPointer((byte*)locInner);
    }

    throw new NotSupportedException("Unknown function prologue");

    bool Equals(byte* ptr, ReadOnlySpan<byte> arr) => arr.SequenceEqual(new ReadOnlySpan<byte>(ptr, arr.Length));
}