param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [int]$TimeoutSeconds = 90,

    [switch]$AllowHostExecution
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-WindowsSandbox {
    if ($env:USERNAME -eq 'WDAGUtilityAccount') { return $true }
    if (Test-Path 'C:\Users\WDAGUtilityAccount') { return $true }
    return $false
}

if (-not (Test-WindowsSandbox) -and -not $AllowHostExecution) {
    throw 'Refusing to execute outside Windows Sandbox. Use launch-sandbox.ps1, or pass -AllowHostExecution only inside a disposable offline VM.'
}

$ExePath = (Resolve-Path $ExePath).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$nativeSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class NativeDump
{
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_GUARD = 0x100;
    const uint PAGE_NOACCESS = 0x01;

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, int size, out IntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION buffer, IntPtr length);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    static bool IsReadable(MEMORY_BASIC_INFORMATION mbi)
    {
        if (mbi.State != MEM_COMMIT) return false;
        if ((mbi.Protect & PAGE_GUARD) != 0) return false;
        if ((mbi.Protect & 0xFF) == PAGE_NOACCESS) return false;
        return true;
    }

    public static double SampleNonZeroRatio(int pid, long moduleBase, int sectionRva, int sectionSize)
    {
        IntPtr process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (process == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            const int windows = 24;
            const int windowSize = 4096;
            long nonZero = 0;
            long readTotal = 0;
            for (int i = 0; i < windows; i++)
            {
                long relative = sectionRva;
                if (sectionSize > windowSize)
                    relative += ((long)(sectionSize - windowSize) * i) / Math.Max(1, windows - 1);
                byte[] buffer = new byte[windowSize];
                IntPtr read;
                if (ReadProcessMemory(process, new IntPtr(moduleBase + relative), buffer, buffer.Length, out read))
                {
                    int count = read.ToInt32();
                    readTotal += count;
                    for (int j = 0; j < count; j++) if (buffer[j] != 0) nonZero++;
                }
            }
            return readTotal == 0 ? 0.0 : (double)nonZero / readTotal;
        }
        finally { CloseHandle(process); }
    }

    public static void DumpModule(int pid, long moduleBase, int imageSize, string imagePath, string mapPath)
    {
        IntPtr process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (process == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        byte[] image = new byte[imageSize];
        var map = new List<string>();
        try
        {
            long cursor = moduleBase;
            long end = moduleBase + imageSize;
            int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            while (cursor < end)
            {
                MEMORY_BASIC_INFORMATION mbi;
                IntPtr queried = VirtualQueryEx(process, new IntPtr(cursor), out mbi, new IntPtr(mbiSize));
                if (queried == IntPtr.Zero) break;
                long regionBase = mbi.BaseAddress.ToInt64();
                long regionSize = (long)mbi.RegionSize.ToUInt64();
                if (regionSize <= 0) break;
                long readStart = Math.Max(regionBase, moduleBase);
                long readEnd = Math.Min(regionBase + regionSize, end);
                long requested = Math.Max(0, readEnd - readStart);
                long bytesCopied = 0;
                if (requested > 0 && IsReadable(mbi))
                {
                    long position = readStart;
                    while (position < readEnd)
                    {
                        int chunk = (int)Math.Min(1024 * 1024, readEnd - position);
                        byte[] buffer = new byte[chunk];
                        IntPtr bytesRead;
                        if (!ReadProcessMemory(process, new IntPtr(position), buffer, chunk, out bytesRead)) break;
                        int count = bytesRead.ToInt32();
                        if (count <= 0) break;
                        Buffer.BlockCopy(buffer, 0, image, checked((int)(position - moduleBase)), count);
                        position += count;
                        bytesCopied += count;
                    }
                }
                map.Add(String.Format("{{\"base\":\"0x{0:x}\",\"size\":{1},\"state\":{2},\"protect\":{3},\"type\":{4},\"copied\":{5}}}",
                    regionBase, regionSize, mbi.State, mbi.Protect, mbi.Type, bytesCopied));
                cursor = regionBase + regionSize;
            }
            File.WriteAllBytes(imagePath, image);
            File.WriteAllText(mapPath, "[\n" + String.Join(",\n", map.ToArray()) + "\n]\n", Encoding.UTF8);
        }
        finally { CloseHandle(process); }
    }

    static int Align(int value, int alignment)
    {
        return checked((value + alignment - 1) / alignment * alignment);
    }

    static ushort U16(byte[] data, int offset) { return BitConverter.ToUInt16(data, offset); }
    static int I32(byte[] data, int offset) { return BitConverter.ToInt32(data, offset); }
    static void PutI32(byte[] data, int offset, int value)
    {
        byte[] encoded = BitConverter.GetBytes(value);
        Buffer.BlockCopy(encoded, 0, data, offset, 4);
    }

    public static void SplitAndRebuild(string originalPath, string memoryPath, string outputDir)
    {
        byte[] original = File.ReadAllBytes(originalPath);
        byte[] memory = File.ReadAllBytes(memoryPath);
        int peOffset = I32(original, 0x3c);
        int coff = peOffset + 4;
        int sectionCount = U16(original, coff + 2);
        int optionalSize = U16(original, coff + 16);
        int optional = coff + 20;
        int fileAlignment = I32(original, optional + 36);
        int sizeOfHeaders = I32(original, optional + 60);
        int sectionTable = optional + optionalSize;
        Directory.CreateDirectory(Path.Combine(outputDir, "sections"));

        int nextRaw = Align(sizeOfHeaders, fileAlignment);
        var sections = new List<Tuple<int, int, int, int, string>>();
        for (int i = 0; i < sectionCount; i++)
        {
            int header = sectionTable + i * 40;
            string name = Encoding.ASCII.GetString(original, header, 8).TrimEnd('\0');
            int virtualSize = I32(original, header + 8);
            int virtualAddress = I32(original, header + 12);
            int rawSize = Align(Math.Max(virtualSize, 1), fileAlignment);
            sections.Add(Tuple.Create(header, virtualAddress, virtualSize, rawSize, name));
            nextRaw += rawSize;
        }

        byte[] rebuilt = new byte[nextRaw];
        Buffer.BlockCopy(original, 0, rebuilt, 0, Math.Min(sizeOfHeaders, original.Length));
        int rawCursor = Align(sizeOfHeaders, fileAlignment);
        foreach (var section in sections)
        {
            int header = section.Item1;
            int rva = section.Item2;
            int virtualSize = section.Item3;
            int rawSize = section.Item4;
            string safeName = String.IsNullOrWhiteSpace(section.Item5) ? "section" : section.Item5.TrimStart('.').Replace("/", "_");
            int available = Math.Max(0, Math.Min(virtualSize, memory.Length - rva));
            byte[] sectionBytes = new byte[available];
            if (available > 0) Buffer.BlockCopy(memory, rva, sectionBytes, 0, available);
            File.WriteAllBytes(Path.Combine(outputDir, "sections", safeName + ".bin"), sectionBytes);
            if (available > 0) Buffer.BlockCopy(memory, rva, rebuilt, rawCursor, available);
            PutI32(rebuilt, header + 16, rawSize);
            PutI32(rebuilt, header + 20, rawCursor);
            rawCursor += rawSize;
        }
        File.WriteAllBytes(Path.Combine(outputDir, "rebuilt-memory-image.exe"), rebuilt);
    }
}
'@

Add-Type -TypeDefinition $nativeSource -Language CSharp

$originalBytes = [System.IO.File]::ReadAllBytes($ExePath)
$peOffset = [BitConverter]::ToInt32($originalBytes, 0x3c)
$coff = $peOffset + 4
$optionalSize = [BitConverter]::ToUInt16($originalBytes, $coff + 16)
$optional = $coff + 20
$imageBase = [BitConverter]::ToUInt32($originalBytes, $optional + 28)
$imageSize = [BitConverter]::ToInt32($originalBytes, $optional + 56)
$sectionCount = [BitConverter]::ToUInt16($originalBytes, $coff + 2)
$sectionTable = $optional + $optionalSize
$textRva = 0x1000
$textSize = 0
for ($i = 0; $i -lt $sectionCount; $i++) {
    $header = $sectionTable + $i * 40
    $name = [Text.Encoding]::ASCII.GetString($originalBytes, $header, 8).Trim([char]0)
    if ($name -eq '.text') {
        $textSize = [BitConverter]::ToInt32($originalBytes, $header + 8)
        $textRva = [BitConverter]::ToInt32($originalBytes, $header + 12)
        break
    }
}
if ($textSize -le 0) { throw 'Could not locate the .text section.' }

$workDir = Join-Path $env:TEMP ('spark-unpack-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$targetCopy = Join-Path $workDir ([IO.Path]::GetFileName($ExePath))
Copy-Item -LiteralPath $ExePath -Destination $targetCopy -Force

$start = Get-Date
$process = Start-Process -FilePath $targetCopy -WorkingDirectory $workDir -PassThru
$ratio = 0.0
$stable = 0
$lastRatio = -1.0
$dumped = $false
$moduleBase = [int64]$imageBase

try {
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Milliseconds 150
        $process.Refresh()
        if ($process.HasExited) { break }
        try {
            if ($process.MainModule -and $process.MainModule.BaseAddress) {
                $moduleBase = $process.MainModule.BaseAddress.ToInt64()
            }
        } catch { }
        try {
            $ratio = [NativeDump]::SampleNonZeroRatio($process.Id, $moduleBase, $textRva, $textSize)
        } catch {
            continue
        }
        if ($ratio -gt 0.03 -and [Math]::Abs($ratio - $lastRatio) -lt 0.0005) {
            $stable++
        } else {
            $stable = 0
        }
        $lastRatio = $ratio
        if (($ratio -gt 0.08 -and $stable -ge 5) -or ($ratio -gt 0.03 -and ((Get-Date) - $start).TotalSeconds -gt 8)) {
            $memoryPath = Join-Path $OutDir 'memory-image.bin'
            $mapPath = Join-Path $OutDir 'memory-map.json'
            [NativeDump]::DumpModule($process.Id, $moduleBase, $imageSize, $memoryPath, $mapPath)
            [NativeDump]::SplitAndRebuild($ExePath, $memoryPath, $OutDir)
            $dumped = $true
            break
        }
    }
}
finally {
    try {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    } catch { }
}

$metadata = [ordered]@{
    collected_at = (Get-Date).ToString('o')
    sandbox = (Test-WindowsSandbox)
    source_file = [IO.Path]::GetFileName($ExePath)
    process_id = $process.Id
    module_base = ('0x{0:x8}' -f $moduleBase)
    image_size = $imageSize
    text_rva = ('0x{0:x8}' -f $textRva)
    text_size = $textSize
    final_nonzero_ratio = $ratio
    elapsed_seconds = [Math]::Round(((Get-Date) - $start).TotalSeconds, 3)
    dumped = $dumped
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $OutDir 'collector.json')

if (-not $dumped) {
    throw 'The process exited or timed out before the original .text section became stable. collector.json was written for diagnosis.'
}

Write-Host "Collection completed: $OutDir"
