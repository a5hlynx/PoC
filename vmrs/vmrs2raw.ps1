Param (
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

function Resolve-Path {
    param([string]$InputPath)

    if ([System.IO.Path]::IsPathRooted($InputPath)) {
        return $InputPath
    }

    $resolvedPath = Join-Path (Get-Location) $InputPath
    return $resolvedPath
}

function Convert-VMRSToRAW ($InputPath, $OutputPath) {
    $vmDumpHandle = [IntPtr]::Zero
    $resultCode = [VmSavedStateDumpProvider]::LoadSavedStateFile($InputPath, [ref]$vmDumpHandle)

    if ($resultCode -ne 0) {
        Write-Error "Failed to load VMRS file: 0x$($resultCode.ToString('X8'))"
        return $false
    }

    try {
        [uint32]$chunkPageSize = 0
        [uint32]$chunkCount = 0

        $resultCode = [VmSavedStateDumpProvider]::GetGuestPhysicalMemoryChunks(
            $vmDumpHandle,
            [ref]$chunkPageSize,
            [IntPtr]::Zero,
            [ref]$chunkCount
        )

        if (($resultCode -ne [VmSavedStateDumpProvider]::E_OUTOFMEMORY) -or ($chunkCount -eq 0)) {
            Write-Error "Failed to get memory chunks: 0x$($resultCode.ToString('X8'))"
            return $false
        }

        $chunkStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][GPA_MEMORY_CHUNK])
        $totalSize = [UIntPtr]($chunkCount * $chunkStructSize)

        $memoryChunks = [VmSavedStateDumpProvider]::LocalAlloc(
            [VmSavedStateDumpProvider]::LMEM_ZEROINIT,
            $totalSize
        )

        $resultCode = [VmSavedStateDumpProvider]::GetGuestPhysicalMemoryChunks(
            $vmDumpHandle,
            [ref]$chunkPageSize,
            $memoryChunks,
            [ref]$chunkCount
        )

        if (($resultCode -lt 0) -or ($chunkCount -eq 0)) {
            Write-Error "Failed to get memory chunks: 0x$($resultCode.ToString('X8'))"
            return $false
        }

        $outputStream = [System.IO.FileStream]::new(
            $OutputPath,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write
        )

        $totalBytesWritten = [uint64]0
        $lastEndAddress = [uint64]0
        $buffer = New-Object byte[] $chunkPageSize
        $zeroBuffer = New-Object byte[] $chunkPageSize

        Write-Host "Conversion initiated"

        for ($i = 0; $i -lt $chunkCount; $i++) {
            Write-Host "Processing chunk $($i + 1) of $chunkCount"

            $chunkPtr = [IntPtr]::Add($memoryChunks, $i * $chunkStructSize)
            $chunk = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                $chunkPtr,
                [type][GPA_MEMORY_CHUNK]
            )

            $startAddress = $chunk.GuestPhysicalStartPageIndex * $chunkPageSize
            $endAddress = $startAddress + ($chunk.PageCount * $chunkPageSize)

            Write-Host "  Start: 0x$($startAddress.ToString('X'))"
            Write-Host "  Pages: $($chunk.PageCount)"
            Write-Host "  Size:  0x$(($chunk.PageCount * $chunkPageSize).ToString('X')) bytes"

            if ($startAddress -gt $lastEndAddress -and $lastEndAddress -gt 0) {
                $gapSize = $startAddress - $lastEndAddress
                Write-Host "  Filling gap: 0x$($gapSize.ToString('X')) bytes"

                $filled = [uint64]0
                while ($filled -lt $gapSize) {
                    $toWrite = [Math]::Min($gapSize - $filled, $chunkPageSize)
                    $outputStream.Write($zeroBuffer, 0, $toWrite)
                    $totalBytesWritten += $toWrite
                    $filled += $toWrite
                }
            }

            $bufferHandle = [System.Runtime.InteropServices.GCHandle]::Alloc(
                $buffer,
                [System.Runtime.InteropServices.GCHandleType]::Pinned
            )

            try {
                $pageWidth = $chunk.PageCount.ToString().Length
                for ([uint64]$page = 0; $page -lt $chunk.PageCount; $page++) {
                    $currentAddress = $startAddress + ($page * $chunkPageSize)
                    [uint32]$bytesRead = 0

                    $bufferPtr = $bufferHandle.AddrOfPinnedObject()
                    $resultCode = [VmSavedStateDumpProvider]::ReadGuestPhysicalAddress(
                        $vmDumpHandle,
                        $currentAddress,
                        $bufferPtr,
                        $chunkPageSize,
                        [ref]$bytesRead
                    )

                    if ($resultCode -ge 0 -and $bytesRead -gt 0) {
                        $outputStream.Write($buffer, 0, [int]$bytesRead)
                        $totalBytesWritten += $bytesRead
                    } else {
                        [Array]::Clear($buffer, 0, $buffer.Length)
                        $outputStream.Write($buffer, 0, [int]$chunkPageSize)
                        $totalBytesWritten += $chunkPageSize
                    }

                    if ((($page + 1) % 1000) -eq 0 -or $page -eq ($chunk.PageCount - 1)) {
                        #Write-Host "    Progress: $($page + 1)/$($chunk.PageCount) pages"
                        $currentPage = ($page + 1).ToString().PadLeft($pageWidth)
                        Write-Host "    Progress: $currentPage/$($chunk.PageCount) pages"
                    }
                }
            } finally {
                if ($bufferHandle.IsAllocated) {
                    $bufferHandle.Free()
                }
            }

            $lastEndAddress = $endAddress
        }

        Write-Host "Conversion completed"
        Write-Host "Total bytes written: 0x$($totalBytesWritten.ToString('X')) ($totalBytesWritten bytes)"

        return $true
    } catch {
        Write-Error "Error during conversion: $($_.Exception.Message)"
        Write-Error "Stack trace: $($_.Exception.StackTrace)"
        return $false
    } finally {
        Write-Host "Cleanup initiated"

        if ($outputStream) {
            $outputStream.Close()
            $outputStream.Dispose()
            Write-Host "Output stream closed"
        }

        if ($memoryChunks -ne [IntPtr]::Zero) {
            [VmSavedStateDumpProvider]::LocalFree($memoryChunks) | Out-Null
            Write-Host "Memory chunks freed"
        }

        if ($vmDumpHandle -ne [IntPtr]::Zero) {
            [VmSavedStateDumpProvider]::ReleaseSavedStateFiles($vmDumpHandle) | Out-Null
            Write-Host "VMRS context released"
        }

        Write-Host "Cleanup completed"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$dllName = "vmsavedstatedumpprovider.dll"

$dllPath = Join-Path $scriptDir $dllName
if (-not (Test-Path $dllPath)) {
    $pathDll = Get-Command $dllName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($pathDll) {
        $dllPath = $pathDll.Source
    } else {
        Write-Error "Dll not found: $dllName"
        exit 1
    }
}

$escapedDllPath = $dllPath -replace '\\', '\\'

if (-not ('VmSavedStateDumpProvider' -as [type])) {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    [StructLayout(LayoutKind.Sequential)]
    public struct GPA_MEMORY_CHUNK {
        public ulong GuestPhysicalStartPageIndex;
        public ulong PageCount;
    }

    public class VmSavedStateDumpProvider {
        [DllImport(@"$escapedDllPath", CharSet = CharSet.Unicode)]
        public static extern int LoadSavedStateFile(string VmrsFile, out IntPtr LoadContext);

        [DllImport(@"$escapedDllPath")]
        public static extern int GetGuestPhysicalMemoryChunks(
            IntPtr LoadContext,
            out ulong MemoryChunkPageSize,
            IntPtr MemoryChunks,
            out uint MemoryChunkCount
        );

        [DllImport(@"$escapedDllPath")]
        public static extern int ReadGuestPhysicalAddress(
            IntPtr LoadContext,
            ulong PhysicalAddress,
            IntPtr Buffer,
            uint BufferSize,
            out uint BytesRead
        );

        [DllImport(@"$escapedDllPath")]
        public static extern int ReleaseSavedStateFiles(IntPtr LoadContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalAlloc(uint uFlags, UIntPtr uBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        public const uint LMEM_ZEROINIT = 0x0040;
        public const int E_OUTOFMEMORY = unchecked((int)0x8007000E);
    }
"@
}

$resolvedInputPath = Resolve-Path -InputPath $InputPath
$resolvedOutputPath = Resolve-Path -InputPath $OutputPath

if (-not (Test-Path $resolvedInputPath)) {
    Write-Error "Input file not found: $resolvedInputPath"
    exit 1
}

Convert-VMRSToRAW $resolvedInputPath $resolvedOutputPath | Out-Null
