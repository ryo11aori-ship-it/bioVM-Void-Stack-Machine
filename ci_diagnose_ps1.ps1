param(
    [string]$ExePath = ".\biovm_gen1.exe",
    [string]$Args = "ribosome compiler_v15_native.bio biovm_gen2.exe",
    [int]$HeadBytes = 64
)

function Hex([byte[]]$b) {
    ($b | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
}

function Read-Uint16LE($br) { return [BitConverter]::ToUInt16($br,0) }
function Read-Uint32LE($br) { return [BitConverter]::ToUInt32($br,0) }
function Read-Uint64LE($br) { return [BitConverter]::ToUInt64($br,0) }

Write-Host "=== CI DIAGNOSE START ==="
Write-Host "ExePath:" $ExePath
if (-not (Test-Path $ExePath)) {
    Write-Host "[ERROR] EXE not found at path:" $ExePath
    exit 2
}

# Basic file info
$fi = Get-Item $ExePath
Write-Host "File size:" $fi.Length "bytes"
Write-Host "LastWriteTime:" $fi.LastWriteTime

# Dump head bytes
$fs = [System.IO.File]::OpenRead($ExePath)
$br = New-Object System.IO.BinaryReader($fs)
$fs.Seek(0, 'Begin') | Out-Null
$head = $br.ReadBytes($HeadBytes)
Write-Host "`n-- Head ($HeadBytes bytes) --"
Write-Host (Hex $head)

# Check MZ
if ($head.Length -ge 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A) {
    Write-Host "DOS signature: MZ (OK)"
} else {
    Write-Host "DOS signature: NOT MZ -- file is not a valid PE (FAILED)"
}

# Read e_lfanew (offset 0x3C)
$fs.Seek(0x3C, 'Begin') | Out-Null
$e_lfanew_bytes = $br.ReadBytes(4)
$e_lfanew = [BitConverter]::ToUInt32($e_lfanew_bytes,0)
Write-Host "`n e_lfanew (PE header offset) = 0x{0:X}" -f $e_lfanew

# Read PE signature
$fs.Seek($e_lfanew, 'Begin') | Out-Null
$pesig = $br.ReadBytes(4)
Write-Host " PE signature bytes:" (Hex $pesig)
if ($pesig[0] -eq 0x50 -and $pesig[1] -eq 0x45 -and $pesig[2] -eq 0 -and $pesig[3] -eq 0) {
    Write-Host " PE sig: 'PE\\0\\0' (OK)"
} else {
    Write-Host " PE sig is NOT PE\\0\\0 (FAILED)"
}

# Read COFF Header
# Machine (2), NumberOfSections (2), TimeDateStamp(4), PointerToSymbolTable(4), NumberOfSymbols(4), SizeOfOptionalHeader(2), Characteristics(2)
$coff = $br.ReadBytes(20)
$machine = [BitConverter]::ToUInt16($coff,0)
$number_of_sections = [BitConverter]::ToUInt16($coff,2)
$size_of_optional_header = [BitConverter]::ToUInt16($coff,16)
$characteristics = [BitConverter]::ToUInt16($coff,18)
Write-Host "`n-- COFF Header --"
Write-Host (" Machine = 0x{0:X}" -f $machine) `
          (" (0x8664 = x64, 0x014C = x86)")
Write-Host (" NumberOfSections = {0}" -f $number_of_sections)
Write-Host (" SizeOfOptionalHeader = {0}" -f $size_of_optional_header)
Write-Host (" Characteristics = 0x{0:X}" -f $characteristics)

# Read Optional Header magic (first 2 bytes of opt header)
$fs.Seek($e_lfanew + 24, 'Begin') | Out-Null
$opt_magic_bytes = $br.ReadBytes(2)
$opt_magic = [BitConverter]::ToUInt16($opt_magic_bytes,0)
Write-Host "`n-- Optional Header --"
Write-Host (" Magic = 0x{0:X}" -f $opt_magic) 
if ($opt_magic -eq 0x20B) { Write-Host "  (PE32+ / x64 expected)" } elseif ($opt_magic -eq 0x10B) { Write-Host "  (PE32 / x86)"} else { Write-Host "  (unexpected)" }

# Read AddressOfEntryPoint (offset into optional header: 16 for PE32+, but better to parse generically)
# For PE32+, AddressOfEntryPoint offset from optional header start: 16 (0x10) bytes
$fs.Seek($e_lfanew + 24 + 16, 'Begin') | Out-Null
$aep = [BitConverter]::ToUInt32($br.ReadBytes(4),0)
Write-Host (" AddressOfEntryPoint = 0x{0:X}" -f $aep)

# Read ImageBase (PE32+ at offset 24, 8 bytes)
$fs.Seek($e_lfanew + 24 + 24, 'Begin') | Out-Null
$imagebase = [BitConverter]::ToUInt64($br.ReadBytes(8),0)
Write-Host (" ImageBase = 0x{0:X}" -f $imagebase)

# Read SizeOfImage (PE32+ offset 56)
$fs.Seek($e_lfanew + 24 + 56, 'Begin') | Out-Null
$size_of_image = [BitConverter]::ToUInt32($br.ReadBytes(4),0)
Write-Host (" SizeOfImage = 0x{0:X} ({0})" -f $size_of_image)

# Read SizeOfHeaders (offset 60)
$fs.Seek($e_lfanew + 24 + 60, 'Begin') | Out-Null
$size_of_headers = [BitConverter]::ToUInt32($br.ReadBytes(4),0)
Write-Host (" SizeOfHeaders = 0x{0:X} ({0})" -f $size_of_headers)

# Read NumberOfRvaAndSizes (PE32+ offset 108)
$fs.Seek($e_lfanew + 24 + 108, 'Begin') | Out-Null
$num_rva = [BitConverter]::ToUInt32($br.ReadBytes(4),0)
Write-Host (" NumberOfRvaAndSizes = {0}" -f $num_rva)

# Read Import Directory (DataDirectory[1]) RVA and Size (each directory entry is 8 bytes; index1 starts at opt_start+128? but we can compute)
$data_dirs_offset = $e_lfanew + 24 + 112  # core(112) then data dirs start
$fs.Seek($data_dirs_offset + 1*8, 'Begin') | Out-Null
$import_rva = [BitConverter]::ToUInt32($br.ReadBytes(4),0)
$import_size = [BitConverter]::ToUInt32($br.ReadBytes(4),0)
Write-Host (" Import Directory RVA = 0x{0:X}  Size = 0x{1:X}" -f $import_rva, $import_size)

# Section headers: immediately after OptionalHeader (24 + SizeOfOptionalHeader)
$section_start = $e_lfanew + 24 + $size_of_optional_header
Write-Host "`n-- Section headers (up to {0}) at offset 0x{1:X} --" -f $number_of_sections, $section_start
$fs.Seek($section_start, 'Begin') | Out-Null
$sections = @()
for ($i=0; $i -lt $number_of_sections; $i++) {
    $sh = $br.ReadBytes(40)
    if ($sh.Length -lt 40) { break }
    $name = ([System.Text.Encoding]::ASCII.GetString($sh[0..7])).Trim([char]0)
    $virtSize = [BitConverter]::ToUInt32($sh,8)
    $virtAddr = [BitConverter]::ToUInt32($sh,12)
    $rawSize = [BitConverter]::ToUInt32($sh,16)
    $rawPtr  = [BitConverter]::ToUInt32($sh,20)
    $chars   = [BitConverter]::ToUInt32($sh,36)
    $sections += [pscustomobject]@{Name=$name;VirtualSize=$virtSize;VirtualAddress=$virtAddr;SizeOfRawData=$rawSize;PointerToRawData=$rawPtr;Characteristics = ("0x{0:X}" -f $chars)}
}
$sections | Format-Table -AutoSize

# Basic consistency checks
Write-Host "`n-- Consistency checks --"
if ($aep -lt $sections[0].VirtualAddress -or $aep -gt ($sections[0].VirtualAddress + $sections[0].VirtualSize)) {
    Write-Host "[WARN] AddressOfEntryPoint (0x{0:X}) not inside first section (.text?) range 0x{1:X}-0x{2:X}" -f $aep, $sections[0].VirtualAddress, ($sections[0].VirtualAddress + $sections[0].VirtualSize)
} else {
    Write-Host "[OK] EntryPoint looks inside .text"
}

# Check import directory addresses map into a section and raw file offsets
if ($import_rva -eq 0 -or $import_size -eq 0) {
    Write-Host "[WARN] Import Directory RVA/Size is zero -> no imports registered"
} else {
    $found = $false
    foreach ($s in $sections) {
        if ($import_rva -ge $s.VirtualAddress -and $import_rva -lt ($s.VirtualAddress + $s.VirtualSize)) {
            $found = $true
            # convert RVA to file offset: filePtr = PointerToRawData + (import_rva - VirtualAddress)
            $filePtr = $s.PointerToRawData + ($import_rva - $s.VirtualAddress)
            Write-Host (" Import dir maps to file offset 0x{0:X}" -f $filePtr)
            if ($filePtr -ge $fi.Length) {
                Write-Host "[ERROR] Import directory file offset is beyond file length -> truncated file"
            } else {
                Write-Host "[OK] Import dir offset inside file"
            }
            break
        }
    }
    if (-not $found) { Write-Host "[WARN] Import directory RVA not inside any section" }
}

# Close file
$br.Close(); $fs.Close()

# -------------- Try to run the EXE and capture stdout/stderr and exitcode --------------
Write-Host "`n-- Run the EXE (capturing stdout/stderr) --"
$runlog = "ci_gen1_runlog.txt"
$runArgs = $Args -split '\s+'
# Build invocation with redirection
try {
    # Use Start-Process to collect output reliably
    $si = New-Object System.Diagnostics.ProcessStartInfo
    $si.FileName = (Resolve-Path $ExePath).ProviderPath
    $si.RedirectStandardOutput = $true
    $si.RedirectStandardError  = $true
    $si.UseShellExecute = $false
    $si.Arguments = $Args
    $si.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($si)
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $outTxt = $stdout.Result
    $errTxt = $stderr.Result
    $exitCode = $proc.ExitCode

    # Write logs
    $outTxt | Out-File -FilePath $runlog -Encoding utf8
    Add-Content $runlog "`n--- STDERR ---"
    $errTxt | Out-File -FilePath $runlog -Append -Encoding utf8

    Write-Host "ExitCode:" $exitCode
    Write-Host "Run log ($runlog) contents:"
    Get-Content $runlog -Raw | Write-Host

} catch {
    Write-Host "[ERROR] Exception while starting process:" $_.Exception.Message
}

Write-Host "`n=== CI DIAGNOSE END ==="