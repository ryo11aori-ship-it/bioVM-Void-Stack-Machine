param(
  [string]$ExePath = ".\biovm_compiler.exe"
)

Write-Host "=== run_compiler_if_exists.ps1 ==="
Write-Host "Checking for: $ExePath"

if (Test-Path $ExePath) {
    Write-Host "OK: $ExePath found"
    Get-Item $ExePath | Format-List Name,Length,LastWriteTime

    try {
        Write-Host "Running: $ExePath"
        # 実行して終了コードをそのまま返す
        & $ExePath
        $code = $LASTEXITCODE
        Write-Host "$ExePath exited with code $code"
        exit $code
    } catch {
        Write-Error "Execution failed: $_"
        exit 2
    }

} else {
    Write-Error "NG: $ExePath NOT FOUND"
    Write-Host "Workspace dump (files & dirs):"
    Get-ChildItem -Recurse -Force | Format-Table FullName,Length,LastWriteTime -AutoSize
    exit 1
}