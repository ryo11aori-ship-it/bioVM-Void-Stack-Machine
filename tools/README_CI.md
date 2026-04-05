# tools/ README for CI helpers

- ensure_biovm_compiler.py
  - Ensures biovm_compiler.exe exists by calling bootstrap_fixed.py ribosome or fallback-copying biovm_native.exe.
  - Exit code 0 on success, non-zero on failure.

- run_compiler_if_exists.ps1
  - PowerShell wrapper to run biovm_compiler.exe if present; otherwise dumps workspace for debugging.

Usage:
  - On CI windows-latest runner:
    python tools/ensure_biovm_compiler.py
    powershell -File tools/run_compiler_if_exists.ps1