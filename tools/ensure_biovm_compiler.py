#!/usr/bin/env python3
# tools/ensure_biovm_compiler.py
# Ensure biovm_compiler.exe exists by invoking bootstrap_fixed.py (ribosome) or fallback copy.
# Improved: auto-detect reasonable .bio sources and accept env override.

import os
import sys
import shutil
import subprocess

# Allow overriding from environment (convenience for CI)
ENV_SRC = os.environ.get("BIO_SRC")  # optional override

# candidate list (order of preference)
CANDIDATES = [
    "compiler_v16_titan.bio",
    "compiler_v15_native.bio",
    "compiler_v14_bitpacker.bio",
    "compiler_v15.bio",
    "compiler_v14.bio",
]

if ENV_SRC:
    SRC_BIO = ENV_SRC
else:
    SRC_BIO = None
    for c in CANDIDATES:
        if os.path.exists(c):
            SRC_BIO = c
            break

DST_EXE = "biovm_compiler.exe"
BOOTSTRAP = "bootstrap_fixed.py"
NATIVE = "biovm_native.exe"

def try_ribosome():
    if not os.path.exists(BOOTSTRAP):
        print("[ensure] bootstrap_fixed.py not found, cannot ribosome.", file=sys.stderr)
        return False
    if not SRC_BIO:
        print("[ensure] No .bio source found (checked candidates).", file=sys.stderr)
        print(f"[ensure] Candidates: {CANDIDATES}", file=sys.stderr)
        return False
    if not os.path.exists(SRC_BIO):
        print(f"[ensure] source {SRC_BIO} not found on disk, cannot ribosome.", file=sys.stderr)
        return False
    try:
        cmd = [sys.executable, BOOTSTRAP, "ribosome", SRC_BIO, DST_EXE]
        print(f"[ensure] Running: {' '.join(cmd)}")
        subprocess.check_call(cmd)
        exists = os.path.exists(DST_EXE)
        print(f"[ensure] After ribosome: {DST_EXE} exists? {exists}")
        return exists
    except subprocess.CalledProcessError as e:
        print(f"[ensure] ribosome failed: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[ensure] ribosome unexpected error: {e}", file=sys.stderr)
        return False

def try_fallback_copy():
    if os.path.exists(NATIVE):
        try:
            shutil.copyfile(NATIVE, DST_EXE)
            print(f"[ensure] Fallback: copied {NATIVE} -> {DST_EXE}")
            return True
        except Exception as e:
            print(f"[ensure] Fallback copy failed: {e}", file=sys.stderr)
            return False
    else:
        print(f"[ensure] No fallback native ({NATIVE}) found.", file=sys.stderr)
        return False

def main():
    if os.path.exists(DST_EXE):
        print(f"[ensure] {DST_EXE} already exists, nothing to do.")
        return 0

    ok = try_ribosome()
    if ok:
        print(f"[ensure] Successfully created {DST_EXE} via ribosome.")
        return 0

    print("[ensure] ribosome did not produce the compiler; trying fallback copy...")
    if try_fallback_copy():
        return 0

    print("[ensure] Could not produce biovm_compiler.exe. Workspace dump:", file=sys.stderr)
    for root, dirs, files in os.walk("."):
        for f in files:
            print(os.path.join(root, f))
    return 2

if __name__ == "__main__":
    sys.exit(main())