# bootstrap_driver.py
from pe_builder import build_pe_from_parts

# ExitProcess スタブ（確実に実行される）
CODE = bytes([
    0x31, 0xC9,             # xor ecx, ecx
    0xFF, 0x15, 0,0,0,0     # call [ExitProcess]（仮）
])

build_pe_from_parts("biovm_gen0.exe", CODE, b"", ["ExitProcess"])
print("[OK] biovm_gen0.exe created")