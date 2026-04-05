# pe_builder.py
import struct

def align(v, a):
    return (v + a - 1) & ~(a - 1)

def build_pe_from_parts(dst, code_bytes, data_bytes, imports):
    FILE_ALIGN = 0x200
    SECT_ALIGN = 0x1000

    # --- DOS header ---
    mz = bytearray(b"MZ")
    mz += b"\x90" * 58
    e_lfanew = 0x80
    mz += struct.pack("<I", e_lfanew)
    mz += b"\x00" * (e_lfanew - len(mz))

    # --- PE header ---
    pe = bytearray(b"PE\x00\x00")
    pe += struct.pack("<H", 0x8664)     # x64
    pe += struct.pack("<H", 1)          # sections
    pe += b"\x00" * 12
    pe += struct.pack("<H", 0xF0)
    pe += struct.pack("<H", 0x2022)

    # --- Optional header ---
    opt = bytearray()
    opt += struct.pack("<H", 0x20B)
    opt += b"\x00" * 14
    opt += struct.pack("<I", 0x1000)    # Entry
    opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<Q", 0x400000)
    opt += struct.pack("<I", SECT_ALIGN)
    opt += struct.pack("<I", FILE_ALIGN)
    opt += b"\x00" * 64
    opt += struct.pack("<I", align(len(code_bytes), SECT_ALIGN))
    opt += struct.pack("<I", 0x200)
    opt += b"\x00" * (0xF0 - len(opt))

    # --- Section header ---
    sh = bytearray(b".text\x00\x00\x00")
    sh += struct.pack("<I", len(code_bytes))
    sh += struct.pack("<I", 0x1000)
    sh += struct.pack("<I", align(len(code_bytes), FILE_ALIGN))
    sh += struct.pack("<I", 0x200)
    sh += b"\x00" * 16
    sh += struct.pack("<I", 0x60000020)

    headers = mz + pe + opt + sh
    headers += b"\x00" * (0x200 - len(headers))

    body = code_bytes + b"\x00" * (align(len(code_bytes), FILE_ALIGN) - len(code_bytes))

    with open(dst, "wb") as f:
        f.write(headers)
        f.write(body)