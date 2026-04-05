# quick_check_abs.py
import sys, struct
def find_pe(b):
    if b[0:2]!=b'MZ':
        return None
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe+4]!=b'PE\x00\x00':
        return None
    return pe

def parse_sections(b, pe):
    num = struct.unpack_from("<H", b, pe+6)[0]
    opt_size = struct.unpack_from("<H", b, pe+20)[0]
    sect_table = pe + 24 + opt_size
    secs = []
    for i in range(num):
        off = sect_table + i*40
        name = b[off:off+8].rstrip(b'\x00').decode(errors='ignore')
        vs, va, rs, ra = struct.unpack_from("<IIII", b, off+8)
        secs.append((name, vs, va, rs, ra))
    return secs

def hexdump(b):
    return ' '.join(f"{x:02X}" for x in b)

if __name__=="__main__":
    if len(sys.argv)<2:
        print("Usage: quick_check_abs.py <file>")
        sys.exit(1)
    fn = sys.argv[1]
    b = open(fn,'rb').read()
    pe = find_pe(b)
    if pe is None:
        print("Not a PE")
        sys.exit(1)
    print("PE at",hex(pe))
    secs = parse_sections(b, pe)
    for s in secs:
        print(s)
    # search for IMAGE_BASE dword pattern in first 64KB
    pattern = b'\x00\x00\x40\x00'
    locs = [i for i in range(min(len(b),0x10000)-3) if b[i:i+4]==pattern]
    print("Found IMAGE_BASE pattern locations (first 64KB):", locs[:20])
    # Dump first 64 bytes of .text (if present)
    text = next((s for s in secs if s[0]=='.text'), None)
    if text:
        name, vs, va, rs, ra = text
        print(".text: VA",hex(va),"Raw@",&ra if False else ra,"SizeRaw",hex(rs))
        start = ra
        sample = b[start:start+64]
        print("first 64b of .text:", hexdump(sample))
    else:
        print("No .text found")