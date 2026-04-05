import sys
import struct
import os

def check_pe(filepath):
    print(f"--- DIAGNOSING: {filepath} ---")
    if not os.path.exists(filepath):
        print("Error: File not found.")
        return

    with open(filepath, "rb") as f:
        data = f.read()

    print(f"File Size: {len(data)} bytes")

    # 1. DOS Header
    if data[0:2] != b'MZ':
        print("FATAL: No MZ signature.")
        return
    
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    print(f"e_lfanew (PE Header Offset): {hex(e_lfanew)}")

    # 2. PE Header
    pe_sig = data[e_lfanew:e_lfanew+4]
    if pe_sig != b'PE\x00\x00':
        print(f"FATAL: Invalid PE signature: {pe_sig}")
        return

    # File Header
    machine, num_sects = struct.unpack_from("<HH", data, e_lfanew + 4)
    print(f"Machine: {hex(machine)} (Expect 0x14c for i386)")
    print(f"Number of Sections: {num_sects}")

    # Optional Header
    opt_offset = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    print(f"Optional Header Magic: {hex(magic)} (Expect 0x10b for PE32)")

    # Alignment & Sizes
    entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
    image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
    sect_align = struct.unpack_from("<I", data, opt_offset + 32)[0]
    file_align = struct.unpack_from("<I", data, opt_offset + 36)[0]
    size_image = struct.unpack_from("<I", data, opt_offset + 56)[0]
    size_headers = struct.unpack_from("<I", data, opt_offset + 60)[0]

    print(f"EntryPoint: {hex(entry_point)}")
    print(f"SectionAlignment: {hex(sect_align)}")
    print(f"FileAlignment: {hex(file_align)}")
    print(f"SizeOfImage: {hex(size_image)}")
    print(f"SizeOfHeaders: {hex(size_headers)}")

    if file_align != 0x200:
        print("WARNING: FileAlignment is usually 0x200.")
    
    if len(data) < size_headers:
        print("FATAL: File is smaller than header definition!")

    # Data Directories (Import Table is index 1)
    dir_offset = opt_offset + 96
    import_rva, import_size = struct.unpack_from("<II", data, dir_offset + 8) # Index 1
    print(f"Import Directory RVA: {hex(import_rva)}, Size: {hex(import_size)}")

    # 3. Section Headers
    sect_table_offset = opt_offset + 224 # Standard PE32 opt header size assumed
    # Adjust if NumberOfRvaAndSizes != 16, but usually it is.
    
    print("\n[Section Table]")
    print("Name     VirtAddr  VirtSize  RawAddr   RawSize")
    print("-------  --------  --------  --------  --------")
    
    found_import_in_section = False
    
    for i in range(num_sects):
        off = sect_table_offset + (i * 40)
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        v_size, v_addr, r_size, r_addr = struct.unpack_from("<IIII", data, off + 8)
        
        print(f"{name:<8} {hex(v_addr):<9} {hex(v_size):<9} {hex(r_addr):<9} {hex(r_size):<9}")

        # Validation
        if r_addr % file_align != 0:
            print(f"  -> ERROR: RawAddr not aligned to {hex(file_align)}")
        if r_size % file_align != 0:
            print(f"  -> ERROR: RawSize not aligned to {hex(file_align)}")
        if r_addr + r_size > len(data):
             print(f"  -> FATAL: Section extends beyond file end! (Req: {r_addr+r_size}, Actual: {len(data)})")

        # Check Import
        if import_rva >= v_addr and import_rva < v_addr + v_size:
            print(f"  -> Info: Import Directory is in this section.")
            found_import_in_section = True
            
            # Detailed Import Check
            # Check if RVA points to valid raw data
            raw_import_offset = r_addr + (import_rva - v_addr)
            if raw_import_offset + import_size > len(data):
                print("  -> FATAL: Import data is truncated in file.")

    if not found_import_in_section and import_size > 0:
        print("\nFATAL: Import Directory RVA does not fall into any section!")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        check_pe(sys.argv[1])
    else:
        print("Usage: python diagnose_pe.py <path_to_exe>")
