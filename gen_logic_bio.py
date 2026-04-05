import struct
import bootstrap_fixed as b

# Dummy GEN2 setup
vars_gen2 = {}
data_content = bytearray(64)
layout = b.calculate_layout(512, len(data_content))
gen2_bin = bytearray(b"dummy")

# --- GEN1 SOURCE ---
bio_code = []

bio_code.append('H_STD = 0')
bio_code.append('TRACE_CHAR = 0')
bio_code.append('BYTES_WRITTEN = 0')

bio_code.append('[NUCLEUS]')

# TEST: ExitProcess(42)
bio_code.append('ENCODE 42')
bio_code.append('EXPRESS ExitProcess')

# Fail Safe
bio_code.append('MARKER FAIL')
bio_code.append('ENCODE 99')
bio_code.append('EXPRESS ExitProcess')

with open("compiler_v15_native.bio", "w") as f:
    f.write("\n".join(bio_code))
