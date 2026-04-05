import sys,struct
IMAGE_BASE=0x400000
SECT_ALIGN=0x1000
FILE_ALIGN=0x200
SAFE_DATA_SIZE=0x8000
FUNCS=["ExitProcess","CreateFileA","ReadFile","WriteFile","CloseHandle","GetStdHandle"]
def align(val,al):
    return (val+al-1)&~(al-1)
def to_u32(val):
    return int(val&0xFFFFFFFF).to_bytes(4,'little')
def to_i32(val):
    val=int(val)
    return (val-0x100000000 if val>=0x80000000 else val).to_bytes(4,'little',signed=True)
def build_idata_content(rva_base,funcs):
    buf=bytearray()
    buf.extend(b'\x00'*40)
    table_size=(len(funcs)+1)*4
    ilt_off=len(buf)
    buf.extend(b'\x00'*table_size)
    iat_off=len(buf)
    buf.extend(b'\x00'*table_size)
    name_offsets=[]
    for f in funcs:
        blob=b'\x00\x00'+f.encode('ascii')+b'\x00'
        if len(blob)%2!=0:
            blob+=b'\x00'
        name_offsets.append(len(buf))
        buf.extend(blob)
    dll_off=len(buf)
    buf.extend(b"KERNEL32.dll\x00")
    if rva_base>0:
        struct.pack_into("<IIIII",buf,0,rva_base+ilt_off,0,0,rva_base+dll_off,rva_base+iat_off)
        for i,noff in enumerate(name_offsets):
            val=rva_base+noff
            struct.pack_into("<I",buf,ilt_off+i*4,val)
            struct.pack_into("<I",buf,iat_off+i*4,val)
    return bytes(buf),iat_off
def calculate_layout(code_len,data_len):
    rva_text=0x1000
    pre_size=16
    raw_text=align(pre_size+code_len,FILE_ALIGN)
    vsize_text=align(pre_size+code_len,SECT_ALIGN)
    rva_data=rva_text+vsize_text
    idata_dummy,_=build_idata_content(0,FUNCS)
    off_vars=align(len(idata_dummy),16)
    total_data=off_vars+data_len
    raw_data=align(max(total_data,SAFE_DATA_SIZE),FILE_ALIGN)
    vsize_data=align(max(total_data,SAFE_DATA_SIZE),SECT_ALIGN)
    _,iat_rel=build_idata_content(rva_data,FUNCS)
    return {"rva_text":rva_text,"raw_text":raw_text,"vsize_text":vsize_text,"rva_data":rva_data,"raw_data":raw_data,"vsize_data":vsize_data,"iat_rva":rva_data+iat_rel,"vars_off":off_vars,"size_of_image":rva_data+vsize_data}
def compile_instruction(cmd,arg,labels,curr_off,vars,data_base,iat_rva):
    blob=b''
    if cmd=="ENCODE": blob=b"\x68"+to_i32(arg)
    elif cmd=="ENCODE_ADDR": blob=b"\x68"+to_u32(data_base+vars.get(arg,0))
    elif cmd=="ADD": blob=b"\x5B\x58\x01\xD8\x50"
    elif cmd=="SUB": blob=b"\x5B\x58\x29\xD8\x50"
    elif cmd=="MUL": blob=b"\x5B\x58\x0F\xAF\xC3\x50"
    elif cmd=="DIV": blob=b"\x5B\x58\x99\xF7\xFB\x50"
    elif cmd=="MOD": blob=b"\x5B\x58\x99\xF7\xFB\x52"
    elif cmd=="AND": blob=b"\x5B\x58\x21\xD8\x50"
    elif cmd=="OR": blob=b"\x5B\x58\x09\xD8\x50"
    elif cmd=="XOR": blob=b"\x5B\x58\x31\xD8\x50"
    elif cmd=="SHL": blob=b"\x59\x58\xD3\xE0\x50"
    elif cmd=="SHR": blob=b"\x59\x58\xD3\xE8\x50"
    elif cmd=="NOT": blob=b"\x58\xF7\xD0\x50"
    elif cmd=="LOAD": blob=b"\x5F\xFF\x37"
    elif cmd=="STORE": blob=b"\x5F\x58\x89\x07"
    elif cmd=="LOAD_B": blob=b"\x5B\x0F\xB6\x03\x50"
    elif cmd=="STORE_B": blob=b"\x5F\x58\x88\x07"
    elif cmd=="DROP": blob=b"\x58"
    elif cmd=="DUP": blob=b"\xFF\x34\x24"
    elif cmd=="MATCH": blob=b"\x81\x3C\x24"+to_i32(arg)
    elif cmd=="JUMP" or cmd=="JUMP_EQ":
        op=b"\xE9" if cmd=="JUMP" else b"\x0F\x84"
        sz=5 if cmd=="JUMP" else 6
        target=labels.get(arg,curr_off+sz)
        blob=op+to_i32(target-(curr_off+sz))
    elif cmd=="EXPRESS":
        idx=FUNCS.index(arg) if arg in FUNCS else 0
        blob=b"\xFF\x15"+to_u32(IMAGE_BASE+iat_rva+idx*4)+b"\x50"
    else:
        print("FAIL: Unknown opcode "+cmd)
        sys.exit(1)
    return blob
def parse_val(v):
    if v.startswith('"'):
        return v[1:-1].encode()+b'\x00'
    elif v.startswith('[') and v.endswith(']'):
        return b'\x00'*int(v[1:-1])
    else:
        return b'\x00'*4
def main():
    if len(sys.argv)<3:
        return
    src=sys.argv[2]
    out=sys.argv[3]
    with open(src,'r') as f:
        lines=f.read().splitlines()
    vars={}
    curr=0
    mode_nucleus=False
    for l in lines:
        l=l.split(';')[0].strip()
        if not l or l in ["[GENOME]","STRINGS"]:
            continue
        if l=="[NUCLEUS]":
            mode_nucleus=True
            continue
        if not mode_nucleus and "=" in l:
            k,v=l.split("=",1)
            k=k.strip()
            v=v.strip()
            val=parse_val(v)
            while curr%4!=0:
                curr+=1
            vars[k]=curr
            curr+=len(val)
    db=bytearray(curr)
    cf=0
    mode_nucleus=False
    for l in lines:
        l=l.split(';')[0].strip()
        if not l or l in ["[GENOME]","STRINGS"]:
            continue
        if l=="[NUCLEUS]":
            mode_nucleus=True
            continue
        if not mode_nucleus and "=" in l:
            v=l.split("=",1)[1].strip()
            val=parse_val(v)
            while cf%4!=0:
                cf+=1
            db[cf:cf+len(val)]=val
            cf+=len(val)
    lbs={}
    co=16
    mode_nucleus=False
    for l in lines:
        l=l.split(';')[0].strip()
        if not l or l in ["[GENOME]","STRINGS"] or "=" in l:
            if l=="[NUCLEUS]":
                mode_nucleus=True
            continue
        if mode_nucleus:
            if l.startswith("MARKER"):
                lbs[l.split()[1]]=co
                continue
            co+=len(compile_instruction(l.split()[0],l.split()[1] if " " in l else "0",{},0,vars,0,0))
    lo=calculate_layout(co-16,len(db))
    real_db=IMAGE_BASE+lo["rva_data"]+lo["vars_off"]
    cd=bytearray()
    co=16
    mode_nucleus=False
    for l in lines:
        l=l.split(';')[0].strip()
        if not l or l in ["[GENOME]","STRINGS"] or "=" in l or l.startswith("MARKER"):
            if l=="[NUCLEUS]":
                mode_nucleus=True
            continue
        if mode_nucleus:
            blob=compile_instruction(l.split()[0],l.split()[1] if " " in l else "0",lbs,co,vars,real_db,lo["iat_rva"])
            cd.extend(blob)
            co=len(cd)+16
    dos=b"MZ"+b"\x00"*58+struct.pack("<I",0x80)+b"\x00"*64
    pe=b"PE\x00\x00"+struct.pack("<HHIIIHH",0x014C,2,0,0,0,0xE0,0x0102)
    opt=struct.pack("<HBBIIIIIIIIIIHHHHHHIIIIHHIIIIII",0x10B,6,0,lo["vsize_text"],lo["vsize_data"],0,lo["rva_text"],lo["rva_text"],lo["rva_data"],IMAGE_BASE,SECT_ALIGN,FILE_ALIGN,6,0,0,0,6,0,0,lo["size_of_image"],0x200,0,3,0,0x100000,0x1000,0x100000,0x1000,0,16)
    dd=struct.pack("<II",0,0)+struct.pack("<II",lo["rva_data"],40)+b"\x00"*(8*14)
    sh=b".text\x00\x00\x00"+struct.pack("<IIIIIIHHI",lo["vsize_text"],lo["rva_text"],lo["raw_text"],0x200,0,0,0,0,0x60000020)
    sh+=b".data\x00\x00\x00"+struct.pack("<IIIIIIHHI",lo["vsize_data"],lo["rva_data"],lo["raw_data"],0x200+lo["raw_text"],0,0,0,0,0xC0000040)
    headers=(dos+pe+opt+dd+sh).ljust(0x200,b'\x00')
    body_text=(b'\x90'*16+cd).ljust(lo["raw_text"],b'\x00')
    idata_bin,_=build_idata_content(lo["rva_data"],FUNCS)
    body_data=(idata_bin.ljust(lo["vars_off"],b'\x00')+db).ljust(lo["raw_data"],b'\x00')
    with open(out,'wb') as f:
        f.write(headers+body_text+body_data)
if __name__=="__main__":
    main()
