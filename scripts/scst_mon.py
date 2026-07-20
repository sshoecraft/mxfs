#!/usr/bin/env python3
# Fast continuous monitor of ONE scst device's block state via /proc/kcore.
# Initializes drgn + offsets once, then polls sub-millisecond. Tracks peak
# on_dev_cmd_count, whether sscw/blocked ever fired, and detects a persistent
# block_count leak (nonzero for > hold seconds). Prints a summary on SIGTERM.
import os, re, signal, struct, subprocess, sys, time
import drgn

KO = "/src/scst/scst/src/scst.ko"
DEVNAME = sys.argv[1] if len(sys.argv) > 1 else "disk2"
# optional self-timeout (seconds) so the harness needn't signal across sudo
DURATION = float(sys.argv[2]) if len(sys.argv) > 2 else None

def gdb_off():
    fields = ["block_count","on_dev_cmd_count","virt_name","dev_list_entry","blocked_cmd_list","dev_scsi_atomic_cmd_active"]
    ex=[]
    for f in fields: ex += ["-ex","print &((struct scst_device *)0)->%s"%f]
    out=subprocess.check_output(["gdb","-q","-batch",KO]+ex,stderr=subprocess.DEVNULL).decode()
    nums=[int(h,16) if h else int(d) for h,d in re.findall(r"0x([0-9a-fA-F]+)|= (\d+)",out)]
    off=dict(zip(fields,nums))
    pt=subprocess.check_output(["gdb","-q","-batch",KO,"-ex","ptype /o struct scst_device"],stderr=subprocess.DEVNULL).decode()
    off["bb"]=off["sb"]=None
    for ln in pt.splitlines():
        m=re.search(r"/\*\s*(\d+):\s*(\d+)\s*\|",ln)
        if m and "strictly_serialized_cmd_waiting" in ln:
            off["bb"],off["sb"]=int(m.group(1)),int(m.group(2))
    return off

def kallsym(n):
    for line in open("/proc/kallsyms"):
        p=line.split()
        if len(p)>=3 and p[2]==n: return int(p[0],16)

off=gdb_off()
head=kallsym("scst_dev_list")
prog=drgn.program_from_kernel()
rd=lambda a,n: prog.read(a,n)
ru64=lambda a: struct.unpack("<Q",rd(a,8))[0]
ri32=lambda a: struct.unpack("<i",rd(a,4))[0]
ru32=lambda a: struct.unpack("<I",rd(a,4))[0]
def cstr(a):
    if not a: return ""
    o=b""
    while len(o)<64:
        c=rd(a+len(o),1)
        if c==b"\x00": break
        o+=c
    return o.decode(errors="replace")

# locate our device base once
base=None
node=ru64(head)
while node!=head:
    b=node-off["dev_list_entry"]
    if cstr(ru64(b+off["virt_name"]))==DEVNAME:
        base=b; break
    node=ru64(node)
if base is None: sys.exit("dev %s not found"%DEVNAME)

POISON=(0xdead000000000100, 0xdead000000000122)
def blkcnt(lh):
    # racy walk without dev_lock: bail to -1 if we hit list poison / a fault
    n=0;cur=ru64(lh)
    while cur!=lh and n<100000:
        if cur in POISON or cur < 0xffff000000000000: return -1
        n+=1;cur=ru64(cur)
    return n

OFF_AC=off["dev_scsi_atomic_cmd_active"]
peak_od=0; ever_sscw=0; peak_blk=0; peak_ac=0; leak=None
samples=0
running=[True]
def stop(*a): running[0]=False
signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)

print("monitor base=%#x dev=%s offs bc=%#x od=%#x ac=%#x bb=%s sb=%s"%(base,DEVNAME,off["block_count"],off["on_dev_cmd_count"],OFF_AC,off["bb"],off["sb"]),flush=True)
# leak = block_count, blocked_cmd_list, OR dev_scsi_atomic_cmd_active held
# nonzero with NO load (on_dev_cmd_count==0) for > 1.5s.
nonzero_since=None
t0=time.time()
while running[0]:
    if DURATION is not None and time.time()-t0>DURATION: break
    try:
        bc=ri32(base+off["block_count"])
        od=ri32(base+off["on_dev_cmd_count"])
        ac=ri32(base+OFF_AC)
        bits=ru32(base+off["bb"]) if off["bb"] is not None else 0
        sscw=(bits>>off["sb"])&1 if off["sb"] is not None else 0
        blk=blkcnt(base+off["blocked_cmd_list"])
    except drgn.FaultError:
        continue
    if blk<0: blk=0  # racy read this sample; don't treat as leak
    samples+=1
    if od>peak_od: peak_od=od
    if sscw: ever_sscw=1
    if blk>peak_blk: peak_blk=blk
    if ac>peak_ac: peak_ac=ac
    now=time.time()
    stuck = (bc!=0 or blk!=0 or ac!=0) and od==0
    if stuck:
        if nonzero_since is None: nonzero_since=now
        elif now-nonzero_since>1.5 and leak is None:
            leak=(bc,blk,ac,sscw)
            print("LEAK: block_count=%d blocked=%d atomic_active=%d sscw=%d on_dev=%d (held %.1fs)"%(bc,blk,ac,sscw,od,now-nonzero_since),flush=True)
    else:
        nonzero_since=None
print("SUMMARY dev=%s samples=%d peak_on_dev=%d peak_atomic=%d ever_sscw=%d peak_blocked=%d leak=%s"%(DEVNAME,samples,peak_od,peak_ac,ever_sscw,peak_blk,leak),flush=True)
