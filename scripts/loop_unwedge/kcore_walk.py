#!/usr/bin/env python3
# kcore_walk.py — READ-ONLY /proc/kcore walker for the sess141 loop0
# flush_rq strand. Layouts are 6.8.0-101-generic, extracted from vmlinux BTF
# via pahole (see pahole_layouts.txt in this directory). No writes anywhere.
#
# Usage: sudo python3 kcore_walk.py <lo_addr_hex>
#   lo_addr from lo_capture.bt (kprobe on lo_ioctl + losetup trigger).
#
# Dumps: loop_device state, rootcg_cmd_list, rootcg_work decode, per-blkcg
# loop_worker rbtree, lo->workqueue pwqs -> worker_pool worklist / idle /
# busy_hash (with task-validity cross-check against /proc), each busy
# worker's ->scheduled list, and the hctx0 blk_flush_queue state machine.

import bisect, os, struct, sys

KADDR_MIN = 0xffff800000000000

class Kcore:
    def __init__(self, path="/proc/kcore"):
        self.f = open(path, "rb", buffering=0)
        hdr = self.f.read(64)
        assert hdr[:4] == b"\x7fELF"
        e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
        e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
        self.segs = []
        self.f.seek(e_phoff)
        pht = self.f.read(e_phentsize * e_phnum)
        for i in range(e_phnum):
            p_type, _fl = struct.unpack_from("<II", pht, i * e_phentsize)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset, p_vaddr, _pa, _fsz, p_memsz = struct.unpack_from(
                "<QQQQQ", pht, i * e_phentsize + 8)
            self.segs.append((p_vaddr, p_memsz, p_offset))
        self.segs.sort()
        self.starts = [s[0] for s in self.segs]

    def read(self, addr, size):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            raise IOError(f"addr {addr:#x} below all segments")
        va, msz, off = self.segs[i]
        if addr + size > va + msz:
            raise IOError(f"addr {addr:#x}+{size} outside segment")
        self.f.seek(off + (addr - va))
        d = self.f.read(size)
        if len(d) != size:
            raise IOError(f"short read at {addr:#x}")
        return d

    def u64(self, a): return struct.unpack("<Q", self.read(a, 8))[0]
    def u32(self, a): return struct.unpack("<I", self.read(a, 4))[0]
    def s32(self, a): return struct.unpack("<i", self.read(a, 4))[0]
    def u8(self, a):  return self.read(a, 1)[0]
    def cstr(self, a, maxlen=64):
        d = self.read(a, maxlen)
        n = d.find(b"\0")
        return d[:n if n >= 0 else maxlen].decode(errors="replace")

class Ksyms:
    def __init__(self):
        self.addrs, self.names = [], []
        self.byname = {}
        with open("/proc/kallsyms") as f:
            rows = []
            for line in f:
                p = line.split()
                if len(p) < 3:
                    continue
                a = int(p[0], 16)
                if a == 0:
                    continue
                rows.append((a, p[2]))
                self.byname.setdefault(p[2], a)
            rows.sort()
            for a, n in rows:
                self.addrs.append(a); self.names.append(n)

    def sym(self, addr):
        if addr == 0: return "NULL"
        if addr < KADDR_MIN: return f"{addr:#x}(!kaddr)"
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i < 0: return f"{addr:#x}(?)"
        off = addr - self.addrs[i]
        if off > 0x100000: return f"{addr:#x}(?)"
        return f"{self.names[i]}+{off:#x}" if off else self.names[i]

kc = Kcore()
ks = Ksyms()

def walk_list(head, entry_off, cap=64):
    """Yield struct addresses for a list_head-linked list."""
    try:
        nxt = kc.u64(head)
    except IOError as e:
        print(f"   [list head @{head:#x} unreadable: {e}]")
        return
    seen = set()
    while nxt != head and len(seen) < cap:
        if nxt < KADDR_MIN or nxt in seen:
            print(f"   [list corrupt/loop at {nxt:#x}]")
            return
        seen.add(nxt)
        yield nxt - entry_off
        nxt = kc.u64(nxt)

lo = int(sys.argv[1], 16)
W = lo + 136  # &lo->rootcg_work

print(f"=== loop_device @ {lo:#x} ===")
print(f"lo_number={kc.s32(lo)} lo_flags={kc.u32(lo+24):#x} lo_state={kc.s32(lo+120)} use_dio={kc.u8(lo+248)}")
bf = kc.u64(lo + 96)
print(f"lo_backing_file={bf:#x}")
wq = kc.u64(lo + 128)
q = kc.u64(lo + 256)
print(f"workqueue={wq:#x} name={kc.cstr(wq+176, 24)!r} wq.flags={kc.u32(wq+256):#x}")
print(f"lo_queue={q:#x}")

print(f"\n=== rootcg_cmd_list @ {lo+168:#x} ===")
n = 0
for cmd in walk_list(lo + 168, 0):
    n += 1
    rq = cmd - 272
    print(f" cmd@{cmd:#x} use_aio={kc.u8(cmd+16)} ret={struct.unpack('<q', kc.read(cmd+24,8))[0]} css={kc.u64(cmd+88):#x}")
    print(f"   rq@{rq:#x} tag={kc.s32(rq+32)} cmd_flags={kc.u32(rq+24):#x} rq_flags={kc.u32(rq+28):#x} state={kc.u32(rq+148)} ref={kc.u32(rq+152)} end_io={ks.sym(kc.u64(rq+256))}")
print(f" -> {n} entries")

print(f"\n=== rootcg_work @ {W:#x} ===")
data = kc.u64(W)
func = kc.u64(W + 24)
print(f"data={data:#x} PENDING={data&1} INACTIVE={(data>>1)&1} PWQ={(data>>2)&1} LINKED={(data>>3)&1}")
print(f"func={ks.sym(func)}")
if (data >> 2) & 1:
    pwq = data & ~0xFF
    print(f" queued on pwq@{pwq:#x} pool@{kc.u64(pwq):#x} pool_id={kc.s32(kc.u64(pwq)+12)} pwq.wq={kc.u64(pwq+8):#x}")
else:
    print(f" offq: last pool_id={data >> 5}")
we_next, we_prev = kc.u64(W + 8), kc.u64(W + 16)
print(f"entry.next={we_next:#x} entry.prev={we_prev:#x} self={W+8:#x} listed={we_next != W+8}")

print(f"\n=== per-blkcg loop_workers (worker_tree @ {lo+200:#x}) ===")
def rb_walk(node, depth=0):
    if node == 0 or depth > 12:
        return
    if node < KADDR_MIN:
        print(f"   [rb corrupt {node:#x}]"); return
    rb_walk(kc.u64(node + 16), depth + 1)  # left
    lw = node  # rb_node at offset 0
    wdata = kc.u64(lw + 24)
    ncmd = sum(1 for _ in walk_list(lw + 56, 0))
    print(f" loop_worker@{lw:#x} css={kc.u64(lw+96):#x} work.data={wdata:#x} PENDING={wdata&1} cmds={ncmd} last_ran_at={kc.u64(lw+104):#x}")
    for cmd in walk_list(lw + 56, 0):
        rq = cmd - 272
        print(f"    cmd@{cmd:#x} rq tag={kc.s32(rq+32)} cmd_flags={kc.u32(rq+24):#x}")
    rb_walk(kc.u64(node + 8), depth + 1)  # right
rb_root = kc.u64(lo + 200)
if rb_root == 0:
    print(" (tree empty)")
else:
    rb_walk(rb_root)

print(f"\n=== idle_worker_list @ {lo+184:#x} ===")
for lw in walk_list(lo + 184, 72):
    print(f" idle loop_worker@{lw:#x} css={kc.u64(lw+96):#x} work.data={kc.u64(lw+24):#x} cmds={sum(1 for _ in walk_list(lw+56,0))}")

def task_info(t):
    if t == 0:
        return "task=NULL"
    try:
        comm = kc.cstr(t + 3032, 16)
        pid = kc.s32(t + 2488)
        st = kc.u32(t + 24)
        ex = kc.s32(t + 2384)
        alive = "?"
        if 0 < pid < 4194304:
            try:
                with open(f"/proc/{pid}/comm") as f:
                    pc = f.read().strip()
                alive = f"PROC_ALIVE({pc})" if pc == comm.split("+")[0][:15] or comm.startswith(pc[:13]) else f"PROC_MISMATCH({pc})"
            except OSError:
                alive = "NO_PROC_ENTRY"
        return f"task@{t:#x} pid={pid} comm={comm!r} __state={st:#x} exit_state={ex:#x} {alive}"
    except IOError as e:
        return f"task@{t:#x} UNREADABLE({e})"

print(f"\n=== workqueue pools (wq @ {wq:#x}) ===")
seen_pools = set()
for pwq in walk_list(wq + 0, 120):
    pool = kc.u64(pwq)
    print(f"\npwq@{pwq:#x} refcnt={kc.s32(pwq+24)} pool@{pool:#x}")
    ninact = sum(1 for _ in walk_list(pwq + 104, 8))
    for wk in walk_list(pwq + 104, 8):
        mark = "  <=== lo->rootcg_work!" if wk == W else ""
        print(f"  inactive_works: work@{wk:#x} func={ks.sym(kc.u64(wk+24))}{mark}")
    if pool in seen_pools:
        print("  (pool already dumped)")
        continue
    seen_pools.add(pool)
    print(f"  pool id={kc.s32(pool+12)} cpu={kc.s32(pool+4)} node={kc.s32(pool+8)} flags={kc.u32(pool+16):#x} nr_running={kc.s32(pool+36)} nr_workers={kc.s32(pool+56)} nr_idle={kc.s32(pool+60)}")
    nwl = 0
    for wk in walk_list(pool + 40, 8):
        nwl += 1
        mark = "  <=== lo->rootcg_work!" if wk == W else ""
        print(f"  worklist: work@{wk:#x} func={ks.sym(kc.u64(wk+24))}{mark}")
    if nwl == 0:
        print("  worklist: empty")
    nbusy = 0
    for b in range(64):
        head = pool + 192 + b * 8
        node = kc.u64(head)
        seen = set()
        while node and node not in seen and len(seen) < 32:
            seen.add(node)
            if node < KADDR_MIN:
                print(f"  busy_hash[{b}] corrupt node {node:#x}"); break
            wk = node  # hentry at offset 0
            nbusy += 1
            cw = kc.u64(wk + 16)
            cf = kc.u64(wk + 24)
            cpwq = kc.u64(wk + 32)
            t = kc.u64(wk + 80)
            mark = "  <=== executing lo->rootcg_work!" if cw == W else ""
            print(f"  BUSY[{b}] worker@{wk:#x} id={kc.s32(wk+124)} flags={kc.u32(wk+120):#x} cur_work={cw:#x} cur_func={ks.sym(cf)} cur_pwq={cpwq:#x}{mark}")
            print(f"     {task_info(t)}")
            ns = 0
            for swk in walk_list(wk + 64, 8, cap=32):
                ns += 1
                m2 = "  <=== lo->rootcg_work!" if swk == W else ""
                print(f"     scheduled: work@{swk:#x} func={ks.sym(kc.u64(swk+24))}{m2}")
            if ns == 0:
                print("     scheduled: empty")
            node = kc.u64(node)  # hlist_node.next at 0
    if nbusy == 0:
        print("  busy_hash: all empty")
    print(f"  workers-attached ({pool+712:#x}):")
    for wk in walk_list(pool + 712, 96):
        t = kc.u64(wk + 80)
        print(f"   worker@{wk:#x} id={kc.s32(wk+124)} flags={kc.u32(wk+120):#x} cur_work={kc.u64(wk+16):#x} {task_info(t)}")
    ndy = 0
    for wk in walk_list(pool + 728, 96):
        ndy += 1
        print(f"   DYING worker@{wk:#x} id={kc.s32(wk+124)} {task_info(kc.u64(wk+80))}")
    if ndy == 0:
        print("   dying_workers: empty")

print(f"\n=== flush machinery (q @ {q:#x}) ===")
nr_hw = kc.u32(q + 52)
xa_head = kc.u64(q + 56 + 8)
print(f"nr_hw_queues={nr_hw} hctx_table.xa_head={xa_head:#x}")
hctx = xa_head
if hctx & 3:
    print(f" xa_head tagged ({hctx & 3}) — not a direct entry; abort hctx decode")
else:
    hq = kc.u64(hctx + 184)
    print(f"hctx@{hctx:#x} queue={hq:#x} (match={hq == q}) queue_num={kc.u32(hctx+340)}")
    fq = kc.u64(hctx + 192)
    bits = kc.u8(fq + 4)
    print(f"fq@{fq:#x} pending_idx={bits & 1} running_idx={(bits >> 1) & 1} rq_status={kc.u8(fq+5)} data_in_flight={kc.u64(fq+48)}")
    print(f"flush_pending_since={kc.u64(fq+8):#x}")
    for i in (0, 1):
        m = 0
        for rq in walk_list(fq + 16 + i * 16, 72, cap=16):
            m += 1
            print(f" flush_queue[{i}]: rq@{rq:#x} tag={kc.s32(rq+32)} cmd_flags={kc.u32(rq+24):#x} rq_flags={kc.u32(rq+28):#x} state={kc.u32(rq+148)} flush.seq={kc.u32(rq+232)} end_io={ks.sym(kc.u64(rq+256))}")
        if m == 0:
            print(f" flush_queue[{i}]: empty")
    frq = kc.u64(fq + 56)
    print(f"flush_rq@{frq:#x} tag={kc.s32(frq+32)} state={kc.u32(frq+148)} ref={kc.u32(frq+152)} cmd_flags={kc.u32(frq+24):#x} rq_flags={kc.u32(frq+28):#x} end_io={ks.sym(kc.u64(frq+256))}")
    fcmd = frq + 272
    fn, fp = kc.u64(fcmd), kc.u64(fcmd + 8)
    print(f"flush_rq pdu(loop_cmd)@{fcmd:#x} list_entry.next={fn:#x} prev={fp:#x} self={fcmd:#x} on_list={fn != fcmd}")
    print(f"  pdu css={kc.u64(fcmd+88):#x} use_aio={kc.u8(fcmd+16)} ret={struct.unpack('<q', kc.read(fcmd+24,8))[0]}")

print("\nDONE (read-only)")
