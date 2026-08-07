#!/usr/bin/env drgn
# wq_probe.py — READ-ONLY drgn probe for the sess141 loop0 flush_rq strand.
#
# Anchors on /sys/kernel/debug/block/loop0/hctx0 (dir inode i_private ==
# struct blk_mq_hw_ctx *, set by blk-mq-debugfs debugfs_create_files) so no
# module symbol lookup is needed; all layouts come from kernel/module BTF.
#
# Dumps, without writing anything:
#   1. loop_device identity (backing file, flags, state)
#   2. rootcg_cmd_list contents (is the stranded flush cmd parked there?)
#   3. rootcg_work.data decode (PENDING? on which pool/pwq?)
#   4. per-blkcg loop_worker rbtree (other cmd lists + work states)
#   5. lo->workqueue -> every pwq -> pool: worklist, idle/busy counts,
#      busy_hash walk — looking for a worker whose current_func is a loop
#      work fn but whose task is dead/garbage (the busy_hash-swallow theory)
#      + each busy worker's ->scheduled list
#   6. hctx->fq flush state machine: pending/running idx, both flush_queue
#      lists, flush_data_in_flight, flush_rq state
#
# Run: sudo PYTHONPATH=<site-packages> /home/steve/.local/bin/drgn wq_probe.py

import drgn
from drgn import Object, cast, sizeof
from drgn.helpers.linux.fs import path_lookup
from drgn.helpers.linux.list import list_for_each_entry, list_empty, list_for_each

def sym(addr):
    try:
        a = int(addr)
    except Exception:
        return "?"
    if a == 0:
        return "NULL"
    try:
        s = prog.symbol(a)
        off = a - s.address
        return f"{s.name}+{off:#x}" if off else s.name
    except Exception:
        return f"{a:#x}(nosym)"

def safe_str(obj):
    try:
        return obj.string_().decode(errors="replace")
    except Exception as e:
        return f"<unreadable {type(e).__name__}>"

print("=== anchor: debugfs hctx0 ===")
p = path_lookup(prog, "/sys/kernel/debug/block/loop0/hctx0")
hctx = cast("struct blk_mq_hw_ctx *", p.dentry.d_inode.i_private)
print(f"hctx = {hctx.value_():#x}  queue_num={int(hctx.queue_num)}")
q = hctx.queue
disk = q.disk
print(f"q = {q.value_():#x}  disk name = {safe_str(disk.disk_name)}")
lo = cast("struct loop_device *", disk.private_data)
print(f"lo = {lo.value_():#x}")

print("\n=== 1. loop_device ===")
print(f"lo_state={int(lo.lo_state)} lo_flags={int(lo.lo_flags):#x} (DIRECT_IO=0x10 per LO_FLAGS)")
bf = lo.lo_backing_file
try:
    print(f"backing dentry name = {safe_str(bf.f_path.dentry.d_name.name)}")
except Exception as e:
    print(f"backing file read fail: {e}")
print(f"lo_device=major{int(lo.lo_device.bd_dev)>>20}:minor{int(lo.lo_device.bd_dev)&0xfffff}" if lo.lo_device else "no bdev")
wq = lo.workqueue
print(f"lo->workqueue = {wq.value_():#x}  name={safe_str(wq.name)} flags={int(wq.flags):#x}")

print("\n=== 2. rootcg_cmd_list ===")
rq_sz = sizeof(prog.type("struct request"))
n = 0
for cmd in list_for_each_entry("struct loop_cmd", lo.rootcg_cmd_list.address_of_(), "list_entry"):
    n += 1
    rq = Object(prog, "struct request *", value=cmd.value_() - rq_sz)
    try:
        print(f"  cmd@{cmd.value_():#x} rq@{rq.value_():#x} tag={int(rq.tag)} cmd_flags={int(rq.cmd_flags):#x} rq_flags={int(rq.rq_flags):#x} state={int(rq.state)}")
    except Exception as e:
        print(f"  cmd@{cmd.value_():#x} rq read fail: {e}")
print(f"rootcg_cmd_list: {n} entries (empty={bool(list_empty(lo.rootcg_cmd_list.address_of_()))})")

print("\n=== 3. rootcg_work ===")
w = lo.rootcg_work
data = int(w.data.counter)
print(f"&lo->rootcg_work = {w.address_of_().value_():#x}  func={sym(w.func)}")
print(f"work.data = {data:#x}  PENDING={data & 1}  PWQ_bit={(data >> 2) & 1}  LINKED={(data >> 3) & 1}")
if (data >> 2) & 1:
    pwq_addr = data & ~0xFF
    print(f"  -> queued: pwq @ {pwq_addr:#x}")
    try:
        dpwq = Object(prog, "struct pool_workqueue *", value=pwq_addr)
        print(f"     pwq.wq={dpwq.wq.value_():#x} ({safe_str(dpwq.wq.name)}) pool={dpwq.pool.value_():#x} pool_id={int(dpwq.pool.id)}")
    except Exception as e:
        print(f"     pwq decode fail: {e}")
else:
    print(f"  -> offq: last pool_id = {data >> 5}")
ent = w.entry
print(f"work.entry.next={int(ent.next):#x} prev={int(ent.prev):#x} (self={ent.address_of_().value_():#x}; self==next means unlisted)")

print("\n=== 4. per-blkcg loop_workers (rbtree) ===")
try:
    from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry
    nw = 0
    for lw in rbtree_inorder_for_each_entry("struct loop_worker", lo.worker_tree.address_of_(), "rb_node"):
        nw += 1
        wdata = int(lw.work.data.counter)
        print(f"  loop_worker@{lw.value_():#x} css={lw.blkcg_css.value_():#x} cmd_list_empty={bool(list_empty(lw.cmd_list.address_of_()))} work.data={wdata:#x} PENDING={wdata & 1}")
    print(f"{nw} per-blkcg workers")
except Exception as e:
    print(f"rbtree walk fail: {e}")

print("\n=== 5. lo->workqueue pools ===")
seen_pools = {}
for pwq in list_for_each_entry("struct pool_workqueue", wq.pwqs.address_of_(), "pwqs_node"):
    pool = pwq.pool
    pid_ = int(pool.id)
    if pid_ in seen_pools:
        continue
    seen_pools[pid_] = pool
    print(f"\n-- pool id={pid_} @ {pool.value_():#x} cpu={int(pool.cpu)} node={int(pool.node)} nr_workers={int(pool.nr_workers)} nr_idle={int(pool.nr_idle)} nr_running={int(pool.nr_running)}")
    nwl = 0
    for wk in list_for_each_entry("struct work_struct", pool.worklist.address_of_(), "entry"):
        nwl += 1
        mark = "  <=== lo->rootcg_work!" if wk.value_() == w.address_of_().value_() else ""
        print(f"   worklist: work@{wk.value_():#x} func={sym(wk.func)}{mark}")
        if nwl > 40:
            print("   ... (truncated)")
            break
    if nwl == 0:
        print("   worklist: empty")
    # busy_hash walk
    from drgn.helpers.linux.list import hlist_for_each_entry
    nbusy = 0
    for bkt in range(len(pool.busy_hash)):
        for wker in hlist_for_each_entry("struct worker", pool.busy_hash[bkt].address_of_(), "hentry"):
            nbusy += 1
            t = wker.task
            tinfo = "task=NULL"
            if t:
                try:
                    comm = safe_str(t.comm)
                    st = int(t.__state)
                    ex = int(t.exit_state)
                    pidn = int(t.pid)
                    tinfo = f"task@{t.value_():#x} pid={pidn} comm={comm!r} __state={st:#x} exit_state={ex:#x}"
                except Exception as e:
                    tinfo = f"task@{t.value_():#x} UNREADABLE({type(e).__name__})"
            print(f"   BUSY[{bkt}] worker@{wker.value_():#x} cur_work={int(wker.current_work):#x} cur_func={sym(wker.current_func)}")
            print(f"        {tinfo}")
            ns = 0
            for swk in list_for_each_entry("struct work_struct", wker.scheduled.address_of_(), "entry"):
                ns += 1
                mark = "  <=== lo->rootcg_work!" if swk.value_() == w.address_of_().value_() else ""
                print(f"        scheduled: work@{swk.value_():#x} func={sym(swk.func)}{mark}")
                if ns > 20:
                    print("        ... (truncated)")
                    break
            if ns == 0:
                print("        scheduled: empty")
    if nbusy == 0:
        print("   busy_hash: empty")

print("\n=== 6. flush state machine (hctx->fq) ===")
fq = hctx.fq
print(f"fq @ {fq.value_():#x} flush_pending_idx={int(fq.flush_pending_idx)} flush_running_idx={int(fq.flush_running_idx)} rq_status={int(fq.rq_status)}")
try:
    jn = prog["jiffies_64"]
    now = int(jn)
except Exception:
    now = None
try:
    fps = int(fq.flush_pending_since)
    if now:
        print(f"flush_pending_since={fps:#x} (age ~{(now - fps)//250}s @HZ=250)" )
    else:
        print(f"flush_pending_since={fps:#x}")
except Exception as e:
    print(f"pending_since fail: {e}")
for i in (0, 1):
    m = 0
    for rq in list_for_each_entry("struct request", fq.flush_queue[i].address_of_(), "queuelist"):
        m += 1
        try:
            print(f"  flush_queue[{i}]: rq@{rq.value_():#x} tag={int(rq.tag)} cmd_flags={int(rq.cmd_flags):#x} rq_flags={int(rq.rq_flags):#x} state={int(rq.state)} end_io={sym(rq.end_io)}")
        except Exception as e:
            print(f"  flush_queue[{i}]: rq@{rq.value_():#x} read fail {e}")
        if m > 10:
            break
    if m == 0:
        print(f"  flush_queue[{i}]: empty")
m = 0
for rq in list_for_each_entry("struct request", fq.flush_data_in_flight.address_of_(), "queuelist"):
    m += 1
    print(f"  flush_data_in_flight: rq@{rq.value_():#x} tag={int(rq.tag)}")
if m == 0:
    print("  flush_data_in_flight: empty")
frq = fq.flush_rq
print(f"flush_rq @ {frq.value_():#x} tag={int(frq.tag)} state={int(frq.state)} cmd_flags={int(frq.cmd_flags):#x} rq_flags={int(frq.rq_flags):#x} end_io={sym(frq.end_io)}")
fcmd = Object(prog, "struct loop_cmd *", value=frq.value_() + rq_sz)
print(f"flush_rq pdu (loop_cmd) @ {fcmd.value_():#x} css={int(fcmd.blkcg_css) if hasattr(fcmd, 'blkcg_css') else '?'}")
print(f"  cmd.list_entry.next={int(fcmd.list_entry.next):#x} prev={int(fcmd.list_entry.prev):#x} (self={fcmd.list_entry.address_of_().value_():#x})")
print("\nDONE (read-only)")
