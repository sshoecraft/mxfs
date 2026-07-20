# gdb -P helper: print the scsi_atomic_blocked_cmds edge arrays for the
# wedged commands on a device.  Companion to scst_atomic_wedge_diag.py —
# that script prints per-cmd counts; this one prints WHO each blocker blocks
# so the full deadlock graph can be reconstructed.
#
# Run (same symbol setup as scst_atomic_wedge_diag.py):
#   cd /sys/module/scst/sections && sudo gdb -q -batch -ex "set confirm off" \
#     -ex "add-symbol-file /lib/modules/$(uname -r)/extra/scst.ko $(cat .text) \
#          -s .data $(cat .data) -s .bss $(cat .bss) -s .rodata $(cat .rodata)" \
#     -ex "core-file /proc/kcore" -x /src/mxfs/scripts/scst_atomic_edges.py

import gdb


def offsetof(struct, member):
    return int(gdb.parse_and_eval(f"(unsigned long)&(({struct} *)0)->{member}"))


def walk_list(head_addr, struct, member):
    off = offsetof(struct, member)
    ptype = gdb.lookup_type(struct).pointer()
    ulong = gdb.lookup_type("unsigned long")
    head = int(head_addr)
    nxt = int(gdb.parse_and_eval(f"((struct list_head *){head})->next"))
    seen = 0
    while nxt != head:
        yield gdb.Value(nxt - off).cast(ulong).cast(ptype)
        nxt = int(gdb.parse_and_eval(f"((struct list_head *){nxt})->next"))
        seen += 1
        if seen > 256:
            print("  ... (list truncated at 256)")
            break


def kallsyms(name):
    with open("/proc/kallsyms") as f:
        for line in f:
            parts = line.split()
            if parts[2] == name:
                return int(parts[0], 16)
    raise KeyError(name)


def main():
    head = kallsyms("scst_dev_list")
    for dev in walk_list(head, "struct scst_device", "dev_list_entry"):
        try:
            name = dev["virt_name"].string() if int(dev["virt_name"]) else "<scsi-dev>"
        except gdb.error:
            name = "<unreadable>"
        if name != "disk1":
            continue
        for cmd in walk_list(dev["dev_exec_cmd_list"].address,
                             "struct scst_cmd", "dev_exec_cmd_list_entry"):
            cnt = int(cmd["scsi_atomic_blocked_cmds_count"])
            arr = cmd["scsi_atomic_blocked_cmds"]
            edges = []
            if cnt and int(arr):
                for i in range(min(cnt, 32)):
                    edges.append(f"{int(arr[i]):#x}")
            print(f"cmd {int(cmd):#x} op={int(cmd['cdb'][0]):#x} "
                  f"blockers={int(cmd['scsi_atomic_blockers'])} "
                  f"blocks[{cnt}]: {' '.join(edges)}")


main()
