#!/usr/bin/env gdb -P
# Diagnose the SCST "EXEC_CHECK_BLOCKING forever" wedge: commands parked on a
# leaked SCSI-atomicity blocker (CAW aborted without releasing its blocked
# readers).  Read-only — walks scst_dev_list in /proc/kcore using the scst.ko
# DWARF relocated to the live module section addresses.
#
# Run:
#   sudo gdb -q -batch \
#     -ex "set confirm off" \
#     -ex "add-symbol-file /lib/modules/$(uname -r)/extra/scst.ko \
#          $(cat /sys/module/scst/sections/.text) \
#          -s .data $(cat /sys/module/scst/sections/.data) \
#          -s .bss  $(cat /sys/module/scst/sections/.bss) \
#          -s .rodata $(cat /sys/module/scst/sections/.rodata)" \
#     -ex "core-file /proc/kcore" \
#     -x scripts/scst_atomic_wedge_diag.py
#
# Background (sess43): destroying all 16 VMs mid-I/O aborted a COMPARE AND
# WRITE while overlapping READ(10)s of the CAW slot LBA were atomic-blocked
# on it.  scst_unblock_aborted_cmds() only rescues cmds on blocked_cmd_list /
# deferred_cmd_list, so atomic-blocked cmds leak; scst_suspend_activity then
# waits on them forever and `scst stop` wedges in D-state.

import gdb

SCST_CMD_ABORTED = 9  # bit number, scst.h cmd_flags


def offsetof(struct, member):
    return int(gdb.parse_and_eval(f"(unsigned long)&(({struct} *)0)->{member}"))


def walk_list(head_addr, struct, member):
    """Yield gdb.Value pointers to containing structs of a list_head."""
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


def dump_dev(dev):
    try:
        name = dev["virt_name"].string() if int(dev["virt_name"]) else "<scsi-dev>"
    except gdb.error:
        name = "<unreadable>"
    print(f"=== dev {name} ({int(dev):#x}) block_count={int(dev['block_count'])} "
          f"on_dev_cmd_count={int(dev['on_dev_cmd_count'])} "
          f"scsi_atomic_cmd_active={int(dev['dev_scsi_atomic_cmd_active'])} "
          f"double_ua_possible={int(dev['dev_double_ua_possible'])}")
    n = 0
    for cmd in walk_list(dev["dev_exec_cmd_list"].address, "struct scst_cmd",
                         "dev_exec_cmd_list_entry"):
        n += 1
        flags = int(cmd["cmd_flags"])
        aborted = bool(flags >> SCST_CMD_ABORTED & 1)
        print(f"  cmd {int(cmd):#x} state={int(cmd['state'])} "
              f"op={int(cmd['cdb'][0]):#x} lba={int(cmd['lba'])} "
              f"blockers={int(cmd['scsi_atomic_blockers'])} "
              f"blocked_cnt={int(cmd['scsi_atomic_blocked_cmds_count'])} "
              f"aborted={aborted} flags={flags:#x}")
    blocked = sum(1 for _ in walk_list(dev["blocked_cmd_list"].address,
                                       "struct scst_cmd", "blocked_cmd_list_entry"))
    print(f"  dev_exec_cmd_list={n} blocked_cmd_list={blocked}")


def kallsyms(name):
    """Address from /proc/kallsyms — immune to add-symbol-file misplacement."""
    with open("/proc/kallsyms") as f:
        for line in f:
            parts = line.split()
            if parts[2] == name:
                return int(parts[0], 16)
    raise KeyError(name)


def main():
    # Devices mid-unregister are already unlinked from scst_dev_list, so also
    # walk scst_vdisk's own vdev_list (needs scst_vdisk.ko symbols loaded).
    try:
        vhead = kallsyms("vdev_list")
        print(f"vdev_list @ {int(vhead):#x}")
        for vv in walk_list(vhead, "struct scst_vdisk_dev", "vdev_list_entry"):
            vname = vv["name"].string()
            dev = vv["dev"]
            print(f"vdev {vname} dev={int(dev):#x}")
            if int(dev):
                dump_dev(dev)
    except gdb.error as e:
        print(f"(vdev_list walk unavailable: {e})")

    head = kallsyms("scst_dev_list")
    print(f"scst_dev_list @ {int(head):#x}")
    for dev in walk_list(head, "struct scst_device", "dev_list_entry"):
        dump_dev(dev)


main()
