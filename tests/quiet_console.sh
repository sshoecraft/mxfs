#!/bin/bash
# quiet_console.sh — the remote snippet every marking/harvesting harness must
# run instead of `dmesg -n 8`.  Source it; it exports $QUIET_CONSOLE.
#
# ─── WHY THIS FILE EXISTS (ccloop c7ee71c6 sess130) ─────────────────────────
#
# `dmesg -n 8` DOES NOT AFFECT WHAT `dmesg` CAN HARVEST.  printk always stores
# every message into the kernel ring buffer; the console loglevel gates only
# what is additionally pushed to the CONSOLE.  So the `dmesg -n 8` that
# cc_grantwait.sh and cc_bastcensus.sh used to run before marking bought
# nothing at all for harvesting — and cost enormously.
#
# THE COST, MEASURED ON THIS RIG.  Every test VM has an emulated isa-serial
# console backed by a host file:
#     <serial type='pty'> <log file='/var/log/libvirt/qemu/testN-serial.log'/>
# At console loglevel 8 every mxfs pr_warn/pr_info goes through that emulated
# 16550 UART, synchronously, under console_lock.  MXFS's ALWAYS-ON probes are
# thousands of lines per node per run (P170-CLWR alone is ~800/node, plus
# P-DIRBAST, P50-RD, P144-WR, P218-*, P265-BASTQ-STATS...).
#
# DIRECT EVIDENCE (sess130): crash_consistency on a VIRGIN fs, 0.11.453, quiet
# rig (hostload 11.08):
#     with `dmesg -n 8` set by the mark harness  -> FAIL 0/32 90s/90s
#                                                   NO_TERMINAL_RECORD=32
#                                                   7061 mxfs lines written to
#                                                   test1's serial log
#     without it (run.sh's own printk='1 4 1 1')  -> see the ledger entry
# run.sh's prep_cluster deliberately sets `sysctl -w kernel.printk='1 4 1 1'`
# on every node for exactly this reason.  A harness that silently reverses that
# is measuring the console, not the filesystem.
#
# The project already documented the sibling trap for mxfs.instr
# (tests/cluster_authority_merge.sh: instr=1 turned a PASS 32/32 109s into a
# FAIL 0/32 111s).  This is the same trap through a different knob, and it
# fires even with instr=0.
#
# So: never raise the console loglevel to mark a window.  RE-ASSERT the quiet
# level instead, so the harness guarantees the non-perturbing state rather than
# merely not breaking it.
QUIET_CONSOLE="sysctl -w kernel.printk='1 4 1 1' >/dev/null 2>&1;"
export QUIET_CONSOLE
