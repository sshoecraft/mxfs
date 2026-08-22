#!/usr/bin/env python3
"""verdict.py — score one arm of the PR in-flight exclusion A/B.

Reads an arm directory produced by inflight_ab.sh and places every event on the
single host monotonic timeline (ftrace runs with trace_clock=mono, so its
timestamps ARE CLOCK_MONOTONIC and compare directly with prprobe's
clock_gettime output).  Scores the three properties separately and applies the
sess133 RULE-5 validity predicate.

Usage: verdict.py <armdir> [--json]
"""
import os
import re
import sys
import json

RE_FUNC = re.compile(r"^\s*\S+\s+\[\d+\]\s+\S+\s+(\d+\.\d+):\s+(\w+)\s+<-")
# The three block tracepoints print DIFFERENT shapes after the rw field:
#   block_bio_queue:    7,0 W 135168 + 8 [comm]
#   block_rq_issue:     7,0 W 4096 () 135168 + 8 [comm]      <- extra nr_bytes
#   block_rq_complete:  7,0 W () 135168 + 8 [0]
# Both the nr_bytes and the (cmd) field must therefore be optional, or
# block_rq_issue silently never parses and the report shows "--" for an event
# that IS in the trace.  Backtracking resolves the bio_queue case correctly.
RE_TP = re.compile(
    r"^\s*\S+\s+\[\d+\]\s+\S+\s+(\d+\.\d+):\s+(block_\w+):\s+(\d+),(\d+)\s+(\S+)"
    r"(?:\s+\d+)?(?:\s+\(\S*\))?\s+(\d+)\s+\+\s+(\d+)")

# Initiator-side error recovery.  A run that coincides with any of these is
# INVALID, not "the target blocked correctly" (ruling).
#
# NOTE: "reservation conflict" is deliberately NOT in this list.  Property (C)
# provokes exactly one on purpose, so a blanket match here scores a perfectly
# good run INVALID (it did, on the sess133 0x04 run).  Conflicts are instead
# accounted exactly, by item 4b below: the number of sd-layer conflict lines
# must equal the number of probe commands that actually reported
# RESERVATION_CONFLICT.  That is strictly stronger than the blanket match --
# it catches an unexpected conflict AND an unexplained one.
EH_MARKERS = [
    "DID_TIME_OUT", "timing out command", "abort_task", "ABORT TASK",
    "task abort", "scsi_eh", "SCSI EH", "Unhandled error code",
    "connection.*error", "session recovery", "conn .* error",
    "iscsi: cmd .* is not in", "target reset", "bus reset", "host reset",
    "LUN reset",
]

# One line per command the SCSI midlayer completed with RESERVATION CONFLICT.
RE_SD_CONFLICT = re.compile(r"sd \d+:\d+:\d+:\d+: reservation conflict", re.I)

# TARGET-STACK LINES ARE NOT INITIATOR ERROR RECOVERY.
#
# EH_MARKERS exists to invalidate a run that coincided with INITIATOR error
# recovery.  But clyde runs the target too, and SCST's 'pr' tracing is
# deliberately left on, so the same dmesg carries the target's own task-
# management activity -- which on the 0x05 arm is THE MECHANISM UNDER TEST:
#
#   scst: scst_abort_task_set:5560:Aborting task set (lun=0, mcmd=...)
#
# That line is PREEMPT AND ABORT doing exactly what it promises, and a blanket
# case-insensitive match on "abort_task" scored a perfect safety arm INVALID.
# It is the same failure as the "reservation conflict" marker sess133 removed:
# a marker that matches the deliberate behaviour.  It could only ever surface
# on the 0x05 arm, because plain PREEMPT (0x04) never issues PR_ABORT_ALL --
# which is why stage (i), 0x04-only, never caught it.
#
# SCST's trace format stamps every one of its own lines with the emitting pid
# in brackets ("[632981]: ..."), immediately after the kernel timestamp.  The
# initiator's messages never carry it ("sd 12:0:0:0: reservation conflict").
# So the pid-bracket IS the target/initiator discriminator, and it is a
# structural one rather than a keyword blacklist.  Target lines are removed
# before EH scanning and reported separately, so nothing is hidden.
RE_TARGET_STACK = re.compile(r"^(?:\[[\d\s.]+\]\s*)?\[\d+\]:")
RE_TM_ACTIVITY = re.compile(r"scst_abort_task_set|PR_ABORT_ALL|scst_abort_cmd")


def split_stacks(dmesg):
    """-> (initiator_only_text, target_stack_lines)"""
    ini, tgt = [], []
    for ln in dmesg.splitlines():
        (tgt if RE_TARGET_STACK.search(ln) else ini).append(ln)
    return "\n".join(ini), tgt


def readenv(p):
    env = {}
    with open(p) as f:
        for ln in f:
            if "=" in ln:
                k, v = ln.strip().split("=", 1)
                env[k] = v
    return env


def kv(line):
    out = {}
    for tok in line.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = v
    return out


def find_line(path, prefix):
    if not os.path.exists(path):
        return None
    with open(path, errors="replace") as f:
        for ln in f:
            if ln.startswith(prefix):
                return ln.strip()
    return None


def parse_trace(path, majmin_loop, majmin_dm, lba, nsect):
    """Return (funcs, blk) — funcs: name -> [ts]; blk: list of dicts."""
    funcs = {}
    blk = []
    if not os.path.exists(path):
        return funcs, blk
    with open(path, errors="replace") as f:
        for ln in f:
            if ln.startswith("#"):
                continue
            m = RE_TP.match(ln)
            if m:
                ts, ev, maj, mi, rw, sect, cnt = m.groups()
                dev = "%s,%s" % (maj, mi)
                sect = int(sect)
                cnt = int(cnt)
                # Only the request that carries our observation block.
                if not (sect <= lba < sect + max(cnt, 1)):
                    continue
                if dev not in (majmin_loop, majmin_dm):
                    continue
                blk.append(dict(ts=float(ts), ev=ev, dev=dev, rw=rw,
                                sector=sect, nsect=cnt))
                continue
            m = RE_FUNC.match(ln)
            if m:
                ts, fn = m.groups()
                funcs.setdefault(fn, []).append(float(ts))
    return funcs, blk


def first(lst):
    return min(lst) if lst else None


def last(lst):
    return max(lst) if lst else None


def fmt(t, base):
    if t is None:
        return "        --      "
    return "%+12.6f" % (t - base) if base is not None else "%.6f" % t


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    d = sys.argv[1]
    want_json = "--json" in sys.argv
    env = readenv(os.path.join(d, "arm.env"))
    sa = env["SA"]
    lba = int(env["LBA"])
    lba_c = int(env["LBA_C"])
    pat = int(env["PAT"], 16)
    pat_c = int(env["PAT_C"], 16)
    clean = int(env["CLEAN"], 16)

    def majmin(devno):
        n = int(devno)
        return "%d,%d" % (n // 1048576, n % 1048576)

    mm_loop = majmin(env["LOOP_DEVNO"])
    mm_dm = majmin(env["DM_DEVNO"])

    # The block tracepoints below dm-delay carry the PHYSICAL sector, which is
    # the LUN LBA only in blockio mode.  In fileio mode the LUN is a file, so
    # the sector to correlate on is the FIEMAP-resolved one recorded by
    # inflight_ab.sh.  Older arm directories predate PHYS_LBA512 and are
    # blockio-only, where the two are equal by construction.
    sect_lba = int(env.get("PHYS_LBA512", lba))

    funcs, blk = parse_trace(os.path.join(d, "trace.txt"), mm_loop, mm_dm, sect_lba, 8)

    def blk_ts(ev, dev, rw_has="W"):
        c = [b["ts"] for b in blk
             if b["ev"] == ev and b["dev"] == dev and rw_has in b["rw"]]
        return first(c)

    t_bio_dm = blk_ts("block_bio_queue", mm_dm)
    t_issue_loop = blk_ts("block_rq_issue", mm_loop)
    t_land = blk_ts("block_rq_complete", mm_loop)

    t_do_preempt = first(funcs.get("scst_pr_do_preempt", []))
    t_pa = first(funcs.get("scst_pr_preempt_and_abort", []))
    t_abort_reg = first(funcs.get("scst_pr_abort_reg", []))
    # scst_cmd_done_pr_preempt is installed as the PROUT command's cmd_done hook
    # and fires once per pending PR_ABORT_ALL mgmt cmd plus once for the PROUT's
    # own exec-done; only the call that drives pr_abort_pending_cnt to 0 restores
    # saved_cmd_done and actually completes the PROUT (scst_pres.c:2228-2244).
    # That is the LAST one, and it is still strictly earlier than the wire GOOD
    # (saved_cmd_done only hands the cmd to the transport xmit path).  Taking
    # first() here would be earlier than the real completion and could fail the
    # safety arm spuriously.  Only one PROUT is inside the trace window --
    # setup PROUTs run before ftrace is armed and the PRINs after it is stopped.
    done_pr_all = funcs.get("scst_cmd_done_pr_preempt", [])
    t_done_pr = last(done_pr_all)
    t_done_pr_first = first(done_pr_all)

    pr_issue = kv(find_line(os.path.join(d, "prout.txt"), "prout_issue") or "")
    pr_done = kv(find_line(os.path.join(d, "prout.txt"), "prout_done") or "")
    w_issue = kv(find_line(os.path.join(d, "victim_write.txt"), "write_issue") or "")
    w_done = kv(find_line(os.path.join(d, "victim_write.txt"), "write_done") or "")
    wc_done = kv(find_line(os.path.join(d, "victim_write_post.txt"), "write_done") or "")
    poll_end = kv(find_line(os.path.join(d, "poll.txt"), "poll_end") or "")
    poll_fp = kv(find_line(os.path.join(d, "poll.txt"), "poll_first_present") or "")

    t_prout_sub = float(pr_issue.get("t_pre", "nan")) if pr_issue else None
    t_prout_ret = float(pr_done["t_return"]) if pr_done.get("t_return") else None
    t_w_sub = float(w_issue["t_pre"]) if w_issue.get("t_pre") else None
    t_w_ret = float(w_done["t_return"]) if w_done.get("t_return") else None
    t_poll_first = float(poll_fp["t"]) if poll_fp.get("t") else None

    base = t_w_sub or t_prout_sub or t_land

    # ------------------------------------------------------------- properties
    # Boundary is chosen per arm so each direction is CONSERVATIVE.
    if sa == "0x05":
        boundary_name = ("scst_cmd_done_pr_preempt, last of %d (ftrace, strictly "
                         "EARLIER than wire GOOD)" % len(done_pr_all))
        boundary = t_done_pr
    else:
        boundary_name = "userspace PROUT return (strictly LATER than wire GOOD)"
        boundary = t_prout_ret

    landed = t_land is not None
    final_obs = find_line(os.path.join(d, "final_read.txt"), "dread ")
    final_first = None
    if final_obs:
        final_first = int(kv(final_obs).get("first", "0x0"), 16)

    prop_a = (not landed) and (final_first != pat) and \
        (poll_end.get("present") == "0")

    # (B) LINEARIZATION: no victim modification becomes observable at or after
    # the PR completed.  If the victim's write never reached the medium at all
    # there is no modification to order, so (B) holds vacuously -- but only once
    # the boundary itself is established, otherwise the arm proved nothing.
    prop_b = None
    if boundary is not None:
        prop_b = (t_land < boundary) if landed else True
    violation_shown = None
    if sa == "0x04" and landed and boundary is not None:
        violation_shown = t_land > boundary

    # (C): a NEW victim write after the fence must get RESERVATION CONFLICT and
    # must not modify the store.
    c_conflict = wc_done.get("RESERVATION_CONFLICT") == "1" or \
        wc_done.get("scsi_status") == "0x18"
    finals = []
    if os.path.exists(os.path.join(d, "final_read.txt")):
        with open(os.path.join(d, "final_read.txt"), errors="replace") as f:
            finals = [kv(l) for l in f if l.startswith("dread ")]
    c_first = int(finals[1]["first"], 16) if len(finals) > 1 else None
    prop_c = bool(c_conflict) and (c_first == clean)

    # -------------------------------------------------------------- validity
    v = {}
    v["1_two_distinct_nexuses"] = env["VICTIM_IQN"] != env["SURVIVOR_IQN"] \
        and env["VICTIM"] != env["SURVIVOR"]
    before = open(os.path.join(d, "pr_before.txt"), errors="replace").read() \
        if os.path.exists(os.path.join(d, "pr_before.txt")) else ""
    after = open(os.path.join(d, "pr_after.txt"), errors="replace").read() \
        if os.path.exists(os.path.join(d, "pr_after.txt")) else ""
    vk = "0x00000000feed0001"
    sk = "0x00000000feed0002"
    v["2_keys_as_intended"] = (vk in before) and (sk in before)
    runlog = open(os.path.join(d, "run.log"), errors="replace").read() \
        if os.path.exists(os.path.join(d, "run.log")) else ""
    # The command must be shown IN the victim's task set at the target (SCST's
    # own per-session active_commands) AND at the block layer below the target.
    # Both, not either: the first proves the target admitted it, the second
    # proves it was really issued downward and is what dm-delay is holding.
    v["3_write_observed_in_flight"] = ("in-flight observed" in runlog) \
        and (t_bio_dm is not None)
    dmesg = ""
    if os.path.exists(os.path.join(d, "dmesg.txt")):
        dmesg = open(os.path.join(d, "dmesg.txt"), errors="replace").read()
    dmesg_ini, tgt_lines = split_stacks(dmesg)
    tm_lines = [l for l in tgt_lines if RE_TM_ACTIVITY.search(l)]
    eh_hits = [m for m in EH_MARKERS if re.search(m, dmesg_ini, re.I)]
    v["4_no_eh_reset_timeout"] = not eh_hits
    # 4d: item 4 is only meaningful if the window's kernel log was actually
    # CAPTURED.  An empty or truncated dmesg.txt makes "no EH markers" true
    # vacuously -- the single most dangerous way for this harness to report a
    # clean run.  The arm stamps a unique token into /dev/kmsg at its start and
    # slices from it; if the token is not in the file, the printk ring buffer
    # evicted the window and the evidence is LOST, not absent.
    tok_p = os.path.join(d, "dmesg_token.txt")
    tok = open(tok_p, errors="replace").read().strip() \
        if os.path.exists(tok_p) else ""
    if tok:
        v["4d_dmesg_window_captured"] = tok in dmesg
    else:
        # Pre-token artifact: fall back to "the capture is non-empty", which is
        # weaker but still catches the failure that motivated this item.
        v["4d_dmesg_window_captured"] = bool(dmesg.strip())
    # 4b: every RESERVATION CONFLICT in the window must be accounted for by a
    # probe command that reported one.  An unexplained conflict means some
    # command we did not intend was rejected -- exactly the "the write was never
    # admitted" wrong answer -- and invalidates the arm.
    n_conflict_dmesg = len(RE_SD_CONFLICT.findall(dmesg))
    probes = [w_done, wc_done]
    n_conflict_probe = sum(1 for p in probes
                           if p.get("RESERVATION_CONFLICT") == "1"
                           or p.get("scsi_status") == "0x18")
    v["4b_conflicts_all_accounted"] = (n_conflict_dmesg == n_conflict_probe)
    # 4c: the HELD write must have been ADMITTED, not rejected before execution
    # ("the write was never admitted" is the wrong answer that would fake a PASS).
    #
    # Admission is proven by item 3 -- the command counted in the victim's task
    # set AT THE TARGET, and its bio queued at dm-delay below the target.  A
    # rejected command never reaches either.  The initiator-side completion is
    # therefore only a NEGATIVE check: if the write did come back, it must not
    # have come back as RESERVATION CONFLICT.
    #
    # It legitimately may not come back at all.  PREEMPT AND ABORT with TAS off
    # is REQUIRED to drop the victim's command without notification, so an absent
    # write_done is the CORRECT target behavior for the 0x05 arm, not a broken
    # measurement.  Requiring it here would fail the safety arm for doing the
    # right thing.
    v["4c_held_write_admitted"] = \
        w_done.get("RESERVATION_CONFLICT") != "1" and \
        w_done.get("scsi_status") != "0x18"
    v["5_one_scsi_good"] = pr_done.get("good") == "1"
    # 6: TARGET-observed service action, from ftrace on SCST's own PR entry
    # points -- direct evidence of which code path the target took, and immune
    # to the SCST trace level being off.  scst_pr_preempt() calls
    # scst_pr_do_preempt(abort=false) and never touches scst_pr_abort_reg();
    # scst_pr_preempt_and_abort() calls scst_pr_do_preempt(abort=true), which
    # calls scst_pr_abort_reg() per preempted registrant (scst_pres.c:2110-2186,
    # 2213-2278).  So the two service actions are distinguishable by presence.
    if sa == "0x05":
        v["6_target_observed_sa"] = (t_pa is not None) and \
            (t_do_preempt is not None) and (t_abort_reg is not None)
    else:
        v["6_target_observed_sa"] = (t_do_preempt is not None) and \
            (t_pa is None) and (t_abort_reg is None)
    # 7: one common timeline.  Requires the completion boundary to exist and
    # ftrace to have been on CLOCK_MONOTONIC -- that is the only reason an
    # ftrace timestamp may be compared with a userspace clock_gettime stamp.
    # It must NOT require t_land: an arm where the write never reaches the
    # medium is a legitimate (and better) outcome, not a broken measurement.
    tclk_p = os.path.join(d, "trace_clock.txt")
    tclk = open(tclk_p, errors="replace").read() if os.path.exists(tclk_p) else ""
    v["7_common_timeline"] = (boundary is not None) and ("[mono]" in tclk)
    # The held write may have had to be released by a session teardown AFTER the
    # measurement window closed (0x05 + TAS off).  That teardown is initiator
    # error recovery by construction, so it is captured separately and reported
    # rather than hidden -- item 4 still scores dmesg.txt, the window itself.
    held_answered = None
    if "HELD_WRITE_ANSWERED" in env:      # absent in pre-restructure artifacts
        held_answered = env["HELD_WRITE_ANSWERED"] == "1"
    held_by = env.get("HELD_WRITE_RELEASED_BY", "not recorded")
    dmesg_post = ""
    if os.path.exists(os.path.join(d, "dmesg_post.txt")):
        dmesg_post = open(os.path.join(d, "dmesg_post.txt"),
                          errors="replace").read()
    dmesg_post_ini, _ = split_stacks(dmesg_post)
    post_eh_hits = [m for m in EH_MARKERS if re.search(m, dmesg_post_ini, re.I)]

    v["8_post_state_correct"] = (vk not in after) and (sk in after)
    v["9_post_fence_conflict"] = bool(c_conflict)
    v["10_replay_gate"] = None    # only meaningful in the real-MXFS stage (C3)

    valid = all(x for k, x in v.items() if x is not None)

    # ----------------------------------------------------------------- report
    L = []
    L.append("=" * 78)
    L.append("PR IN-FLIGHT EXCLUSION — arm SA=%s   (%s)" % (sa, d))
    L.append("=" * 78)
    L.append("timeline (seconds relative to the victim write submit):")
    rows = [
        ("victim write submit (userspace)", t_w_sub),
        ("write bio queued at dm-delay   ", t_bio_dm),
        ("PROUT submit (userspace)       ", t_prout_sub),
        ("scst_pr_do_preempt             ", t_do_preempt),
        ("scst_pr_preempt_and_abort      ", t_pa),
        ("scst_pr_abort_reg              ", t_abort_reg),
        ("delayed write issued to loop   ", t_issue_loop),
        ("LOWER-DEVICE WRITE COMPLETE    ", t_land),
        ("poller first sees the pattern  ", t_poll_first),
        ("scst_cmd_done_pr_preempt first ", t_done_pr_first),
        ("scst_cmd_done_pr_preempt LAST  ", t_done_pr),
        ("PROUT return (userspace)       ", t_prout_ret),
        ("victim write return (userspace)", t_w_ret),
    ]
    for name, t in rows:
        L.append("   %s  %s" % (name, fmt(t, base)))
    L.append("")
    L.append("boundary for this arm: %s" % boundary_name)
    L.append("   t_land   = %s" % ("%.6f" % t_land if t_land else "--"))
    L.append("   boundary = %s" % ("%.6f" % boundary if boundary else "--"))
    if t_land is not None and boundary is not None:
        L.append("   margin   = %+.6f s  (land - boundary)" % (t_land - boundary))
    L.append("")
    L.append("PROPERTIES")
    L.append("  (A) CANCELLATION  : %s   [victim bytes never observable]"
             % ("PASS" if prop_a else "FAIL"))
    L.append("  (B) LINEARIZATION : %s   [no victim modification at/after PR completion]"
             % ("PASS" if prop_b else ("FAIL" if prop_b is not None else "n/a")))
    if sa == "0x04":
        L.append("  ->  VIOLATION SHOWN: %s   [0x04 let the write land AFTER the PR returned]"
                 % ("YES" if violation_shown else "NO"))
    L.append("  (C) CONT. EXCLUSION: %s   [post-fence victim write -> RESERVATION CONFLICT, store unchanged]"
             % ("PASS" if prop_c else "FAIL"))
    L.append("")
    L.append("VALIDITY PREDICATE")
    for k in sorted(v):
        val = v[k]
        L.append("  %-28s %s" % (k, "n/a" if val is None else ("ok" if val else "VIOLATED")))
    if eh_hits:
        L.append("  initiator EH markers seen: %s" % ", ".join(eh_hits))
    L.append("  reservation conflicts: %d in dmesg, %d reported by probes"
             % (n_conflict_dmesg, n_conflict_probe))
    if held_answered is None:
        L.append("  held write answered by the target: not recorded "
                 "(pre-restructure artifact)")
    else:
        L.append("  held write answered by the target: %s"
                 % ("yes" if held_answered
                    else "NO — dropped without a response, released by %s "
                         "post-window" % held_by))
    if post_eh_hits:
        L.append("  post-window EH (dmesg_post.txt, OUTSIDE the measurement "
                 "window, expected when the write had to be released): %s"
                 % ", ".join(post_eh_hits))
    L.append("  target-stack TM activity in window (EXPECTED on 0x05, not "
             "initiator EH): %d line(s)" % len(tm_lines))
    for l in tm_lines[:4]:
        L.append("     %s" % l.strip()[:150])
    L.append("  target PR path (ftrace): do_preempt=%s preempt_and_abort=%s "
             "abort_reg=%s cmd_done_pr_preempt=%d"
             % (t_do_preempt is not None, t_pa is not None,
                t_abort_reg is not None, len(done_pr_all)))
    L.append("")
    L.append("RUN IS %s" % ("VALID" if valid else "INVALID — do not interpret"))
    L.append("=" * 78)
    print("\n".join(L))

    if want_json:
        out = dict(sa=sa, dir=d, valid=valid, prop_a=prop_a, prop_b=prop_b,
                   prop_c=prop_c, violation_shown=violation_shown,
                   t_land=t_land, boundary=boundary,
                   boundary_name=boundary_name, validity=v,
                   n_conflict_dmesg=n_conflict_dmesg,
                   n_conflict_probe=n_conflict_probe,
                   held_write_answered=held_answered,
                   held_write_released_by=held_by,
                   post_window_eh=post_eh_hits,
                   target_tm_lines=len(tm_lines),
                   ftrace=dict(do_preempt=t_do_preempt, preempt_and_abort=t_pa,
                               abort_reg=t_abort_reg,
                               cmd_done_pr_preempt_n=len(done_pr_all)),
                   margin=(t_land - boundary) if (t_land and boundary) else None)
        with open(os.path.join(d, "verdict.json"), "w") as f:
            json.dump(out, f, indent=1)
        print("wrote %s/verdict.json" % d)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
