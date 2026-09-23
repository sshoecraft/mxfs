#!/usr/bin/env python3
"""Issue one LOGICAL UNIT RESET and report a witness bound to the invocation.

This is the userspace half of the retirement witness. The kernel module owns
the decision to fence and owns the nonce; this program owns nothing. It
performs exactly one task-management function against exactly one logical unit
and reports what it observed, in a form the module can check against what it
asked for.

WHAT THE RETURN VALUE MEANS, and why this program may issue it at all:
    ioctl(fd, SG_SCSI_RESET, SG_SCSI_RESET_DEVICE | SG_SCSI_RESET_NO_ESCALATE)
returning 0 is not "the error handler coped".  scsi_ioctl_reset() with
NO_ESCALATE maps to exactly scsi_try_bus_device_reset() with no fallthrough to
target, bus or host reset, and returns 0 only for SUCCESS;
iscsi_eh_device_reset() returns SUCCESS only from case TMF_SUCCESS; and
TMF_SUCCESS is set in exactly one place, from a received iSCSI Task Management
Response PDU carrying Function Complete.  The per-operation association is
supplied by libiscsi's one-TMF-per-session serialization rather than by task
tag matching -- iscsi_tmf_rsp() does not check the Initiator Task Tag.  The
whole argument, and the kernel versions it was audited against, are in
docs/rulings/lu-reset-witness-is-per-operation-by-serialization-not-by-tag.md.
Because it rests on that invariant and not on a protocol field, the caller must
pin the audited kernel releases; this program reports the release it ran on and
refuses to decide that question itself.

ESCALATION IS FORBIDDEN AND THAT IS LOAD-BEARING.  Without NO_ESCALATE the
kernel falls through to target, bus and host reset, and a success could come
from any of them -- a different operation with a different scope, and no
witness for the one that was asked for.

THIS PROGRAM NEVER RETRIES.  One invocation issues at most one reset.  A second
attempt is the module's decision to make, under a fresh nonce, because a reset
whose outcome is unknown is indeterminate rather than absent: killing this
process does not cancel an ioctl already executing in the kernel.

THE DEVICE IS RESOLVED BY IDENTITY, NEVER BY PATH.  The caller names the LUN by
the designator the node reports in /sys/block/<disk>/device/wwid.  A /dev/sdX
that is not that LUN is refused, and so is an ambiguous match -- resetting the
wrong logical unit destroys in-flight I/O on a device nobody was fencing.

usage:
    mxfs_lu_reset_witness.py <nonce-hex16> <wwid> <epoch> <victim-tag> [report-path]

The four required arguments are echoed back verbatim in the report so the module
can bind the result to the invocation it made.  The report is key=value lines
framed by MXFS-LURW-BEGIN / MXFS-LURW-END, always written to stdout and, when
`report-path` is given, written there too in ONE write.

report-path is how the module gets the answer, and it is not a file in the
ordinary sense: the module exports /proc/fs/mxfs/lu_reset_report, which exists
only while an invocation is outstanding and refuses a write when none is.  A
result file on disk would be stale, substitutable and replayable; a write into
the module that asked the question is none of those, and the nonce binds it to
that one question.  A write that fails is not fatal here -- the module treats a
missing report as INDETERMINATE, which is the right reading of "the helper may
have issued a reset and could not tell us".

exit 0  a reset was issued and the witness holds (WITNESSED=1)
exit 1  no reset was issued: a precondition failed (WITNESSED=0 REASON=...)
exit 2  a reset WAS issued and the witness does NOT hold -- INDETERMINATE
exit 3  usage / environment error before anything was touched
"""

import fcntl
import os
import re
import struct
import subprocess
import sys
import time

SG_SCSI_RESET = 0x2284
SG_SCSI_RESET_DEVICE = 1
SG_SCSI_RESET_NO_ESCALATE = 0x100

report = []
REPORT_PATH = None


def secure_fds():
    """Make file descriptors 0, 1 and 2 exist before anything else opens a file.

    MEASURED, not assumed: a kernel upcall gives its child the helper thread's
    file table, in which those three are CLOSED.  Two things go wrong then, and
    the second is much worse than the first.  CPython leaves sys.stdout as None
    when descriptor 1 is missing, so the first write to it raises and this
    program dies before reporting anything -- which the caller can only read as
    INDETERMINATE.  And the first os.open() in the program is handed descriptor
    0, the next 1: a later write to what the runtime still believes is standard
    output would land in whatever that descriptor now names.  In this program
    the first thing opened is the block device being reset.  So the three are
    filled with /dev/null before any other descriptor is allocated, and a file
    this program opens can never be mistaken for a stream."""
    for want in (0, 1, 2):
        try:
            os.fstat(want)
        except OSError:
            try:
                got = os.open(os.devnull, os.O_RDWR)
            except OSError:
                return
            if got != want:
                try:
                    os.dup2(got, want)
                finally:
                    os.close(got)


def emit(key, value):
    report.append("%s=%s" % (key, value))


def flush(code):
    """Frame the report and deliver it, once, on every exit path.

    EVERY exit goes through here, including the argument check, because a
    caller that gets no report at all cannot tell a helper that refused before
    touching anything from one that issued a reset and died -- and those two
    have opposite meanings.  The module's channel is written with a single
    write so a partial report can only be produced by the write itself being
    cut short, which the module detects by the missing end marker."""
    text = "MXFS-LURW-BEGIN\n" + "\n".join(report) + "\nMXFS-LURW-END\n"
    # THE CHANNEL FIRST, ALWAYS.  It is the only delivery that matters -- the
    # caller is waiting on it, and a failure printing to a terminal that may
    # not exist must never cost the report.
    if REPORT_PATH:
        try:
            fd = os.open(REPORT_PATH, os.O_WRONLY)
            try:
                os.write(fd, text.encode("utf-8", "replace"))
            finally:
                os.close(fd)
        except OSError:
            # The module reads a missing report as INDETERMINATE when the
            # command boundary was crossed, which is correct and is not
            # something this program may improve on by retrying.
            pass
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except (OSError, ValueError, AttributeError):
        pass
    sys.exit(code)


def refuse(reason, code=1):
    emit("WITNESSED", 0)
    emit("REASON", reason)
    flush(code)


def readattr(path):
    """One sysfs attribute, or None.  Never raises: an unreadable attribute is
    a fact to report, not an exception to unwind through."""
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


def normwwid(s):
    """Compare designators by content.  /sys/.../wwid prints a prefixed form
    ('naa.6e84...' or 't10.ATA ...') and callers carry whichever the rig
    declared; lowercase and drop separators so the two spellings of one LUN are
    one value.  Anything that is not hex after that is kept as-is rather than
    silently mangled into a match."""
    if s is None:
        return None
    s = s.strip().lower()
    s = re.sub(r"^(naa\.|eui\.|t10\.|0x)", "", s)
    return re.sub(r"[^0-9a-z]", "", s)


def resolve_by_wwid(want):
    """Every block device whose wwid is the one asked for.  Returns a list, and
    the caller refuses anything but exactly one -- an ambiguous match is a
    multipath map or a stale device node, and guessing between them resets a
    logical unit nobody was fencing."""
    found = []
    base = "/sys/block"
    try:
        disks = sorted(os.listdir(base))
    except OSError:
        return found
    for d in disks:
        w = readattr(os.path.join(base, d, "device", "wwid"))
        if w is not None and normwwid(w) == want:
            found.append((d, w))
    return found


def iscsi_paths(disk):
    """The iSCSI session and connection directories backing a disk, found by
    walking the device's own sysfs ancestry rather than by assuming there is
    only one session on the node."""
    try:
        real = os.path.realpath(os.path.join("/sys/block", disk, "device"))
    except OSError:
        return (None, None)
    sess = None
    part = real
    while part not in ("/", "", "/sys"):
        base = os.path.basename(part)
        if base.startswith("session") and base[7:].isdigit():
            sess = part
            break
        part = os.path.dirname(part)
    if sess is None:
        return (None, None)
    conn = None
    try:
        for e in sorted(os.listdir(sess)):
            if e.startswith("connection"):
                conn = os.path.join(sess, e, "iscsi_connection", e)
                if not os.path.isdir(conn):
                    conn = os.path.join(sess, e)
                break
    except OSError:
        conn = None
    sid = os.path.basename(sess)
    scls = os.path.join("/sys/class/iscsi_session", sid)
    return (scls if os.path.isdir(scls) else sess, conn)


# The transport incarnation, as much of it as sysfs exposes.  The session's own
# identity fields pin WHICH session; local_port pins the TCP connection, which a
# relogin replaces; exp_statsn advances as PDUs with a StatSN arrive, so it is
# corroboration that the connection was carrying traffic across the call rather
# than a fresh one wearing the same name.
SESS_FIELDS = ("state", "targetname", "initiatorname", "tpgt", "target_id",
               "ifacename", "recovery_tmo", "lu_reset_tmo")
CONN_FIELDS = ("state", "address", "port", "persistent_address",
               "persistent_port", "local_port", "exp_statsn")


def snapshot(sess, conn):
    snap = {}
    for f in SESS_FIELDS:
        snap["sess." + f] = readattr(os.path.join(sess, f)) if sess else None
    for f in CONN_FIELDS:
        snap["conn." + f] = readattr(os.path.join(conn, f)) if conn else None
    return snap


def tmfrsp_total():
    """Task-management RESPONSE PDUs the transport has counted.  This is not in
    sysfs -- it arrives over netlink -- so it costs an iscsiadm invocation and
    may legitimately be unavailable.  It is CORROBORATION, never the witness:
    the ioctl return path is the proof, and this number says the target's answer
    was counted.  Unavailable is reported as such and never as zero, because a
    zero would read as 'the target never answered'."""
    try:
        out = subprocess.run(["iscsiadm", "-m", "session", "-s"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=4).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return None
    total = 0
    seen = False
    for line in out.splitlines():
        if "tmfrsp_pdus" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[-1].isdigit():
                total += int(parts[-1])
                seen = True
    return total if seen else None


def main():
    global REPORT_PATH
    secure_fds()
    if len(sys.argv) not in (5, 6):
        emit("WITNESSED", 0)
        emit("REASON", "usage")
        flush(3)
    nonce, wwid_arg, epoch, victim = sys.argv[1:5]
    if len(sys.argv) == 6:
        REPORT_PATH = sys.argv[5]

    # Echo the invocation back first.  If this report is truncated, what
    # survives must still say which invocation it belongs to -- a witness whose
    # binding was cut off is not a witness.
    emit("NONCE", nonce)
    emit("WWID_REQ", wwid_arg)
    emit("EPOCH", epoch)
    emit("VICTIM", victim)
    emit("KREL", os.uname().release)
    emit("PID", os.getpid())

    if not re.fullmatch(r"[0-9a-fA-F]{16}", nonce):
        refuse("nonce-malformed", 3)
    want = normwwid(wwid_arg)
    if not want:
        refuse("wwid-empty", 3)

    matches = resolve_by_wwid(want)
    emit("WWID_MATCHES", len(matches))
    if len(matches) != 1:
        # Zero: the LUN this fence is about is not attached here.  More than
        # one: ambiguous, and the right device cannot be chosen by guessing.
        refuse("wwid-matches-%d" % len(matches))
    disk, wwid_seen = matches[0]
    emit("DISK", disk)
    emit("WWID_SEEN", wwid_seen)

    sess, conn = iscsi_paths(disk)
    emit("SESS_PATH", sess if sess else "none")
    emit("CONN_PATH", conn if conn else "none")
    if sess is None:
        # Not an iSCSI logical unit, so the argument that makes rc=0 a target
        # response does not apply to it.  Refuse rather than reset a device
        # whose witness would mean something else.
        refuse("not-an-iscsi-lun")

    before = snapshot(sess, conn)
    for k in sorted(before):
        emit("PRE." + k, before[k] if before[k] is not None else "")
    tmf0 = tmfrsp_total()
    emit("PRE.tmfrsp", tmf0 if tmf0 is not None else "")

    if before.get("sess.state") != "LOGGED_IN":
        # iscsi_eh_device_reset() returns FAILED without sending anything when
        # the session is not logged in.  Refusing here keeps that case out of
        # the witness path entirely.
        refuse("session-state-%s" % (before.get("sess.state") or "unknown"))

    devpath = "/dev/" + disk
    try:
        fd = os.open(devpath, os.O_RDWR)
    except OSError as e:
        refuse("open-%d" % e.errno)

    # ---- the one command this program exists to issue ----
    buf = bytearray(struct.pack("i",
                                SG_SCSI_RESET_DEVICE | SG_SCSI_RESET_NO_ESCALATE))
    t0 = time.monotonic()
    rc = 0
    try:
        fcntl.ioctl(fd, SG_SCSI_RESET, buf, True)
    except OSError as e:
        rc = e.errno if e.errno else -1
    wall_ms = int((time.monotonic() - t0) * 1000)
    os.close(fd)
    # From here the command may have reached the target whatever rc says, so
    # every exit below is INDETERMINATE rather than "nothing happened".
    emit("RESET_ISSUED", 1)
    emit("RESET_RC", rc)
    emit("RESET_WALL_MS", wall_ms)

    after = snapshot(sess, conn)
    for k in sorted(after):
        emit("POST." + k, after[k] if after[k] is not None else "")
    tmf1 = tmfrsp_total()
    emit("POST.tmfrsp", tmf1 if tmf1 is not None else "")
    emit("WWID_AFTER", readattr(os.path.join("/sys/block", disk, "device",
                                             "wwid")) or "")

    if rc != 0:
        emit("WITNESSED", 0)
        emit("REASON", "reset-rc-%d" % rc)
        flush(2)

    # The identity that must not have moved across the call.  A relogin or a
    # session replacement between the two snapshots means the success belongs to
    # a transport incarnation other than the one the module asked about, and the
    # module is told that rather than handed a witness.
    stable = ("sess.targetname", "sess.initiatorname", "sess.tpgt",
              "sess.target_id", "sess.ifacename", "conn.address", "conn.port",
              "conn.persistent_address", "conn.persistent_port",
              "conn.local_port")
    moved = [k for k in stable if before.get(k) != after.get(k)]
    if moved:
        emit("WITNESSED", 0)
        emit("REASON", "incarnation-moved:" + ",".join(moved))
        flush(2)
    if after.get("sess.state") != "LOGGED_IN":
        emit("WITNESSED", 0)
        emit("REASON", "post-session-state-%s" % (after.get("sess.state") or "unknown"))
        flush(2)
    # exp_statsn and tmfrsp are reported PRE and POST and deliberately NOT
    # asserted here: they are corroboration, and the module decides what it
    # requires of them.  This program's verdict is the ioctl result plus an
    # unmoved transport incarnation, which is what the witness argument rests
    # on; folding a corroborating counter into the verdict would let a reader
    # believe the counter was the proof.
    emit("WITNESSED", 1)
    flush(0)


if __name__ == "__main__":
    main()
