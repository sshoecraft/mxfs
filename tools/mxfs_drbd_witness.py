#!/usr/bin/env python3
"""Report what DRBD and the fence authority say about one DRBD device.

This is the userspace half of the drbd attachment's admission and fence
evidence (docs/rulings/drbd-dual-primary-attachment.md). The kernel module owns
the question, the nonce and the verdict; this program owns nothing. It reads
facts and reports them, and the module checks every field it relies on.

WHY USERSPACE. DRBD exports no in-kernel interface for its state or its
configuration. Its connection, role and disk states are in /proc/drbd and its
configuration is what drbdadm parses, so the facts are read where they are.

WHAT IT READS, for the DRBD minor the module names:
  - /proc/drbd: connection state, both roles, both disk states, the
    replication protocol and the I/O-suspended flag;
  - `drbdadm dump`: the resource's configuration as drbdadm parses it --
    protocol, allow-two-primaries, fencing policy, fence-peer handler, the
    after-split-brain policies, and each endpoint's host and address;
  - `drbdadm get-gi`: the resource's current data generation;
  - the fence record the fence-peer handler appends (/var/lib/mxfs): the
    newest STONITHED receipt, its peer and its episode;
  - the fence authority's live answer about the peer (/etc/mxfs/drbd-fence.conf):
    its power state and the episode it is inhibited under, if any.

The fence record alone is not evidence: it is a local file and says what
happened once. The authority's answer, read now, is what says the peer is
still off and still held under that same episode.

usage:
    mxfs_drbd_witness.py <nonce-hex16> <mode> <minor> [report-path]
      mode: arm | fence | recheck | monitor   (echoed back; the module decides
            what each mode requires)

The report is key=value lines framed by MXFS-DRBDW-BEGIN / MXFS-DRBDW-END,
written in ONE write to report-path (the module's /proc channel) and to stdout.

exit 0  report delivered (whatever it says)
exit 3  usage error; a report naming the error is still delivered
"""

import os
import re
import subprocess
import sys

report = []
REPORT_PATH = None
FENCE_CONF = "/etc/mxfs/drbd-fence.conf"
FENCE_RECORD_DIR = "/var/lib/mxfs"
HANDLER = "/usr/sbin/mxfs-drbd-fence-peer"
SELF_AUTHORITY = "/usr/sbin/mxfs-drbd-fence-self"


def secure_fds():
    """Descriptors 0-2 exist before anything else is opened: a kernel upcall
    starts its child with them closed (see mxfs_lu_reset_witness.py)."""
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
    value = "" if value is None else str(value)
    report.append("%s=%s" % (key, value.replace("\n", " ")))


def flush(code):
    text = "MXFS-DRBDW-BEGIN\n" + "\n".join(report) + "\nMXFS-DRBDW-END\n"
    if REPORT_PATH:
        try:
            fd = os.open(REPORT_PATH, os.O_WRONLY)
            try:
                os.write(fd, text.encode("utf-8", "replace"))
            finally:
                os.close(fd)
        except OSError:
            pass
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except (OSError, ValueError, AttributeError):
        pass
    sys.exit(code)


def run(argv, timeout):
    """stdout of a command, or None. Never raises."""
    env = {"PATH": "/usr/lib/drbd:/sbin:/usr/sbin:/bin:/usr/bin", "LC_ALL": "C"}
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return p.stdout.decode("utf-8", "replace")


def proc_drbd(minor):
    """The /proc/drbd line of one minor, parsed."""
    try:
        with open("/proc/drbd") as fh:
            text = fh.read()
    except OSError:
        return None
    # drbd_proc.c prints the protocol column as a blank when the resource has
    # no network configuration (StandAlone), so the column is one character
    # that may be a space; requiring a non-space there dropped the roles, the
    # disk states and the suspend flag of every StandAlone line.
    m = re.search(r"^\s*%d: cs:(\S+)(?: ro:(\S+) ds:(\S+) (\S| ) (\S+))?" % minor, text, re.M)
    if not m:
        return None
    out = {"cstate": m.group(1)}
    if m.group(2):
        out["role_local"], _, out["role_peer"] = m.group(2).partition("/")
        out["disk_local"], _, out["disk_peer"] = m.group(3).partition("/")
        out["protocol"] = m.group(4).strip()
        # drbd_proc.c: the flag field's first character is 's' when I/O is
        # suspended for any reason (user, no-data, or the fencing freeze).
        out["suspended"] = "1" if m.group(5)[0] == "s" else "0"
    return out


def resource_of(minor):
    """The resource whose device is /dev/drbd<minor>, by drbdadm's own answer."""
    names = run(["drbdadm", "sh-resources"], 10)
    if not names:
        return None
    hits = []
    for name in names.split():
        dev = run(["drbdadm", "sh-dev", name], 10)
        if dev and dev.strip() == "/dev/drbd%d" % minor:
            hits.append(name)
    return hits[0] if len(hits) == 1 else None


def parse_dump(text, host):
    """The settings this attachment depends on, from `drbdadm dump <res>`."""
    out = {}

    def opt(name):
        m = re.search(r"\b%s\s+([^;\s]+)\s*;" % re.escape(name), text)
        return m.group(1).strip('"') if m else None

    out["protocol_cfg"] = opt("protocol")
    out["two_primaries"] = opt("allow-two-primaries")
    out["fencing"] = opt("fencing")
    out["fence_handler"] = opt("fence-peer")
    for k in ("after-sb-0pri", "after-sb-1pri", "after-sb-2pri"):
        out[k] = opt(k)
    # each endpoint: `on <host> { ... address [ipv4] a.b.c.d:port; ... }`
    ends = re.findall(r"\bon\s+(\S+)\s*\{(.*?)\}", text, re.S)
    peers = []
    for name, body in ends:
        a = re.search(r"\baddress\s+(?:ipv4\s+)?([0-9.]+):(\d+)", body)
        addr = a.group(1) if a else None
        if name == host:
            out["local_addr"] = addr
        else:
            peers.append((name, addr))
    out["endpoints"] = len(ends)
    if len(peers) == 1:
        out["peer_host"], out["peer_addr"] = peers[0]
    return out


def fence_conf(host):
    """The fence configuration.  No file means the built-in two-node authority
    (agent=self), which needs no names: this node is `host` and the peer is
    the resource's other endpoint."""
    conf = {}
    try:
        with open(FENCE_CONF) as fh:
            for line in fh:
                line = line.strip()
                if "=" in line and not line.startswith("peer ") and not line.startswith("self "):
                    k, _, v = line.partition("=")
                    conf[k] = v
                elif line.startswith("self "):
                    conf["self"] = line.split()[1]
    except FileNotFoundError:
        conf = {"agent": "self"}
    except OSError:
        return None
    if conf.get("agent") == "self":
        conf.setdefault("self", host)
    return conf


def newest_receipt(res):
    """The newest exclusion line of the fence record, STONITHED (a node fence)
    or EXCLUDED (the built-in authority): (time, peer, episode, kind)."""
    try:
        with open(os.path.join(FENCE_RECORD_DIR, "drbd-fence.%s" % res)) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        kind = ("STONITHED" if " result=STONITHED " in line else
                "EXCLUDED" if " result=EXCLUDED " in line else None)
        if not kind:
            continue
        f = dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv)
        return line.split()[0], f.get("peer"), f.get("episode"), kind
    return None


def authority_argv(conf, verb_args):
    """The command that asks the fence authority, by the configured agent:
    ssh (rig-virsh is its older name) reaches an authority on another host
    whose forced command speaks the protocol; exec runs a local program that
    does.  Same verbs and answers either way (see mxfs_drbd_fence_peer.sh)."""
    agent = conf.get("agent") if conf else None
    if agent in ("ssh", "rig-virsh"):
        return ["ssh", "-i", conf.get("key", ""), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
                "%s@%s" % (conf.get("user", ""), conf.get("host", "")), " ".join(verb_args)]
    if agent == "exec" and conf.get("cmd"):
        return [conf["cmd"]] + verb_args
    if agent == "self":
        return [SELF_AUTHORITY] + verb_args
    return None


def authority_status(conf, peer):
    """The fence authority's answer about peer: (state, inhibit), or None."""
    argv = authority_argv(conf, ["status", peer])
    if not argv:
        return None
    try:
        p = subprocess.run(argv,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = p.stdout.decode("utf-8", "replace").strip().splitlines()
    m = re.match(r"^STATE (\S+) (.+) inhibit=(\S+)$", lines[-1] if lines else "")
    if not m or m.group(1) != peer:
        return None
    return m.group(2), m.group(3)


def main():
    global REPORT_PATH
    secure_fds()
    args = sys.argv[1:]
    if len(args) == 4:
        REPORT_PATH = args[3]
    if len(args) not in (3, 4) or not re.fullmatch(r"[0-9a-f]{16}", args[0]) \
            or args[1] not in ("arm", "fence", "recheck", "monitor", "startfence") or not args[2].isdigit():
        emit("ERROR", "usage: <nonce-hex16> <arm|fence|recheck|monitor> <minor> [report-path]")
        flush(3)
    nonce, mode, minor = args[0], args[1], int(args[2])
    emit("NONCE", nonce)
    emit("MODE", mode)
    emit("MINOR", minor)
    host = os.uname().nodename
    emit("HOST", host)

    if mode == "startfence":
        # Startup fencing after a pair outage (dlm/v5_mount.c
        # v5_drbd_startup_fence): run DRBD's own fence-peer handler with the
        # environment DRBD gives it, so the grant, the receipt and the inhibit
        # are exactly the ones a lost link produces.  Its answer is in the fence
        # record; this report then shows the state it left.
        r0 = resource_of(minor)
        c0 = {}
        if r0:
            d0 = run(["drbdadm", "dump", r0], 10)
            if d0:
                c0 = parse_dump(d0, host)
        env = dict(os.environ, DRBD_RESOURCE=r0 or "",
                   DRBD_PEER_ADDRESS=c0.get("peer_addr") or "")
        try:
            p = subprocess.run([HANDLER], env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=150)
            emit("STARTFENCE_RC", p.returncode)
        except (OSError, subprocess.SubprocessError):
            emit("STARTFENCE_RC", -1)

    st = proc_drbd(minor) or {}
    for k in ("cstate", "role_local", "role_peer", "disk_local", "disk_peer",
              "protocol", "suspended"):
        emit(k.upper(), st.get(k))

    res = resource_of(minor)
    emit("RESOURCE", res)
    cfg = {}
    if res:
        dump = run(["drbdadm", "dump", res], 10)
        if dump:
            cfg = parse_dump(dump, host)
        gi = run(["drbdadm", "get-gi", res], 10)
        emit("GI", gi.strip().split(":")[0] if gi else None)
    emit("PROTOCOL_CFG", cfg.get("protocol_cfg"))
    emit("TWO_PRIMARIES", cfg.get("two_primaries"))
    emit("FENCING", cfg.get("fencing"))
    emit("FENCE_HANDLER", cfg.get("fence_handler"))
    emit("AFTER_SB", "%s,%s,%s" % (cfg.get("after-sb-0pri"), cfg.get("after-sb-1pri"),
                                   cfg.get("after-sb-2pri")))
    emit("ENDPOINTS", cfg.get("endpoints"))
    emit("LOCAL_ADDR", cfg.get("local_addr"))
    emit("PEER_HOST", cfg.get("peer_host"))
    emit("PEER_ADDR", cfg.get("peer_addr"))
    emit("HANDLER_INSTALLED", 1 if os.access(HANDLER, os.X_OK) else 0)

    conf = fence_conf(host)
    emit("FENCE_SELF", conf.get("self") if conf else None)
    rc = newest_receipt(res) if res else None
    emit("RECEIPT_TIME", rc[0] if rc else None)
    emit("RECEIPT_PEER", rc[1] if rc else None)
    emit("RECEIPT_EPISODE", rc[2] if rc else None)
    emit("RECEIPT_KIND", rc[3] if rc else None)
    peer = cfg.get("peer_host")
    auth = authority_status(conf, peer) if peer else None
    emit("AUTH_STATE", auth[0] if auth else None)
    emit("AUTH_INHIBIT", auth[1] if auth else None)
    flush(0)


if __name__ == "__main__":
    main()
