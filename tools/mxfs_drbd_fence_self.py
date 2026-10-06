#!/usr/bin/python3 -I
"""mxfs-drbd-fence-self: the DRBD pair's built-in fence authority.

The default for an MXFS DRBD pair when /etc/mxfs/drbd-fence.conf names no
node fence (or does not exist): two hosts, no IPMI/PDU, no third vote.  The
design and the consult behind it are in
docs/rulings/drbd-two-node-self-exclusion.md; in short:

  * ONE fixed tie-break decides every uncoordinated split: participant 0, the
    endpoint with the lower DRBD IPv4 address (the same rule the module uses
    for its compare-and-swap enrollment, and corosync's auto_tie_breaker /
    OCFS2's even-split rule).  It never mixes in a second rule, so the two
    sides can never both win.
  * The WINNER, inside DRBD's fence-peer handler and before DRBD resumes I/O:
    isolates the peer from this host (nftables drops the DRBD port and the
    MXFS ports to and from the peer's address), writes a durable inhibit and
    an EXCLUDED receipt, exits 7, and then takes DRBD StandAlone.  The module
    certifies the peer's slice for replay (fence kind 26) only once the
    witness sees all of it.  The inhibit survives reboot: `guard` re-applies
    the isolation at boot, before DRBD comes up.
  * The LOSER exits 1: DRBD keeps its I/O frozen, so nothing it does reaches
    a disk.  It says why in the kernel log and, if MXFS is mounted on the
    resource, restarts the host so it can rejoin cleanly.  After that restart
    nothing promotes or mounts it until it is Connected and resynced.
  * RELEASE happens only on positive evidence, never on elapsed time: over
    the root ssh trust a Proxmox cluster already has, the peer must report no
    live MXFS superblock (no mount, module refcount 0) and DRBD not Primary.
    The same evidence lets participant 1 carry on when participant 0 left on
    purpose (a planned restart), instead of losing the tie-break.
  * When participant 0 is the one that died, participant 1 cannot tell that
    from a cut link.  It does not take over; it logs that a two-node pair
    without a third vote or a node fence cannot recover automatically.

Subcommands:
  fence-peer                      DRBD's handler action (DRBD_RESOURCE,
                                  DRBD_PEER_ADDRESS in the environment)
  fence <target> <requester>      the authority verb (startup fencing): refused
  status <target>                 STATE <target> excluded|unfenced|... inhibit=<ep>|none
  release <target> <ep> <req>     release now if the evidence holds
  guard                           daemon: keep isolation in place, release on evidence
  boot <resource> <mountpoint>    bring the resource up and mount it when safe
"""

import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time

STATE_DIR = "/var/lib/mxfs"
RECORD_FMT = os.path.join(STATE_DIR, "drbd-fence.%s")      # shared with the handler
INHIBIT_FMT = os.path.join(STATE_DIR, "drbd-inhibit.%s.json")
NFT_TABLE_FMT = "mxfs_fence_%s"
# MXFS's ports: 7600/tcp carries the network lock manager, 7601-7603/udp
# discovery, lock hints and heartbeat (README "firewall-cmd" line).
MXFS_TCP_PORTS = "7600"
MXFS_UDP_PORTS = "7601-7603"
RESTART_DELAY_S = 10
GUARD_INTERVAL_S = 5


def log(msg, crit=False):
    """To the journal and the kernel log, so a frozen node says why."""
    line = "mxfs-drbd-fence-self: " + msg
    try:
        subprocess.run(["logger", "-p", "daemon.crit" if crit else "daemon.notice",
                        "-t", "mxfs-drbd-fence", msg], timeout=5,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open("/dev/kmsg", "w") as k:
            k.write(("<2>" if crit else "<5>") + line + "\n")
    except OSError:
        pass
    print(line, file=sys.stderr)


def run(argv, timeout=15, check=False):
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError("%s rc=%d %s" % (" ".join(argv), p.returncode,
                                            p.stderr.decode(errors="replace").strip()))
    return p.returncode, p.stdout.decode(errors="replace")


def durable_write(path, text):
    """Write, fsync the file and its directory: the inhibit and the receipt are
    evidence only once they survive a crash.  /var/lib is on the root
    filesystem, never on the MXFS volume being recovered."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def append_record(res, line):
    path = RECORD_FMT % res
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    dfd = os.open(STATE_DIR, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            return fh.read().strip()
    except OSError:
        return "?"


def record_line(res, peer_addr, peer, result, detail):
    return "%.9f res=%s peer_addr=%s peer=%s result=%s boot_id=%s %s" % (
        time.time(), res, peer_addr or "?", peer, result, boot_id(), detail)


# ---------------------------------------------------------------- DRBD facts

def drbd_endpoints(res):
    """(local_host, local_addr, local_port, peer_host, peer_addr, peer_port)
    from `drbdadm dump`, or None when the resource is not exactly two IPv4
    endpoints with this host as one of them."""
    rc, out = run(["drbdadm", "dump", res], timeout=10)
    if rc != 0:
        return None
    me = socket.gethostname()
    hosts = []
    for m in re.finditer(r"\bon\s+(\S+)\s*\{(.*?)\n\s*\}", out, re.S):
        a = re.search(r"address\s+(?:ipv4\s+)?([0-9.]+):(\d+);", m.group(2))
        if a:
            hosts.append((m.group(1), a.group(1), int(a.group(2))))
    if len(hosts) != 2:
        return None
    mine = [h for h in hosts if h[0] == me]
    other = [h for h in hosts if h[0] != me]
    if len(mine) != 1 or len(other) != 1:
        return None
    return mine[0] + other[0]


def ipv4(s):
    parts = s.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return None
    v = 0
    for p in parts:
        v = (v << 8) | int(p)
    return v


def participant_index(local_addr, peer_addr):
    a, b = ipv4(local_addr), ipv4(peer_addr)
    if a is None or b is None or a == b:
        return None
    return 0 if a < b else 1


def cstate(res):
    rc, out = run(["drbdadm", "cstate", res], timeout=10)
    return out.strip() if rc == 0 else ""


def role(res):
    rc, out = run(["drbdadm", "role", res], timeout=10)
    return out.strip() if rc == 0 else ""


def drbd_device(res):
    rc, out = run(["drbdadm", "sh-dev", res], timeout=10)
    return out.strip().splitlines()[0] if rc == 0 and out.strip() else ""


def mxfs_mounted_on(dev):
    try:
        real = os.path.realpath(dev) if dev else ""
        with open("/proc/mounts") as fh:
            for line in fh:
                f = line.split()
                if len(f) >= 3 and f[2] == "mxfs" and (f[0] == dev or os.path.realpath(f[0]) == real):
                    return f[1]
    except OSError:
        pass
    return None


# ------------------------------------------------------------ isolation (nft)

def nft_rules(res, peer_addr, drbd_port):
    t = NFT_TABLE_FMT % res
    return (
        "table inet %(t)s {\n"
        "  chain input {\n"
        "    type filter hook input priority -300; policy accept;\n"
        "    ip saddr %(p)s tcp sport %(d)d drop\n"
        "    ip saddr %(p)s tcp dport %(d)d drop\n"
        "    ip saddr %(p)s tcp sport %(mt)s drop\n"
        "    ip saddr %(p)s tcp dport %(mt)s drop\n"
        "    ip saddr %(p)s udp dport %(mu)s drop\n"
        "    ip saddr %(p)s udp sport %(mu)s drop\n"
        "  }\n"
        "  chain output {\n"
        "    type filter hook output priority -300; policy accept;\n"
        "    ip daddr %(p)s tcp dport %(d)d drop\n"
        "    ip daddr %(p)s tcp sport %(d)d drop\n"
        "    ip daddr %(p)s tcp dport %(mt)s drop\n"
        "    ip daddr %(p)s tcp sport %(mt)s drop\n"
        "    ip daddr %(p)s udp dport %(mu)s drop\n"
        "    ip daddr %(p)s udp sport %(mu)s drop\n"
        "  }\n"
        "}\n" % {"t": t, "p": peer_addr, "d": drbd_port,
                 "mt": MXFS_TCP_PORTS, "mu": MXFS_UDP_PORTS})


def nft_present(res):
    rc, _ = run(["nft", "list", "table", "inet", NFT_TABLE_FMT % res], timeout=10)
    return rc == 0


def nft_apply(res, peer_addr, drbd_port):
    if nft_present(res):
        return
    p = subprocess.run(["nft", "-f", "-"], input=nft_rules(res, peer_addr, drbd_port).encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if p.returncode != 0 or not nft_present(res):
        raise RuntimeError("nft isolation of %s failed: %s" % (
            peer_addr, p.stderr.decode(errors="replace").strip()))


def nft_remove(res):
    if nft_present(res):
        run(["nft", "delete", "table", "inet", NFT_TABLE_FMT % res], timeout=10, check=True)


# ------------------------------------------------------------------ inhibit

def read_inhibit(res):
    try:
        with open(INHIBIT_FMT % res) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def all_inhibits():
    out = []
    try:
        names = os.listdir(STATE_DIR)
    except OSError:
        return out
    for n in sorted(names):
        m = re.fullmatch(r"drbd-inhibit\.(.+)\.json", n)
        if m:
            inh = read_inhibit(m.group(1))
            if inh:
                out.append(inh)
    return out


# --------------------------------------------------------------- fence-peer

def cmd_fence_peer():
    res = os.environ.get("DRBD_RESOURCE", "")
    ep = drbd_endpoints(res) if res else None
    if not ep:
        log("fence-peer: resource '%s' is not two IPv4 endpoints including this host; "
            "I/O stays frozen" % res, crit=True)
        return 1
    me, my_addr, _, peer, peer_addr, drbd_port = ep
    env_peer = os.environ.get("DRBD_PEER_ADDRESS", "")
    if env_peer and env_peer != peer_addr:
        log("fence-peer: DRBD names peer address %s, the resource %s; I/O stays frozen"
            % (env_peer, peer_addr), crit=True)
        return 1
    idx = participant_index(my_addr, peer_addr)
    if idx is None:
        log("fence-peer: no participant index from %s/%s; I/O stays frozen"
            % (my_addr, peer_addr), crit=True)
        return 1
    if cstate(res) == "Connected":
        # Not a lost link: the module's startup fence after a pair outage
        # runs the handler too.  A connected, live peer is not excluded.
        return cmd_fence(peer, me)

    if idx == 1:
        # A peer that left on purpose (unmounted, demoted) cannot be the
        # winner of a split -- DRBD runs this handler only on a Primary -- so
        # positive evidence of that lets participant 1 carry on.  Without it,
        # a planned restart of participant 0 would restart this node too.
        gone, why = peer_evidence(res, peer, peer_addr)
        if gone:
            log("DRBD %s: peer %s departed (%s); this node continues" % (res, peer, why),
                crit=True)
            idx = 0
    if idx == 1:
        append_record(res, record_line(res, peer_addr, peer, "TIEBREAK_LOST",
                                       "participant=1"))
        log("DRBD %s lost its peer %s (%s). This node (%s, participant 1) loses the "
            "pair's fixed tie-break: its I/O stays frozen and nothing it holds reaches "
            "a disk. If %s is alive it excludes this node and carries on. If %s is "
            "DOWN, this two-node pair cannot recover automatically (no third vote, no "
            "node fence): bring %s back, or configure a node fence (IPMI/PDU) in "
            "/etc/mxfs/drbd-fence.conf." % (res, peer, peer_addr, me, peer, peer, peer),
            crit=True)
        mnt = mxfs_mounted_on(drbd_device(res))
        if mnt:
            log("restarting %s in %d s: MXFS on %s holds state the survivor is replacing, "
                "and a restart is the only way back in (it rejoins once %s releases it)"
                % (me, RESTART_DELAY_S, mnt, peer), crit=True)
            # detached: DRBD waits for this handler; the restart must not.
            # No sync: the frozen device would hang it.
            subprocess.Popen(["/bin/sh", "-c", "sleep %d; echo b > /proc/sysrq-trigger"
                              % RESTART_DELAY_S], start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        return 1

    # participant 0: the winner.  Isolation first, then the durable inhibit,
    # then the receipt; only then does DRBD get the exit code that resumes I/O.
    episode = "%d-%s" % (time.time_ns(), secrets.token_hex(4))
    try:
        nft_apply(res, peer_addr, drbd_port)
        durable_write(INHIBIT_FMT % res, json.dumps({
            "resource": res, "peer": peer, "peer_addr": peer_addr,
            "drbd_port": drbd_port, "episode": episode,
            "excluded_at": time.time(), "excluded_by_boot": boot_id(),
        }, indent=1) + "\n")
        append_record(res, record_line(res, peer_addr, peer, "EXCLUDED",
                                       "episode=%s agent=self participant=0" % episode))
    except Exception as e:  # any failure leaves DRBD frozen: never exit 7 half-done
        log("fence-peer: excluding %s failed (%s); I/O stays frozen" % (peer, e), crit=True)
        return 1
    log("DRBD %s lost its peer %s (%s). This node (%s, participant 0) wins the pair's "
        "fixed tie-break: %s is isolated from this host (DRBD and MXFS ports), the "
        "resource goes StandAlone, and %s is held out (episode %s) until it reports no "
        "live MXFS and DRBD not Primary (a restart does that). I/O resumes now."
        % (res, peer, peer_addr, me, peer, peer, episode), crit=True)
    # StandAlone after DRBD has the answer: disconnecting from inside the
    # handler would wait on the state machine the handler is holding.  The
    # isolation already keeps the old peer from reconnecting meanwhile, and
    # the module's fence leg waits until the witness sees StandAlone.
    subprocess.Popen(["/bin/sh", "-c", "sleep 1; drbdadm disconnect %s" % res],
                     start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 7


# -------------------------------------------------------- authority verbs

def cmd_status(target):
    for inh in all_inhibits():
        if inh.get("peer") == target:
            state = "excluded" if nft_present(inh["resource"]) else "isolation-missing"
            print("STATE %s %s inhibit=%s" % (target, state, inh["episode"]))
            return 0
    print("STATE %s unfenced inhibit=none" % target)
    return 0


def cmd_fence(target, requester):
    # Asked outside the handler: startup fencing after a pair outage.  This
    # authority cannot prove a peer's earlier incarnation gone while it is
    # alive and connected; that needs a node fence.
    log("startup fence of %s refused: the built-in two-node authority cannot exclude a "
        "live peer's earlier incarnation after both nodes crashed; configure a node "
        "fence (IPMI/PDU) in /etc/mxfs/drbd-fence.conf for automatic recovery from a "
        "pair outage" % target, crit=True)
    print("FENCE_REFUSED %s self authority performs no startup fence" % target)
    return 1


def peer_evidence(res, peer, peer_addr):
    """(True, why) when the peer provably holds nothing that can write to this
    resource: no MXFS superblock alive (no mxfs mount, and the module's
    reference count 0 or the module not loaded, so a lazily unmounted
    filesystem still counts), and DRBD not Primary.  An MXFS incarnation is a
    live superblock, so this is positive evidence that the old one is gone,
    whether the peer rebooted or only unmounted.  Read over ssh, which a
    Proxmox cluster authenticates with its root key trust; anything short of a
    clean answer is (False, why)."""
    # Authenticate the peer the way Proxmox's own migrations do: its key from
    # the cluster's per-node file under its node name (PVE 9 keeps no cluster
    # host keys in the shared known_hosts).  Elsewhere, the system's known
    # hosts under the same name.
    opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=" + peer]
    pve_keys = "/etc/pve/nodes/%s/ssh_known_hosts" % peer
    if os.path.exists(pve_keys):
        opts += ["-o", "UserKnownHostsFile=" + pve_keys]
    try:
        rc, out = run(["ssh"] + opts + ["root@" + peer_addr,
                       "echo ROLE=$(drbdadm role %s 2>/dev/null || echo Unconfigured); "
                       "echo MOUNTS=$(grep -c ' mxfs ' /proc/mounts); "
                       "echo REFCNT=$(cat /sys/module/mxfs/refcnt 2>/dev/null || echo unloaded); "
                       "echo BOOT=$(cat /proc/sys/kernel/random/boot_id)" % res],
                      timeout=20)
    except subprocess.SubprocessError:
        return False, "ssh to %s timed out" % peer
    f = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    if rc != 0 or not {"ROLE", "MOUNTS", "REFCNT", "BOOT"} <= f.keys():
        return False, "no answer from %s over ssh (rc=%d)" % (peer, rc)
    if f["ROLE"].startswith("Primary"):
        return False, "%s is DRBD %s" % (peer, f["ROLE"])
    if f["MOUNTS"] != "0":
        return False, "%s has %s MXFS mount(s)" % (peer, f["MOUNTS"])
    if f["REFCNT"] not in ("0", "unloaded"):
        return False, "%s still holds %s MXFS superblock reference(s)" % (peer, f["REFCNT"])
    return True, "%s answers: DRBD %s, no MXFS mount, module refcnt %s, boot %s" % (
        peer, f["ROLE"], f["REFCNT"], f["BOOT"][:8])


def release(inh, why):
    res = inh["resource"]
    nft_remove(res)
    append_record(res, record_line(res, inh["peer_addr"], inh["peer"], "RELEASED",
                                   "episode=%s %s" % (inh["episode"], why.replace(" ", "_"))))
    os.unlink(INHIBIT_FMT % res)
    dfd = os.open(STATE_DIR, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    run(["drbdadm", "connect", res], timeout=15)
    log("released %s (episode %s): %s; DRBD %s reconnects and %s resyncs from this node"
        % (inh["peer"], inh["episode"], why, res, inh["peer"]), crit=True)


def cmd_release(target, episode):
    for inh in all_inhibits():
        if inh.get("peer") == target and inh.get("episode") == episode:
            ok, why = peer_evidence(inh["resource"], inh["peer"], inh["peer_addr"])
            if not ok:
                print("RELEASE_REFUSED %s %s" % (target, why))
                return 1
            release(inh, why)
            print("RELEASED %s episode=%s" % (target, episode))
            return 0
    print("RELEASE_REFUSED %s no inhibit under episode %s" % (target, episode))
    return 1


def cmd_guard():
    """Keep every inhibit's isolation in place (it does not survive a reboot
    on its own) and release an inhibit once the peer's evidence holds."""
    last = {}
    while True:
        for inh in all_inhibits():
            res = inh["resource"]
            try:
                if not nft_present(res):
                    nft_apply(res, inh["peer_addr"], int(inh["drbd_port"]))
                    log("re-applied the isolation of %s for %s (episode %s)"
                        % (inh["peer"], res, inh["episode"]), crit=True)
                if cstate(res) not in ("StandAlone", "Unconfigured", ""):
                    run(["drbdadm", "disconnect", res], timeout=15)
                ok, why = peer_evidence(res, inh["peer"], inh["peer_addr"])
                if ok:
                    release(inh, why)
                elif last.get(res) != why:
                    log("holding %s out (episode %s): %s" % (inh["peer"], inh["episode"], why))
                    last[res] = why
            except Exception as e:
                log("guard: %s: %s" % (res, e), crit=True)
        time.sleep(GUARD_INTERVAL_S)


# ---------------------------------------------------------------------- boot

def cmd_boot(res, mountpoint):
    """Bring the resource up and mount it, only in a state the module admits:
    connected with both disks UpToDate, or the survivor of an exclusion.
    Never promotes a disconnected node that holds no exclusion: that is how a
    restarted loser would come back on stale data."""
    dev = drbd_device(res)
    if mxfs_mounted_on(dev):
        return 0
    inh = read_inhibit(res)
    if inh:
        nft_apply(res, inh["peer_addr"], int(inh["drbd_port"]))
    if cstate(res) == "":
        run(["drbdadm", "up", res], timeout=30, check=True)
    if inh:
        run(["drbdadm", "disconnect", res], timeout=15)
        log("%s: this node holds %s excluded (episode %s); mounting as the survivor"
            % (res, inh["peer"], inh["episode"]))
    else:
        said = 0
        while True:
            cs = cstate(res)
            rc, ds = run(["drbdadm", "dstate", res], timeout=10)
            ds = ds.strip()
            if cs == "Connected" and ds == "UpToDate/UpToDate":
                break
            if time.time() - said > 60:
                log("%s: waiting to mount %s until DRBD is Connected and both disks are "
                    "UpToDate (now %s, %s)" % (res, mountpoint, cs, ds))
                said = time.time()
            time.sleep(2)
    if not role(res).startswith("Primary"):
        run(["drbdadm", "primary", res], timeout=30, check=True)
    os.makedirs(mountpoint, exist_ok=True)
    rc, _ = run(["mount", "-t", "mxfs", dev, mountpoint], timeout=180)
    if rc != 0:
        log("%s: mount of %s on %s failed (rc=%d); the reason is in the kernel log "
            "(dmesg | grep mxfs)" % (res, dev, mountpoint, rc), crit=True)
        return 1
    log("%s: mounted %s on %s" % (res, dev, mountpoint))
    return 0


def main():
    a = sys.argv[1:]
    try:
        if a[:1] == ["fence-peer"]:
            return cmd_fence_peer()
        if len(a) == 2 and a[0] == "status":
            return cmd_status(a[1])
        if len(a) == 3 and a[0] == "fence":
            return cmd_fence(a[1], a[2])
        if len(a) >= 3 and a[0] == "release":
            return cmd_release(a[1], a[2])
        if a == ["guard"]:
            return cmd_guard()
        if len(a) == 3 and a[0] == "boot":
            return cmd_boot(a[1], a[2])
    except Exception as e:
        log("%s: %s" % (" ".join(a), e), crit=True)
        return 1
    print(__doc__.split("Subcommands:")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
