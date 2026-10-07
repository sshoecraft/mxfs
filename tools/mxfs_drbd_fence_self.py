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
    That evidence only ever lets the excluded peer back in to resync; it
    never makes participant 1 a winner.  A peer that looks idle is a
    snapshot, not a promise: its own handler may already be running.
  * When participant 0 is the one that died, participant 1 cannot tell that
    from a cut link.  It does not take over; it logs that a two-node pair
    without a third vote or a node fence cannot recover automatically.  A
    planned restart of participant 0 is a graceful DRBD disconnect, for which
    DRBD runs no handler, so participant 1 simply carries on.
  * Participant 0, restarting while participant 1 is still away, keeps its
    standing from DRBD's own record, released or not: attaching
    UpToDate/Outdated, it holds the newest replica, so when the peer does not
    connect within ALONE_GRACE_S `boot` excludes it again and mounts alone.
    Participant 1 never takes the pair alone, at boot or on a lost link.
  * DRBD also runs the handler to promote a disconnected Secondary.  A node
    that was Secondary when the link failed cannot know what its peer did
    since, so a promotion is granted only under this node's own standing
    exclusion of the peer, never on the tie-break.

Subcommands:
  fence-peer                      DRBD's handler action (DRBD_RESOURCE,
                                  DRBD_PEER_ADDRESS in the environment)
  fence <target> <requester>      the authority verb (startup fencing): refused
  status <target>                 STATE <target> excluded|unfenced|... inhibit=<ep>|none
  release <target> <ep> <req>     release now if the evidence holds
  guard                           daemon: keep isolation in place, release on evidence,
                                  rejoin a mount that has shut down
  boot <resource> <mountpoint>    bring the resource up and mount it when safe
  stop <resource> <mountpoint>    unmount, step down and take the resource down
  rejoin <resource>               bring a shut-down MXFS mount back: stop what
                                  holds it, unmount it, restart its unit
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
# What `boot` is doing, one line "<state> pid=<pid> boot=<boot id>", read by
# the peer's `boot` over ssh.  /run is emptied at every boot, so the file never
# describes an earlier one.
BOOT_STATE_FMT = "/run/mxfs/drbd-boot.%s"
# A refused mount is retried after stepping down, so the peer can recover
# first; the backoff doubles from the first value up to the second, and the
# attempts stop after the third.
MOUNT_RETRY_FIRST_S = 15
MOUNT_RETRY_MAX_S = 120
MOUNT_ATTEMPTS = 6
# One mount attempt.  The module bounds each of its own waits and says why it
# refused: after both nodes crashed, the bootstrap scan waits out the dead
# heartbeat window (62 s), the DRBD startup fence waits at most 120 s more, and
# then the old incarnations' journals are replayed (13 s on the rig).  A bound
# below that sum kills a mount just before the module would have refused it:
# measured on the rig at 180 s, killed 3 s short of the module's own refusal.
MOUNT_TIMEOUT_S = 300
# Participant 1 starts without participant 0 only once participant 0's boot
# program has been seen not running for this long: systemd starts it within
# seconds of the boot, and DRBD may be Connected before it starts.
NOT_STARTING_GRACE_S = 30
# A node whose DRBD record holds its peer Outdated (it attaches
# UpToDate/Outdated) has the newest replica, and DRBD will not promote the
# peer until it has resynced from it.  At boot the peer gets this long to
# connect -- connected, the pair takes its ordinary path -- and then this node
# excludes it as the fence-peer winner does and mounts alone.  DRBD's own
# init script waits the same way (outdated-wfc-timeout).
ALONE_GRACE_S = 30
# How long a connected node stays Secondary, before it promotes, while its
# mounted peer still owes the recovery of this node's previous incarnation
# (Boot.wait_peer_recovered).  The peer proves that incarnation ended at its
# next fence retry (at most ~6 s apart) and then replays its journal slice: up
# to 162 s measured on the physical pair for both journals after a pair outage.
# Past this the mount goes ahead and the module decides.
PEER_RECOVERY_WAIT_S = 180
# DRBD 8.4 connection states with no peer attached.
DISCONNECTED = ("StandAlone", "Disconnecting", "Unconnected", "Timeout", "BrokenPipe",
                "NetworkFailure", "ProtocolError", "TearDown", "WFConnection")
NFT_TABLE_FMT = "mxfs_fence_%s"
# MXFS's ports: 7600/tcp carries the network lock manager, 7601-7603/udp
# discovery, lock hints and heartbeat (README "firewall-cmd" line).
MXFS_TCP_PORTS = "7600"
MXFS_UDP_PORTS = "7601-7603"
RESTART_DELAY_S = 10
# The longest the winner waits for its own `drbdadm resume-io` before it
# answers DRBD anyway (resume_frozen_io).  The command is one state change on
# a device whose I/O is frozen: milliseconds.
RESUME_IO_WAIT_S = 10
GUARD_INTERVAL_S = 5
# A shut-down MXFS mount never serves again: its authority lease expired, a
# heartbeat detector or a peer fenced it, or it was forced down for another
# cause, and every access to it fails with EIO.  The module says so per mount
# in SHUTDOWN_ATTR_FMT.  `guard` sees it and starts `rejoin`, which brings the
# mount back the way a restart of the host would, without restarting the
# host: it stops the guests holding the mount, unmounts it, and restarts the
# resource's unit, whose boot program mounts it again once DRBD and the peer
# allow; the on-boot guests then start.  At most REJOIN_MAX rejoins in
# REJOIN_WINDOW_S (a mount that keeps shutting down is left down and says
# so).  An unmount still refused after REJOIN_UMOUNT_TRIES rounds, or that
# does not finish within REJOIN_UMOUNT_S, restarts the host: nothing else is
# left that can release the old mount.
SHUTDOWN_ATTR_FMT = "/sys/fs/mxfs/%s/shutdown"
REJOIN_RECORD_FMT = os.path.join(STATE_DIR, "drbd-rejoin.%s")
REJOIN_UNIT_FMT = "mxfs-drbd-rejoin-%s"
REJOIN_MAX = 3
REJOIN_WINDOW_S = 3600
REJOIN_UMOUNT_S = 170
REJOIN_UMOUNT_TRIES = 3
# A holder killed by the rejoin exits once its operation in flight returns,
# and on a shut-down mount every one fails at once.  Each round waits this
# long for the holders to be gone before it unmounts; one still there makes
# the unmount refuse, and the next round kills it again.
REJOIN_HOLDER_EXIT_S = 30
QEMU_PID_DIR = "/var/run/qemu-server"
# Tells the MXFS mount on a resource that its peer is excluded: the module
# then asks its own witness at once instead of declaring the death after its
# lock link's timeout and grace.  A cue, never evidence -- the module judges
# the exclusion itself.  Without the module (or an older one) it does nothing.
EXCLUSION_NOTICE = ("m=$(drbdadm sh-minor %s 2>/dev/null) && "
                    "[ -w /proc/fs/mxfs/drbd_excluded ] && "
                    "echo \"$m\" > /proc/fs/mxfs/drbd_excluded")


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


def dstate(res):
    """'<this node's disk>/<the peer's disk>', e.g. UpToDate/Outdated."""
    rc, out = run(["drbdadm", "dstate", res], timeout=10)
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


def exclude(res, peer, peer_addr, drbd_port, detail):
    """Exclude the peer in a new episode: isolation first, then the durable
    inhibit, then the EXCLUDED receipt, in that order, so a crash leaves at
    worst an isolation with no claim on it.  Returns the episode; raises when
    any of the three fails."""
    episode = "%d-%s" % (time.time_ns(), secrets.token_hex(4))
    nft_apply(res, peer_addr, drbd_port)
    durable_write(INHIBIT_FMT % res, json.dumps({
        "resource": res, "peer": peer, "peer_addr": peer_addr,
        "drbd_port": drbd_port, "episode": episode,
        "excluded_at": time.time(), "excluded_by_boot": boot_id(),
    }, indent=1) + "\n")
    append_record(res, record_line(res, peer_addr, peer, "EXCLUDED",
                                   "episode=%s %s" % (episode, detail)))
    return episode


# --------------------------------------------------------------- fence-peer

def resume_frozen_io(res):
    """Resume the resource's frozen I/O ourselves, once the peer is excluded
    and before DRBD has the exit code.

    On an exit of 4 or 7 DRBD 8.4 resumes I/O frozen by fencing in its state
    machine (drbd_state.c, after_conn_state_ch: "the outdate peer handler is
    successful"), and that path writes the new current UUID to the metadata
    inside rcu_read_lock().  The write sleeps, and every exclusion logged a
    kernel WARNING, "Voluntary context switch within RCU read-side critical
    section!", with a stack through drbd_uuid_new_current, on both pairs; a
    sleep there on a slow disk also holds up every RCU grace period of the
    host for as long as the metadata write takes.  `drbdadm resume-io` makes
    the same UUID rotation outside RCU (drbd_nl.c drbd_adm_resume_io), clears
    the freeze and restarts the requests the lost link held, so that when the
    exit code arrives nothing is frozen and DRBD only records the peer
    Outdated.

    Safe here only: DRBD runs this handler for a Primary that lost its link
    from its own drbd_async_h thread, which holds none of the locks the
    command takes.  A promotion runs it inside drbdadm primary, under the
    resource's admin mutex, and is never resumed from here.  Bounded and never
    fatal: a resume-io that fails, or has not returned in RESUME_IO_WAIT_S, is
    logged and left, and DRBD resumes the I/O itself on the exit code as
    before."""
    try:
        p = subprocess.Popen(["drbdadm", "resume-io", res], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             start_new_session=True)
    except OSError as e:
        log("fence-peer: drbdadm resume-io %s could not start (%s); DRBD resumes "
            "the I/O on the exit code" % (res, e), crit=True)
        return False
    t0 = time.time()
    while p.poll() is None and time.time() - t0 < RESUME_IO_WAIT_S:
        time.sleep(0.05)
    if p.returncode is None:
        # not waited on: a command stuck in the kernel cannot be killed, and
        # DRBD's own resume after the exit code releases whatever holds it
        log("fence-peer: drbdadm resume-io %s has not returned after %d s; DRBD "
            "resumes the I/O on the exit code" % (res, RESUME_IO_WAIT_S), crit=True)
        return False
    err = p.stderr.read().decode(errors="replace").strip() if p.stderr else ""
    if p.returncode != 0:
        log("fence-peer: drbdadm resume-io %s exited %d (%s); DRBD resumes the I/O "
            "on the exit code" % (res, p.returncode, err), crit=True)
        return False
    return True


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

    # DRBD runs this handler for two requests (drbd_nl.c): a Primary that lost
    # its link, and the promotion of a disconnected Secondary whose peer is
    # unknown (drbd_set_role: SS_PRIMARY_NOP for an UpToDate disk,
    # SS_NO_UP_TO_DATE_DISK for one that is only Consistent).  A node that saw
    # the link fail while it was Secondary cannot know what the peer did
    # since: the peer may be Primary and writing, its replica newer.  So a
    # promotion is granted only under this node's own standing exclusion of
    # the peer (it won, and stopped before DRBD recorded the peer Outdated).
    # Refused, the answer is 1, never DRBD's "peer unreachable" (5): on an
    # UpToDate disk 5 outdates the peer and the promotion goes ahead.  When
    # this node's role or disk cannot be read the answer is 1 as well, which
    # for a Primary leaves I/O frozen.
    mine_role = mine = ""
    for i in range(3):
        mine_role, mine = role(res).split("/")[0], dstate(res).split("/")[0]
        if mine_role and mine:
            break
        time.sleep(1)
    if not mine_role or not mine:
        log("fence-peer: DRBD %s: this node's role or disk state cannot be read (%s, %s); "
            "nothing is granted" % (res, mine_role or "?", mine or "?"), crit=True)
        return 1
    if mine_role != "Primary":
        # Only participant 0 ever excludes; an inhibit on participant 1 can
        # only be an earlier version's, and grants nothing.
        inh = read_inhibit(res) if idx == 0 else None
        if inh and inh.get("peer") == peer:
            try:
                nft_apply(res, peer_addr, drbd_port)
            except Exception as e:
                log("fence-peer: re-isolating %s failed (%s); not promoting" % (peer, e), crit=True)
                return 1
            log("fence-peer: DRBD %s: this node holds %s excluded (episode %s); its %s disk "
                "is promoted under that exclusion" % (res, peer, inh.get("episode"), mine),
                crit=True)
            return 7
        log("DRBD %s: refusing to promote this node (%s) while %s is unreachable: only a "
            "node that holds %s excluded may become Primary alone, and %s may have carried "
            "on without this one (this disk is %s). It is promoted once DRBD is connected "
            "to %s again." % (res, me, peer, peer, peer, mine, peer), crit=True)
        return 1
    if mine != "UpToDate":
        log("fence-peer: DRBD %s: this node is Primary on a %s disk; nothing is granted"
            % (res, mine), crit=True)
        return 1

    # A Primary that lost its link.  The fixed tie-break alone decides:
    # participant 0 carries on, participant 1 freezes.  Participant 1 never
    # carries on because the peer looks idle -- Secondary, unmounted -- since
    # that is a snapshot, not a promise: the peer's own handler may already be
    # running (it lost the link while Primary and demoted since), or it may be
    # promoting.  A peer that leaves on purpose disconnects gracefully (its
    # unit unmounts, steps down and takes DRBD down, outdating its own disk),
    # and DRBD runs no handler for that.
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
    try:
        episode = exclude(res, peer, peer_addr, drbd_port, "agent=self participant=0")
    except Exception as e:  # any failure leaves DRBD frozen: never exit 7 half-done
        log("fence-peer: excluding %s failed (%s); I/O stays frozen" % (peer, e), crit=True)
        return 1
    log("DRBD %s lost its peer %s (%s). This node (%s, participant 0) wins the pair's "
        "fixed tie-break: %s is isolated from this host (DRBD and MXFS ports), the "
        "resource goes StandAlone, and %s is held out (episode %s) until it reports no "
        "live MXFS and DRBD not Primary (a restart does that). I/O resumes now."
        % (res, peer, peer_addr, me, peer, peer, episode), crit=True)
    resume_frozen_io(res)
    # StandAlone after DRBD has the answer: disconnecting from inside the
    # handler would wait on the state machine the handler is holding.  The
    # isolation already keeps the old peer from reconnecting meanwhile, and
    # the module's fence leg waits until the witness sees StandAlone.  Then
    # the MXFS mount on the resource is told (EXCLUSION_NOTICE), so it asks
    # its witness now instead of after its lock link's timeout and grace.
    subprocess.Popen(["/bin/sh", "-c", "sleep 1; drbdadm disconnect %s; %s"
                      % (res, EXCLUSION_NOTICE % res)],
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
    # Asked outside the handler: startup fencing after a pair outage, which
    # the module asks for only when the peer is neither excluded nor
    # Secondary on a Connected link.  This authority powers nothing off, so
    # it cannot make a live Primary's earlier incarnation provably gone; the
    # mount waits for the peer to step down (its boot program does when its
    # own mount is refused) or for the link to be lost and the tie-break.
    log("startup fence of %s refused: the built-in two-node authority powers nothing "
        "off; recovery after both nodes crashed proceeds once %s is Secondary on a "
        "Connected link (its boot program waits for, or steps down to, that)"
        % (target, target), crit=True)
    print("FENCE_REFUSED %s self authority performs no startup fence" % target)
    return 1


def peer_facts(res, peer, peer_addr):
    """The peer's own answer over ssh, as a dict, or (None, why).  ROLE is
    `drbdadm role`, MOUNTS the number of MXFS mounts, REFCNT the module's
    reference count, BOOT its boot id, BOOTSTATE what its boot program
    published (BOOT_STATE_FMT; 'none' when there is no such file),
    BOOTLIVE whether that program is still running, and RECOVERY its mount's
    /sys/fs/mxfs/<dev>/recovery_pending ('none' with no such mount or a
    module without it)."""
    # Authenticate the peer the way Proxmox's own migrations do: its key from
    # the cluster's per-node file under its node name (PVE 9 keeps no cluster
    # host keys in the shared known_hosts).  Elsewhere, the system's known
    # hosts under the same name.
    opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=" + peer]
    pve_keys = "/etc/pve/nodes/%s/ssh_known_hosts" % peer
    if os.path.exists(pve_keys):
        opts += ["-o", "UserKnownHostsFile=" + pve_keys]
    state = BOOT_STATE_FMT % res
    try:
        rc, out = run(["ssh"] + opts + ["root@" + peer_addr,
                       "echo ROLE=$(drbdadm role %s 2>/dev/null || echo Unconfigured); "
                       "echo MOUNTS=$(grep -c ' mxfs ' /proc/mounts); "
                       "echo REFCNT=$(cat /sys/module/mxfs/refcnt 2>/dev/null || echo unloaded); "
                       "echo BOOT=$(cat /proc/sys/kernel/random/boot_id); "
                       "d=$(drbdadm sh-dev %s 2>/dev/null); "
                       "r=$(cat /sys/fs/mxfs/${d##*/}/recovery_pending 2>/dev/null); "
                       "echo RECOVERY=${r:-none}; "
                       "s=$(cat %s 2>/dev/null); echo BOOTSTATE=${s:-none}; "
                       "p=${s##* pid=}; p=${p%%%% *}; "
                       "[ -n \"$s\" ] && kill -0 \"$p\" 2>/dev/null && echo BOOTLIVE=1 || echo BOOTLIVE=0"
                       % (res, res, state)],
                      timeout=20)
    except subprocess.SubprocessError:
        return None, "ssh to %s timed out" % peer
    f = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    if rc != 0 or not {"ROLE", "MOUNTS", "REFCNT", "BOOT", "BOOTSTATE", "BOOTLIVE"} <= f.keys():
        return None, "no answer from %s over ssh (rc=%d)" % (peer, rc)
    return f, ""


def peer_evidence(res, peer, peer_addr):
    """(True, why) when the peer provably holds nothing that can write to this
    resource: no MXFS superblock alive (no mxfs mount, and the module's
    reference count 0 or the module not loaded, so a lazily unmounted
    filesystem still counts), and DRBD not Primary.  An MXFS incarnation is a
    live superblock, so this is positive evidence that the old one is gone,
    whether the peer rebooted or only unmounted.  Read over ssh, which a
    Proxmox cluster authenticates with its root key trust; anything short of a
    clean answer is (False, why)."""
    f, why = peer_facts(res, peer, peer_addr)
    if f is None:
        return False, why
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


def own_mount_pending(res):
    """Why a release must wait, or "" when it need not: this node's boot
    program is running and has not mounted yet.  It mounts as the survivor on
    the exclusion, and the module's startup fence judges that exclusion until
    the mount completes.  Released under it, with a peer that is up but has no
    DRBD, the fence has neither the exclusion nor a Connected Secondary peer,
    and the mount is refused (pve1, 2026-10-06)."""
    try:
        with open(BOOT_STATE_FMT % res) as fh:
            f = fh.read().split()
    except OSError:
        return ""
    if not f or f[0] in ("mounted", "failed"):
        return ""
    kv = dict(x.split("=", 1) for x in f[1:] if "=" in x)
    try:
        pid = int(kv.get("pid", "0"))
        if kv.get("boot") != boot_id() or pid <= 0:
            return ""
        os.kill(pid, 0)
    except (ValueError, OSError):
        return ""
    return "this node's boot program is %s on the exclusion; released once it has mounted" % f[0]


def cmd_release(target, episode):
    for inh in all_inhibits():
        if inh.get("peer") == target and inh.get("episode") == episode:
            ok, why = peer_evidence(inh["resource"], inh["peer"], inh["peer_addr"])
            if ok and own_mount_pending(inh["resource"]):
                ok, why = False, own_mount_pending(inh["resource"])
            if not ok:
                print("RELEASE_REFUSED %s %s" % (target, why))
                return 1
            release(inh, why)
            print("RELEASED %s episode=%s" % (target, episode))
            return 0
    print("RELEASE_REFUSED %s no inhibit under episode %s" % (target, episode))
    return 1


# ------------------------------------------------------------------- rejoin

def active_resources():
    """The DRBD resources whose mxfs-drbd@ unit is active on this node."""
    rc, out = run(["systemctl", "list-units", "--plain", "--no-legend", "--state=active",
                   "mxfs-drbd@*.service"], timeout=15)
    return [m.group(1) for m in re.finditer(r"^mxfs-drbd@(\S+)\.service\s", out, re.M)]


def mount_shut_down(dev):
    """True once the MXFS mount of `dev` has shut down, False before it has;
    None when the module does not say (a build without the flag)."""
    try:
        with open(SHUTDOWN_ATTR_FMT % os.path.basename(os.path.realpath(dev))) as fh:
            return fh.read().strip() == "1"
    except OSError:
        return None


def mount_holders(mnt):
    """{pid: comm} of the processes with an open file, working directory or
    root under `mnt`, from the /proc/<pid>/{fd,cwd,root} links: the kernel
    names those without asking the filesystem, which answers EIO once it is
    withdrawn.  Memory maps are not read (/proc/<pid>/maps takes the process's
    mmap lock, which a task stuck in the filesystem can hold), so a map with
    no open file is missed and the unmount reports it busy."""
    under = mnt.rstrip("/") + "/"
    found = {}
    for p in os.listdir("/proc"):
        if not p.isdigit() or int(p) == os.getpid():
            continue
        links = ["/proc/%s/cwd" % p, "/proc/%s/root" % p]
        try:
            links += ["/proc/%s/fd/%s" % (p, fd) for fd in os.listdir("/proc/%s/fd" % p)]
        except OSError:
            pass
        for link in links:
            try:
                target = os.readlink(link)
            except OSError:
                continue
            if target == mnt or target.startswith(under):
                try:
                    with open("/proc/%s/comm" % p) as fh:
                        found[int(p)] = fh.read().strip()
                except OSError:
                    found[int(p)] = "?"
                break
    return found


def qemu_vmids(pids):
    """{pid: vmid} for the Proxmox VMs whose QEMU process is among `pids`."""
    out = {}
    try:
        names = os.listdir(QEMU_PID_DIR)
    except OSError:
        return out
    for n in names:
        m = re.fullmatch(r"(\d+)\.pid", n)
        if not m:
            continue
        try:
            with open(os.path.join(QEMU_PID_DIR, n)) as fh:
                pid = int(fh.read().split()[0])
        except (OSError, ValueError, IndexError):
            continue
        if pid in pids:
            out[pid] = m.group(1)
    return out


def rejoin_times(res):
    """When this resource's recent rejoins started, oldest first."""
    try:
        with open(REJOIN_RECORD_FMT % res) as fh:
            times = [float(line.split()[0]) for line in fh if line.strip()]
    except (OSError, ValueError, IndexError):
        return []
    return [t for t in times if time.time() - t < REJOIN_WINDOW_S]


def restart_host(why):
    """The last way back in, as the fence-peer loser takes it: a restart in
    RESTART_DELAY_S, with no sync (a stuck filesystem would hang it).

    It waits and restarts in this process, and returns only if the restart
    could not be asked for.  The rejoin that calls it runs as a transient
    unit, and a child started to do it later does not outlive that unit: once
    the rejoin returns, systemd stops the unit and kills every process left in
    its cgroup (KillMode=control-group), a new session or not."""
    log("restarting this host in %d s: %s" % (RESTART_DELAY_S, why), crit=True)
    # sysrq b resets with nothing synced, journald's files included.  The
    # restart's reason must survive it: on both pairs (0.90.75, withdraw-held)
    # the previous boot's journal ended at the first refused unmount, and the
    # two rounds after it and this line were gone.  journalctl --sync returns
    # once journald has written its files out; it touches no other filesystem.
    try:
        run(["journalctl", "--sync"], timeout=RESTART_DELAY_S)
    except subprocess.SubprocessError:
        pass
    time.sleep(RESTART_DELAY_S)
    try:
        with open("/proc/sysrq-trigger", "w") as fh:
            fh.write("b")
    except OSError as e:
        log("the restart could not be asked for (/proc/sysrq-trigger: %s); this host "
            "stays up with its mount shut down until it is restarted" % e, crit=True)


def bounded_umount(mnt, limit):
    """umount's exit code, or None when it has not finished within `limit`
    seconds.  An unmount stuck in the kernel cannot be killed, so it is never
    waited on past the bound (subprocess.run would wait for it forever)."""
    p = subprocess.Popen(["umount", mnt], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    until = time.time() + limit
    while time.time() < until:
        rc = p.poll()
        if rc is not None:
            return rc
        time.sleep(1)
    return None


def stop_holders(res, mnt):
    """Stop what holds the shut-down mount, all at once: every holder is
    killed (SIGKILL), then this waits up to REJOIN_HOLDER_EXIT_S for them to
    be gone.  Every one of them has had only EIO from the mount since it shut
    down, and the peer cannot finish recovering this node's old incarnation
    until this node has unmounted and stepped down, so no holder is waited on
    in turn.  A Proxmox VM is killed like any other process: `qm stop` ends
    the same way for the guest (power pulled), and Proxmox's qmeventd cleans
    up a QEMU that exited without a guest shutdown (`qm cleanup`), as after
    a guest crash.  Stopping each VM with `qm stop` in turn, on pve1 with the
    host swapping (0.90.76), took 90, 90 and 74 s for three VMs, and the peer
    failed its own guests' I/O meanwhile.  Returns how many processes were
    found."""
    holders = mount_holders(mnt)
    vms = qemu_vmids(holders)
    t0 = time.time()
    for pid, comm in sorted(holders.items()):
        try:
            os.kill(pid, 9)
        except OSError:
            continue
        if pid in vms:
            log("%s: killed VM %s (QEMU pid %d), whose disk is on the shut-down %s"
                % (res, vms[pid], pid, mnt))
        else:
            log("%s: killed %s (pid %d), which held the shut-down %s open" % (res, comm, pid, mnt))
    if not holders:
        return 0
    left = holders
    while left and time.time() - t0 < REJOIN_HOLDER_EXIT_S:
        time.sleep(0.5)
        left = mount_holders(mnt)
    if left:
        log("%s: %d of the %d processes killed still hold the shut-down %s after %.1f s: %s"
            % (res, len(left), len(holders), mnt, time.time() - t0,
               " ".join("%s(%d)" % (c, p) for p, c in sorted(left.items()))), crit=True)
    else:
        log("%s: the %d processes that held the shut-down %s are gone (%.1f s)"
            % (res, len(holders), mnt, time.time() - t0))
    return len(holders)


def cmd_rejoin(res):
    """Bring this node's shut-down MXFS mount of `res` back (see
    SHUTDOWN_ATTR_FMT): stop what holds it, unmount it, restart the unit and,
    once its boot program has mounted it again, start the on-boot guests."""
    dev = drbd_device(res)
    mnt = mxfs_mounted_on(dev)
    if not mnt or not mount_shut_down(dev):
        log("%s: rejoin: no shut-down MXFS mount of %s here; nothing to do" % (res, dev or "?"))
        return 0
    times = rejoin_times(res)
    if len(times) >= REJOIN_MAX:
        log("%s: %s has shut down again and has been rejoined %d times in the last %d s; "
            "it stays down until an operator restarts mxfs-drbd@%s (the kernel log says why "
            "each shut down)" % (res, mnt, len(times), REJOIN_WINDOW_S, res), crit=True)
        return 1
    durable_write(REJOIN_RECORD_FMT % res, "".join("%.3f\n" % t for t in times + [time.time()]))
    log("%s: the MXFS mount %s on %s has shut down (withdrawn from the cluster; the kernel "
        "log says why) and every access to it fails.  Rejoining (%d of at most %d in %d s): "
        "stopping what holds it, unmounting it, and restarting mxfs-drbd@%s, which mounts it "
        "again once DRBD and the peer allow" % (res, dev, mnt, len(times) + 1, REJOIN_MAX,
                                               REJOIN_WINDOW_S, res), crit=True)
    for attempt in range(1, REJOIN_UMOUNT_TRIES + 1):
        stop_holders(res, mnt)
        rc = bounded_umount(mnt, REJOIN_UMOUNT_S)
        if rc is None:
            restart_host("the unmount of the shut-down %s did not finish in %d s"
                         % (mnt, REJOIN_UMOUNT_S))
            return 1
        if rc == 0:
            break
        log("%s: umount of the shut-down %s refused (rc=%d, round %d of %d)"
            % (res, mnt, rc, attempt, REJOIN_UMOUNT_TRIES), crit=True)
        time.sleep(5)
    else:
        restart_host("the shut-down %s could not be unmounted in %d rounds (something "
                     "this program cannot stop holds it)" % (mnt, REJOIN_UMOUNT_TRIES))
        return 1
    log("%s: unmounted the shut-down %s; restarting mxfs-drbd@%s" % (res, mnt, res))
    unit = "mxfs-drbd@%s.service" % res
    rc, _ = run(["systemctl", "restart", "--no-block", unit], timeout=30)
    if rc != 0:
        log("%s: systemctl restart %s failed (rc=%d)" % (res, unit, rc), crit=True)
        return 1
    # The boot program bounds each of its own waits; this only follows it.  A
    # restart passes through deactivating, and can read inactive for a moment
    # between its stop and its start, so only failed, or inactive on two
    # passes running, means the unit ended.
    idle = False
    while True:
        time.sleep(GUARD_INTERVAL_S)
        mnt2 = mxfs_mounted_on(dev)
        if mnt2 and mount_shut_down(dev):
            # this run ends, so the guard can start the next one if it may
            log("%s: %s was mounted again and has shut down again" % (res, mnt2), crit=True)
            return 1
        if mnt2:
            log("%s: rejoined: %s is mounted again" % (res, mnt2), crit=True)
            start_onboot_guests(res, mnt2)
            return 0
        rc, out = run(["systemctl", "is-active", unit], timeout=10)
        state = out.strip()
        if state == "failed" or (state == "inactive" and idle):
            log("%s: mxfs-drbd@%s ended %s without mounting %s; its journal says why"
                % (res, res, state, mnt), crit=True)
            return 1
        idle = state == "inactive"


def watch_mounts(said):
    """One guard pass over this node's MXFS-on-DRBD mounts: start a rejoin
    for each that has shut down, unless one is running already or the
    resource has used its rejoins (said once every ten minutes)."""
    for res in active_resources():
        dev = drbd_device(res)
        if not mxfs_mounted_on(dev) or not mount_shut_down(dev):
            continue
        if len(rejoin_times(res)) >= REJOIN_MAX:
            if time.time() - said.get(res, 0) > 600:
                log("%s: the MXFS mount of %s has shut down and its rejoins are used up "
                    "(%d in %d s); it stays down until an operator restarts mxfs-drbd@%s"
                    % (res, dev, REJOIN_MAX, REJOIN_WINDOW_S, res), crit=True)
                said[res] = time.time()
            continue
        # One rejoin at a time: systemd refuses a second unit of that name
        # while the first is loaded.
        unit = REJOIN_UNIT_FMT % res
        rc, out = run(["systemctl", "is-active", unit], timeout=10)
        if out.strip() in ("active", "activating"):
            continue
        rc, _ = run(["systemd-run", "--no-block", "--collect", "--unit=" + unit,
                     os.path.realpath(sys.argv[0]), "rejoin", res], timeout=15)
        log("%s: the MXFS mount of %s has shut down; %s" % (
            res, dev, "rejoining it (unit %s)" % unit if rc == 0 else
            "the rejoin could not be launched (systemd-run rc=%d)" % rc), crit=True)


def cmd_guard():
    """Keep every inhibit's isolation in place (it does not survive a reboot
    on its own), release an inhibit once the peer's evidence holds, and
    rejoin an MXFS mount that has shut down."""
    last = {}
    said = {}
    while True:
        try:
            watch_mounts(said)
        except Exception as e:
            log("guard: rejoin watch: %s" % e, crit=True)
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
                if ok and own_mount_pending(res):
                    ok, why = False, own_mount_pending(res)
                if ok:
                    release(inh, why)
                elif last.get(res) != why:
                    log("holding %s out (episode %s): %s" % (inh["peer"], inh["episode"], why))
                    last[res] = why
            except Exception as e:
                log("guard: %s: %s" % (res, e), crit=True)
        time.sleep(GUARD_INTERVAL_S)


# ---------------------------------------------------------------------- boot

def sd_notify(state):
    """Report to systemd (the unit is Type=notify); nothing when not run by it."""
    addr = os.environ.get("NOTIFY_SOCKET", "")
    if not addr:
        return
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(state.encode())
    except OSError:
        pass


def guest_wait_s():
    """How long the guests' start waits for this mount at boot.  The unit
    reports ready when the mount is done, and Proxmox starts its on-boot
    guests (pve-guests) and HA services (pve-ha-lrm) only after that; past
    this bound it reports ready anyway, so guests on local storage are not
    held while the peer is down, and the on-boot guests that need this mount
    are started once it is done (start_onboot_guests)."""
    try:
        return max(0, int(os.environ.get("GUEST_WAIT", "300")))
    except ValueError:
        return 300


def start_onboot_guests(res, mountpoint):
    """The mount came after Proxmox's boot-time start of guests: start the
    on-boot guests now, with the same call that start makes (it skips guests
    already running).  It runs as its own transient unit, so its progress is
    in the journal and the task log, and this step does not wait on it."""
    rc, _ = run(["systemctl", "is-active", "--quiet", "pve-guests.service"], timeout=10)
    if rc != 0 or not os.path.exists("/usr/bin/pvesh"):
        return
    rc, _ = run(["systemd-run", "--no-block", "--collect",
                 "--unit=mxfs-drbd-onboot-%s" % res,
                 "/usr/bin/pvesh", "--nooutput", "create", "/nodes/localhost/startall"],
                timeout=15)
    log("%s: %s was mounted after the boot-time start of guests; %s" % (
        res, mountpoint,
        "starting the on-boot guests that could not start without it "
        "(unit mxfs-drbd-onboot-%s)" % res if rc == 0 else
        "the start of the on-boot guests could not be launched (systemd-run rc=%d)" % rc),
        crit=rc != 0)


def write_boot_state(res, state):
    path = BOOT_STATE_FMT % res
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w") as fh:
            fh.write("%s pid=%d boot=%s\n" % (state, os.getpid(), boot_id()))
        os.replace(path + ".tmp", path)
    except OSError:
        pass


class Boot:
    """One run of `boot`: when it started, and whether systemd has been told
    the guests may start without the mount (GUEST_WAIT)."""

    def __init__(self, res, mountpoint):
        self.res = res
        self.mountpoint = mountpoint
        self.t0 = time.time()
        self.ready = False

    def ready_if_due(self, status):
        if not self.ready and time.time() - self.t0 >= guest_wait_s():
            self.ready = True
            log("%s: the start of guests no longer waits for %s (%d s); on-boot "
                "guests that need it start once it is mounted"
                % (self.res, self.mountpoint, guest_wait_s()))
            sd_notify("READY=1\nSTATUS=%s" % status)

    def exclude_outdated_peer(self):
        """The survivor's standing after a restart, from DRBD's own record.
        A node that excluded its peer and later released it (the peer
        answered with no MXFS, then never connected), or whose peer left
        cleanly (a departing Secondary outdates itself), holds no inhibit;
        DRBD's metadata still says which replica is the newest.  A node that
        attaches UpToDate/Outdated is that replica's holder: the peer's disk
        is Outdated or Inconsistent until it resyncs from this one, DRBD
        refuses to promote it without --force, and the fence-peer handler
        refuses to promote it while it is disconnected.  The flag is set by
        excluding the peer or by the peer departing, and cleared by the next
        connection -- but DRBD writes it to disk only after the state change
        (after_state_ch), so a crash in between can leave it set on a node
        whose peer has since resynced and carried on.  It is therefore acted
        on only by participant 0, the one node the tie-break lets carry on
        alone: participant 1 never continues without participant 0, so
        participant 0's replica holds every write the pair acknowledged
        whenever it is the one restarting.  When no connection comes within
        ALONE_GRACE_S, participant 0 excludes the peer exactly as the
        fence-peer winner excludes it and mounts as the survivor.  Returns
        the inhibit, or None when the ordinary path decides (the peer
        connected, DRBD does not hold it Outdated, or this is participant
        1)."""
        cs, ds = cstate(self.res), dstate(self.res)
        if ds != "UpToDate/Outdated" or cs not in DISCONNECTED:
            return None
        ep = drbd_endpoints(self.res)
        if not ep:
            log("%s: DRBD holds the peer Outdated, but the resource is not two IPv4 "
                "endpoints including this host; waiting for the peer" % self.res, crit=True)
            return None
        me, my_addr, _, peer, peer_addr, drbd_port = ep
        if participant_index(my_addr, peer_addr) != 0:
            log("%s: DRBD's record holds %s Outdated, but this node (%s) is participant 1, "
                "which never takes the pair alone; waiting for %s to connect"
                % (self.res, peer, me, peer))
            return None
        t0 = time.time()
        while True:
            cs, ds = cstate(self.res), dstate(self.res)
            if ds != "UpToDate/Outdated" or cs not in DISCONNECTED:
                return None
            if time.time() - t0 >= ALONE_GRACE_S:
                break
            self.ready_if_due("waiting for DRBD %s's peer (%s, %s)" % (self.res, cs, ds))
            time.sleep(2)
        nft_apply(self.res, peer_addr, drbd_port)
        run(["drbdadm", "disconnect", self.res], timeout=15)
        cs, ds = cstate(self.res), dstate(self.res)
        if cs != "StandAlone" or ds not in ("UpToDate/Outdated", "UpToDate/Inconsistent"):
            # The peer connected as the isolation went in: let it resync.
            nft_remove(self.res)
            run(["drbdadm", "connect", self.res], timeout=15)
            log("%s: DRBD changed while %s was being isolated (%s, %s); waiting for "
                "it instead" % (self.res, peer, cs, ds))
            return None
        episode = exclude(self.res, peer, peer_addr, drbd_port,
                          "agent=self participant=%s reason=peer-outdated-at-boot"
                          % participant_index(my_addr, peer_addr))
        log("DRBD %s: this node (%s) holds the newest replica -- DRBD's record holds %s "
            "Outdated, and DRBD does not promote it until it has resynced from this node "
            "-- and %s did not connect within %d s. %s is excluded (episode %s) and this "
            "node mounts alone; %s rejoins once it reports no live MXFS and DRBD not "
            "Primary." % (self.res, me, peer, peer, ALONE_GRACE_S, peer, episode, peer),
            crit=True)
        return read_inhibit(self.res)

    def wait_connected(self):
        said = 0
        while True:
            # An isolation with no inhibit claims nothing: exclude() puts the
            # isolation in first, so a crash before the inhibit leaves one,
            # and so does dropping an earlier version's inhibit.  It would
            # keep DRBD from ever connecting.
            if read_inhibit(self.res) is None and nft_present(self.res):
                nft_remove(self.res)
                log("%s: removed an isolation of the peer that no exclusion holds" % self.res)
            cs = cstate(self.res)
            rc, ds = run(["drbdadm", "dstate", self.res], timeout=10)
            ds = ds.strip()
            if cs == "Connected" and ds == "UpToDate/UpToDate":
                return
            if time.time() - said > 60:
                log("%s: waiting to mount %s until DRBD is Connected and both disks are "
                    "UpToDate (now %s, %s)" % (self.res, self.mountpoint, cs, ds))
                said = time.time()
            self.ready_if_due("waiting for DRBD %s (%s, %s)" % (self.res, cs, ds))
            time.sleep(2)

    def wait_participant0(self):
        """Participant 1 promotes only once participant 0 has MXFS mounted, or
        once participant 0's boot program has not been running for
        NOT_STARTING_GRACE_S.  After both nodes crashed, the first mount
        recovers both old incarnations, and proving them ended needs the
        other node Secondary (fence kind 27): two nodes promoting at once
        would leave neither able to.  This is ordering for liveness only;
        the module refuses an unsafe mount whatever the order."""
        ep = drbd_endpoints(self.res)
        if not ep:
            return
        me, my_addr, _, peer, peer_addr, _ = ep
        if participant_index(my_addr, peer_addr) != 1:
            return
        said, last, idle_since = 0, None, None
        while True:
            f, why = peer_facts(self.res, peer, peer_addr)
            if f is not None:
                if f["MOUNTS"] != "0":
                    log("%s: %s (participant 0) has MXFS mounted; mounting here"
                        % (self.res, peer))
                    return
                if f["BOOTLIVE"] != "1":
                    idle_since = idle_since or time.time()
                    if time.time() - idle_since >= NOT_STARTING_GRACE_S:
                        log("%s: %s (participant 0) is not starting MXFS (boot program: "
                            "%s); mounting here" % (self.res, peer, f["BOOTSTATE"].split()[0]))
                        return
                else:
                    idle_since = None
                why = "%s is %s, its boot program %s" % (
                    peer, f["ROLE"], f["BOOTSTATE"].split()[0])
            if why != last or time.time() - said > 60:
                log("%s: waiting to mount %s until %s (participant 0) has mounted it or "
                    "is not starting it (%s)" % (self.res, self.mountpoint, peer, why))
                said, last = time.time(), why
            self.ready_if_due("waiting for %s to mount first" % peer)
            time.sleep(5)

    def wait_peer_recovered(self):
        """Promote only once a peer with MXFS mounted owes no recovery.

        When this node's previous incarnation died or withdrew, the mounted
        peer recovers it, and it can prove that incarnation ended only while
        this node is DRBD Secondary on a connected link (fence kind
        DRBD_PEER_SECONDARY_V1).  A node that promotes as soon as both disks
        are UpToDate holds that proof off.  The peer cannot replay the old
        journal slice, and this node's own mount, which waits for that replay,
        is refused at its bound.  On 2026-10-06 the withdraw-p1 rejoin on both
        pairs mounted only after a refused mount had stepped the node down
        (pve9-1 5.5 min, pve2 73 s), and the peer certified in that window.

        Waits while the peer answers that it has MXFS mounted and that its
        mount's recovery_pending is 1, for at most PEER_RECOVERY_WAIT_S.  No
        answer, no mount there, or a module without the attribute: the mount
        goes ahead, and the module's own barrier decides as before."""
        ep = drbd_endpoints(self.res)
        if not ep:
            return
        _, _, _, peer, peer_addr, _ = ep
        t0, said = time.time(), 0
        while True:
            f, why = peer_facts(self.res, peer, peer_addr)
            if f is None:
                if said:
                    log("%s: no answer from %s (%s); promoting" % (self.res, peer, why))
                return
            if f["MOUNTS"] == "0" or f.get("RECOVERY", "none") != "1":
                if said:
                    log("%s: %s has recovered this node's previous incarnation (%d s); "
                        "promoting" % (self.res, peer, time.time() - t0))
                return
            if time.time() - t0 >= PEER_RECOVERY_WAIT_S:
                log("%s: %s still owes a recovery after %d s; promoting anyway, and the "
                    "module decides whether this mount may proceed"
                    % (self.res, peer, PEER_RECOVERY_WAIT_S), crit=True)
                return
            if not said or time.time() - said > 60:
                log("%s: staying Secondary until %s has recovered this node's previous "
                    "incarnation: it can prove that incarnation ended only while this "
                    "node is Secondary" % (self.res, peer))
                said = time.time()
            self.ready_if_due("waiting for %s to recover this node's previous incarnation"
                              % peer)
            time.sleep(2)


def cmd_boot(res, mountpoint):
    """Bring the resource up and mount it, only in a state the module admits:
    connected with both disks UpToDate, or the survivor of an exclusion --
    which participant 0 becomes when its DRBD record holds the peer Outdated
    and the peer does not connect (Boot.exclude_outdated_peer).  Never
    promotes a disconnected node that holds no exclusion of its peer: that is
    how a restarted loser would come back on stale data.  Connected,
    participant 1 waits for participant 0 to mount first, and a refused mount
    steps down to Secondary and is retried, so the other node can recover the
    pair first."""
    b = Boot(res, mountpoint)
    dev = drbd_device(res)
    if mxfs_mounted_on(dev):
        sd_notify("READY=1\nSTATUS=%s mounted" % mountpoint)
        return 0
    write_boot_state(res, "starting")
    inh = read_inhibit(res)
    ep = drbd_endpoints(res)
    if inh and ep and participant_index(ep[1], ep[4]) == 1:
        # Only participant 0 ever excludes; this inhibit is an earlier
        # version's and authorises nothing.  Its isolation would keep DRBD
        # from connecting, and connecting is how this node gets back in:
        # DRBD's handshake decides which replica is the newer.  The inhibit
        # goes first, so the guard stops re-applying the isolation, and
        # wait_connected removes the isolation left without one.
        os.unlink(INHIBIT_FMT % res)
        append_record(res, record_line(res, inh["peer_addr"], inh["peer"], "DROPPED",
                                       "episode=%s participant=1" % inh["episode"]))
        log("%s: dropped this node's exclusion of %s (episode %s): participant 1 never "
            "takes the pair alone; waiting for %s to connect"
            % (res, inh["peer"], inh["episode"], inh["peer"]), crit=True)
        inh = None
    if inh:
        nft_apply(res, inh["peer_addr"], int(inh["drbd_port"]))
    if cstate(res) == "":
        run(["drbdadm", "up", res], timeout=30, check=True)
    if not inh:
        inh = b.exclude_outdated_peer()
    if inh:
        run(["drbdadm", "disconnect", res], timeout=15)
        log("%s: this node holds %s excluded (episode %s); mounting as the survivor"
            % (res, inh["peer"], inh["episode"]))
    os.makedirs(mountpoint, exist_ok=True)
    backoff = MOUNT_RETRY_FIRST_S
    for attempt in range(1, MOUNT_ATTEMPTS + 1):
        if not inh:
            write_boot_state(res, "waiting")
            b.wait_connected()
            b.wait_participant0()
            b.wait_connected()
            if not role(res).startswith("Primary"):
                b.wait_peer_recovered()
        write_boot_state(res, "mounting")
        # The promotion can race the link: lost after the wait above, it goes
        # through the fence-peer handler, which refuses a promotion without
        # an exclusion of the peer.  That is a failed attempt like a refused
        # mount, never the end of the boot.  So is a mount past its bound:
        # raised out of here, it ended the whole boot with this node still
        # Primary, which keeps the peer from recovering.  mount(8)'s own
        # message carries the module's reason for a refusal.
        rc, what = 0, "mount of %s on %s" % (dev, mountpoint)
        if not role(res).startswith("Primary"):
            what = "promotion of %s" % res
            try:
                p = subprocess.run(["drbdadm", "primary", res], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                rc, err = p.returncode, " ".join(p.stderr.decode(errors="replace").split())
            except subprocess.TimeoutExpired:
                rc, err = 124, "no answer in 60 s"
        if rc == 0:
            what = "mount of %s on %s" % (dev, mountpoint)
            try:
                p = subprocess.run(["mount", "-t", "mxfs", dev, mountpoint],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=MOUNT_TIMEOUT_S)
                rc, err = p.returncode, " ".join(p.stderr.decode(errors="replace").split())
            except subprocess.TimeoutExpired:
                rc, err = 124, "no answer in %d s" % MOUNT_TIMEOUT_S
        if rc == 0:
            break
        log("%s: %s failed (rc=%d, attempt %d of %d): %s"
            % (res, what, rc, attempt, MOUNT_ATTEMPTS,
               err or "the reason is in the kernel log (dmesg | grep -E 'mxfs|drbd')"), crit=True)
        if inh or attempt == MOUNT_ATTEMPTS:
            write_boot_state(res, "failed")
            return 1
        # Step down so the peer, if it is starting too, can mount first.
        rc, _ = run(["drbdadm", "secondary", res], timeout=30)
        write_boot_state(res, "retrying")
        log("%s: stepped down to Secondary (rc=%d); mounting again in %d s"
            % (res, rc, backoff))
        until = time.time() + backoff
        while time.time() < until:
            b.ready_if_due("retrying the mount of %s" % mountpoint)
            time.sleep(2)
        backoff = min(backoff * 2, MOUNT_RETRY_MAX_S)
    write_boot_state(res, "mounted")
    log("%s: mounted %s on %s" % (res, dev, mountpoint))
    sd_notify("READY=1\nSTATUS=%s mounted" % mountpoint)
    if b.ready:
        start_onboot_guests(res, mountpoint)
    return 0


def cmd_stop(res, mountpoint):
    """A clean departure: unmount MXFS from the resource's device, then step
    down and take the resource down, so the peer carries on.  Whether MXFS is
    mounted is read from /proc/mounts, never from stat(2) on the mountpoint:
    a withdrawn or recovery-blocked MXFS mount answers stat with ESTALE or
    EIO, and `mountpoint -q` then calls it unmounted.  Measured on pve1: the
    unit's stop skipped the umount of such a mount, `drbdadm secondary` and
    `down` failed under it, and the unit still reported itself stopped."""
    dev = drbd_device(res)
    mnt = mxfs_mounted_on(dev)
    if mnt:
        rc, _ = run(["umount", mnt], timeout=170)
        if rc != 0:
            log("%s: umount of %s failed (rc=%d); DRBD stays Primary under it, so the "
                "peer will treat this node's departure as a loss" % (res, mnt, rc), crit=True)
            return 1
        log("%s: unmounted %s" % (res, mnt))
    elif mountpoint and os.path.ismount(mountpoint):
        log("%s: %s is mounted but not from %s; left alone" % (res, mountpoint, dev))
    rc, _ = run(["drbdadm", "secondary", res], timeout=30)
    if rc != 0:
        log("%s: drbdadm secondary failed (rc=%d)" % (res, rc), crit=True)
        return 1
    run(["drbdadm", "down", res], timeout=30)
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
        if len(a) == 3 and a[0] == "stop":
            return cmd_stop(a[1], a[2])
        if len(a) == 2 and a[0] == "rejoin":
            return cmd_rejoin(a[1])
    except Exception as e:
        log("%s: %s" % (" ".join(a), e), crit=True)
        return 1
    print(__doc__.split("Subcommands:")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
