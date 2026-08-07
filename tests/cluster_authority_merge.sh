#!/bin/bash
# cluster_authority_merge.sh — turn the inode-cluster AUTHORITY signal into a
# DIVERGENCE verdict, by merging every node's write timeline.
# (ccloop c7ee71c6 sess29, D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY.)
#
# WHY THIS EXISTS
#   tests/cluster_authority_census.sh proves a node PUBLISHED bytes it had no
#   write tenure for.  That is an authority violation, not yet a corruption:
#   rewriting bytes nobody changed is harmless.  The detector cannot answer
#   "were those bytes stale?" on its own, and a synchronous platter read from
#   the write-submit path is not safe to add there.
#
#   But the answer is already in the logs.  Every node emits P170-CLWR for every
#   inode-cluster write with EVERY slot's ino:mode:gen-tail and a wall-clock
#   realns, and sess29 added P218-CLUSTER-PASSENGER naming the specific slots a
#   node wrote WITHOUT authority.  Merging both streams across all nodes by
#   realns gives the sess27 evidence shape mechanically:
#
#     node B publishes ino X as (mode_b, gen_b, cc_b) at T_b        <- authoritative
#     node A publishes ino X as (mode_a, gen_a, cc_a) at T_a > T_b  <- passenger
#     gen/mode differ  -> A reverted X to an OLDER INCARNATION
#     gen equal, cc_a < cc_b -> A reverted X WITHIN its incarnation
#
#   The changecount arm matters: mode+gen alone only distinguish incarnations, so
#   a merge built on them is BLIND to the common case (same inode, same
#   incarnation, older content). The first run of this harness reported
#   DIVERGENT=0 on 2130 passengers using mode+gen only -- a real result, but a
#   partial one. di_changecount is monotone per incarnation and is now carried in
#   both probes.
#
#   That last line is the defect with divergence attached: A's cluster write
#   reverted an image another node had already published.
#
# CLOCKS
#   realns is CLOCK_REALTIME on each node and the rig keeps the nodes in UTC via
#   NTP, but this is still a cross-node comparison.  A verdict is only reported
#   when the gap exceeds --skew (default 50 ms), so ordinary clock error cannot
#   manufacture one.  The observed sess27 case had a 2.5 SECOND gap.
#
# ⚠ `arm` PERTURBS THE SYSTEM -- NEVER RUN IT ALONGSIDE A CRITERION VERDICT
#   `arm` raises mxfs.instr, which uncaps probe printing. MEASURED: with instr=1,
#   dir_reuse_coherency FAILED 0/32 (111s/120s); with instr=0 on the same build
#   it PASSED 32/32 (109s). The printk cost alone is enough to fail a pace
#   assertion -- the same trap P56's comment records. Use `arm` only for a
#   dedicated diagnostic run, and re-run any criterion with instr back to 0.
#   Without `arm`, P170-CLWR still gives 800 lines/node always-on (32 x 800 =
#   25600 cluster writes), which is normally plenty and costs nothing.
#
# ⚠ RE-MARK AFTER EVERY PREP
#   A prep re-mkfs's the device, so inode NUMBERS are reused with fresh
#   generations.  Comparing a publish from before a prep against one from after
#   is meaningless, and it manufactures verdicts: an unmarked window produced 20
#   "divergences" with 269-271 SECOND gaps, all of them straddling a prep.
#   `mark` stamps the window WITHOUT touching mxfs.instr, so it is safe to run
#   immediately before a criterion.  --maxgap (default 60 s) is a second guard:
#   a real clobber lands within seconds of the publish it reverts.
#
# USAGE
#   tests/cluster_authority_merge.sh mark  <nodes>           # stamp window only (SAFE)
#   tests/cluster_authority_merge.sh arm   <nodes>           # + raise instr (PERTURBS)
#   tests/cluster_authority_merge.sh check <nodes> [skew_ms] [maxgap_s]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

STAGE="${1:?usage: cluster_authority_merge.sh <arm|check> <nodes> [skew_ms]}"
N="${2:-32}"
SKEW_MS="${3:-50}"

nodes() { local i; for ((i = 1; i <= N; i++)); do echo "test$i"; done; }

MAXGAP_S="${4:-60}"

if [ "$STAGE" = mark ]; then
    for h in $(nodes); do
        tools/mxfs_sshpass.sh "$h" \
            "echo 'MXFS_CLAUTH_WINDOW mark' > /dev/kmsg" >/dev/null 2>&1 &
    done
    wait
    echo "--- MXFS_CLAUTH_WINDOW stamped on $N node(s) (instr untouched) ---"
    exit 0
fi

if [ "$STAGE" = arm ]; then
    for h in $(nodes); do
        tools/mxfs_sshpass.sh "$h" \
            "echo 1 > /sys/module/mxfs/parameters/instr 2>/dev/null
             echo 'MXFS_CLAUTH_WINDOW mark' > /dev/kmsg" >/dev/null 2>&1 &
    done
    wait
    echo "--- mxfs.instr raised + MXFS_CLAUTH_WINDOW stamped on $N node(s) ---"
    exit 0
fi

D=$(mktemp -d)
for h in $(nodes); do
    (
        timeout 40 tools/mxfs_sshpass.sh "$h" '
            dmesg | awk "/MXFS_CLAUTH_WINDOW/{m=NR} {l[NR]=\$0}
                         END{ if (m) for(i=m+1;i<=NR;i++) print l[i]; else for(i=1;i<=NR;i++) print l[i] }" |
            grep -E "P170-CLWR|P218-CLUSTER-PASSENGER|P219-LOGGED-NO-AUTHORITY"
        ' 2>/dev/null > "$D/$h"
    ) >/dev/null 2>&1 &
done
wait

python3 - "$D" "$N" "$SKEW_MS" "$MAXGAP_S" <<'PY'
import os, re, sys, glob

d, n, skew_ms = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
maxgap_ns = int(sys.argv[4]) * 1000000000
skew_ns = skew_ms * 1000000

# node -> authoritative publications: ino -> [(realns, mode, gentail)]
pub = {}
# passenger writes without authority: (node, realns, ino, gentail, mode, why)
pas = []
# sess30 P219 class: (node, ns, ino, gentail, mode, cc, stale, isdir, dlm_mode, se, ne)
logw = []
skipped_n = [0]

re_clwr = re.compile(r'P170-CLWR .*?\[(?P<slots>[^\]]*)\].*?realns=(?P<ns>\d+)')
# sess30 — GPT review item 2.  Second numerator class: a slot this node DID log
# this round, published to home after the tenure it was staged under was lost
# (i_dlm_epoch moved between xfs_iflush's copy-in and xfsaild's submit), or with
# no write authority at all at submit time.  Same merge, different population.
re_logged = re.compile(
    r'P219-LOGGED-NO-AUTHORITY .*?ino=(?P<ino>\d+) isdir=(?P<isdir>\d) '
    r'staged=(?P<staged>\d) dlm_mode=(?P<dm>-?\d+) stage_mode=(?P<sm>-?\d+) '
    r'relflush=(?P<rf>\d) demoter=(?P<dem>\d) stage_epoch=(?P<se>\d+) '
    r'now_epoch=(?P<ne>\d+) stale=(?P<stale>\d) img_gen=(?P<gen>\d+) '
    r'img_cc=(?P<cc>\d+) img_mode=(?P<mode>\d+) img_nl=(?P<nl>\d+) '
    r'stage_ns=(?P<sns>\d+).*?realns=(?P<ns>\d+)')

re_pass = re.compile(
    r'P218-CLUSTER-PASSENGER .*?ino=(?P<ino>\d+) img_gen=(?P<gen>\d+) '
    r'img_cc=(?P<cc>\d+) '
    r'incore_gen=(?P<icg>-?\d+) img_mode=(?P<mode>\d+) dlm_mode=(?P<dm>-?\d+) '
    r'pr=(?P<pr>\d) genmm=(?P<gm>\d) nocore=(?P<nc>\d)'
    r'(?: skipped=(?P<sk>\d))?.*?realns=(?P<ns>\d+)')

for f in sorted(glob.glob(os.path.join(d, 'test*'))):
    node = os.path.basename(f)
    for line in open(f, errors='replace'):
        m = re_clwr.search(line)
        if m:
            ns = int(m.group('ns'))
            for tri in m.group('slots').split(','):
                if not tri or tri == 'x':
                    continue
                parts = tri.split(':')
                if len(parts) < 3:
                    continue
                parts = tri.split(':')
                try:
                    ino = int(parts[0]); mode = parts[1]; gen = int(parts[2])
                    cc = int(parts[3]) if len(parts) > 3 else -1
                except (ValueError, IndexError):
                    continue
                pub.setdefault(ino, []).append((ns, node, mode, gen, cc))
            continue
        m = re_logged.search(line)
        if m:
            logw.append((node, int(m.group('ns')), int(m.group('ino')),
                         int(m.group('gen')) % 10000, int(m.group('mode'), 8),
                         int(m.group('cc')), int(m.group('stale')),
                         int(m.group('isdir')), int(m.group('dm')),
                         int(m.group('se')), int(m.group('ne')),
                         int(m.group('sns'))))
            continue
        m = re_pass.search(line)
        if m:
            # img_mode is printed with %o by the kernel probe, exactly like
            # P170-CLWR's triples, so it MUST be parsed base 8.  Parsing it as
            # decimal makes every passenger look mode-divergent (100644 vs
            # int('100644',8)=33188) and manufactured 2115 false verdicts on the
            # first run of this harness.
            # A slot the fix DROPPED was never written; counting it as a
            # publication reports divergences for writes that never happened.
            if m.group('sk') == '1':
                skipped_n[0] += 1
                continue
            pas.append((node, int(m.group('ns')), int(m.group('ino')),
                        int(m.group('gen')) % 10000, int(m.group('mode'), 8),
                        int(m.group('cc')),
                        int(m.group('pr')), int(m.group('gm')), int(m.group('nc'))))

for ino in pub:
    pub[ino].sort()

print("=== INPUT ===")
print("  nodes read            : %d" % len(glob.glob(os.path.join(d, 'test*'))))
print("  distinct inodes seen  : %d" % len(pub))
print("  cluster-slot publishes: %d" % sum(len(v) for v in pub.values()))
print("  passenger slots DROPPED by the fix (not written): %d" % skipped_n[0])
print("  passenger writes      : %d" % len(pas))
print("  LOGGED-no-authority writes (sess30 P219): %d" % len(logw))


def verdict(label, rows, note):
    """rows = [(node, ns, ino, gentail, mode, cc), ...] -- shared merge."""
    regress, checked, nopeer, nocc = [], 0, 0, 0
    for row in rows:
        node, ns, ino, gentail, mode, cc = row[:6]
        prior = [p for p in pub.get(ino, [])
                 if ns - maxgap_ns < p[0] < ns - skew_ns and p[1] != node]
        if not prior:
            nopeer += 1
            continue
        checked += 1
        pns, pnode, pmode, pgen, pcc = prior[-1]
        why = ''
        if pgen != gentail:
            why = 'incarnation'
        elif int(pmode, 8) != mode:
            why = 'mode'
        elif pcc < 0 or cc < 0:
            nocc += 1
        elif cc < pcc:
            why = 'changecount %d < %d' % (cc, pcc)
        if why:
            regress.append((node, ns, ino, mode, gentail, cc,
                            pnode, pns, pmode, pgen, pcc, why))
    print("\n=== %s (skew guard %d ms, max gap %d s) ===" %
          (label, skew_ms, maxgap_ns // 1000000000))
    print("  %s" % note)
    print("  writes with a prior PEER publish : %d" % checked)
    print("  writes with no peer publish      : %d  (cannot be judged)" % nopeer)
    print("  compared on incarnation ONLY     : %d  (blind to same-incarnation reverts)" % nocc)
    print("  DIVERGENT (we reverted a peer image) : %d" % len(regress))
    for r in regress[:15]:
        node, ns, ino, mode, gentail, cc, pnode, pns, pmode, pgen, pcc, why = r
        print("\n  ino=%d" % ino)
        print("    %-8s published mode=%s gen..%d cc..%d at %d   <- authoritative" %
              (pnode, pmode, pgen, pcc, pns))
        print("    %-8s published mode=%o gen..%d cc..%d at %d   <- ours, no tenure"
              % (node, mode, gentail, cc, ns))
        print("    gap = %.3f s   differs in: %s" % ((ns - pns) / 1e9, why))
    if len(regress) > 15:
        print("\n  ... %d more" % (len(regress) - 15))
    return len(regress)


def verdict_directed(rows):
    """
    sess30 DIRECTION PROOF.  Two publishes of one ino with different di_gen
    tails prove different INCARNATIONS but not which is older -- a chunk-init
    generation is random, so the tails are not ordered.  The merge above
    therefore reports "incarnation" for a legitimate newer publish as readily
    as for a revert.

    P219 carries stage_ns: the instant xfs_iflush copied these exact bytes into
    the buffer.  A PEER publish that lands strictly inside (stage_ns, write_ns)
    is unambiguously NEWER than our bytes -- we cannot have observed it, because
    our image was already frozen in the buffer -- so writing over it is a
    REVERT, whatever the generations say.  No direction inference needed.
    """
    reverts, checked, nopeer = [], 0, 0
    for row in rows:
        node, ns, ino, gentail, mode, cc = row[:6]
        sns = row[11]
        if not sns:
            continue
        # peer publishes strictly between our copy-in and our submit
        mid = [p for p in pub.get(ino, [])
               if sns + skew_ns < p[0] < ns - skew_ns and p[1] != node]
        if not mid:
            nopeer += 1
            continue
        checked += 1
        pns, pnode, pmode, pgen, pcc = mid[-1]
        if pgen == gentail and pcc <= cc:
            continue     # same incarnation, our content is not older
        reverts.append((node, ns, sns, ino, mode, gentail, cc,
                        pnode, pns, pmode, pgen, pcc))
    print("\n=== DIRECTION-PROVEN REVERTS (P219 logged class) ===")
    print("  a PEER published this ino strictly between our copy-in and our submit,")
    print("  so its image is provably newer than the bytes we then wrote over it")
    print("  writes with a peer publish inside the staging window : %d" % checked)
    print("  writes with none (cannot be judged)                  : %d" % nopeer)
    print("  PROVEN REVERTS                                       : %d" % len(reverts))
    for r in reverts[:15]:
        node, ns, sns, ino, mode, gentail, cc, pnode, pns, pmode, pgen, pcc = r
        print("\n  ino=%d" % ino)
        print("    %-8s copy-in   mode=%o gen..%d cc..%d at %d" % (node, mode, gentail, cc, sns))
        print("    %-8s published mode=%s gen..%d cc..%d at %d   <- +%.3f s, newer than our bytes"
              % (pnode, pmode, pgen, pcc, pns, (pns - sns) / 1e9))
        print("    %-8s submitted mode=%o gen..%d cc..%d at %d   <- +%.3f s, REVERTS it"
              % (node, mode, gentail, cc, ns, (ns - pns) / 1e9))
    if len(reverts) > 15:
        print("\n  ... %d more" % (len(reverts) - 15))
    return len(reverts)


if logw:
    verdict("VERDICT -- LOGGED class (P219, sess30)", logw,
            "slots we DID log, published after the staging tenure was lost")
    verdict_directed(logw)

if not pas:
    print("\n  No P218-CLUSTER-PASSENGER lines in the window.")
    print("  Either the workload never wrote a multi-slot cluster, or the ring")
    print("  wrapped. This run proved NOTHING about divergence -- re-arm and")
    print("  use a shared-directory churn workload.")
    raise SystemExit(0)

regress, checked, nopeer, nocc = [], 0, 0, 0
for node, ns, ino, gentail, mode, cc, pr, gm, nc in pas:
    prior = [p for p in pub.get(ino, [])
             if ns - maxgap_ns < p[0] < ns - skew_ns and p[1] != node]
    if not prior:
        nopeer += 1
        continue
    checked += 1
    pns, pnode, pmode, pgen, pcc = prior[-1]
    why = ''
    if pgen != gentail:
        why = 'incarnation'
    elif int(pmode, 8) != mode:
        why = 'mode'
    elif pcc < 0 or cc < 0:
        # Pre-sess29 log line with no changecount field: incarnation-only
        # comparison. Count it so the blind fraction is visible.
        nocc += 1
    elif cc < pcc:
        # Same incarnation, our image carries an OLDER monotone changecount
        # than the one a peer already published: a content revert.
        why = 'changecount %d < %d' % (cc, pcc)
    if why:
        regress.append((node, ns, ino, mode, gentail, cc,
                        pnode, pns, pmode, pgen, pcc, why))

print("\n=== VERDICT (skew guard %d ms, max gap %d s) ===" %
      (skew_ms, maxgap_ns // 1000000000))
print("  passengers with a prior PEER publish : %d" % checked)
print("  passengers with no peer publish      : %d  (cannot be judged)" % nopeer)
print("  compared on incarnation ONLY (no cc)  : %d  (blind to same-incarnation reverts)" % nocc)
print("  DIVERGENT (we reverted a peer image) : %d" % len(regress))

for r in regress[:15]:
    node, ns, ino, mode, gentail, cc, pnode, pns, pmode, pgen, pcc, why = r
    print("\n  ino=%d" % ino)
    print("    %-8s published mode=%s gen..%d cc..%d at %d   <- authoritative" %
          (pnode, pmode, pgen, pcc, pns))
    print("    %-8s published mode=%o gen..%d cc..%d at %d   <- passenger, no tenure"
          % (node, mode, gentail, cc, ns))
    print("    gap = %.3f s   differs in: %s" % ((ns - pns) / 1e9, why))
if len(regress) > 15:
    print("\n  ... %d more" % (len(regress) - 15))

print("\nREAD IT LIKE THIS:")
print("  DIVERGENT > 0 = the authority violation is a real overwrite: this node's")
print("  cluster write reverted an image a PEER had already published.")
print("  DIVERGENT = 0 with 'passengers with a prior PEER publish' > 0 = exposure")
print("  present and every passenger image AGREED with the peer's -- an authority")
print("  violation that did not diverge on this workload. Report both numbers.")
PY
