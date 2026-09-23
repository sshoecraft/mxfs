#!/bin/bash
# dirshard_stage1_selftest.sh [node1] [node2]
#
# Rig verification of directory sharding stage 1 (sess466, docs/dir-sharding.md
# "Stage 1 wiring checklist"): the opt-in sharded mkdir ioctl, lifecycle to
# PUBLISHED, routed create/lookup/unlink/readdir/stat on two nodes, Model-A
# refusals (-EOPNOTSUPP), the rmdir emptiness barrier, teardown, the SipHash
# cross-check, and zero P-DIRSHARD-CORRUPT/STRANGER/ABANDON or kernel splats.
# Leaves TWO published sharded directories (dirshard_vectors N=16 with 64
# files, dirshard_n64 N=64 with 1500 files) for chk_mxfs to verify on the
# platter after the fleet unmount (the chain does that step).
#
# Preconditions: both nodes have /mnt/shared mounted on a build that carries
# the P-DIRSHARD markers (prep_cluster on 0.64.0+; a 0.63 module lacks the
# ioctl and every arm fails INFRA).
#
# derived time budgets (derived): sharded mkdir N=16 = 18 transactions < 2 s,
# N=64 = 66 transactions < 4 s; 64 local creates ~1 s, 1500 creates < 40 s
# (native XFS ~2 s; mxfs local create measured 5-25 ms each), cross-node
# listing < 5 s per call.  Per-ssh bound 90 s, whole script < 240 s.
# Exit 0 PASS, 1 FAIL, 2 INFRA.
set -u
N1=${1:-test1}; N2=${2:-test2}
MNT=/mnt/shared
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH=$REPO/tools/mxfs_sshpass.sh
PY=/src/mxfs/tests/dirshard_ioctl.py
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/tests/evidence/${TS}_dirshard_stage1
mkdir -p "$OUT"
fails=0
say() { echo "[dirshard_s1] $*"; }
fail() { say "FAIL: $*"; fails=$((fails+1)); }
pass() { say "PASS: $*"; }
r() { # r <node> <cmd>  (banner-stripped stdout; rc in $RC)
    local n="$1"; shift
    local o
    o=$(timeout 90 "$SSH" "$n" "$@" 2>&1); RC=$?
    echo "$o" | grep -av '^Unauthorized access\|^If you are not\|^Warning: Permanently\|^$'
}
echo "=== dirshard_stage1_selftest N1=$N1 N2=$N2 @ $TS out=$OUT ==="

# ── 0. preconditions ────────────────────────────────────────────────────────
for n in $N1 $N2; do
    sv=$(r $n "cat /sys/module/mxfs/srcversion; grep -c ' $MNT ' /proc/mounts; grep -c P-DIRSHARD-CORRUPT /proc/kallsyms >/dev/null; strings -a /src/mxfs/mxfs.ko | grep -c P-DIRSHARD-CORRUPT" | tr '\n' ' ')
    echo "$n: $sv" | tee "$OUT/pre_$n.txt"
    set -- $sv
    [ "${2:-0}" = 1 ] || { say "INFRA: $MNT not mounted on $n"; exit 2; }
    [ "${3:-0}" -ge 1 ] || { say "INFRA: module on $n lacks the dirshard markers (0.63 build?)"; exit 2; }
    # sharded mkdir is refused unless the module parameter allows it
    r $n "dmesg --clear; echo 1 > /sys/module/mxfs/parameters/dirshard_mkdir_enable" >/dev/null
done

D=$MNT/dirshard_vectors
r $N1 "rm -rf $MNT/dirshard_vectors $MNT/dirshard_n64 2>/dev/null; true" >/dev/null

# ── 1. sharded mkdir N=16 → PUBLISHED ───────────────────────────────────────
T0=$(date +%s)
o=$(r $N1 "python3 $PY mkdir $MNT dirshard_vectors 16"); echo "$o" > "$OUT/mkdir16.txt"
say "mkdir N=16 rc=$RC wall=$(( $(date +%s) - T0 ))s: $o"
# the parameter is on, so a refusal here means the filesystem has no sharding gates
echo "$o" | grep -q 'Operation not supported' && { say "INFRA: $MNT was not formatted with mkfs.mxfs -D (prep with MXFS_MKFS_OPTS=-D)"; exit 2; }
[ "$RC" = 0 ] && [ "$(echo "$o" | tail -1)" = OK ] && pass "sharded mkdir N=16" || fail "sharded mkdir N=16: rc=$RC $o"
j=$(r $N1 "python3 $PY info $D" | sed -n '/^{/,$p'); echo "$j" > "$OUT/info16.json"
st=$(echo "$j" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["state"], d["nshards"], d["nentries"], d["valid_mask"], sum(1 for s in d["shards"] if s["live"] and s["nlink"]==2 and s["gen"]!=0 and s["ino"]!=0))' 2>/dev/null)
[ "$st" = "PUBLISHED 16 16 0x000000000000ffff 16" ] && pass "INFO: $st" || fail "INFO after mkdir: '$st' (want PUBLISHED 16 16 0x000000000000ffff 16)"

# ── 2. Model-A refusals under the sharded parent ────────────────────────────
# sess472 (0.64.18, D-0531 item 4): an xattr set on the sharded parent is
# refused too — the attr fork must stay the shortform locator alone.
o=$(r $N1 "mkdir $D/sub 2>&1; ln -s x $D/lnk 2>&1; touch $MNT/plain_$TS && ln $MNT/plain_$TS $D/hl 2>&1; mv $MNT/plain_$TS $D/moved 2>&1; rm -f $MNT/plain_$TS; python3 -c \"import os; os.open('$D', os.O_TMPFILE|os.O_RDWR, 0o600)\" 2>&1 | tail -1; python3 -c \"import os; os.setxattr('$D', 'user.dirshard_probe', b'1')\" 2>&1 | tail -1; ls -A $D | wc -l"); echo "$o" > "$OUT/refusals.txt"
nrefuse=$(echo "$o" | grep -c 'Operation not supported\|EOPNOTSUPP')
left=$(echo "$o" | tail -1)
[ "$nrefuse" = 6 ] && [ "$left" = 0 ] && pass "mkdir/symlink/link/rename-into/O_TMPFILE/setxattr all -EOPNOTSUPP, dir still empty" || fail "Model-A refusals: $nrefuse of 6 refused, entries left=$left: $(echo "$o" | tr '\n' '|' | cut -c1-300)"

# ── 3. routed create / lookup / stat / readdir on N1 ────────────────────────
T0=$(date +%s)
# sess471: names are f_0001..f_0064 (seq -f %04g); the checks below read
# f_0007/f_0064 and the peer reads f_0001/g_0032 — a `seq -w` here made
# f_01..f_64 and every by-name check ENOENT'd on a healthy kernel (chain 109).
o=$(r $N1 "cd $D && for i in \$(seq -f %04g 1 64); do echo data\$i > f_\$i || echo CREATE_FAIL \$i; done; ls -a | grep -c '^\.\$'; ls -a | grep -c '^\.\.\$'; ls | wc -l; ls | sort -u | wc -l; cat f_0007; stat -c '%h %s' .; stat -c '%s' f_0064"); echo "$o" > "$OUT/create64.txt"
say "64 creates wall=$(( $(date +%s) - T0 ))s"
echo "$o" | grep -q CREATE_FAIL && fail "create into the sharded dir: $(echo "$o" | grep CREATE_FAIL | head -3 | tr '\n' ' ')"
set -- $(echo "$o" | tail -7 | tr '\n' ' ')
[ "${1:-}" = 1 ] && [ "${2:-}" = 1 ] && pass "readdir emits exactly one . and one .." || fail "readdir dots: .=${1:-} ..=${2:-}"
[ "${3:-}" = 64 ] && [ "${4:-}" = 64 ] && pass "readdir lists 64 unique names" || fail "readdir: count=${3:-} unique=${4:-}"
[ "${5:-}" = data0007 ] && pass "lookup + read through a shard" || fail "lookup/read f_0007: '${5:-}'"
[ "${6:-}" = 2 ] && [ "${7:-0}" -gt 0 ] && pass "stat synthesis: nlink 2, logical size ${7:-}" || fail "stat synthesis: nlink=${6:-} size=${7:-}"
[ "${8:-}" = 9 ] && pass "file size through the shard" || fail "f_0064 size ${8:-} != 9"

# ── 4. hash cross-check: kernel routing vs chk_mxfs mirror ──────────────────
o=$("$REPO/tests/dirshard_hash_vectors.sh" "$N1" "$D" 2>&1); echo "$o" > "$OUT/hash_vectors.txt"
echo "$o" | grep -q '^VERDICT PASS' && pass "hash vectors (kernel == chk_mxfs == published)" || fail "hash vectors: $(echo "$o" | grep FAIL | head -3 | tr '\n' ' ')"
# every file really lives in the shard the hash names
# sess472: the sed range end was written as \\\$p, which the local double
# quotes turned into \$p and the remote single quotes kept literal — sed then
# refused 'unterminated address regex' on every lap (chain 112 s472a, 0.64.14).
# \$p here reaches the remote shell as $p.
o=$(r $N1 "for f in f_0001 f_0032 f_0064; do python3 $PY info $D \$f | sed -n '/^{/,\$p' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[\"name_shard\"], d[\"shards\"][d[\"name_shard\"]][\"ino\"])'; done"); echo "$o" > "$OUT/route.txt"
say "routes: $(echo "$o" | tr '\n' ' ')"
[ "$(echo "$o" | grep -c '^[0-9]* [0-9]*$')" = 3 ] && pass "INFO routes three names to live shards" || fail "INFO routing: $o"

# ── 5. cross-node: N2 sees, creates, N1 sees, N1 unlinks, N2 sees ──────────
o=$(r $N2 "ls $D | wc -l; cat $D/f_0001; cd $D && for i in \$(seq -f %04g 1 32); do echo peer\$i > g_\$i || echo CREATE_FAIL \$i; done; ls | wc -l"); echo "$o" > "$OUT/peer_create.txt"
set -- $(echo "$o" | tr '\n' ' ')
[ "${1:-}" = 64 ] && [ "${2:-}" = data0001 ] && pass "$N2 sees 64 entries and reads f_0001" || fail "$N2 view: count=${1:-} read='${2:-}'"
[ "${3:-}" = 96 ] && pass "$N2 created 32, sees 96" || fail "$N2 after create: ${3:-} ($o)"
o=$(r $N1 "ls $D | wc -l; cat $D/g_0032; cd $D && rm -f f_* ; ls | wc -l; stat -c %h ."); echo "$o" > "$OUT/n1_after_peer.txt"
set -- $(echo "$o" | tr '\n' ' ')
[ "${1:-}" = 96 ] && [ "${2:-}" = peer0032 ] && pass "$N1 sees the peer's 32 (96 total) and reads g_0032" || fail "$N1 view after peer: ${1:-} '${2:-}'"
[ "${3:-}" = 32 ] && pass "$N1 unlinked 64 through the shards (32 left)" || fail "$N1 after unlink: ${3:-}"
o=$(r $N2 "ls $D | wc -l; stat $D/f_0001 2>&1 | grep -c 'No such file'; cd $D && rm -f g_* ; ls | wc -l"); echo "$o" > "$OUT/n2_after_unlink.txt"
set -- $(echo "$o" | tr '\n' ' ')
[ "${1:-}" = 32 ] && [ "${2:-}" = 1 ] && [ "${3:-}" = 0 ] && pass "$N2 sees the unlinks (32, f_0001 ENOENT) and empties the dir" || fail "$N2 after unlink: ${1:-} ${2:-} ${3:-}"

# ── 6. rmdir barrier: non-empty refused, empty succeeds, gone on both ───────
o=$(r $N1 "echo x > $D/last; rmdir $D 2>&1; ls $D | wc -l; rm -f $D/last; rmdir $D 2>&1; echo RMDIR_RC=\$?; stat $D 2>&1 | grep -c 'No such file'"); echo "$o" > "$OUT/rmdir.txt"
echo "$o" | grep -q 'Directory not empty' && pass "rmdir of a non-empty sharded dir -ENOTEMPTY" || fail "rmdir non-empty: $o"
echo "$o" | grep -q 'RMDIR_RC=0' && echo "$o" | tail -1 | grep -q '^1$' && pass "rmdir of the emptied sharded dir succeeded" || fail "rmdir empty: $o"
o=$(r $N2 "stat $D 2>&1 | grep -c 'No such file'; python3 $PY info $D 2>&1 | head -1")
echo "$o" | head -1 | grep -q '^1$' && pass "$N2: the removed sharded dir is gone" || fail "$N2 after rmdir: $o"

# ── 7. N=64 with 1500 files: multi-getdents readdir, block-format shards ────
T0=$(date +%s)
# sess473: the info tool prints a header line before the JSON — steps 1 and 4
# strip it with sed; this step did not, so json.load raised on every lap
# (chain 113 s472j, 0.64.18: 'N=64 info' FAIL on a healthy creator).
o=$(r $N1 "python3 $PY mkdir $MNT dirshard_n64 64 && cd $MNT/dirshard_n64 && seq -w 1 1500 | xargs -n 250 sh -c 'for i in \"\$@\"; do : > n_\$i; done' _ ; ls | wc -l; ls | sort -u | wc -l; python3 -c 'import os; l=os.listdir(\".\"); print(len(l), len(set(l)))'; python3 $PY info . | sed -n '/^{/,\$p' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[\"state\"], d[\"nshards\"], min(s[\"nlink\"] for s in d[\"shards\"]), max(s[\"nlink\"] for s in d[\"shards\"]))'"); echo "$o" > "$OUT/n64.txt"
say "N=64 mkdir + 1500 creates wall=$(( $(date +%s) - T0 ))s"
set -- $(echo "$o" | tail -4 | tr '\n' ' ')
[ "${1:-}" = 1500 ] && [ "${2:-}" = 1500 ] && [ "${3:-}" = 1500 ] && [ "${4:-}" = 1500 ] && pass "N=64: 1500 files listed once each by ls and getdents" || fail "N=64 listing: ${1:-} ${2:-} ${3:-} ${4:-}"
[ "${5:-}" = PUBLISHED ] && [ "${6:-}" = 64 ] && [ "${7:-}" = 2 ] && [ "${8:-}" = 2 ] && pass "N=64 PUBLISHED, all containers nlink 2" || fail "N=64 info: ${5:-} ${6:-} nlink ${7:-}..${8:-}"
o=$(r $N2 "ls $MNT/dirshard_n64 | wc -l; ls $MNT/dirshard_n64 | sort -u | wc -l")
[ "$(echo "$o" | tr '\n' ' ')" = "1500 1500 " ] && pass "$N2 lists the 1500 once each" || fail "$N2 N=64 listing: $o"
# re-create the vectors dir (64 files) for the on-platter check
o=$(r $N1 "python3 $PY mkdir $MNT dirshard_vectors 16 && cd $D && for i in \$(seq -f %04g 1 64); do echo data\$i > f_\$i; done; ls | wc -l")
[ "$(echo "$o" | tail -1)" = 64 ] && pass "vectors dir re-created with 64 files for chk" || fail "re-create vectors dir: $o"

# ── 8. kernel-side health on both nodes ─────────────────────────────────────
for n in $N1 $N2; do
    o=$(r $n "dmesg | grep -c 'P-DIRSHARD-CORRUPT\|P-DIRSHARD-STRANGER\|P-DIRSHARD-ABANDON\|P-DIRSHARD-LOCATOR-DEFERRED'; dmesg | grep -c 'Oops\|WARNING:\|BUG:\|general protection\|Corruption of in-memory'; dmesg | grep -c 'P-DIRSHARD'"); echo "$o" > "$OUT/health_$n.txt"
    set -- $(echo "$o" | tr '\n' ' ')
    [ "${1:-1}" = 0 ] && [ "${2:-1}" = 0 ] && pass "$n: zero P-DIRSHARD corruption lines, zero splats (dirshard lines=${3:-})" || fail "$n health: corrupt=${1:-} splats=${2:-}"
    r $n "dmesg | grep -a 'P-DIRSHARD\|Oops\|WARNING:\|BUG:' | head -40" > "$OUT/dmesg_$n.txt"
done

say "fails=$fails out=$OUT"
[ "$fails" -eq 0 ] && { echo "VERDICT PASS dirshard_stage1 out=$OUT"; exit 0; } || { echo "VERDICT FAIL dirshard_stage1 fails=$fails out=$OUT"; exit 1; }
