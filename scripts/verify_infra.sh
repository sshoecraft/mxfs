#!/bin/bash
# MXFS INFRA verifier — INFRA ONLY.  Confirms the shared LUN is correctly
# PRESENTED to each node for a given deploy condition.  It does NOT touch the
# filesystem: no mkfs, no `mount -t mxfs`, no mxfs module load, no workload.
# Testing the filesystem/CAW coordination is the test harness's job
# (tests/run_tests.sh) and is deliberately out of scope here.
#
# Per-node checks (raw block device only):
#   * the shared LUN is present with the expected vendor + size
#   * it is readable as a raw block device (a direct dd of one block)
#   * it is the SAME LUN on every node — proven by the cross-node SCSI CAW
#     check for CAW modes, or by matching SCSI unit serial for TCP/LIO
# The raw SCSI COMPARE AND WRITE check (tools/caw_verify) is a STORAGE
# capability check on the LUN (does the target honour CAW 0x89 cross-initiator),
# NOT a filesystem test.
#
# Usage: scripts/verify_infra.sh {tcp|direct|passthrough|multipath} [N]
#   tcp         — LIO/tcm_loop shared LUN, virtio passthrough (vendor LIO-ORG)
#   passthrough — SCST + clyde-initiator passthrough (vendor SCST_FIO, N sd* on clyde)
#   direct      — SCST + each VM its own iSCSI initiator, single path (SCST_FIO)
#   multipath   — SCST advertised on TWO portals; each VM logs into both -> a
#                 2-path dm-multipath device /dev/mapper/mpathX.  CHARACTERISES
#                 whether CAW (retry-aware) and PR work through dm-multipath —
#                 the enterprise-SAN case.  See docs/condition4_multipath_scope.md.
#   N — node count 1..32 (default 2)

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"

MODE="${1:-}"; N="${2:-2}"
case "$MODE" in tcp|direct|passthrough|multipath) ;; *) echo "usage: $0 {tcp|direct|passthrough|multipath} [N]" >&2; exit 2 ;; esac
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] && [ "$N" -le 32 ] || { echo "N out of range 1..32" >&2; exit 2; }

export MXFS_SSH_TIMEOUT=120
CAW="$MXFS_REPO/tools/caw_verify"
PORTAL1="192.168.120.1:3260"
PORTAL2_IP="192.168.120.2"                     # 2nd br0 alias for the multipath cond
PORTAL2="${PORTAL2_IP}:3260"
EXPECT_VENDOR=$([ "$MODE" = "tcp" ] && echo LIO-ORG || echo SCST_FIO)
EXPECT_SECTORS=$((50*1024*1024*1024/512))     # 50 GiB LUN
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done
say() { echo "$@"; }

restart_nodes() {
    local n pids=()
    for n in "$@"; do
        ( virsh -c qemu:///system destroy "$n" 2>/dev/null
          sleep 2; virsh -c qemu:///system start "$n" 2>/dev/null
          for try in $(seq 1 20); do
              timeout 8 "$MXFS_SSH" "$n" "$MXFS_PASS" "
                  mkdir -p /src
                  mountpoint -q /src || mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null
                  [ -x $CAW ]" >/dev/null 2>&1 && break
              sleep 3
          done ) &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
}

# size of any block device in 512-byte sectors (works for sd* AND dm-multipath)
dev_sectors() { ssh_node "$1" "blockdev --getsz $2 2>/dev/null" | tr -cd '0-9'; }

# Find the single-path shared LUN device (vendor match) on a node.
find_dev() {
    ssh_node "$1" "for d in /dev/sd?; do [ -b \$d ] || continue; v=\$(cat /sys/block/\$(basename \$d)/device/vendor 2>/dev/null | tr -d ' '); [ \"\$v\" = '$EXPECT_VENDOR' ] && { echo \$d; break; }; done" | tr -d '[:space:]'
}

# Present the single-path LUN on one node (no mxfs), retrying, return its device.
present_and_find() {
    local n="$1" dev="" try
    for try in 1 2 3 4 5; do
        dev=$(find_dev "$n"); [ -n "$dev" ] && break
        if [ "$MODE" = direct ]; then
            ssh_node_quiet "$n" "
                iscsiadm -m node -u all 2>/dev/null
                iscsiadm -m node -o delete 2>/dev/null
                iscsiadm -m discovery -t st -p $PORTAL1 >/dev/null 2>&1
                iscsiadm -m node --login >/dev/null 2>&1
                iscsiadm -m session --rescan >/dev/null 2>&1"
        fi
        sleep 4
        dev=$(find_dev "$n"); [ -n "$dev" ] && break
    done
    [ -n "$dev" ] && ssh_node_quiet "$n" "echo 180 > /sys/block/$(basename "$dev")/device/timeout 2>/dev/null"
    echo "$dev"
}

read_serial() {
    local n="$1" dev="$2" s="" k
    for k in 1 2; do
        s=$(ssh_node "$n" "sg_inq -p 0x80 $dev 2>/dev/null | sed -n 's/.*erial number: *//p'" | tr -cd '[:alnum:]')
        [ -n "$s" ] && break; sleep 1
    done
    echo "$s"
}

# ======================================================================
# CONDITION 4 — CAW over dm-multipath (characterisation harness)
# ======================================================================
verify_multipath() {
    say "=== INFRA verify: mode=multipath N=$N nodes=${NODES[*]} (no filesystem ops) ==="

    # 1. host: 2nd br0 portal + SCST advertised on BOTH portals.
    say "--- host: 2nd br0 alias $PORTAL2_IP + scst_setup on 2 portals ---"
    $SUDO ip addr add "${PORTAL2_IP}/24" dev br0 2>/dev/null || true   # idempotent
    "$SCRIPT_DIR/scst_wire_passthrough.sh" detach "$N" >/dev/null 2>&1 || true
    "$SCRIPT_DIR/wire_vms.sh" detach "$N" >/dev/null 2>&1 || true
    MXFS_SCST_PORTAL_IP="192.168.120.1 $PORTAL2_IP" "$SCRIPT_DIR/scst_setup.sh" setup >/dev/null \
        || { echo "SCST 2-portal setup failed"; return 1; }

    # 2. guest buildup: find_multipaths yes (+ clear wwids) so the 2-path device
    #    IS assembled into /dev/mapper/mpathX.  multipathd stays running.
    say "--- guest buildup: find_multipaths yes on ${NODES[*]} ---"
    for n in "${NODES[@]}"; do
        ( timeout 25 "$MXFS_SSH" "$n" "$MXFS_PASS" '
            mkdir -p /etc/multipath/conf.d
            printf "defaults {\n    find_multipaths yes\n}\n" > /etc/multipath/conf.d/mxfs.conf
            : > /etc/multipath/wwids
            iscsiadm -m node -u all 2>/dev/null; iscsiadm -m node -o delete 2>/dev/null
            multipath -F 2>/dev/null; systemctl restart multipathd 2>/dev/null' >/dev/null 2>&1 ) &
    done; wait

    say "--- restarting ${NODES[*]} to apply wiring ---"
    restart_nodes "${NODES[@]}"

    # 3. present: log into BOTH portals -> 2 sessions -> /dev/mapper/mpathX
    say "--- per-node multipath presentation checks ---"
    local ok=0 twopaths=0 n dev sectors readable serial base="" serial_same=yes got=0
    declare -A MPDEV
    for n in "${NODES[@]}"; do
        local mp="" try
        for try in 1 2 3 4 5; do
            ssh_node_quiet "$n" "
                iscsiadm -m node -u all 2>/dev/null; iscsiadm -m node -o delete 2>/dev/null
                iscsiadm -m discovery -t st -p $PORTAL1 >/dev/null 2>&1
                iscsiadm -m discovery -t st -p $PORTAL2 >/dev/null 2>&1
                iscsiadm -m node --login >/dev/null 2>&1
                iscsiadm -m session --rescan >/dev/null 2>&1
                multipath 2>/dev/null"
            sleep 4
            mp=$(ssh_node "$n" "for d in /dev/mapper/mpath*; do [ -b \$d ] && { echo \$d; break; }; done" | tr -d '[:space:]')
            [ -n "$mp" ] && break
        done
        MPDEV[$n]="$mp"
        if [ -z "$mp" ]; then say "  $n: FAIL — no /dev/mapper/mpath device"; continue; fi
        local paths
        paths=$(ssh_node "$n" "multipath -ll $mp 2>/dev/null | grep -cE 'sd[a-z] '" | tr -cd '0-9'); paths=${paths:-0}
        sectors=$(dev_sectors "$n" "$mp")
        readable=$(ssh_node "$n" "dd if=$mp of=/dev/null bs=4096 count=1 iflag=direct >/dev/null 2>&1 && echo R" | tr -cd 'R')
        serial=$(read_serial "$n" "$mp"); [ -n "$serial" ] && { got=$((got+1)); [ -z "$base" ] && base="$serial"; [ "$serial" = "$base" ] || serial_same=no; }
        [ "${paths:-0}" -ge 2 ] && twopaths=$((twopaths+1))
        if [ "${sectors:-0}" = "$EXPECT_SECTORS" ] && [ "$readable" = "R" ] && [ "${paths:-0}" -ge 2 ]; then
            say "  $n: OK  dev=$mp paths=$paths sectors=$sectors readable=yes serial=${serial:-?}"
            ok=$((ok+1))
        else
            say "  $n: FAIL dev=$mp paths=${paths:-0} (want>=2) sectors=${sectors:-?} readable=${readable:-no}"
        fi
    done
    [ "$got" -ge 1 ] || serial_same=unknown
    say "--- shared-LUN identity: serial=$base read_on=$got/$N match=$serial_same ---"

    # 4. CHARACTERISE: retry-aware CAW cross-node THROUGH /dev/mapper/mpathX.
    local A="${NODES[0]}" B="${NODES[1]:-}" MPA="${MPDEV[${NODES[0]}]:-}" MPB=""
    [ "$N" -ge 2 ] && MPB="${MPDEV[${NODES[1]}]:-}"
    say "--- CAW through dm-multipath (retry-aware) ---"
    local caw_first="n/a" caw_retry="n/a"
    if [ -n "$MPA" ] && [ -n "$MPB" ]; then
        # first: NO retry (does a bare CAW hit the UA we saw before?)
        if ssh_node "$A" "$CAW write $MPA 2048 c7 2>&1 | tail -1"; then :; fi
        ssh_node "$A" "$CAW write $MPA 2048 c7" >/dev/null 2>&1 && caw_first=PASS || caw_first="FAIL(no-retry)"
        # then: WITH --retry-ua
        ssh_node_quiet "$A" "$CAW --retry-ua write $MPA 2049 d4"
        if timeout "$MXFS_SSH_TIMEOUT" "$MXFS_SSH" "$B" "$MXFS_PASS" "$CAW --retry-ua read $MPB 2049 d4" >/dev/null 2>&1; then
            caw_retry="PASS ($A write / $B read, retry-aware)"
        else caw_retry="FAIL(even with retry)"; fi
    else caw_first="n/a"; caw_retry="n/a (need 2 mpath devices)"; fi
    say "  CAW no-retry : $caw_first"
    say "  CAW retry-ua : $caw_retry"

    # 5. CHARACTERISE: PR (fencing) across paths via sg_persist.
    say "--- PR across multipath paths (sg_persist) ---"
    local pr="n/a"
    if [ -n "$MPA" ] && [ -n "$MPB" ]; then
        # clean any stale PR, then A registers with ALL_TG_PT (key covers all
        # target ports) and reserves WE-RO through its mpath device.
        ssh_node_quiet "$A" "sg_persist --out --register-ignore --param-sark=0x5eed $MPA 2>/dev/null; sg_persist --out --clear --param-rk=0x5eed $MPA 2>/dev/null"
        ssh_node_quiet "$A" "sg_persist --out --register --param-sark=0xa11 --param-alltgpt $MPA 2>/dev/null; sg_persist --out --reserve --param-rk=0xa11 --prout-type=5 $MPA 2>/dev/null"
        local seenB awA fenceB
        seenB=$(ssh_node "$B" "sg_persist --in --read-reservation $MPB 2>/dev/null | grep -ci '0xa11'" | tr -cd '0-9')
        ssh_node_quiet "$A" "$CAW --retry-ua write $MPA 2050 5a" && awA=ok || awA=fail          # registrant writes
        ssh_node_quiet "$B" "$CAW --retry-ua write $MPB 2051 99" && fenceB=WROTE || fenceB=blocked # non-registrant fenced
        if [ "${seenB:-0}" -ge 1 ] && [ "$awA" = ok ] && [ "$fenceB" = blocked ]; then
            pr="PASS (B sees A's WE-RO resv thru its mpath; registrant A writes; non-registrant B fenced)"
        else
            pr="FAIL (B_sees_resv=${seenB:-0} A_registrant_write=$awA B_nonregistrant=$fenceB)"
        fi
        ssh_node_quiet "$A" "sg_persist --out --release --param-rk=0xa11 --prout-type=5 $MPA 2>/dev/null; sg_persist --out --clear --param-rk=0xa11 $MPA 2>/dev/null"
    fi
    say "  PR: $pr"

    # 6. footprint: guests are the initiators (2 sessions each), clyde has none.
    local sess sdc
    sess=$($SUDO iscsiadm -m session 2>/dev/null | grep -c 'iqn.2026-05.local.mxfs'); sess=${sess:-0}
    sdc=$(grep -cE ' sd[a-z]+$' /proc/partitions)
    say "--- clyde footprint: sessions=$sess sd*=$sdc (expect 0/0 — guests initiate) ---"

    say ""
    say "=== INFRA VERIFY: mode=multipath  nodes_ok=$ok/$N  two_paths=$twopaths/$N  same_lun=$serial_same"
    say "      CAW(no-retry)=$caw_first  CAW(retry)=$caw_retry  PR=$pr ==="
    { [ "$ok" -eq "$N" ] && { [ "$serial_same" = yes ] || [ "$serial_same" = unknown ]; }; } || return 1
}

# ---- dispatch ----
if [ "$MODE" = multipath ]; then verify_multipath; exit $?; fi

# ======================================================================
# CONDITIONS 1-3 — single-path presentation
# ======================================================================
say "=== INFRA verify: mode=$MODE N=$N nodes=${NODES[*]} (no filesystem ops) ==="

if [ "$MODE" = "tcp" ]; then
    say "--- host: lio_tcm_setup.sh setup ---"
    "$SCRIPT_DIR/lio_tcm_setup.sh" setup >/dev/null || { echo "LIO setup failed"; exit 1; }
    "$SCRIPT_DIR/scst_wire_passthrough.sh" detach "$N" >/dev/null 2>&1 || true
    "$SCRIPT_DIR/wire_vms.sh" attach "$N" >/dev/null 2>&1 || { echo "wire failed"; exit 1; }
else
    say "--- host: scst_setup.sh setup ---"
    "$SCRIPT_DIR/scst_setup.sh" setup >/dev/null || { echo "SCST setup failed"; exit 1; }
    if [ "$MODE" = "passthrough" ]; then
        "$SCRIPT_DIR/wire_vms.sh" detach "$N" >/dev/null 2>&1 || true
        "$SCRIPT_DIR/scst_wire_passthrough.sh" attach "$N" >/dev/null 2>&1 || { echo "passthrough wiring failed"; exit 1; }
    else
        "$SCRIPT_DIR/wire_vms.sh" detach "$N" >/dev/null 2>&1 || true
        "$SCRIPT_DIR/scst_wire_passthrough.sh" detach "$N" >/dev/null 2>&1 || true
    fi
fi

say "--- restarting ${NODES[*]} to apply wiring ---"
restart_nodes "${NODES[@]}"

say "--- per-node LUN presentation checks ---"
ok=0; declare -A SERIAL
for n in "${NODES[@]}"; do
    dev=$(present_and_find "$n")
    if [ -z "$dev" ]; then say "  $n: FAIL — no $EXPECT_VENDOR LUN present"; continue; fi
    sectors=$(dev_sectors "$n" "$dev")
    readable=$(ssh_node "$n" "dd if=$dev of=/dev/null bs=4096 count=1 iflag=direct >/dev/null 2>&1 && echo R" | tr -cd 'R')
    serial=$(read_serial "$n" "$dev"); SERIAL[$n]="$serial"
    if [ "${sectors:-0}" = "$EXPECT_SECTORS" ] && [ "$readable" = "R" ]; then
        say "  $n: OK  dev=$dev vendor=$EXPECT_VENDOR sectors=$sectors readable=yes serial=${serial:-?}"
        ok=$((ok+1))
    else
        say "  $n: FAIL dev=$dev sectors=${sectors:-?} (want $EXPECT_SECTORS) readable=${readable:-no}"
    fi
done

say "--- shared-LUN identity (matching SCSI serial) ---"
base=""; serial_same=yes; got=0
for n in "${NODES[@]}"; do
    s="${SERIAL[$n]:-}"; [ -n "$s" ] || continue
    got=$((got+1)); [ -z "$base" ] && base="$s"
    [ "$s" = "$base" ] || serial_same=no
done
[ "$got" -ge 1 ] || serial_same=unknown
say "  serial=$base read_on=$got/$N match=$serial_same"

CAWRES="n/a(tcp)"; caw_ok=no
if [ "$MODE" != "tcp" ] && [ "$N" -ge 2 ]; then
    A="${NODES[0]}"; B="${NODES[1]}"
    da=$(find_dev "$A"); db=$(find_dev "$B")
    if [ -n "$da" ] && [ -n "$db" ]; then
        ssh_node_quiet "$A" "$CAW write $da 2048 a5"
        if timeout "$MXFS_SSH_TIMEOUT" "$MXFS_SSH" "$B" "$MXFS_PASS" "$CAW read $db 2048 a5" >/dev/null 2>&1; then
            CAWRES="PASS ($A CAW-write / $B read)"; caw_ok=yes
        else CAWRES="FAIL"; fi
    else CAWRES="FAIL (device missing on $A/$B)"; fi
fi
say "--- raw SCSI CAW capability: $CAWRES ---"

say "--- clyde footprint (mode invariant) ---"
sess=$($SUDO iscsiadm -m session 2>/dev/null | grep -c 'iqn.2026-05.local.mxfs'); sess=${sess:-0}
sdc=$(grep -cE ' sd[a-z]+$' /proc/partitions)
say "  clyde iSCSI sessions=$sess  sd*=$sdc"
foot=ok
case "$MODE" in
    direct)      say "  expect: sessions=0  sd*=0";  { [ "$sess" -eq 0 ] && [ "$sdc" -eq 0 ]; } || foot=MISMATCH ;;
    passthrough) say "  expect: sessions=$N sd*=$N"; { [ "$sess" -eq "$N" ] && [ "$sdc" -eq "$N" ]; } || foot=MISMATCH ;;
    tcp)         say "  expect: sessions=0  sd*=1";  { [ "$sess" -eq 0 ] && [ "$sdc" -eq 1 ]; } || foot=MISMATCH ;;
esac
say "  footprint: $foot"

if [ "$MODE" = tcp ]; then sharing="$serial_same"; else sharing="$caw_ok"; fi
say ""
say "=== INFRA VERIFY: mode=$MODE  nodes_ok=$ok/$N  same_lun=$sharing  footprint=$foot ==="
{ [ "$ok" -eq "$N" ] && [ "$sharing" = yes ] && [ "$foot" = ok ]; } || exit 1
