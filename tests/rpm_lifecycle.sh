#!/bin/bash
#
# rpm_lifecycle.sh — does the RPM leave exactly one working module through
# every transaction a user can run?
#
# On NODE (an EL node with DKMS and kernel headers, MXFS unmounted):
#   1. erase whatever mxfs is installed; nothing may stay registered in DKMS
#   2. install OLD (an earlier dist/ build), then upgrade to NEW: DKMS holds
#      NEW only, installed for the running kernel, and it loads
#   3. dnf reinstall NEW: the module is still installed and loads (a %preun
#      that removed mxfs/NEW unconditionally deleted the build the reinstall's
#      own %post had just made)
#   4. erase: nothing registered, no mxfs.ko under /lib/modules
#
# Budget per transaction: a DKMS build of mxfs on these nodes measured 206 s
# (packaged round install, two nodes at once), so INSTALL_S=420.
#
# Usage: tests/rpm_lifecycle.sh NODE OLD NEW
#   NODE is an address tools/mxfs_sshpass.sh reaches; OLD and NEW are versions
#   in dist/.  Evidence: tests/evidence/rpm_lifecycle/<stamp>/.  Exit 0 on PASS.
#
set -u

NODE="${1:?usage: rpm_lifecycle.sh NODE OLD NEW}"
OLD="${2:?usage: rpm_lifecycle.sh NODE OLD NEW}"
NEW="${3:?usage: rpm_lifecycle.sh NODE OLD NEW}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
INSTALL_S=420
EV="$HERE/tests/evidence/rpm_lifecycle/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
on() { local t=$1; shift; timeout "$t" "$SSH" "$NODE" "$@" </dev/null 2>&1 | grep -v -E "^Warning: Permanently|Unauthorized access|authorized user"; return "${PIPESTATUS[0]}"; }
FAILS=0
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
# what DKMS holds and whether the module loads, as key=value lines
STATE="echo registered=\$(dkms status mxfs 2>/dev/null | sed -n 's|^mxfs[/, ]*\([^,:]*\).*|\1|p' | sort -u | tr '\n' ' ')
       echo kofiles=\$(find /lib/modules -name 'mxfs.ko*' 2>/dev/null | wc -l)
       rmmod mxfs 2>/dev/null; modprobe mxfs 2>/dev/null; echo loads=\$?
       echo version=\$(cat /sys/module/mxfs/version 2>/dev/null)
       rmmod mxfs 2>/dev/null; true"
state() { on 60 "$STATE" > "$EV/state_$1.log"; cat "$EV/state_$1.log" | sed "s/^/  $1: /"; }
val() { sed -n "s/^$2=//p" "$EV/state_$1.log" | sed 's/ *$//'; }

for v in "$OLD" "$NEW"; do
    [ -f "$HERE/dist/$v/mxfs-$v-1.el8.x86_64.rpm" ] || { say "no dist/$v rpm"; exit 2; }
    on 60 "true" && "$SSH" "$NODE" SCP "$HERE/dist/$v/mxfs-$v-1.el8.x86_64.rpm" /root/ >/dev/null 2>&1 || { say "scp $v"; exit 2; }
done
say "node=$NODE old=$OLD new=$NEW evidence=$EV"
on 20 "grep -q ' mxfs ' /proc/mounts" && { say "MXFS is mounted on $NODE; unmount it first"; exit 2; }

# 1. a clean start
on $INSTALL_S "rpm -q mxfs >/dev/null && dnf -y remove mxfs; true" > "$EV/erase0.log"
state erase0
[ -z "$(val erase0 registered)" ] || fail "after the first erase DKMS still holds: $(val erase0 registered)"

# 2. install OLD, upgrade to NEW
on $INSTALL_S "dnf -y install /root/mxfs-$OLD-1.el8.x86_64.rpm; echo rc=\$?" > "$EV/install_old.log"
grep -q "^rc=0" "$EV/install_old.log" || fail "installing $OLD (see install_old.log)"
on $INSTALL_S "dnf -y install /root/mxfs-$NEW-1.el8.x86_64.rpm; echo rc=\$?" > "$EV/upgrade.log"
grep -q "^rc=0" "$EV/upgrade.log" || fail "upgrading to $NEW (see upgrade.log)"
state upgrade
[ "$(val upgrade registered)" = "$NEW" ] || fail "after the upgrade DKMS holds '$(val upgrade registered)', not only $NEW"
[ "$(val upgrade loads)" = 0 ] && [ "$(val upgrade version)" = "$NEW" ] || fail "after the upgrade the module does not load as $NEW"

# 3. reinstall NEW
on $INSTALL_S "dnf -y reinstall /root/mxfs-$NEW-1.el8.x86_64.rpm; echo rc=\$?" > "$EV/reinstall.log"
grep -q "^rc=0" "$EV/reinstall.log" || fail "reinstalling $NEW (see reinstall.log)"
state reinstall
[ "$(val reinstall registered)" = "$NEW" ] || fail "after the reinstall DKMS holds '$(val reinstall registered)', not $NEW"
[ "$(val reinstall loads)" = 0 ] && [ "$(val reinstall version)" = "$NEW" ] || fail "after the reinstall the module does not load as $NEW"

# 4. erase
on $INSTALL_S "dnf -y remove mxfs; echo rc=\$?" > "$EV/erase.log"
state erase
[ -z "$(val erase registered)" ] || fail "after the erase DKMS still holds: $(val erase registered)"
[ "$(val erase kofiles)" = 0 ] || fail "after the erase $(val erase kofiles) mxfs.ko file(s) remain"

[ $FAILS = 0 ] && { say "RESULT PASS"; exit 0; }
say "RESULT FAIL ($FAILS failed)"
exit 1
