---
name: trap-a-guest-file-rewritten-with-sed-i-from-a-host-without-selinux-boots-unlabeled-and-iscsid-caches-no-initiator-name
description: TRAP (0.90.12): sed -i on a mounted clone image from clyde (no SELinux) makes a NEW unlabeled inode; the enforcing Alma clone denied iscsid/chronyd r…
metadata:
  type: feedback
tags: [lab, selinux, clone, iscsi, rhel9]
---

# A file rewritten with `sed -i` from a host without SELinux boots unlabeled on an enforcing clone

**What bit (2026-09-28, cloning alma9-3/alma9-4 from alma9-1 with scripts/lab_clone_node.sh):**
the identity rewrite ran `sed -i` on `/etc/hosts` and `/etc/iscsi/initiatorname.iscsi` inside the
clone's root LV mounted on clyde. GNU sed writes a temp file and renames it, so the file gets a new
inode; sed copies the SELinux context only when SELinux is enabled on the *running* host, and clyde
is Ubuntu with no policy loaded, so the new inode carried no `security.selinux` xattr at all. On the
clone's first boot (Enforcing) both files were `unlabeled_t`: 9 AVC denials, `chronyd`/`rsyslogd`
refused `/etc/hosts`, `iscsid` refused `initiatorname.iscsi` and then answered every login with
`iscsid: No initiator name set. Cannot create session.` — a state it keeps until it is restarted,
because it read the name once at start.

**How to see it:** `ls -Z /etc/hosts /etc/iscsi/initiatorname.iscsi` shows `unlabeled_t`;
`ausearch -m avc --input-logs -ts boot | grep denied`; `journalctl -u iscsid` shows the "No
initiator name set" line although the file is correct.

**Fix, in two places:**
- the script now rewrites through the existing inode (`sudo sed expr file | sudo tee file`, the
  `inplace` helper in scripts/lab_clone_node.sh), which keeps label, mode and owner; the same helper
  reads the root-only initiator file with sudo (on Debian/PVE the unprivileged `sed -n` read had
  failed silently and the case fell to the Debian naming by luck).
- an already-booted clone: `restorecon -v /etc/hosts /etc/iscsi/initiatorname.iscsi` then
  `systemctl restart iscsid` — the relabel alone does not make iscsid re-read its name.

**General form:** any file created from outside the guest's SELinux policy (host-side edit, nbd-mounted
image, `cp` without `--preserve=context`) is unlabeled until `restorecon` or `/.autorelabel`; write
through the inode, or relabel before the first boot.
