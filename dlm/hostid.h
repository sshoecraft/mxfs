/*
 * MXFS — host and boot identity (sess437, docs/whole-cluster-restart.md §1).
 *
 * Nothing in MXFS's identity model tied a SCSI PR registration to a HOST or a
 * BOOT: node_id is per mount context, the epoch per slot claim, the PR key
 * was the node_id.  After a whole-cluster power loss every rebooted host's own
 * predecessor key survives on its I_T nexus (PTPL) and the mount is refused
 * (P305-PR-PREDECESSOR-KEY-PRESENT) because a same-nexus successor cannot tell
 * "a previous boot of this machine" (dead by construction) from "this same
 * boot" (may still issue I/O).  These two identities are what lets it tell.
 *
 *   host_uuid  stable across boots of the same install: /etc/machine-id,
 *              falling back to a hash of the iSCSI initiator name.  If
 *              neither exists the host identity is INVALID and automatic
 *              self-succession stays refused.
 *   boot_uuid  immutable for the kernel boot: /proc/sys/kernel/random/boot_id
 *              (the kernel's sysctl_bootid is file-static; the proc file is
 *              the only stable per-boot source).  Read ONCE per module load
 *              and never regenerated per mount attempt (ruling: the boot
 *              identity must not be minted per attempt).
 *
 * Portable: reads go through mxfs_pal_read_file, so the same code serves the
 * kernel module and the user-mode tools (chk_mxfs prints what a record
 * carries and can compare it to the host it runs on).
 */
#ifndef MXFS_HOSTID_H
#define MXFS_HOSTID_H

#include "../pal/pal.h"

#define MXFS_HOSTID_SRC_MACHINE_ID   1
#define MXFS_HOSTID_SRC_INITIATOR    2

struct mxfs_host_identity {
    uint8_t     host_uuid[16];
    uint8_t     boot_uuid[16];
    bool        host_valid;
    bool        boot_valid;
    int         host_src;           /* MXFS_HOSTID_SRC_* or 0 */
    bool        initialised;
};

/* Read both identities (idempotent: the first call wins for the life of the
 * module / process).  Returns 0 when BOTH are valid, -ENOENT otherwise; the
 * caller decides what a missing identity means (the mount path: refuse
 * automatic self-succession, nothing else changes). */
int mxfs_host_identity_init(void);
const struct mxfs_host_identity *mxfs_host_identity(void);

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" into out[37]. */
void mxfs_uuid_format(const uint8_t u[16], char out[37]);
/* Parse the same text form (or 32 bare hex digits) into u[16]; -EINVAL. */
int mxfs_uuid_parse(const char *s, size_t len, uint8_t u[16]);

#endif /* MXFS_HOSTID_H */
