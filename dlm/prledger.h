/*
 * MXFS — SCSI PR REGISTRANT LEDGER (docs/whole-cluster-restart.md
 * item 2; design-consult ruling ccmemory
 * docs/rulings/prkey64-item2-ledger-not-deferrable.md).
 *
 * The PR key a host registers on a LUN is a 64-bit value DERIVED once per
 * {host boot, LUN} from {host_uuid, boot_uuid, fs_uuid} (see
 * mxfs_prledger_select below for why it is derived and not drawn).  It is
 * recorded HERE, on the LUN, immediately AFTER the REGISTER is verified, so
 * that every PTPL registration the target holds has a durable owner record
 * naming the host, the boot and the key generation that made it.  A host
 * whose module is reloaded, or that retries a mount, recomputes the same
 * key and REUSES its registration rather than minting a second one the
 * target still remembers.  Fencers name their victim by the key in the
 * victim's heartbeat record; the ledger is the owner record for keys that
 * have no slot (yet, or any more).
 *
 * One 512-byte entry per registrant, written with SCSI COMPARE AND WRITE
 * from the exact image last read (CAS; the plain-write fallback exists only
 * for devices without CAW, which cannot run a CAW cluster anyway).  States:
 *
 *   FREE        never used, or wiped by mkfs
 *   PREPARED (only; no longer produced — an unregistered
 *               initiator cannot write under WE-AR.  Still honoured as an
 *               owned state if found on a 0.43.0-written ledger)
 *   REGISTERED  REGISTER succeeded and READ KEYS showed the key
 *   RETIRED     the owner unregistered cleanly (READ KEYS showed it gone)
 *   FENCED      a certified PREEMPT AND ABORT removed the key
 *
 * FREE, RETIRED and FENCED entries are reusable.  PREPARED and REGISTERED
 * entries are owned: only the {host, boot} that wrote them may change them,
 * and only a certified fence may move them to FENCED.
 *
 * crc32c covers the entry with crc32c = 0, and the entry index is folded in
 * so a sector copied to another index does not validate.
 */
#ifndef MXFS_PRLEDGER_H
#define MXFS_PRLEDGER_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_super.h"

#define MXFS_PRLEDGER_MAGIC         0x4B50584Du  /* "MXPK" LE */
#define MXFS_PRLEDGER_VERSION       1

#define MXFS_PRLEDGER_FREE          0
#define MXFS_PRLEDGER_PREPARED      1
#define MXFS_PRLEDGER_REGISTERED    2
#define MXFS_PRLEDGER_RETIRED       3
#define MXFS_PRLEDGER_FENCED        4

/* The lowest key this module will ever select: a legacy 32-bit node_id key
 * can never be mistaken for, or collide with, a per-boot key. */
#define MXFS_PRLEDGER_KEY_MIN       (1ULL << 32)

struct mxfs_prledger_entry {
	uint32_t    magic;          /* MXFS_PRLEDGER_MAGIC */
	uint16_t    ver;            /* MXFS_PRLEDGER_VERSION */
	uint16_t    state;          /* MXFS_PRLEDGER_* */
	uint32_t    key_gen;        /* generation of pr_key for this {boot, LUN} */
	uint32_t    node_id;        /* mount context that registered it; 0 until known */
	uint64_t    pr_key;         /* the registered 64-bit key */
	uint8_t     host_uuid[16];  /* mxfs_host_identity.host_uuid */
	uint8_t     boot_uuid[16];  /* mxfs_host_identity.boot_uuid */
	uint8_t     fs_uuid[16];    /* the LUN's XFS volume uuid */
	uint64_t    stamp_ms;       /* writer's mxfs_pal_time_ms at last change */
	uint64_t    seq;            /* bumped on every CAS transition */
	uint32_t    host_src;       /* MXFS_HOSTID_SRC_* */
	uint32_t    fenced_by;      /* node_id of the certified fencer (FENCED) */
	uint32_t    crc32c;         /* over the entry with crc32c=0, then index */
	/* self-succession (docs/whole-cluster-restart.md §5.2): a
	 * REGISTERED entry whose registration was made by REGISTER(rk=old_key,
	 * sark=pr_key) on the successor's own nexus names the predecessor it
	 * replaced.  The slice-recovery prover consumes this record — together
	 * with READ FULL STATUS showing old_key absent and pr_key present — to
	 * certify SELF_SUCCESSION_DONE for the predecessor's slot.  Zero when
	 * the registration was fresh. */
	uint32_t    succ_pad0;      /* 100: explicit alignment pad */
	uint64_t    succ_old_key;   /* 104 */
	uint32_t    succ_old_key_gen;   /* 112 */
	uint32_t    succ_pad;       /* 116 */
	uint8_t     succ_old_boot[16];  /* 120 */
	uint8_t     reserved[376];  /* 136 .. 512 */
};

/* What a successor's PUBLISH records about the key it replaced. */
struct mxfs_prledger_succ {
	uint64_t    old_key;
	uint32_t    old_key_gen;
	uint8_t     old_boot[16];
};

_Static_assert(sizeof(struct mxfs_prledger_entry) == MXFS_PRLEDGER_ENTRY_BYTES,
	       "prledger entry is one sector (PAL I/O must be sector-sized)");

struct mxfs_prledger {
	mxfs_bdev_t                 *dev;
	uint64_t                    offset;         /* region start */
	uint32_t                    entries;        /* region size / 512 */
	mxfs_mutex_t                *lock;
	/* our own entry, once selected */
	int                         own_idx;        /* -1 = none */
	struct mxfs_prledger_entry  own;            /* exact on-disk image */
	uint8_t                     host_uuid[16];
	uint8_t                     boot_uuid[16];
	uint8_t                     fs_uuid[16];
	uint32_t                    host_src;
	/* SELECT's findings for PUBLISH */
	uint64_t                    derived_key;
	bool                        seen_on_target; /* K in READ KEYS at select */
	uint32_t                    free_idx;       /* reusable entry, or ~0 */
};

/* Open the ledger region (no I/O).  identity: host/boot uuids of THIS boot;
 * fs_uuid: the volume being mounted.  Returns NULL on bad geometry. */
struct mxfs_prledger *mxfs_prledger_open(mxfs_bdev_t *dev, uint64_t offset,
					 uint64_t size,
					 const uint8_t host_uuid[16],
					 const uint8_t boot_uuid[16],
					 uint32_t host_src,
					 const uint8_t fs_uuid[16]);
void mxfs_prledger_close(struct mxfs_prledger *l);

/*
 * (design-consult ruling ccmemory
 * docs/rulings/prkey-register-before-ledger-derived-key.md):
 * the ledger is written AFTER REGISTER, never before.  MEASURED on 0.43.0:
 * under the cluster's Write-Exclusive-All-Registrants reservation an
 * unregistered initiator cannot write ANY sector of the LU, so the
 * PREPARED-before-REGISTER CAS failed with RESERVATION CONFLICT on 31 of 32
 * nodes (P-PRKEY-PREPARE-FAILED rc=-52) and no node but the first could
 * mount.  The durable-owner property the pre-write bought is instead
 * carried by the key itself: it is DERIVED from {host_uuid, boot_uuid,
 * fs_uuid} (mxfs_prledger_derive_key), so the same boot on the same LUN
 * recomputes the identical key with no on-LUN state — a module reload or a
 * retried mount whose earlier REGISTER landed finds its own key on its own
 * nexus (REGISTER rk=K sark=K proves it, mxfs_pal_scsi_pr_register_swap)
 * and reuses it.  What is lost: a crash between REGISTER and the ledger
 * write leaves a registration no peer can attribute; that is an explicit
 * fail-closed state (a bootstrap refuses on an unclassifiable registrant),
 * repaired by the same boot's next mount, never guessed at by a peer.
 *
 * SELECT THIS BOOT'S KEY FOR THIS LUN (no write):
 *   1. K = derived key.  An owned entry with our {host, boot, fs} must carry
 *      exactly K (else -EKEYREJECTED, P-PRKEY-LEDGER-MISMATCH); it is reused.
 *   2. an owned entry of ANOTHER identity carrying K → -EEXIST
 *      (P-PRKEY-COLLISION, no redraw: determinism is the point).
 *   3. key_present(K) (the caller's READ KEYS view) is remembered: if K is
 *      already on the target and no entry of ours explains it, PUBLISH
 *      decides between "our own earlier registration this boot" (the nexus
 *      swap proved it) and a foreign collision (refused).
 *   4. a reusable entry (FREE / RETIRED / FENCED / zeroed / REGISTERED-but-
 *      absent-from-READ-KEYS) is remembered for PUBLISH; none → -ENOSPC.
 * Returns 0 with key and key_gen set.
 */
int mxfs_prledger_select(struct mxfs_prledger *l,
			 bool (*key_present)(void *arg, uint64_t key),
			 void *arg, uint64_t *key, uint32_t *key_gen);

/* The derived per-{host boot, LUN} key (>= MXFS_PRLEDGER_KEY_MIN, != ~0). */
uint64_t mxfs_prledger_derive_key(const uint8_t host_uuid[16],
				  const uint8_t boot_uuid[16],
				  const uint8_t fs_uuid[16]);

/*
 * PUBLISH after a VERIFIED REGISTER (READ KEYS showed our key): CAS the
 * remembered reusable entry straight to REGISTERED {K, gen, node_id, ids},
 * or, when SELECT found our own entry, transition it.  nexus_reused says the
 * REGISTER found our key already on our nexus (same boot); if SELECT saw K
 * on the target and the nexus did NOT hold it, K belongs to another
 * initiator → -EEXIST (P-PRKEY-COLLISION) and the caller must unregister.
 */
int mxfs_prledger_publish(struct mxfs_prledger *l, uint32_t node_id,
			  bool nexus_reused,
			  const struct mxfs_prledger_succ *succ);

/*
 * self-succession, successor side: the ONE REGISTERED entry of a
 * PREVIOUS BOOT of THIS host on this LUN whose key the target still holds
 * (key_present).  0 with old_key/old_boot/old_gen set; -ENOENT none;
 * -EEXIST more than one candidate (ruling §5.4: refuse — never guess).
 */
int mxfs_prledger_find_predecessor(struct mxfs_prledger *l,
				   bool (*key_present)(void *arg, uint64_t key),
				   void *arg, uint64_t *old_key,
				   uint8_t old_boot[16], uint32_t *old_gen);

/*
 * self-succession, prover side: the ONE REGISTERED entry that names
 * {old_key, old_boot} as its predecessor and carries victim_host as its own
 * host.  0 with new_key/new_node set; -ENOENT none; -EEXIST more than one.
 *
 * 0.89.15: `new_boot`, when non-NULL, receives the successor's OWN boot_uuid.
 * A caller classifying what happened to the predecessor's registration needs
 * it to tell a same-boot key replacement from one across a boot boundary —
 * two different observations, neither of which is by itself a statement about
 * the target.
 */
int mxfs_prledger_find_successor(struct mxfs_prledger *l, uint64_t old_key,
				 const uint8_t old_boot[16],
				 const uint8_t victim_host[16],
				 uint64_t *new_key, uint32_t *new_node,
				 uint8_t new_boot[16]);

/* Own-entry transitions (CAS from the remembered image). */
int mxfs_prledger_set_registered(struct mxfs_prledger *l, uint32_t node_id);
int mxfs_prledger_set_retired(struct mxfs_prledger *l);

/* A certified PREEMPT AND ABORT removed victim_key: move its entry (any
 * owner) to FENCED.  -ENOENT when no PREPARED/REGISTERED entry carries the
 * key (a legacy or foreign key — logged, not an error for the fencer). */
int mxfs_prledger_mark_fenced(struct mxfs_prledger *l, uint64_t victim_key,
			      uint32_t fencer_node);

/* Look a node id up (bare fences for slotless lease members): the key its
 * PREPARED/REGISTERED entry carries, or 0. */
uint64_t mxfs_prledger_key_of_node(struct mxfs_prledger *l, uint32_t node_id);
/* (§6.3 key classification): the owned entry carrying `key`, or
 * -ENOENT.  Read-only; the caller decides class 3 vs class 4. */
int mxfs_prledger_find_by_key(struct mxfs_prledger *l, uint64_t key,
			      struct mxfs_prledger_entry *out);

/* Entry validation shared with chk_mxfs. */
uint32_t mxfs_prledger_entry_crc(const struct mxfs_prledger_entry *e,
				 uint32_t idx);
bool mxfs_prledger_entry_valid(const struct mxfs_prledger_entry *e,
			       uint32_t idx);
const char *mxfs_prledger_state_name(uint16_t state);

#endif /* MXFS_PRLEDGER_H */
