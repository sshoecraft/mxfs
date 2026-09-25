/*
 * MXFS — Multinode XFS
 * Symmetric directory sharding: ON-DISK MANIFEST FORMAT and the pure
 * (kernel- and user-mode) manifest structure check.
 *
 * — D-32NODE-SHARED-DIR-CREATE-PACE (board face D-401), on the
 * critical path of D-FOREIGN-REPLAY-UNGATED-IMAGES since.
 * Design: docs/dir-sharding.md.  Design-consult rulings: ccmemory
 * docs/rulings/symmetric-directory-sharding-design.md
 * (shape) and dirshard-stage1-2-concrete-
 * shape (this format: private flags + ROOT-namespace manifest xattr, the
 * verifier split, keyed SipHash routing, cookie partition).
 *
 * A LOGICAL directory is one visible XFS directory inode (the PARENT) whose
 * entries live in N SHARD CONTAINERS: real dir2 directory inodes that never
 * have a dirent, referenced only by the parent's manifest.  Every ordinary
 * operation takes the parent's DLM lock in PR (the manifest pin) and exactly
 * ONE shard's lock; the parent's EX is a barrier reserved for lifecycle,
 * rmdir/emptiness, parent-core metadata, fsync and repair.
 *
 * THREE GATES agree before either private inode flag is legal:
 *   1. XFS superblock: XFS_SB_FEAT_INCOMPAT_MXFS_DIRSHARD (bit 29, next to
 *      PROTOGATE's bit 30; high bits keep clear of upstream's low-bit
 *      allocations — collision watch on every upstream merge).  Every kernel
 *      without the bit refuses the mount through upstream's unknown-incompat
 *      check, so a pre-sharding kernel can never see a container.
 *   2. Envelope: MXFS_FORMAT_F_DIRSHARD in mxfs_ondisk_super.flags (gate-aware
 *      kernels refuse unknown envelope flags).
 *   3. Protocol generation: MXFS_PROTO_GEN bumps when the feature lands, so
 *      a member that does not understand the manifest lifecycle is excluded
 *      cluster-wide by the heartbeat feature block.
 * A flag seen without all three (or outside clustered mode) is corruption.
 *
 * VERIFIER SPLIT (ruling Q1): the dinode verifier enforces ONLY dinode-
 * visible facts — container: S_IFDIR + CONTAINER flag, feature present, not
 * also PARENT, legal fork formats; parent: S_IFDIR + PARENT flag + legal attr
 * fork.  "container nlink == 1" is a scrub check, not a verifier assertion
 * (deletion and recovery pass through transient values).  Everything about
 * the manifest is checked by mxfs_dirshard_manifest_check() below, called
 * under the parent lock by the kernel loader and by chk_mxfs.
 *
 * WHERE THE MANIFEST LIVES (ruling, amending — ccmemory
 * docs/rulings/dirshard-manifest-block-s3-amendment.md):
 *
 *   parent dinode ──ROOT xattr "mxfs.dirshard" (12-byte LOCATOR, written
 *                   ONCE in the parent's allocation transaction while the
 *                   attr fork is empty => shortform, synchronous, no roll)
 *        └──> HOLDER inode (S_IFREG, CONTAINER flag, UNLINKABLE, nlink 1)
 *               └──> fsblock 0 = MANIFEST BLOCK: struct mxfs_dirshard_blk
 *                    header (magic/crc/uuid/owner/blkno/lsn + reciprocal
 *                    parent/holder identity) followed by the manifest.
 *
 * The block is a LOGGED METADATA BUFFER (the symlink-remote pattern with
 * its own magic, verifier and XFS_BLFT_ type), so every lifecycle step —
 * container allocate+append, publish, delete-step — is memcpy +
 * xfs_trans_log_buf in the SAME transaction as the inode work: one commit,
 * no deferred attr intents (LARP) in any journal slice.  A leaf-format xattr
 * value could not give that: 512-byte inodes make a 1120-byte value
 * non-shortform, and in-transaction leaf xattr writes are deferred intents.
 *
 * mgen (manifest generation) increases by one on every write.  All writes
 * happen under the visible parent's DLM EX, so mgen is a globally ordered
 * version of the block across nodes and journal slices; replay of an image
 * whose mgen is not newer than the on-disk block is refused (belt) in
 * addition to the authority-token verdict on the buffer item (braces, the
 * D-0517 INODE-class override of the raw cross-slice LSN compare).
 *
 * All fields are big-endian on disk.  Nothing here calls into the kernel or
 * libc beyond <stdint.h>/<stddef.h>-level types: the check is pure so the
 * kernel (xfs/xfs_mxfs_dirshard.c) and chk_mxfs share ONE implementation.
 */
#ifndef MXFS_DIRSHARD_H
#define MXFS_DIRSHARD_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#endif

/* ---- feature gates ---------------------------------------------------- */

/*
 * XFS superblock incompat bit.  Defined here as a value so the tool side can
 * name it without xfs_format.h; xfs_format.h defines
 * XFS_SB_FEAT_INCOMPAT_MXFS_DIRSHARD to the same value and a build check in
 * xfs_mxfs_dirshard.c pins the two together.
 */
#define MXFS_DIRSHARD_SB_INCOMPAT_BIT   29u
#define MXFS_DIRSHARD_SB_INCOMPAT       (1u << MXFS_DIRSHARD_SB_INCOMPAT_BIT)

/* Envelope flag (mxfs_ondisk_super.flags); joins MXFS_FORMAT_F_KNOWN. */
#define MXFS_FORMAT_F_DIRSHARD          0x00000020u

/*
 * Private di_flags2 bits.  Upstream owns bits 0-5 (DAX..METADATA, 6.19-rc);
 * we take two HIGH bits, mirroring the sb-bit policy, and add them to
 * XFS_DIFLAG2_ANY in xfs_format.h (xfs_dinode_verify does not reject unknown
 * flags2 bits — audited — but formatters, bulkstat and scrub key off
 * XFS_DIFLAG2_ANY and must see them).
 */
#define MXFS_DIFLAG2_DIRSHARD_CONTAINER_BIT 60
#define MXFS_DIFLAG2_DIRSHARD_PARENT_BIT    61
#define MXFS_DIFLAG2_DIRSHARD_CONTAINER (1ULL << MXFS_DIFLAG2_DIRSHARD_CONTAINER_BIT)
#define MXFS_DIFLAG2_DIRSHARD_PARENT    (1ULL << MXFS_DIFLAG2_DIRSHARD_PARENT_BIT)
#define MXFS_DIFLAG2_DIRSHARD_ANY       (MXFS_DIFLAG2_DIRSHARD_CONTAINER | \
                                         MXFS_DIFLAG2_DIRSHARD_PARENT)

/* ---- the locator xattr -------------------------------------------------- */

#define MXFS_DIRSHARD_XATTR_NAME        "mxfs.dirshard"
#define MXFS_DIRSHARD_XATTR_NAMELEN     13

/*
 * Value of the ROOT xattr on the visible parent: which internal inode holds
 * the manifest block.  Written once, never replaced; a parent with the
 * PARENT flag and no valid locator is corruption, as is a locator whose
 * holder does not carry the CONTAINER flag + S_IFREG + this generation.
 */
struct mxfs_dirshard_locator {
	uint64_t	manifest_ino;	/* be64: holder inode */
	uint32_t	manifest_gen;	/* be32: holder generation, != 0 */
} __attribute__((__packed__));
#define MXFS_DIRSHARD_LOCATOR_LEN       12u

/* ---- the manifest block ------------------------------------------------- */

#define MXFS_DIRSHARD_BLK_MAGIC         0x4D534842u  /* 'MSHB' */

/*
 * Block header (symlink-remote pattern).  crc32c covers the WHOLE fsblock
 * with this field zero (the buffer verifier's job); lsn is stamped by the
 * write verifier from the buffer log item like every LSN-stamped block.
 * The reciprocal identity fields make inode reuse detectable from either
 * side: the locator names {holder ino, gen}; the block names the parent and
 * the holder back.
 */
struct mxfs_dirshard_blk {
	uint32_t	magic;		/* be32: MXFS_DIRSHARD_BLK_MAGIC */
	uint32_t	offset;		/* be32: 0 (single block) */
	uint32_t	bytes;		/* be32: manifest length that follows */
	uint32_t	crc32c;		/* be32 */
	uint8_t		uuid[16];	/* sb_meta_uuid */
	uint64_t	owner;		/* be64: holder inode number */
	uint64_t	blkno;		/* be64: daddr of this block */
	uint64_t	lsn;		/* be64 */
	uint64_t	parent_ino;	/* be64: the visible parent */
	uint32_t	parent_gen;	/* be32 */
	uint32_t	holder_gen;	/* be32: the holder inode's generation */
	uint64_t	reserved[2];	/* must be 0 */
	/* struct mxfs_dirshard_manifest follows at MXFS_DIRSHARD_BLK_HDR_LEN */
};
#define MXFS_DIRSHARD_BLK_HDR_LEN       88u
#define MXFS_DIRSHARD_BLK_CRC_OFF       12u
#define MXFS_DIRSHARD_BLK_MIN_BLOCKSIZE \
	(MXFS_DIRSHARD_BLK_HDR_LEN + MXFS_DIRSHARD_MANIFEST_LEN(MXFS_DIRSHARD_N_MAX))

/* Buffer log-format type for recovery to restore the verifier (slot 30:
 * high, to keep clear of upstream's growing low allocations; collision
 * watch on every merge).  xfs_log_format.h must define
 * XFS_BLFT_MXFS_DIRSHARD_BUF to this value. */
#define MXFS_DIRSHARD_BLFT              30u

/* ---- the manifest ------------------------------------------------------- */

#define MXFS_DIRSHARD_MANIFEST_MAGIC    0x4D534844u  /* 'MSHD' */
#define MXFS_DIRSHARD_MANIFEST_VERSION  1u

/* Shard counts.  Fixed at mkdir; no online resharding (v1). */
#define MXFS_DIRSHARD_N_MIN             16u
#define MXFS_DIRSHARD_N_MAX             64u
static inline int mxfs_dirshard_n_valid(unsigned int n)
{
	return n == 16u || n == 32u || n == 64u;
}

/* Hash identifiers (manifest.hash_id). */
#define MXFS_DIRSHARD_HASH_SIPHASH24    1u   /* SipHash-2-4, 128-bit key */

/* Name canonicalization (manifest.name_canon_version). */
#define MXFS_DIRSHARD_CANON_EXACT       1u   /* exact bytes: dir2 compares
                                              * bytes when !asciici, and
                                              * mkfs_mxfs never sets asciici */

/*
 * Lifecycle (manifest.state).  ALLOCATING -> COMPLETE -> PUBLISHED ->
 * DELETING; FREE is the absence of the manifest (parent freed last).
 *
 *  ALLOCATING  parent exists on the AGI unlinked list (unreachable), the
 *              manifest names a committed PREFIX of nentries containers;
 *              each container was allocated AND appended in ONE transaction.
 *  COMPLETE    nentries == nshards, parent still unlinked.  Legal only as a
 *              transient the publication transaction consumes; the loader
 *              treats a COMPLETE+linked parent as corruption.
 *  PUBLISHED   the visible dirent exists and the parent left the unlinked
 *              list in the SAME transaction that moved COMPLETE->PUBLISHED.
 *  DELETING    the parent is unreachable and unlinked-anchored again; each
 *              container is verified {ino,gen}, freed, and its valid_mask bit
 *              cleared atomically; the parent is freed LAST.  Restart: a set
 *              bit whose {ino,gen} no longer matches means "already gone"
 *              (freed and the inode reused) — never free the new inode.
 */
#define MXFS_DIRSHARD_ST_ALLOCATING     1u
#define MXFS_DIRSHARD_ST_COMPLETE       2u
#define MXFS_DIRSHARD_ST_PUBLISHED      3u
#define MXFS_DIRSHARD_ST_DELETING       4u

struct mxfs_dirshard_entry {
	uint64_t	ino;		/* be64: container inode number */
	uint32_t	gen;		/* be32: container generation, != 0 */
	uint32_t	reserved;	/* be32: must be 0 */
};

struct mxfs_dirshard_manifest {
	uint32_t	magic;		/* be32: MXFS_DIRSHARD_MANIFEST_MAGIC */
	uint16_t	version;	/* be16: MXFS_DIRSHARD_MANIFEST_VERSION */
	uint16_t	hash_id;	/* be16: MXFS_DIRSHARD_HASH_* */
	uint32_t	length;		/* be32: exact byte length ==
					 * MANIFEST_LEN(nshards) == blk.bytes */
	uint32_t	mgen;		/* be32: manifest generation, +1 per
					 * write under the parent EX; != 0 */
	uint16_t	nshards;	/* be16: N in {16,32,64} */
	uint16_t	state;		/* be16: MXFS_DIRSHARD_ST_* */
	uint16_t	name_canon_version; /* be16: MXFS_DIRSHARD_CANON_* */
	uint16_t	nentries;	/* be16: entries appended so far; == N
					 * once COMPLETE */
	uint8_t		hash_key[16];	/* per-directory random SipHash key */
	uint8_t		set_uuid[16];	/* identity of this shard set */
	uint64_t	parent_ino;	/* be64: the visible parent; the loader
					 * refuses a manifest on another inode */
	uint32_t	parent_gen;	/* be32: its generation */
	uint32_t	reserved0;	/* be32: must be 0 */
	uint64_t	valid_mask;	/* be64: bit i set = entry i is a live
					 * container.  ALLOCATING/COMPLETE/
					 * PUBLISHED: exactly the low nentries
					 * bits.  DELETING: a subset of them. */
	uint64_t	reserved1[2];	/* must be 0 */
	struct mxfs_dirshard_entry entries[]; /* exactly nshards slots; slots
					 * >= nentries must be all-zero */
};

#define MXFS_DIRSHARD_MANIFEST_HDR_LEN  96u
#define MXFS_DIRSHARD_MANIFEST_LEN(n) \
	(MXFS_DIRSHARD_MANIFEST_HDR_LEN + (n) * (unsigned int)sizeof(struct mxfs_dirshard_entry))
#define MXFS_DIRSHARD_MANIFEST_MAX_LEN  MXFS_DIRSHARD_MANIFEST_LEN(MXFS_DIRSHARD_N_MAX)

#ifdef __KERNEL__
#define MXFS_DIRSHARD_BUILD_CHECKS() do {					\
	BUILD_BUG_ON(sizeof(struct mxfs_dirshard_manifest) !=		\
		     MXFS_DIRSHARD_MANIFEST_HDR_LEN);				\
	BUILD_BUG_ON(sizeof(struct mxfs_dirshard_entry) != 16);		\
	BUILD_BUG_ON(sizeof(struct mxfs_dirshard_blk) !=			\
		     MXFS_DIRSHARD_BLK_HDR_LEN);				\
	BUILD_BUG_ON(sizeof(struct mxfs_dirshard_locator) !=		\
		     MXFS_DIRSHARD_LOCATOR_LEN);				\
} while (0)
#elif !defined(__cplusplus)
_Static_assert(sizeof(struct mxfs_dirshard_manifest) == MXFS_DIRSHARD_MANIFEST_HDR_LEN,
	       "mxfs_dirshard_manifest header must be 96 bytes");
_Static_assert(sizeof(struct mxfs_dirshard_entry) == 16,
	       "mxfs_dirshard_entry must be 16 bytes");
_Static_assert(sizeof(struct mxfs_dirshard_blk) == MXFS_DIRSHARD_BLK_HDR_LEN,
	       "mxfs_dirshard_blk header must be 88 bytes");
_Static_assert(sizeof(struct mxfs_dirshard_locator) == MXFS_DIRSHARD_LOCATOR_LEN,
	       "mxfs_dirshard_locator must be 12 bytes");
#endif

/* ---- routing ------------------------------------------------------------ */

/*
 * shard index = low bits of SipHash-2-4(key, canonical name bytes).  N is a
 * power of two so the mask is exact.  Both sides (kernel: <linux/siphash.h>;
 * chk_mxfs: tools/siphash24.c reference) MUST produce the same u64 for the
 * same key and bytes — tests/dirshard_hash_vectors.sh pins them to each
 * other and to the published SipHash test vector.
 */
static inline unsigned int mxfs_dirshard_index(uint64_t hash, unsigned int nshards)
{
	return (unsigned int)(hash & (uint64_t)(nshards - 1u));
}

/* ---- readdir cookies ---------------------------------------------------- */

/*
 * A logical cookie is {shard slot, local xfs_dir2_dataptr_t}.  Slot 0 is the
 * synthesized "." and ".." (cookies 0 and 1); shard i occupies slot i+1; the
 * EOF sentinel is slot N_MAX+1 = 65, which is why the slot field is 7 bits
 * (index 64 does not fit six).  The local dataptr is 32 bits.  Bits 39..62
 * are zero and bit 63 is never set (loff_t is signed).
 */
#define MXFS_DIRSHARD_COOKIE_SLOT_SHIFT 32
#define MXFS_DIRSHARD_COOKIE_SLOT_BITS  7
#define MXFS_DIRSHARD_COOKIE_SLOT_MASK  ((1ULL << MXFS_DIRSHARD_COOKIE_SLOT_BITS) - 1ULL)
#define MXFS_DIRSHARD_COOKIE_LOCAL_MASK 0xffffffffULL
#define MXFS_DIRSHARD_COOKIE_DOT        0ULL
#define MXFS_DIRSHARD_COOKIE_DOTDOT     1ULL
#define MXFS_DIRSHARD_COOKIE_EOF_SLOT   (MXFS_DIRSHARD_N_MAX + 1u)

static inline uint64_t mxfs_dirshard_cookie(unsigned int slot, uint32_t local)
{
	return ((uint64_t)(slot & MXFS_DIRSHARD_COOKIE_SLOT_MASK)
		<< MXFS_DIRSHARD_COOKIE_SLOT_SHIFT) | (uint64_t)local;
}
static inline unsigned int mxfs_dirshard_cookie_slot(uint64_t cookie)
{
	return (unsigned int)((cookie >> MXFS_DIRSHARD_COOKIE_SLOT_SHIFT)
			      & MXFS_DIRSHARD_COOKIE_SLOT_MASK);
}
static inline uint32_t mxfs_dirshard_cookie_local(uint64_t cookie)
{
	return (uint32_t)(cookie & MXFS_DIRSHARD_COOKIE_LOCAL_MASK);
}
/* True when the cookie has bits set outside the defined layout. */
static inline int mxfs_dirshard_cookie_malformed(uint64_t cookie)
{
	return (cookie & ~((MXFS_DIRSHARD_COOKIE_SLOT_MASK
			    << MXFS_DIRSHARD_COOKIE_SLOT_SHIFT)
			   | MXFS_DIRSHARD_COOKIE_LOCAL_MASK)) != 0
		|| mxfs_dirshard_cookie_slot(cookie) > MXFS_DIRSHARD_COOKIE_EOF_SLOT;
}

/* ---- the pure structure check ---------------------------------------- */

/*
 * Reasons.  Positive small integers so a caller can print the name; 0 = OK.
 * Order is the order the checks run in (the first failure is reported).
 */
enum mxfs_dirshard_check {
	MXFS_DSC_OK = 0,
	MXFS_DSC_SHORT,		/* value shorter than the fixed header */
	MXFS_DSC_MAGIC,
	MXFS_DSC_VERSION,
	MXFS_DSC_LENGTH,	/* length field != value length or != LEN(N) */
	MXFS_DSC_NSHARDS,	/* N not in {16,32,64} */
	MXFS_DSC_HASH_ID,
	MXFS_DSC_CANON,
	MXFS_DSC_STATE,
	MXFS_DSC_NENTRIES,	/* > N, or != N when COMPLETE/PUBLISHED/DELETING */
	MXFS_DSC_RESERVED,	/* a reserved field is nonzero */
	MXFS_DSC_PARENT,	/* parent {ino,gen} does not match the caller's */
	MXFS_DSC_KEY_ZERO,	/* all-zero hash key or set uuid */
	MXFS_DSC_VALID_MASK,	/* mask disagrees with state/nentries */
	MXFS_DSC_ENTRY_ZERO,	/* a live entry has ino 0 or gen 0 */
	MXFS_DSC_ENTRY_SELF,	/* a live entry names the parent itself */
	MXFS_DSC_ENTRY_DUP,	/* two live entries share an ino */
	MXFS_DSC_ENTRY_TAIL,	/* a slot >= nentries is not all-zero */
	MXFS_DSC_MGEN,		/* manifest generation is zero */
	MXFS_DSC_BLK_MAGIC,	/* block: bad magic */
	MXFS_DSC_BLK_BYTES,	/* block: offset != 0, or bytes out of range /
				 * != manifest length */
	MXFS_DSC_BLK_OWNER,	/* block: owner/holder gen/parent mismatch */
	MXFS_DSC_BLK_RESERVED,	/* block: reserved nonzero */
	MXFS_DSC_BLK_CRC,	/* block: crc32c mismatch (caller-computed) */
	MXFS_DSC_NREASONS
};

static inline const char *mxfs_dirshard_check_name(enum mxfs_dirshard_check c)
{
	static const char *const names[MXFS_DSC_NREASONS] = {
		"ok", "short", "magic", "version", "length", "nshards",
		"hash_id", "canon", "state", "nentries", "reserved", "parent",
		"key_zero", "valid_mask", "entry_zero", "entry_self",
		"entry_dup", "entry_tail", "mgen", "blk_magic", "blk_bytes",
		"blk_owner", "blk_reserved", "blk_crc",
	};
	return ((unsigned int)c < MXFS_DSC_NREASONS) ? names[c] : "?";
}

static inline uint16_t mxfs_dirshard_be16(uint16_t v)
{
	return (uint16_t)((v >> 8) | (v << 8));
}
static inline uint32_t mxfs_dirshard_be32(uint32_t v)
{
	return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
	       ((v & 0x00ff0000u) >> 8)  | ((v & 0xff000000u) >> 24);
}
static inline uint64_t mxfs_dirshard_be64(uint64_t v)
{
	return ((uint64_t)mxfs_dirshard_be32((uint32_t)(v & 0xffffffffu)) << 32) |
	       (uint64_t)mxfs_dirshard_be32((uint32_t)(v >> 32));
}

/*
 * Decoded (host-order) view produced by the check so callers never touch the
 * big-endian image after validation.
 */
struct mxfs_dirshard_view {
	unsigned int	nshards;
	unsigned int	state;
	unsigned int	nentries;
	uint32_t	mgen;
	unsigned int	hash_id;
	unsigned int	name_canon_version;
	uint64_t	valid_mask;
	uint64_t	parent_ino;
	uint32_t	parent_gen;
	uint8_t		hash_key[16];
	uint8_t		set_uuid[16];
	/*
	 * Packed to 12 bytes: the view lives on the stack of every routed
	 * operation and the kernel's frame budget is 1 KiB; 64 x 16 would
	 * push nine functions over it, 64 x 12 keeps the whole view under
	 * 900 bytes.  Unaligned 64-bit loads are fine on every target.
	 */
	struct {
		uint64_t ino;
		uint32_t gen;
	} __attribute__((__packed__)) shard[MXFS_DIRSHARD_N_MAX];
};

/*
 * mxfs_dirshard_manifest_check — validate a manifest image.
 *
 * @m, @len: the manifest bytes (blk + MXFS_DIRSHARD_BLK_HDR_LEN) and the
 *           length the block header declares for them.
 * @parent_ino, @parent_gen: the visible parent the block belongs to.
 * @out: decoded view, filled only on MXFS_DSC_OK (may be NULL).
 *
 * Returns MXFS_DSC_OK or the first failing reason.  Pure: the block crc is
 * the buffer verifier's (or chk_mxfs's) business, see
 * mxfs_dirshard_blk_check().
 */
static inline enum mxfs_dirshard_check
mxfs_dirshard_manifest_check(const struct mxfs_dirshard_manifest *m, size_t len,
			     uint64_t parent_ino, uint32_t parent_gen,
			     struct mxfs_dirshard_view *out)
{
	unsigned int n, state, nentries, i, j;
	uint64_t mask, low;
	int allzero;

	if (len < MXFS_DIRSHARD_MANIFEST_HDR_LEN)
		return MXFS_DSC_SHORT;
	if (mxfs_dirshard_be32(m->magic) != MXFS_DIRSHARD_MANIFEST_MAGIC)
		return MXFS_DSC_MAGIC;
	if (mxfs_dirshard_be16(m->version) != MXFS_DIRSHARD_MANIFEST_VERSION)
		return MXFS_DSC_VERSION;
	n = mxfs_dirshard_be16(m->nshards);
	if (!mxfs_dirshard_n_valid(n))
		return MXFS_DSC_NSHARDS;
	if (mxfs_dirshard_be32(m->length) != len ||
	    len != MXFS_DIRSHARD_MANIFEST_LEN(n))
		return MXFS_DSC_LENGTH;
	if (m->mgen == 0)
		return MXFS_DSC_MGEN;
	if (mxfs_dirshard_be16(m->hash_id) != MXFS_DIRSHARD_HASH_SIPHASH24)
		return MXFS_DSC_HASH_ID;
	if (mxfs_dirshard_be16(m->name_canon_version) != MXFS_DIRSHARD_CANON_EXACT)
		return MXFS_DSC_CANON;
	state = mxfs_dirshard_be16(m->state);
	if (state < MXFS_DIRSHARD_ST_ALLOCATING || state > MXFS_DIRSHARD_ST_DELETING)
		return MXFS_DSC_STATE;
	nentries = mxfs_dirshard_be16(m->nentries);
	if (nentries > n)
		return MXFS_DSC_NENTRIES;
	if (state != MXFS_DIRSHARD_ST_ALLOCATING && nentries != n)
		return MXFS_DSC_NENTRIES;
	if (m->reserved0 != 0 || m->reserved1[0] != 0 || m->reserved1[1] != 0)
		return MXFS_DSC_RESERVED;
	if (mxfs_dirshard_be64(m->parent_ino) != parent_ino ||
	    mxfs_dirshard_be32(m->parent_gen) != parent_gen)
		return MXFS_DSC_PARENT;
	allzero = 1;
	for (i = 0; i < 16; i++)
		if (m->hash_key[i]) { allzero = 0; break; }
	if (allzero)
		return MXFS_DSC_KEY_ZERO;
	allzero = 1;
	for (i = 0; i < 16; i++)
		if (m->set_uuid[i]) { allzero = 0; break; }
	if (allzero)
		return MXFS_DSC_KEY_ZERO;

	mask = mxfs_dirshard_be64(m->valid_mask);
	low = (nentries == 64u) ? ~0ULL : ((1ULL << nentries) - 1ULL);
	if (state == MXFS_DIRSHARD_ST_DELETING) {
		if (mask & ~low)
			return MXFS_DSC_VALID_MASK;
	} else if (mask != low) {
		return MXFS_DSC_VALID_MASK;
	}

	for (i = 0; i < n; i++) {
		uint64_t ino = mxfs_dirshard_be64(m->entries[i].ino);
		uint32_t gen = mxfs_dirshard_be32(m->entries[i].gen);

		if (m->entries[i].reserved != 0)
			return MXFS_DSC_RESERVED;
		if (i >= nentries) {
			if (ino != 0 || gen != 0)
				return MXFS_DSC_ENTRY_TAIL;
			continue;
		}
		/*
		 * Appended entries keep their {ino,gen} after DELETING clears
		 * their bit (forensics); only LIVE entries must be sane.
		 */
		if (!(mask & (1ULL << i)))
			continue;
		if (ino == 0 || gen == 0)
			return MXFS_DSC_ENTRY_ZERO;
		if (ino == parent_ino)
			return MXFS_DSC_ENTRY_SELF;
		for (j = 0; j < i; j++)
			if ((mask & (1ULL << j)) &&
			    mxfs_dirshard_be64(m->entries[j].ino) == ino)
				return MXFS_DSC_ENTRY_DUP;
	}

	if (out) {
		memset(out, 0, sizeof(*out));
		out->nshards = n;
		out->state = state;
		out->nentries = nentries;
		out->mgen = mxfs_dirshard_be32(m->mgen);
		out->hash_id = MXFS_DIRSHARD_HASH_SIPHASH24;
		out->name_canon_version = MXFS_DIRSHARD_CANON_EXACT;
		out->valid_mask = mask;
		out->parent_ino = parent_ino;
		out->parent_gen = parent_gen;
		memcpy(out->hash_key, m->hash_key, 16);
		memcpy(out->set_uuid, m->set_uuid, 16);
		for (i = 0; i < n; i++) {
			out->shard[i].ino = mxfs_dirshard_be64(m->entries[i].ino);
			out->shard[i].gen = mxfs_dirshard_be32(m->entries[i].gen);
		}
	}
	return MXFS_DSC_OK;
}

/*
 * mxfs_dirshard_blk_check — validate a manifest BLOCK image (header +
 * manifest) as read from the holder's fsblock 0.
 *
 * @blk, @blocksize: the block and the filesystem block size.
 * @holder_ino, @holder_gen: the inode the block was mapped from (from the
 *           locator, after mxfs_dirshard_iget validated it).
 * @parent_ino, @parent_gen: the visible parent.
 * @crc_ok: the caller's verdict on crc32c(block with crc field zero) ==
 *          blk->crc32c (kernel: the buffer verifier already did it, pass 1;
 *          chk_mxfs: its own crc32c).  Checked LAST so structural reasons
 *          are reported first.
 *
 * uuid, blkno and lsn are the buffer verifier's (location-bound) checks and
 * are not repeated here.
 */
static inline enum mxfs_dirshard_check
mxfs_dirshard_blk_check(const struct mxfs_dirshard_blk *blk, size_t blocksize,
			uint64_t holder_ino, uint32_t holder_gen,
			uint64_t parent_ino, uint32_t parent_gen,
			int crc_ok, struct mxfs_dirshard_view *out)
{
	const struct mxfs_dirshard_manifest *m;
	uint32_t bytes;
	enum mxfs_dirshard_check c;

	if (blocksize < MXFS_DIRSHARD_BLK_MIN_BLOCKSIZE)
		return MXFS_DSC_SHORT;
	if (mxfs_dirshard_be32(blk->magic) != MXFS_DIRSHARD_BLK_MAGIC)
		return MXFS_DSC_BLK_MAGIC;
	bytes = mxfs_dirshard_be32(blk->bytes);
	if (blk->offset != 0 || bytes < MXFS_DIRSHARD_MANIFEST_HDR_LEN ||
	    bytes > blocksize - MXFS_DIRSHARD_BLK_HDR_LEN)
		return MXFS_DSC_BLK_BYTES;
	if (mxfs_dirshard_be64(blk->owner) != holder_ino ||
	    mxfs_dirshard_be32(blk->holder_gen) != holder_gen ||
	    mxfs_dirshard_be64(blk->parent_ino) != parent_ino ||
	    mxfs_dirshard_be32(blk->parent_gen) != parent_gen)
		return MXFS_DSC_BLK_OWNER;
	if (blk->reserved[0] != 0 || blk->reserved[1] != 0)
		return MXFS_DSC_BLK_RESERVED;

	m = (const struct mxfs_dirshard_manifest *)
		((const uint8_t *)blk + MXFS_DIRSHARD_BLK_HDR_LEN);
	c = mxfs_dirshard_manifest_check(m, bytes, parent_ino, parent_gen, out);
	if (c != MXFS_DSC_OK)
		return c;
	if (!crc_ok)
		return MXFS_DSC_BLK_CRC;
	return MXFS_DSC_OK;
}

/* ---- ioctl surface (stage 2; defined with the format so tools and tests
 * can be written against it) ---------------------------------------------- */

/*
 * MXFS has no private ioctl namespace of its own (audited zero
 * MXFS_IOC_* in the tree; upstream XFS uses type 'X').  Type 0xB7 is not in
 * Documentation/userspace-api/ioctl/ioctl-number.rst as of 6.19-rc — collision
 * watch on every upstream merge, like the sb bit.
 */
#define MXFS_IOC_TYPE                   0xB7

/*
 * MXFS_IOC_DIRSHARD_MKDIR — on an fd of the PARENT directory: create the
 * sharded child directory `name` with `nshards` containers, atomically
 * published (ALLOCATING -> COMPLETE -> PUBLISHED inside the call; an error
 * leaves either nothing or an unlinked ALLOCATING set that inactivation and
 * foreign replay reap).  mode is the directory mode (umask applied by the
 * caller as for mkdir(2)).  Fails -EOPNOTSUPP without the feature, -EEXIST if
 * the name exists, -EINVAL for a bad N.
 */
struct mxfs_ioc_dirshard_mkdir {
	uint32_t	nshards;	/* 16, 32 or 64 */
	uint32_t	mode;		/* S_IRWXU.. bits; S_IFDIR implied */
	uint32_t	flags;		/* must be 0 */
	uint32_t	reserved;	/* must be 0 */
	char		name[256];	/* NUL-terminated, < MAXNAMELEN */
};
#define MXFS_IOC_DIRSHARD_MKDIR \
	_IOW(MXFS_IOC_TYPE, 1, struct mxfs_ioc_dirshard_mkdir)

/*
 * MXFS_IOC_DIRSHARD_INFO — on an fd of a directory: report its sharding.
 * For an unsharded directory returns state 0 and nshards 0.  If name[0] is
 * set, also returns that name's SipHash-2-4 under the directory's key and
 * its shard index (the cross-check tests/dirshard_hash_vectors.sh runs
 * against chk_mxfs --dirshard-hash).
 */
struct mxfs_ioc_dirshard_info {
	char		name[256];	/* in: optional name to route */
	uint32_t	state;		/* out: MXFS_DIRSHARD_ST_* or 0 */
	uint32_t	nshards;	/* out */
	uint32_t	nentries;	/* out */
	uint32_t	hash_id;	/* out */
	uint64_t	valid_mask;	/* out */
	uint64_t	name_hash;	/* out: iff name[0] */
	uint32_t	name_shard;	/* out: iff name[0] */
	uint32_t	reserved;
	uint8_t		set_uuid[16];	/* out */
	uint8_t		hash_key[16];	/* out (root only; zeroed otherwise) */
	struct {
		uint64_t ino;
		uint32_t gen;
		uint32_t nlink;		/* out: container nlink (0 if not loaded) */
	} shard[MXFS_DIRSHARD_N_MAX];
};
#define MXFS_IOC_DIRSHARD_INFO \
	_IOWR(MXFS_IOC_TYPE, 2, struct mxfs_ioc_dirshard_info)

/* tests/dirshard_ioctl.py packs these by hand; pin the sizes it assumes. */
#define MXFS_IOC_DIRSHARD_MKDIR_SIZE    272u
#define MXFS_IOC_DIRSHARD_INFO_SIZE     1352u
#ifdef __KERNEL__
#define MXFS_DIRSHARD_IOC_BUILD_CHECKS() do {					\
	BUILD_BUG_ON(sizeof(struct mxfs_ioc_dirshard_mkdir) !=		\
		     MXFS_IOC_DIRSHARD_MKDIR_SIZE);				\
	BUILD_BUG_ON(sizeof(struct mxfs_ioc_dirshard_info) !=		\
		     MXFS_IOC_DIRSHARD_INFO_SIZE);				\
} while (0)
#elif !defined(__cplusplus)
_Static_assert(sizeof(struct mxfs_ioc_dirshard_mkdir) == MXFS_IOC_DIRSHARD_MKDIR_SIZE,
	       "mxfs_ioc_dirshard_mkdir size drifted from tests/dirshard_ioctl.py");
_Static_assert(sizeof(struct mxfs_ioc_dirshard_info) == MXFS_IOC_DIRSHARD_INFO_SIZE,
	       "mxfs_ioc_dirshard_info size drifted from tests/dirshard_ioctl.py");
#endif

#endif /* MXFS_DIRSHARD_H */
