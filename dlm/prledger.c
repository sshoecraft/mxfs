/*
 * MXFS — SCSI PR registrant ledger.  See prledger.h.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include "prledger.h"

const char *mxfs_prledger_state_name(uint16_t state)
{
	switch (state) {
	case MXFS_PRLEDGER_FREE:        return "FREE";
	case MXFS_PRLEDGER_PREPARED:    return "PREPARED";
	case MXFS_PRLEDGER_REGISTERED:  return "REGISTERED";
	case MXFS_PRLEDGER_RETIRED:     return "RETIRED";
	case MXFS_PRLEDGER_FENCED:      return "FENCED";
	default:                        return "?";
	}
}

uint32_t mxfs_prledger_entry_crc(const struct mxfs_prledger_entry *e,
				 uint32_t idx)
{
	struct mxfs_prledger_entry t = *e;
	uint32_t c;

	t.crc32c = 0;
	c = mxfs_pal_crc32c(~0U, &t, sizeof(t));
	return mxfs_pal_crc32c(c, &idx, sizeof(idx));
}

bool mxfs_prledger_entry_valid(const struct mxfs_prledger_entry *e,
			       uint32_t idx)
{
	if (e->magic != MXFS_PRLEDGER_MAGIC || e->ver != MXFS_PRLEDGER_VERSION)
		return false;
	if (e->state > MXFS_PRLEDGER_FENCED)
		return false;
	return e->crc32c == mxfs_prledger_entry_crc(e, idx);
}

static bool prl_entry_owned(const struct mxfs_prledger_entry *e)
{
	return e->state == MXFS_PRLEDGER_PREPARED ||
	       e->state == MXFS_PRLEDGER_REGISTERED;
}

static bool prl_entry_ours(const struct mxfs_prledger *l,
			   const struct mxfs_prledger_entry *e)
{
	return memcmp(e->host_uuid, l->host_uuid, 16) == 0 &&
	       memcmp(e->boot_uuid, l->boot_uuid, 16) == 0 &&
	       memcmp(e->fs_uuid, l->fs_uuid, 16) == 0;
}

static uint64_t prl_off(const struct mxfs_prledger *l, uint32_t idx)
{
	return l->offset + (uint64_t)idx * MXFS_PRLEDGER_ENTRY_BYTES;
}

static int prl_read(struct mxfs_prledger *l, uint32_t idx,
		    struct mxfs_prledger_entry *e)
{
	return mxfs_pal_bdev_read_prio(l->dev, prl_off(l, idx), e, sizeof(*e));
}

/* CAS from the exact image `cur` to `want` at idx; seals want's crc. */
static int prl_cas(struct mxfs_prledger *l, uint32_t idx,
		   const struct mxfs_prledger_entry *cur,
		   struct mxfs_prledger_entry *want)
{
	int rc;

	want->seq = cur->seq + 1;
	want->stamp_ms = mxfs_pal_time_ms();
	want->crc32c = mxfs_prledger_entry_crc(want, idx);
	rc = mxfs_pal_bdev_compare_and_write(l->dev, prl_off(l, idx), cur, want);
	if (rc == -EOPNOTSUPP)
		rc = mxfs_pal_bdev_write_fua(l->dev, prl_off(l, idx), want,
					     sizeof(*want));
	return rc;
}

struct mxfs_prledger *mxfs_prledger_open(mxfs_bdev_t *dev, uint64_t offset,
					 uint64_t size,
					 const uint8_t host_uuid[16],
					 const uint8_t boot_uuid[16],
					 uint32_t host_src,
					 const uint8_t fs_uuid[16])
{
	struct mxfs_prledger *l;

	if (!dev || !offset || size < MXFS_PRLEDGER_ENTRY_BYTES ||
	    size % MXFS_PRLEDGER_ENTRY_BYTES || !host_uuid || !boot_uuid ||
	    !fs_uuid)
		return NULL;
	l = mxfs_pal_alloc(sizeof(*l));
	if (!l)
		return NULL;
	memset(l, 0, sizeof(*l));
	l->lock = mxfs_pal_mutex_create();
	if (!l->lock) {
		mxfs_pal_free(l);
		return NULL;
	}
	l->dev = dev;
	l->offset = offset;
	l->entries = (uint32_t)(size / MXFS_PRLEDGER_ENTRY_BYTES);
	if (l->entries > MXFS_PRLEDGER_ENTRIES)
		l->entries = MXFS_PRLEDGER_ENTRIES;
	l->own_idx = -1;
	l->free_idx = ~0U;
	memcpy(l->host_uuid, host_uuid, 16);
	memcpy(l->boot_uuid, boot_uuid, 16);
	memcpy(l->fs_uuid, fs_uuid, 16);
	l->host_src = host_src;
	return l;
}

void mxfs_prledger_close(struct mxfs_prledger *l)
{
	if (!l)
		return;
	if (l->lock)
		mxfs_pal_mutex_destroy(l->lock);
	mxfs_pal_free(l);
}

uint64_t mxfs_prledger_derive_key(const uint8_t host_uuid[16],
				  const uint8_t boot_uuid[16],
				  const uint8_t fs_uuid[16])
{
	/* Domain-separated canonical encoding: tag ‖ host ‖ boot ‖ fs.  Two
	 * crc32c passes with independent seeds give the 64 bits; the inputs
	 * are 48 random-uuid bytes, so this is a fixed-width mixing, not a
	 * cryptographic hash, and collisions are refused, never redrawn. */
	static const char tag[] = "MXFS-PRKEY-v1";
	uint8_t buf[sizeof(tag) + 48];
	uint32_t hi, lo;
	uint64_t key;

	memcpy(buf, tag, sizeof(tag));
	memcpy(buf + sizeof(tag), host_uuid, 16);
	memcpy(buf + sizeof(tag) + 16, boot_uuid, 16);
	memcpy(buf + sizeof(tag) + 32, fs_uuid, 16);
	hi = mxfs_pal_crc32c(~0U, buf, sizeof(buf));
	lo = mxfs_pal_crc32c(hi ^ 0x9E3779B9u, buf, sizeof(buf));
	key = ((uint64_t)hi << 32) | lo;
	if (key < MXFS_PRLEDGER_KEY_MIN)
		key |= MXFS_PRLEDGER_KEY_MIN;   /* never a legacy 32-bit node_id key */
	if (key == ~0ULL)
		key ^= 1;
	return key;
}

int mxfs_prledger_select(struct mxfs_prledger *l,
			 bool (*key_present)(void *arg, uint64_t key),
			 void *arg, uint64_t *key, uint32_t *key_gen)
{
	struct mxfs_prledger_entry *e;
	uint32_t i, free_idx = ~0U;
	uint64_t k;
	int rc = 0;

	if (!l || !key || !key_gen)
		return -EINVAL;
	e = mxfs_pal_alloc(sizeof(*e));
	if (!e)
		return -ENOMEM;

	mxfs_pal_mutex_lock(l->lock);
	if (l->own_idx >= 0) {
		*key = l->own.pr_key;
		*key_gen = l->own.key_gen;
		goto out;
	}
	k = mxfs_prledger_derive_key(l->host_uuid, l->boot_uuid, l->fs_uuid);
	l->derived_key = k;

	for (i = 0; i < l->entries; i++) {
		rc = prl_read(l, i, e);
		if (rc)
			goto out;
		if (!mxfs_prledger_entry_valid(e, i)) {
			/* zeroed (mkfs) or torn: reusable, but never trusted */
			if (free_idx == ~0U && e->magic == 0)
				free_idx = i;
			continue;
		}
		if (prl_entry_owned(e) && prl_entry_ours(l, e)) {
			if (e->pr_key != k) {
				mxfs_pal_log(MXFS_LOG_ERR,
					     "mxfs: P-PRKEY-LEDGER-MISMATCH idx=%u ledger=0x%llx "
					     "derived=0x%llx gen=%u — the ledger names a "
					     "different key for this boot on this LUN than "
					     "the identity derives; refusing (an identity "
					     "source changed under a live boot)",
					     i, (unsigned long long)e->pr_key,
					     (unsigned long long)k, e->key_gen);
				rc = -EKEYREJECTED;
				goto out;
			}
			l->own_idx = (int)i;
			l->own = *e;
			*key = e->pr_key;
			*key_gen = e->key_gen;
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-PRKEY-REUSED idx=%u key=0x%llx gen=%u "
				     "state=%s — this boot already published a key for "
				     "this LUN; reusing it, never minting a second",
				     i, (unsigned long long)*key, *key_gen,
				     mxfs_prledger_state_name(e->state));
			goto out;
		}
		if (prl_entry_owned(e) && e->pr_key == k) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-PRKEY-COLLISION idx=%u key=0x%llx node=%u — "
				     "another identity's ledger entry carries this boot's "
				     "derived key; refusing (no redraw: the key must be "
				     "reproducible by this boot)",
				     i, (unsigned long long)k, e->node_id);
			rc = -EEXIST;
			goto out;
		}
		if (free_idx == ~0U && !prl_entry_owned(e))
			free_idx = i;
		/*
		 * A REGISTERED entry whose key the target no longer holds belongs to
		 * a registrant that departed without reaching RETIRED (late-release
		 * unregister after the final log write, or a peer's uncertified
		 * preempt).  Nothing is registered under it, so there is nothing to
		 * fence and the entry is reusable.
		 */
		if (free_idx == ~0U && e->state == MXFS_PRLEDGER_REGISTERED &&
		    key_present && !key_present(arg, e->pr_key)) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-PRKEY-STALE-ENTRY idx=%u key=0x%llx node=%u "
				     "— REGISTERED in the ledger but absent from READ "
				     "KEYS; reusable", i,
				     (unsigned long long)e->pr_key, e->node_id);
			free_idx = i;
		}
	}
	if (free_idx == ~0U) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-PRKEY-LEDGER-FULL entries=%u — every registrant "
			     "entry is owned; no key can be published until a "
			     "departure retires one or a fence certifies one.  "
			     "Refusing to register",
			     l->entries);
		rc = -ENOSPC;
		goto out;
	}
	l->free_idx = free_idx;
	/* the target's view of K, decided at PUBLISH together with the nexus
	 * probe the REGISTER performs (own earlier registration vs collision) */
	l->seen_on_target = key_present ? key_present(arg, k) : false;
	*key = k;
	*key_gen = 1;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-PRKEY-SELECTED key=0x%llx gen=1 free_idx=%u "
		     "on_target=%d — derived from {host, boot, LUN}; published "
		     "to the ledger only after a verified REGISTER",
		     (unsigned long long)k, free_idx, l->seen_on_target ? 1 : 0);
out:
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(e);
	return rc;
}

int mxfs_prledger_publish(struct mxfs_prledger *l, uint32_t node_id,
			  bool nexus_reused,
			  const struct mxfs_prledger_succ *succ)
{
	struct mxfs_prledger_entry *cur, want;
	uint32_t idx, tries;
	int rc;

	if (!l)
		return -EINVAL;
	if (l->own_idx >= 0)
		return mxfs_prledger_set_registered(l, node_id);
	if (!l->derived_key)
		return -ENOENT;                 /* SELECT never ran */
	if (l->seen_on_target && !nexus_reused) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-PRKEY-COLLISION key=0x%llx — READ KEYS showed "
			     "this boot's derived key before our REGISTER and the "
			     "REGISTER did not find it on our own nexus: another "
			     "initiator holds it.  Refusing; the caller must "
			     "unregister", (unsigned long long)l->derived_key);
		return -EEXIST;
	}
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(l->lock);
	idx = l->free_idx;
	for (tries = 0; tries < l->entries; tries++) {
		if (idx >= l->entries)
			idx = 0;
		rc = prl_read(l, idx, cur);
		if (rc)
			break;
		if (mxfs_prledger_entry_valid(cur, idx) && prl_entry_owned(cur)) {
			idx++;                      /* raced: taken since SELECT */
			rc = -EAGAIN;
			continue;
		}
		memset(&want, 0, sizeof(want));
		want.magic = MXFS_PRLEDGER_MAGIC;
		want.ver = MXFS_PRLEDGER_VERSION;
		want.state = MXFS_PRLEDGER_REGISTERED;
		want.key_gen = 1;
		want.node_id = node_id;
		want.pr_key = l->derived_key;
		memcpy(want.host_uuid, l->host_uuid, 16);
		memcpy(want.boot_uuid, l->boot_uuid, 16);
		memcpy(want.fs_uuid, l->fs_uuid, 16);
		want.host_src = l->host_src;
		if (succ) {
			want.succ_old_key = succ->old_key;
			want.succ_old_key_gen = succ->old_key_gen;
			memcpy(want.succ_old_boot, succ->old_boot, 16);
		}
		rc = prl_cas(l, idx, cur, &want);
		if (rc == -EAGAIN) {
			idx++;
			continue;
		}
		if (rc == 0) {
			l->own_idx = (int)idx;
			l->own = want;
		}
		break;
	}
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P-PRKEY-PUBLISHED idx=%u key=0x%llx gen=1 node=%u "
		     "nexus_reused=%d succeeds=0x%llx rc=%d%s", idx,
		     (unsigned long long)l->derived_key, node_id,
		     nexus_reused ? 1 : 0,
		     (unsigned long long)(succ ? succ->old_key : 0), rc,
		     rc ? " — the registration stands but is UNATTRIBUTED on the "
			  "LUN; refusing to proceed on it" : "");
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(cur);
	return rc;
}

static int prl_own_transition(struct mxfs_prledger *l, uint16_t state,
			      uint32_t node_id, const char *tag)
{
	struct mxfs_prledger_entry *cur, want;
	int rc;

	if (!l || l->own_idx < 0)
		return -ENOENT;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(l->lock);
	rc = prl_read(l, (uint32_t)l->own_idx, cur);
	if (rc)
		goto out;
	if (!mxfs_prledger_entry_valid(cur, (uint32_t)l->own_idx) ||
	    !prl_entry_ours(l, cur) || cur->pr_key != l->own.pr_key) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-PRKEY-ENTRY-LOST idx=%d key=0x%llx want=%s — "
			     "our ledger entry no longer names us (state=%s "
			     "key=0x%llx valid=%d)",
			     l->own_idx, (unsigned long long)l->own.pr_key, tag,
			     mxfs_prledger_state_name(cur->state),
			     (unsigned long long)cur->pr_key,
			     mxfs_prledger_entry_valid(cur, (uint32_t)l->own_idx));
		rc = -ESTALE;
		goto out;
	}
	want = *cur;
	want.state = state;
	if (node_id)
		want.node_id = node_id;
	rc = prl_cas(l, (uint32_t)l->own_idx, cur, &want);
	if (rc == 0)
		l->own = want;
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_INFO,
		     "mxfs: P-PRKEY-%s idx=%d key=0x%llx gen=%u node=%u rc=%d",
		     tag, l->own_idx, (unsigned long long)want.pr_key,
		     want.key_gen, want.node_id, rc);
out:
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(cur);
	return rc;
}

int mxfs_prledger_set_registered(struct mxfs_prledger *l, uint32_t node_id)
{
	return prl_own_transition(l, MXFS_PRLEDGER_REGISTERED, node_id,
				  "REGISTERED");
}

int mxfs_prledger_set_retired(struct mxfs_prledger *l)
{
	int rc = prl_own_transition(l, MXFS_PRLEDGER_RETIRED, 0, "RETIRED");

	if (rc == 0)
		l->own_idx = -1;
	return rc;
}

int mxfs_prledger_mark_fenced(struct mxfs_prledger *l, uint64_t victim_key,
			      uint32_t fencer_node)
{
	struct mxfs_prledger_entry *cur, want;
	uint32_t i;
	int rc = -ENOENT;

	if (!l || !victim_key)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(l->lock);
	for (i = 0; i < l->entries; i++) {
		rc = prl_read(l, i, cur);
		if (rc)
			break;
		if (!mxfs_prledger_entry_valid(cur, i) || !prl_entry_owned(cur) ||
		    cur->pr_key != victim_key) {
			rc = -ENOENT;
			continue;
		}
		want = *cur;
		want.state = MXFS_PRLEDGER_FENCED;
		want.fenced_by = fencer_node;
		rc = prl_cas(l, i, cur, &want);
		mxfs_pal_log(rc ? MXFS_LOG_WARN : MXFS_LOG_INFO,
			     "mxfs: P-PRKEY-FENCED idx=%u key=0x%llx node=%u by=%u "
			     "rc=%d", i, (unsigned long long)victim_key,
			     cur->node_id, fencer_node, rc);
		break;
	}
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(cur);
	return rc;
}

/*
 * (docs/whole-cluster-restart.md §6.3): the bootstrap owner classifies
 * EVERY key READ KEYS returns.  A key the heartbeat table does not explain is
 * looked up here: an owned (PREPARED/REGISTERED) entry carrying it is a
 * slotless registrant (class 3) or, when its succ_old_key names a victim, a
 * self-successor (class 4).  0 = found (*out filled), -ENOENT = no owned
 * entry carries the key, <0 = I/O.
 */
int mxfs_prledger_find_by_key(struct mxfs_prledger *l, uint64_t key,
			      struct mxfs_prledger_entry *out)
{
	struct mxfs_prledger_entry *cur;
	uint32_t i;
	int rc = -ENOENT;

	if (!l || !key || !out)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(l->lock);
	for (i = 0; i < l->entries; i++) {
		rc = prl_read(l, i, cur);
		if (rc)
			break;
		rc = -ENOENT;
		if (mxfs_prledger_entry_valid(cur, i) && prl_entry_owned(cur) &&
		    cur->pr_key == key) {
			*out = *cur;
			rc = 0;
			break;
		}
	}
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(cur);
	return rc;
}

uint64_t mxfs_prledger_key_of_node(struct mxfs_prledger *l, uint32_t node_id)
{
	struct mxfs_prledger_entry *cur;
	uint64_t key = 0;
	uint32_t i;

	if (!l || !node_id)
		return 0;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return 0;
	mxfs_pal_mutex_lock(l->lock);
	for (i = 0; i < l->entries; i++) {
		if (prl_read(l, i, cur))
			break;
		if (mxfs_prledger_entry_valid(cur, i) && prl_entry_owned(cur) &&
		    cur->node_id == node_id) {
			key = cur->pr_key;
			break;
		}
	}
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(cur);
	return key;
}

int mxfs_prledger_find_predecessor(struct mxfs_prledger *l,
				   bool (*key_present)(void *arg, uint64_t key),
				   void *arg, uint64_t *old_key,
				   uint8_t old_boot[16], uint32_t *old_gen)
{
	struct mxfs_prledger_entry *e;
	uint32_t i, found = 0;
	int rc = 0;

	if (!l || !old_key || !old_boot || !old_gen)
		return -EINVAL;
	e = mxfs_pal_alloc(sizeof(*e));
	if (!e)
		return -ENOMEM;
	*old_key = 0;
	mxfs_pal_mutex_lock(l->lock);
	for (i = 0; i < l->entries; i++) {
		rc = prl_read(l, i, e);
		if (rc)
			goto out;
		if (!mxfs_prledger_entry_valid(e, i) || !prl_entry_owned(e))
			continue;
		if (memcmp(e->host_uuid, l->host_uuid, 16) != 0 ||
		    memcmp(e->fs_uuid, l->fs_uuid, 16) != 0 ||
		    memcmp(e->boot_uuid, l->boot_uuid, 16) == 0)
			continue;
		if (key_present && !key_present(arg, e->pr_key)) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P305-PR-PREDECESSOR-RETIRED idx=%u key=0x%llx "
				     "— a previous boot of this host, but its key is no "
				     "longer registered; not a candidate",
				     i, (unsigned long long)e->pr_key);
			continue;
		}
		found++;
		if (found == 1) {
			*old_key = e->pr_key;
			*old_gen = e->key_gen;
			memcpy(old_boot, e->boot_uuid, 16);
		}
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P305-PR-PREDECESSOR-CANDIDATE idx=%u key=0x%llx "
			     "gen=%u node=%u state=%s candidates=%u",
			     i, (unsigned long long)e->pr_key, e->key_gen, e->node_id,
			     mxfs_prledger_state_name(e->state), found);
	}
	if (found == 0)
		rc = -ENOENT;
	else if (found > 1)
		rc = -EEXIST;
out:
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(e);
	return rc;
}

int mxfs_prledger_find_successor(struct mxfs_prledger *l, uint64_t old_key,
				 const uint8_t old_boot[16],
				 const uint8_t victim_host[16],
				 uint64_t *new_key, uint32_t *new_node,
				 uint8_t new_boot[16])
{
	struct mxfs_prledger_entry *e;
	uint32_t i, found = 0;
	int rc = 0;

	if (!l || !old_key || !old_boot || !victim_host || !new_key || !new_node)
		return -EINVAL;
	e = mxfs_pal_alloc(sizeof(*e));
	if (!e)
		return -ENOMEM;
	*new_key = 0;
	*new_node = 0;
	if (new_boot)
		memset(new_boot, 0, 16);
	mxfs_pal_mutex_lock(l->lock);
	for (i = 0; i < l->entries; i++) {
		rc = prl_read(l, i, e);
		if (rc)
			goto out;
		if (!mxfs_prledger_entry_valid(e, i) ||
		    e->state != MXFS_PRLEDGER_REGISTERED)
			continue;
		if (e->succ_old_key != old_key ||
		    memcmp(e->succ_old_boot, old_boot, 16) != 0 ||
		    memcmp(e->host_uuid, victim_host, 16) != 0 ||
		    memcmp(e->fs_uuid, l->fs_uuid, 16) != 0)
			continue;
		found++;
		if (found == 1) {
			*new_key = e->pr_key;
			*new_node = e->node_id;
			if (new_boot)
				memcpy(new_boot, e->boot_uuid, 16);
		}
	}
	if (found == 0)
		rc = -ENOENT;
	else if (found > 1)
		rc = -EEXIST;
out:
	mxfs_pal_mutex_unlock(l->lock);
	mxfs_pal_free(e);
	return rc;
}
