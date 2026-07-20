/*
 * MXFS — NET2 user-mode protocol harness, gate-1 scenarios.
 *
 * Scenarios (DLM_IMPL_PLAN.md §11 step 1 gate):
 *   wire_golden   — pack/unpack vs checked-in byte vectors, both directions
 *   wire_fuzz     — seeded mutation + noise fuzz over hdr validate/unpack
 *   tlv_roundtrip — SYN TLV build/iterate incl. truncation + unknown-skip
 *   fault_engine  — PRNG/decision goldens, rule matching, parser corpus
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "harness.h"
#include "dlm/net2_wire.h"
#include "dlm/net2.h"
#include "dlm/net2_fault.h"

/* ─── vector file I/O ─── */

static int vec_path(char *out, size_t cap, const struct scenario_ctx *sc,
                    const char *name)
{
	int n = snprintf(out, cap, "%s/%s", sc->vectors_dir, name);
	return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

static int vec_write(const struct scenario_ctx *sc, const char *name,
                     const void *buf, size_t len)
{
	char path[512];
	FILE *f;

	if (vec_path(path, sizeof(path), sc, name))
		return -1;
	f = fopen(path, "wb");
	if (!f)
		return -1;
	if (fwrite(buf, 1, len, f) != len) {
		fclose(f);
		return -1;
	}
	fclose(f);
	printf("  wrote %s (%zu bytes)\n", path, len);
	return 0;
}

/* Compare buf against the stored vector; -1 = missing/short, else #diffs. */
static int vec_check(const struct scenario_ctx *sc, const char *name,
                     const void *buf, size_t len)
{
	char path[512];
	uint8_t stored[16384];
	FILE *f;
	size_t got;
	int diffs = 0;

	if (len > sizeof(stored) || vec_path(path, sizeof(path), sc, name))
		return -1;
	f = fopen(path, "rb");
	if (!f)
		return -1;
	got = fread(stored, 1, sizeof(stored), f);
	fclose(f);
	if (got != len)
		return -1;
	for (size_t i = 0; i < len; i++)
		if (stored[i] != ((const uint8_t *)buf)[i])
			diffs++;
	return diffs;
}

/* ─── canonical builders (shared by golden + write-vectors) ─── */

static void canonical_hdr(struct mxfs_net2_hdr *h, uint8_t fc)
{
	memset(h, 0, sizeof(*h));
	h->magic             = MXFS_NET2_MAGIC;
	h->version           = MXFS_NET2_WIRE_VERSION;
	h->frame_class       = fc;
	h->priority          = NET2_PRI_GRANT;
	h->flags             = MXFS_NET2_F_RELIABLE | MXFS_NET2_F_ACKREQ;
	h->ttl               = 6;
	h->hopcount          = 2;
	h->payload_len       = 0x1234;
	h->cluster_uuid_hash = 0xA1B2C3D4;
	h->membership_epoch  = 0x1122334455667788ULL;
	h->src_slot          = 7;
	h->dst_slot          = 63;
	h->src_incarnation   = 0x01020304;
	h->dst_incarnation   = 0x0A0B0C0D;
	h->seq               = 0xDEADBEEFCAFEF00DULL;
	h->ack               = 0x0123456789ABCDEFULL;
	h->sack_mask         = 0xF0F0F0F0;
	h->msg_id            = 0x00C0FFEE;
	h->pad               = 0;
}

static int canonical_tlv(uint8_t *buf, int cap)
{
	static const uint8_t uuid[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	uint32_t volume_id = 0x564F4C31, fs_gen = 7;
	uint64_t nonce = 0x4E4F4E4345000001ULL;
	uint32_t features = MXFS_NET2_FEAT_MEMBFENCE | MXFS_NET2_FEAT_BAST_WAKE;
	uint16_t wire_ver = MXFS_NET2_WIRE_VERSION;
	uint8_t le[8];
	int off = 0;

	off = mxfs_net2_tlv_put(buf, cap, off, MXFS_NET2_TLV_UUID, uuid, 16);
	mxfs_net2_put_le32(le, volume_id);
	off = mxfs_net2_tlv_put(buf, cap, off, MXFS_NET2_TLV_VOLUME_ID, le, 4);
	mxfs_net2_put_le32(le, fs_gen);
	off = mxfs_net2_tlv_put(buf, cap, off, MXFS_NET2_TLV_FS_GEN, le, 4);
	mxfs_net2_put_le64(le, nonce);
	off = mxfs_net2_tlv_put(buf, cap, off, MXFS_NET2_TLV_NONCE, le, 8);
	mxfs_net2_put_le32(le, features);
	off = mxfs_net2_tlv_put(buf, cap, off, MXFS_NET2_TLV_FEATURES, le, 4);
	mxfs_net2_put_le16(le, wire_ver);
	off = mxfs_net2_tlv_put(buf, cap, off, MXFS_NET2_TLV_WIRE_VER, le, 2);
	return off;
}

#define FAULT_PRNG_SEED   0xC0FFEEULL
#define FAULT_PRNG_COUNT  64
#define FAULT_SEQ_SEED    42ULL
#define FAULT_SEQ_COUNT   256
#define FAULT_SEQ_RULE    "a:*:*:drop:500000:*:0"

static void canonical_fault_prng(uint8_t *buf /* 8*FAULT_PRNG_COUNT */)
{
	uint64_t st = FAULT_PRNG_SEED;

	for (int i = 0; i < FAULT_PRNG_COUNT; i++)
		mxfs_net2_put_le64(buf + 8 * i,
		                   mxfs_net2_fault_prng_next(&st));
}

static void canonical_fault_seq(uint8_t *buf /* FAULT_SEQ_COUNT */)
{
	struct mxfs_net2_fault_state st;
	struct mxfs_net2_fault_rule rule;
	struct mxfs_net2_fault_hit hit;

	mxfs_net2_fault_init(&st, FAULT_SEQ_SEED);
	if (mxfs_net2_fault_parse_rule(FAULT_SEQ_RULE, &rule) ||
	    mxfs_net2_fault_set(&st, 0, &rule)) {
		memset(buf, 0xEE, FAULT_SEQ_COUNT);   /* poison: test fails */
		return;
	}
	for (int i = 0; i < FAULT_SEQ_COUNT; i++)
		buf[i] = (uint8_t)mxfs_net2_fault_eval(&st,
				MXFS_NET2_FAULT_SEND, MXFS_NET2_FC_DATA,
				4 /* MXFS_MSG_LOCK_RELEASE */, &hit);
}

/* ─── scenario: wire_golden ─── */

static int scen_wire_golden(struct scenario_ctx *sc)
{
	for (uint8_t fc = 0; fc < MXFS_NET2_FC_COUNT; fc++) {
		struct mxfs_net2_hdr h, back;
		uint8_t buf[MXFS_NET2_HDR_SIZE];
		char name[32];

		snprintf(name, sizeof(name), "v1_frame_fc%u.bin", fc);
		canonical_hdr(&h, fc);
		mxfs_net2_hdr_pack(&h, buf);

		if (sc->write_vectors) {
			ck(sc, vec_write(sc, name, buf, sizeof(buf)) == 0,
			   "write frame vector");
			continue;
		}
		ck(sc, vec_check(sc, name, buf, sizeof(buf)) == 0,
		   "pack matches checked-in vector");
		mxfs_net2_hdr_unpack(buf, &back);
		ck(sc, memcmp(&h, &back, sizeof(h)) == 0,
		   "unpack(pack(h)) round-trips all fields");
		ck(sc, mxfs_net2_hdr_validate(&back) == MXFS_NET2_HDR_OK,
		   "canonical frame validates OK");
	}
	if (!sc->write_vectors) {
		/* Spot-check wire offsets independently of pack/unpack:
		 * epoch at 16, seq at 36 (the misalignment-prone ones). */
		struct mxfs_net2_hdr h;
		uint8_t buf[MXFS_NET2_HDR_SIZE];

		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		mxfs_net2_hdr_pack(&h, buf);
		ck(sc, mxfs_net2_get_le64(buf + 16) == h.membership_epoch,
		   "epoch at wire offset 16");
		ck(sc, mxfs_net2_get_le64(buf + 36) == h.seq,
		   "seq at wire offset 36");
		ck(sc, mxfs_net2_get_le64(buf + 44) == h.ack,
		   "ack at wire offset 44");
		ck(sc, mxfs_net2_get_le16(buf + 10) == h.payload_len,
		   "payload_len at wire offset 10");
	}
	return sc->failed ? 1 : 0;
}

/* ─── scenario: wire_fuzz ─── */

static int scen_wire_fuzz(struct scenario_ctx *sc)
{
	uint64_t st = sc->seed ? sc->seed : 0xF422ULL;
	long iters = 100000;
	long rejected = 0, accepted = 0;

	/* Targeted malformed corpus — exact reject reasons. */
	{
		struct mxfs_net2_hdr h;
		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		h.magic ^= 1;
		ck(sc, mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_EMAGIC,
		   "bad magic rejected");
		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		h.version = 2;
		ck(sc, mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_EVERSION,
		   "bad version rejected");
		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		h.frame_class = MXFS_NET2_FC_COUNT;
		ck(sc, mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_ECLASS,
		   "bad class rejected");
		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		h.priority = MXFS_NET2_WIRE_PRI_COUNT;
		ck(sc, mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_EPRIORITY,
		   "bad priority rejected");
		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		h.payload_len = MXFS_NET2_MAX_MSG_SIZE + 1;
		ck(sc, mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_ELEN,
		   "oversize payload_len rejected");
		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		h.flags = 0x80;
		ck(sc, mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_EFLAGS,
		   "unknown flag rejected");
		canonical_hdr(&h, MXFS_NET2_FC_DATA);
		h.pad = 1;
		ck(sc, mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_EPAD,
		   "nonzero pad rejected");
	}

	/* Seeded mutation + noise sweep: must never crash; valid frames
	 * must round-trip stably; results deterministic per seed. */
	for (long i = 0; i < iters; i++) {
		uint8_t buf[MXFS_NET2_HDR_SIZE];
		struct mxfs_net2_hdr h, h2;
		uint64_t r = mxfs_net2_fault_prng_next(&st);

		if (r & 1) {
			/* mutate a canonical frame in 1..8 random bytes */
			canonical_hdr(&h, (uint8_t)((r >> 1) % MXFS_NET2_FC_COUNT));
			mxfs_net2_hdr_pack(&h, buf);
			int muts = 1 + (int)((r >> 8) % 8);
			for (int m = 0; m < muts; m++) {
				uint64_t rr = mxfs_net2_fault_prng_next(&st);
				buf[rr % MXFS_NET2_HDR_SIZE] ^=
					(uint8_t)(rr >> 16);
			}
		} else {
			/* pure noise */
			for (int b = 0; b < MXFS_NET2_HDR_SIZE; b += 8)
				mxfs_net2_put_le64(buf + b,
					mxfs_net2_fault_prng_next(&st));
		}

		mxfs_net2_hdr_unpack(buf, &h);
		if (mxfs_net2_hdr_validate(&h) == MXFS_NET2_HDR_OK) {
			uint8_t buf2[MXFS_NET2_HDR_SIZE];

			accepted++;
			mxfs_net2_hdr_pack(&h, buf2);
			mxfs_net2_hdr_unpack(buf2, &h2);
			if (memcmp(&h, &h2, sizeof(h)) != 0) {
				ck(sc, 0, "accepted frame round-trip unstable");
				break;
			}
			if (memcmp(buf, buf2, sizeof(buf)) != 0) {
				ck(sc, 0, "accepted frame repack differs");
				break;
			}
		} else {
			rejected++;
		}
	}
	printf("  fuzz: %ld iters, %ld accepted, %ld rejected\n",
	       iters, accepted, rejected);
	ck(sc, accepted + rejected == iters, "every frame classified");
	return sc->failed ? 1 : 0;
}

/* ─── scenario: tlv_roundtrip ─── */

static int scen_tlv_roundtrip(struct scenario_ctx *sc)
{
	uint8_t buf[256];
	int len = canonical_tlv(buf, sizeof(buf));

	ck(sc, len == 62, "canonical TLV block is 62 bytes");

	if (sc->write_vectors)
		return ck(sc, vec_write(sc, "v1_syn_tlv.bin", buf, (size_t)len) == 0,
		          "write tlv vector") ? 0 : 1;

	ck(sc, vec_check(sc, "v1_syn_tlv.bin", buf, (size_t)len) == 0,
	   "TLV block matches checked-in vector");

	/* Full iteration: exactly 6 records, right types/lens. */
	{
		static const uint16_t want_type[6] = { 1, 2, 3, 4, 5, 6 };
		static const uint16_t want_len[6]  = { 16, 4, 4, 8, 4, 2 };
		int off = 0, n = 0, rc;
		uint16_t type, tlen;
		const uint8_t *val;

		while ((rc = mxfs_net2_tlv_next(buf, len, &off, &type, &tlen,
		                                &val)) == 1) {
			if (n < 6) {
				ck(sc, type == want_type[n], "tlv type order");
				ck(sc, tlen == want_len[n], "tlv len");
			}
			n++;
		}
		ck(sc, rc == 0, "iteration ends cleanly");
		ck(sc, n == 6, "exactly 6 records");
	}

	/* Truncation at every byte: never a crash; -1 unless the cut lands
	 * exactly on a record boundary (then clean end). */
	{
		static const int boundaries[] = { 0, 20, 28, 36, 48, 56, 62 };
		for (int cut = 0; cut < len; cut++) {
			int off = 0, rc;
			uint16_t type, tlen;
			const uint8_t *val;

			while ((rc = mxfs_net2_tlv_next(buf, cut, &off, &type,
			                                &tlen, &val)) == 1)
				;
			int is_boundary = 0;
			for (size_t b = 0;
			     b < sizeof(boundaries) / sizeof(boundaries[0]); b++)
				if (cut == boundaries[b])
					is_boundary = 1;
			if (is_boundary)
				ck(sc, rc == 0, "boundary cut ends cleanly");
			else if (rc != -1)
				ck(sc, 0, "mid-record cut must return -1");
		}
	}

	/* Unknown type is skipped, known ones still found. */
	{
		uint8_t buf2[256];
		uint8_t junk[5] = { 1, 2, 3, 4, 5 };
		int off2 = 0, rc, n = 0;
		uint16_t type, tlen;
		const uint8_t *val;

		off2 = mxfs_net2_tlv_put(buf2, sizeof(buf2), 0, 0x7FFF, junk, 5);
		off2 = mxfs_net2_tlv_put(buf2, sizeof(buf2), off2,
		                         MXFS_NET2_TLV_FS_GEN, junk, 4);
		ck(sc, off2 == 9 + 8, "unknown+known block built");
		{
			int off3 = 0;
			while ((rc = mxfs_net2_tlv_next(buf2, off2, &off3,
			                                &type, &tlen, &val)) == 1)
				n++;
			ck(sc, rc == 0 && n == 2,
			   "iterator delivers unknown + known records");
		}
	}
	return sc->failed ? 1 : 0;
}

/* ─── scenario: fault_engine ─── */

static int scen_fault_engine(struct scenario_ctx *sc)
{
	/* PRNG + decision-stream goldens (cross-build determinism lock). */
	{
		uint8_t prng[8 * FAULT_PRNG_COUNT];
		uint8_t seq[FAULT_SEQ_COUNT];

		canonical_fault_prng(prng);
		canonical_fault_seq(seq);
		if (sc->write_vectors) {
			ck(sc, vec_write(sc, "v1_fault_prng.bin", prng,
			                 sizeof(prng)) == 0, "write prng vector");
			ck(sc, vec_write(sc, "v1_fault_seq.bin", seq,
			                 sizeof(seq)) == 0, "write seq vector");
			return sc->failed ? 1 : 0;
		}
		ck(sc, vec_check(sc, "v1_fault_prng.bin", prng,
		                 sizeof(prng)) == 0,
		   "PRNG stream matches checked-in vector");
		ck(sc, vec_check(sc, "v1_fault_seq.bin", seq,
		                 sizeof(seq)) == 0,
		   "decision stream matches checked-in vector");
	}

	/* Determinism: same seed, same sequence => identical decisions. */
	{
		uint8_t a[FAULT_SEQ_COUNT], b[FAULT_SEQ_COUNT];

		canonical_fault_seq(a);
		canonical_fault_seq(b);
		ck(sc, memcmp(a, b, sizeof(a)) == 0, "replay is deterministic");
	}

	/* Rule matching semantics. */
	{
		struct mxfs_net2_fault_state st;
		struct mxfs_net2_fault_rule r;
		struct mxfs_net2_fault_hit hit;
		int hits = 0;

		mxfs_net2_fault_init(&st, 7);
		memset(&r, 0, sizeof(r));
		r.action = MXFS_NET2_FAULT_DROP;
		r.dir = MXFS_NET2_FAULT_RECV;
		r.frame_class = MXFS_NET2_FC_ACK;
		r.inner_type = MXFS_NET2_FAULT_ANY_TYPE;
		r.prob_ppm = 1000000;
		r.count = 3;
		ck(sc, mxfs_net2_fault_set(&st, 0, &r) == 0, "rule set");

		for (int i = 0; i < 10; i++)
			hits += mxfs_net2_fault_eval(&st, MXFS_NET2_FAULT_RECV,
					MXFS_NET2_FC_ACK, 9, &hit);
		ck(sc, hits == 3, "count-limited rule fires exactly count times");
		ck(sc, st.injected[MXFS_NET2_FAULT_DROP] == 3,
		   "injection counter tracks");

		hits = 0;
		for (int i = 0; i < 10; i++)
			hits += mxfs_net2_fault_eval(&st, MXFS_NET2_FAULT_SEND,
					MXFS_NET2_FC_ACK, 9, &hit);
		ck(sc, hits == 0, "direction filter respected");

		mxfs_net2_fault_init(&st, 7);
		r.dir = MXFS_NET2_FAULT_ANY_DIR;
		r.frame_class = MXFS_NET2_FAULT_ANY_CLASS;
		r.count = MXFS_NET2_FAULT_UNLIMITED;
		r.prob_ppm = 0;
		ck(sc, mxfs_net2_fault_set(&st, 1, &r) == 0, "rule set 2");
		hits = 0;
		for (int i = 0; i < 1000; i++)
			hits += mxfs_net2_fault_eval(&st, MXFS_NET2_FAULT_SEND,
					MXFS_NET2_FC_DATA, 1, &hit);
		ck(sc, hits == 0, "prob 0 never fires");
	}

	/* Parser corpus. */
	{
		struct mxfs_net2_fault_rule r;
		static const char *good[] = {
			"a:*:*:drop:500000:*:0",
			"s:0:4:dup:1000000:10:0",
			"r:3:*:delay:250000:*:50",
			"a:2:6:reorder:1000000:1:5",
			"r:*:*:trunc:1:*:0",
			"s:4:*:corrupt:999999:2:0",
		};
		static const char *bad[] = {
			"", "x:*:*:drop:1:*:0", "a:*:*:nope:1:*:0",
			"a:*:*:drop:1000001:*:0", "a:*:*:drop:1:*:",
			"a:5:*:drop:1:*:0", "a:*:*:drop:1:*:0:extra",
			"a:*:70000:drop:1:*:0", "a:*:*:drop::*:0",
		};
		for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++)
			ck(sc, mxfs_net2_fault_parse_rule(good[i], &r) == 0,
			   good[i]);
		for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
			ck(sc, mxfs_net2_fault_parse_rule(bad[i], &r) == -1,
			   bad[i]);
		ck(sc, mxfs_net2_fault_parse_rule("s:0:4:dup:1000000:10:0",
		                                  &r) == 0 &&
		       r.dir == MXFS_NET2_FAULT_SEND &&
		       r.frame_class == 0 && r.inner_type == 4 &&
		       r.action == MXFS_NET2_FAULT_DUP &&
		       r.prob_ppm == 1000000 && r.count == 10 &&
		       r.delay_ms == 0,
		   "parsed fields exact");
	}
	return sc->failed ? 1 : 0;
}

/* ─── runner ─── */

static const struct scenario scenarios[] = {
	{ "wire_golden",   scen_wire_golden,   0 },
	{ "wire_fuzz",     scen_wire_fuzz,     0 },
	{ "tlv_roundtrip", scen_tlv_roundtrip, 0 },
	{ "fault_engine",  scen_fault_engine,  0 },
};
#define NSCEN (sizeof(scenarios) / sizeof(scenarios[0]))

static int run_one(const struct scenario *s, struct scenario_ctx *base)
{
	struct scenario_ctx sc = *base;
	int rc;

	sc.checks = 0;
	sc.failed = 0;
	rc = s->fn(&sc);
	printf("RESULT: %s | test=net2_%s%s | nodes=1 | "
	       "measured=checks=%d,passed=%d,failed=%d | reason=%s\n",
	       rc ? "FAIL" : "PASS", s->name,
	       sc.real_time ? "_rt" : "", sc.checks,
	       sc.checks - sc.failed, sc.failed, rc ? "check-failures" : "-");
	return rc;
}

static void usage(void)
{
	fprintf(stderr,
	    "usage: net2_harness list\n"
	    "       net2_harness run <scenario|all|rt> [--seed N] "
	    "[--vectors DIR] [--real-time]\n"
	    "       net2_harness write-vectors <dir>\n"
	    "  all = every scenario (midcomms ones time-compressed /10)\n"
	    "  rt  = the pinned real-time subset at spec-default tunables\n");
}

int main(int argc, char **argv)
{
	struct scenario_ctx base = {
		.vectors_dir = "vectors",
		.seed = 0xF422ULL,
		.write_vectors = 0,
	};
	int rc = 0;

	if (argc < 2) {
		usage();
		return 2;
	}

	if (!strcmp(argv[1], "list")) {
		for (size_t i = 0; i < NSCEN; i++)
			printf("%s\n", scenarios[i].name);
		for (int i = 0; i < net2_scen_midcomms_count; i++)
			printf("%s%s\n", net2_scen_midcomms[i].name,
			       net2_scen_midcomms[i].real_time_subset ?
			       " [rt-subset]" : "");
		for (int i = 0; i < net2_scen_shard_count; i++)
			printf("%s%s\n", net2_scen_shard[i].name,
			       net2_scen_shard[i].real_time_subset ?
			       " [rt-subset]" : "");
		for (int i = 0; i < net2_scen_mepoch_count; i++)
			printf("%s%s\n", net2_scen_mepoch[i].name,
			       net2_scen_mepoch[i].real_time_subset ?
			       " [rt-subset]" : "");
		return 0;
	}

	if (!strcmp(argv[1], "write-vectors")) {
		if (argc < 3) {
			usage();
			return 2;
		}
		base.vectors_dir = argv[2];
		base.write_vectors = 1;
		for (size_t i = 0; i < NSCEN; i++)
			rc |= run_one(&scenarios[i], &base);
		return rc ? 1 : 0;
	}

	if (strcmp(argv[1], "run") || argc < 3) {
		usage();
		return 2;
	}

	for (int a = 3; a < argc; a++) {
		if (!strcmp(argv[a], "--seed") && a + 1 < argc)
			base.seed = strtoull(argv[++a], NULL, 0);
		else if (!strcmp(argv[a], "--vectors") && a + 1 < argc)
			base.vectors_dir = argv[++a];
		else if (!strcmp(argv[a], "--real-time"))
			base.real_time = 1;
		else {
			usage();
			return 2;
		}
	}

	if (!strcmp(argv[2], "all")) {
		for (size_t i = 0; i < NSCEN; i++)
			rc |= run_one(&scenarios[i], &base);
		for (int i = 0; i < net2_scen_midcomms_count; i++)
			rc |= run_one(&net2_scen_midcomms[i], &base);
		for (int i = 0; i < net2_scen_shard_count; i++)
			rc |= run_one(&net2_scen_shard[i], &base);
		for (int i = 0; i < net2_scen_mepoch_count; i++)
			rc |= run_one(&net2_scen_mepoch[i], &base);
		return rc ? 1 : 0;
	}
	if (!strcmp(argv[2], "midcomms")) {
		/* gate-2 matrix: wire statics + §13.1 midcomms family
		 * (gate 4 owns shard, gate 5 owns mepoch) */
		for (size_t i = 0; i < NSCEN; i++)
			rc |= run_one(&scenarios[i], &base);
		for (int i = 0; i < net2_scen_midcomms_count; i++)
			rc |= run_one(&net2_scen_midcomms[i], &base);
		return rc ? 1 : 0;
	}
	if (!strcmp(argv[2], "shard")) {
		/* gate-4 group: the §13.2 family only */
		for (int i = 0; i < net2_scen_shard_count; i++)
			rc |= run_one(&net2_scen_shard[i], &base);
		return rc ? 1 : 0;
	}
	if (!strcmp(argv[2], "mepoch")) {
		/* gate-5 group: the §7.C membership family only */
		for (int i = 0; i < net2_scen_mepoch_count; i++)
			rc |= run_one(&net2_scen_mepoch[i], &base);
		return rc ? 1 : 0;
	}
	if (!strcmp(argv[2], "rt")) {
		/* Pinned real-time subset: spec-default tunables, because
		 * time compression can mask races (DLM_IMPL_PLAN.md). */
		base.real_time = 1;
		for (int i = 0; i < net2_scen_midcomms_count; i++)
			if (net2_scen_midcomms[i].real_time_subset)
				rc |= run_one(&net2_scen_midcomms[i], &base);
		return rc ? 1 : 0;
	}
	for (size_t i = 0; i < NSCEN; i++)
		if (!strcmp(argv[2], scenarios[i].name))
			return run_one(&scenarios[i], &base) ? 1 : 0;
	for (int i = 0; i < net2_scen_midcomms_count; i++)
		if (!strcmp(argv[2], net2_scen_midcomms[i].name))
			return run_one(&net2_scen_midcomms[i], &base) ? 1 : 0;
	for (int i = 0; i < net2_scen_shard_count; i++)
		if (!strcmp(argv[2], net2_scen_shard[i].name))
			return run_one(&net2_scen_shard[i], &base) ? 1 : 0;
	for (int i = 0; i < net2_scen_mepoch_count; i++)
		if (!strcmp(argv[2], net2_scen_mepoch[i].name))
			return run_one(&net2_scen_mepoch[i], &base) ? 1 : 0;
	fprintf(stderr, "unknown scenario: %s\n", argv[2]);
	return 2;
}
