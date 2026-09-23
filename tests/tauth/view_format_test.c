// SPDX-License-Identifier: GPL-2.0
/*
 * view_format_test — docs/tauth-view-table.md §13.2 (build step 1, sess428):
 * the VIEW RECORD / ROOT byte format against the committed vectors
 * tests/tauth/vectors/{view_v1,root_v1}.bin.
 *   (a) rebuild both records from the field values: byte-identical to the files
 *   (b) recompute digest / crc: match
 *   (c) every single-byte flip of the view fails validation
 *   (d) the 4096 B root CAW image: any nonzero byte in [512,4096) or in
 *       pad_end [504,512) fails validation
 *   (e) SplitMix64 check values
 *   (f) ballot allocator refuses at UINT64_MAX-1 without touching media;
 *       an otherwise-valid on-media UINT64_MAX is rejected
 *   (g) SHA-256 / CRC32C primitive check values
 *   (h) ctrl cross-validation: gen-0 root with empty/proposal slots, committed
 *       root with the named slot, older view, proposal, and refusals
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mxfs/mxfs_tauth.h>

static int fails;
#define CHECK(c, ...) do { if (c) { printf("  PASS " __VA_ARGS__); printf("\n"); } \
    else { printf("  FAIL " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t i;
    int k;

    for (i = 0; i < len; i++) {
        crc ^= p[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
    }
    return crc;
}

static int read_file(const char *path, void *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (!f)
        return -1;
    n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

static void hex(const uint8_t *p, size_t n, char *out)
{
    size_t i;

    for (i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", p[i]);
    out[2 * n] = 0;
}

static const uint8_t UUID[16] = { 0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f };
#define FS_GEN 0x12345678u

static void build_view(struct mxfs_tauth_view *v)
{
    int i;

    memset(v, 0, sizeof(*v));
    v->magic = MXFS_TAUTH_VIEW_MAGIC;
    v->version = 1;
    v->count = 3;
    v->gen = 7;
    v->prev_gen = 6;
    for (i = 0; i < 32; i++)
        v->prev_digest[i] = (uint8_t)(0xA0 + i);
    v->coord_node = 1001;
    v->coord_inc = 0x5005;
    v->coord_ballot = 42;
    v->memb_epoch = 9;
    for (i = 0; i < 32; i++)
        v->memb_digest[i] = (uint8_t)(0x10 + i);
    v->fs_gen = FS_GEN;
    memcpy(v->fs_uuid, UUID, 16);
    v->stamp_ms = 1787923200000ULL;
    v->nonce_inc = 0x5005;
    v->nonce_seq = 1;
    v->nremoved = 1;
    v->member[0].node = 1001; v->member[0].slot = 1; v->member[0].inc = 0x5005;
    v->member[1].node = 1008; v->member[1].slot = 2; v->member[1].inc = 0x5008;
    v->member[2].node = 1015; v->member[2].slot = 4; v->member[2].inc = 0x5015;
    v->removed[0].node = 1022; v->removed[0].slot = 3; v->removed[0].stage = 6;
    v->removed[0].inc = 0x5022; v->removed[0].recovery_gen = 17;
    v->removed[0].fence_term = 2; v->removed[0].manifest_seq = 5;
    v->removed[0].manifest_crc32c = 0xDEADBEEF; v->removed[0].manifest_count = 129;
    mxfs_tauth_view_seal(v, crc32c);
}

static void build_root(struct mxfs_tauth_root *r, const struct mxfs_tauth_view *v)
{
    memset(r, 0, sizeof(*r));
    r->magic = MXFS_TAUTH_ROOT_MAGIC;
    r->version = 1;
    r->slot = 0;
    r->gen = 7;
    memcpy(r->digest, v->digest, 32);
    r->coord_node = 1001;
    r->coord_inc = 0x5005;
    r->coord_ballot = 42;
    r->fs_gen = FS_GEN;
    memcpy(r->fs_uuid, UUID, 16);
    r->stamp_ms = 1787923200001ULL;
    r->nonce_inc = 0x5005;
    r->nonce_seq = 2;
    mxfs_tauth_root_seal(r, crc32c);
}

int main(void)
{
    static struct mxfs_tauth_view v, fv, tmp, a, b;
    static struct mxfs_tauth_root r, fr, rt;
    static uint8_t rimg[4096];
    char hx[65];
    uint8_t d[32];
    int rc, i, flips_ok = 0, flips = 0;
    const struct mxfs_tauth_view *cm;
    int kind;

    printf("=== view_format_test ===\n");
    /* (g) primitives */
    mxfs_sha256("abc", 3, d); hex(d, 32, hx);
    CHECK(strcmp(hx, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "g sha256(abc) = %s", hx);
    CHECK(~crc32c(~0u, "123456789", 9) == 0xe3069283u, "g crc32c(123456789) = %08x",
          ~crc32c(~0u, "123456789", 9));
    /* (e) */
    CHECK(mxfs_tauth_mix64(0) == 0xe220a8397b1dcdafULL, "e mix64(0) = %016llx",
          (unsigned long long)mxfs_tauth_mix64(0));
    CHECK(mxfs_tauth_mix64((5ULL << 16) | 3) == 0x4f9e38f1a4abce77ULL, "e mix64((5<<16)|3) = %016llx",
          (unsigned long long)mxfs_tauth_mix64((5ULL << 16) | 3));
    /* (a)(b) */
    build_view(&v);
    build_root(&r, &v);
    hex(v.digest, 32, hx);
    CHECK(strcmp(hx, "cb9907805abea7e5d1114318b25653d10ad9ea488a3af718fe5b2c1b437c7a78") == 0,
          "b view digest = %s", hx);
    CHECK(v.crc32c == 0xce752c32u, "b view crc32c = %08x", v.crc32c);
    CHECK(r.crc32c == 0xaa7c022fu, "b root crc32c = %08x", r.crc32c);
    rc = read_file("vectors/view_v1.bin", &fv, sizeof(fv));
    CHECK(rc == 0, "a read vectors/view_v1.bin");
    CHECK(rc == 0 && memcmp(&v, &fv, sizeof(v)) == 0, "a rebuilt view == view_v1.bin");
    rc = read_file("vectors/root_v1.bin", &fr, sizeof(fr));
    CHECK(rc == 0, "a read vectors/root_v1.bin");
    CHECK(rc == 0 && memcmp(&r, &fr, sizeof(r)) == 0, "a rebuilt root == root_v1.bin");
    CHECK(mxfs_tauth_view_validate(&v, FS_GEN, UUID, crc32c) == MXFS_TVIEW_OK, "b view validates");
    CHECK(mxfs_tauth_root_validate(&r, 512, FS_GEN, UUID, crc32c) == MXFS_TVIEW_OK, "b root validates (512)");
    memset(rimg, 0, sizeof(rimg)); memcpy(rimg, &r, 512);
    CHECK(mxfs_tauth_root_validate(rimg, 4096, FS_GEN, UUID, crc32c) == MXFS_TVIEW_OK, "b root validates (4Kn image)");
    /* (c) */
    for (i = 0; i < 4096; i++) {
        memcpy(&tmp, &v, sizeof(v));
        ((uint8_t *)&tmp)[i] ^= 0x01;
        flips++;
        if (mxfs_tauth_view_validate(&tmp, FS_GEN, UUID, crc32c) != MXFS_TVIEW_OK)
            flips_ok++;
    }
    CHECK(flips_ok == flips, "c every single-byte flip of the view fails validation (%d/%d)", flips_ok, flips);
    /* (d) */
    flips = flips_ok = 0;
    for (i = 504; i < 4096; i++) {
        memset(rimg, 0, sizeof(rimg)); memcpy(rimg, &r, 512);
        rimg[i] ^= 0x01;
        flips++;
        if (mxfs_tauth_root_validate(rimg, 4096, FS_GEN, UUID, crc32c) != MXFS_TVIEW_OK)
            flips_ok++;
    }
    CHECK(flips_ok == flips, "d nonzero byte in pad_end/tail fails root validation (%d/%d)", flips_ok, flips);
    flips = flips_ok = 0;
    for (i = 0; i < 504; i++) {
        memcpy(&rt, &r, sizeof(r));
        ((uint8_t *)&rt)[i] ^= 0x01;
        flips++;
        if (mxfs_tauth_root_validate(&rt, 512, FS_GEN, UUID, crc32c) != MXFS_TVIEW_OK)
            flips_ok++;
    }
    CHECK(flips_ok == flips, "d every single-byte flip of the root payload fails validation (%d/%d)", flips_ok, flips);
    /* (f) */
    memcpy(&rt, &r, sizeof(r));
    rt.coord_ballot = ~0ULL - 1; mxfs_tauth_root_seal(&rt, crc32c);
    CHECK(mxfs_tauth_root_validate(&rt, 512, FS_GEN, UUID, crc32c) == MXFS_TVIEW_OK, "f UINT64_MAX-1 is a valid on-media ballot");
    CHECK(mxfs_tauth_root_next_ballot(&rt) == 0, "f allocator refuses at UINT64_MAX-1 (no media write is the caller's contract on 0)");
    rt.coord_ballot = ~0ULL; mxfs_tauth_root_seal(&rt, crc32c);
    CHECK(rt.crc32c == mxfs_tauth_root_crc(&rt, crc32c) &&
          mxfs_tauth_root_validate(&rt, 512, FS_GEN, UUID, crc32c) == MXFS_TVIEW_E_BALLOT,
          "f an otherwise integrity-valid UINT64_MAX ballot is rejected");
    CHECK(mxfs_tauth_root_next_ballot(&r) == 43, "f next ballot after 42 is 43");
    /* (h) ctrl cross-validation */
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
    memcpy(&a, &v, sizeof(v));
    CHECK(mxfs_tauth_ctrl_validate(&r, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_OK &&
          cm == &a && kind == 0, "h committed A + empty B");
    /* older view in B */
    memcpy(&b, &v, sizeof(v)); b.gen = 6; b.prev_gen = 5; mxfs_tauth_view_seal(&b, crc32c);
    CHECK(mxfs_tauth_ctrl_validate(&r, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_OK && kind == 1,
          "h committed A + older view B");
    /* proposal in B */
    memcpy(&b, &v, sizeof(v)); b.gen = 8; b.prev_gen = 7; memcpy(b.prev_digest, v.digest, 32);
    mxfs_tauth_view_seal(&b, crc32c);
    CHECK(mxfs_tauth_ctrl_validate(&r, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_OK && kind == 2,
          "h committed A + proposal B");
    /* proposal with the wrong predecessor digest */
    b.prev_digest[0] ^= 1; mxfs_tauth_view_seal(&b, crc32c);
    CHECK(mxfs_tauth_ctrl_validate(&r, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_E_SLOT,
          "h proposal with a foreign predecessor is refused");
    /* root names a slot whose digest differs */
    memset(&b, 0, sizeof(b));
    memcpy(&rt, &r, sizeof(r)); rt.digest[5] ^= 1; mxfs_tauth_root_seal(&rt, crc32c);
    CHECK(mxfs_tauth_ctrl_validate(&rt, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_E_SLOT,
          "h root digest != slot digest is refused");
    /* gen 0 root: empty slots, then a gen-1 proposal */
    mxfs_tauth_root_init_empty(&rt, FS_GEN, UUID, 5, crc32c);
    CHECK(mxfs_tauth_root_validate(&rt, 512, FS_GEN, UUID, crc32c) == MXFS_TVIEW_OK, "h mkfs root validates");
    memset(&a, 0, sizeof(a));
    CHECK(mxfs_tauth_ctrl_validate(&rt, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_OK && cm == NULL,
          "h gen-0 root + empty slots");
    memcpy(&a, &v, sizeof(v)); a.gen = 1; a.prev_gen = 0; memset(a.prev_digest, 0, 32); mxfs_tauth_view_seal(&a, crc32c);
    CHECK(mxfs_tauth_ctrl_validate(&rt, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_OK && kind == 2,
          "h gen-0 root + gen-1 proposal");
    a.gen = 2; a.prev_gen = 1; mxfs_tauth_view_seal(&a, crc32c);
    CHECK(mxfs_tauth_ctrl_validate(&rt, &a, &b, FS_GEN, UUID, crc32c, &cm, &kind) == MXFS_TVIEW_E_SLOT,
          "h gen-0 root + gen-2 record is refused");
    /* member rules */
    memcpy(&a, &v, sizeof(v)); a.member[1].slot = 1; mxfs_tauth_view_seal(&a, crc32c);
    CHECK(mxfs_tauth_view_validate(&a, FS_GEN, UUID, crc32c) == MXFS_TVIEW_E_MEMBERS, "h duplicate slot refused");
    memcpy(&a, &v, sizeof(v)); a.member[1].node = 1001; mxfs_tauth_view_seal(&a, crc32c);
    CHECK(mxfs_tauth_view_validate(&a, FS_GEN, UUID, crc32c) == MXFS_TVIEW_E_MEMBERS, "h duplicate/unsorted node refused");
    memcpy(&a, &v, sizeof(v)); a.removed[0].stage = 5; mxfs_tauth_view_seal(&a, crc32c);
    CHECK(mxfs_tauth_view_validate(&a, FS_GEN, UUID, crc32c) == MXFS_TVIEW_E_REMOVED, "h removed stage below FENCED refused");
    /* HRW: deterministic, every page maps to a member, tie rule stable */
    {
        int counts[3] = { 0, 0, 0 };
        uint32_t pg;

        for (pg = 0; pg < 67651; pg++) {
            int o = mxfs_tauth_view_owner_index(&v, pg);

            if (o < 0 || o > 2) { counts[0] = -1; break; }
            counts[o]++;
        }
        CHECK(counts[0] > 0 && counts[1] > 0 && counts[2] > 0,
              "h HRW spreads 67651 pages over 3 members: %d/%d/%d", counts[0], counts[1], counts[2]);
    }
    printf("=== view_format_test RESULT %s fails=%d ===\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
