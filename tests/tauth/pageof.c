// SPDX-License-Identifier: GPL-2.0
/*
 * pageof — print the TCP authority-ledger page and slot of a resource, so a
 * rig P-line naming {type, ino, ag} can be joined to the P-TAUTH-* page
 * lines of the fleet sweep (D-0345 forensics).
 *
 *   pageof <type> <ino> <ag> [npages] [seed]   type: 1 inode, 3 AG
 *
 * (D-0348 step 2): routing is per-region — pass the region's page
 * count and hash seed (chk_mxfs -v prints both); defaults = the minimum
 * geometry with seed 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mxfs/mxfs_dlm.h"
#include "mxfs/mxfs_tauth.h"
#include "dlm/tauth_ledger.h"

int main(int argc, char **argv)
{
    struct mxfs_resource_id r;

    uint32_t npages = MXFS_TAUTH_NPAGES, hash;
    uint64_t seed = 0;

    if (argc < 4 || argc > 6) {
        fprintf(stderr, "usage: pageof <type> <ino> <ag> [npages] [seed]\n");
        return 2;
    }
    memset(&r, 0, sizeof(r));
    r.type = (uint8_t)atoi(argv[1]);
    r.ino = strtoull(argv[2], NULL, 0);
    r.ag_number = (uint32_t)atoi(argv[3]);
    if (argc > 4)
        npages = (uint32_t)strtoul(argv[4], NULL, 0);
    if (argc > 5)
        seed = strtoull(argv[5], NULL, 0);
    hash = mxfs_tauth_res_hash(&r, sizeof(r), seed);
    printf("type=%u ino=%llu ag=%u npages=%u seed=%016llx hash=%08x page=%u home=%u\n",
           r.type, (unsigned long long)r.ino, r.ag_number, npages,
           (unsigned long long)seed, hash,
           mxfs_tauth_home_page(hash, npages), mxfs_tauth_home_index(hash, npages));
    return 0;
}
