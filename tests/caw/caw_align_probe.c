/*
 * caw_align_probe — establish whether SCSI COMPARE AND WRITE (0x89) data-out
 * corruption on qemu scsi-block passthrough rigs is a function of the USER
 * BUFFER'S PAGE OFFSET (i.e. whether the 1024-byte compare+write payload is
 * mapped as one physical segment or split across a page boundary).
 *
 * Found 2026-07-26 (ccloop c7ee71c6 sess11): on the LIO/tcm_loop rig, CAW
 * from some VMs wrote qemu-heap garbage or a zero tail as the write half
 * while sibling VMs wrote correctly; plain WRITE(16)/READ(16) always fine.
 * This probe sweeps the payload page offset to prove/disprove the
 * multi-segment trigger.
 *
 * Usage: caw_align_probe <device> <lba_512> <page_offset> <pattern_hex>
 *   page_offset 0..4095: byte offset of the 1024B payload inside a 2-page
 *   anonymous mapping.  3584 forces a 512/512 split on 4K pages; 3600 forces
 *   a misaligned split (guest kernel will bounce); 0 is single-segment.
 * Exit 0 = post-read uniformly pattern; 1 = divergence (prints detail).
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <scsi/sg.h>

#define SECTOR 512

static int sgio(int fd, unsigned char *cdb, int cdb_len, void *buf, int len,
                int dir, int *miscompare)
{
    sg_io_hdr_t h;
    unsigned char sense[64];

    memset(&h, 0, sizeof(h));
    memset(sense, 0, sizeof(sense));
    if (miscompare)
        *miscompare = 0;
    h.interface_id = 'S';
    h.cmd_len = cdb_len;
    h.cmdp = cdb;
    h.dxferp = buf;
    h.dxfer_len = len;
    h.dxfer_direction = dir;
    h.sbp = sense;
    h.mx_sb_len = sizeof(sense);
    h.timeout = 30000;
    if (ioctl(fd, SG_IO, &h) < 0) {
        fprintf(stderr, "SG_IO: %s\n", strerror(errno));
        return -1;
    }
    if (h.status || h.host_status || h.driver_status) {
        if (h.sb_len_wr > 2 && (sense[2] & 0x0F) == 0x0E) {
            if (miscompare)
                *miscompare = 1;
            return 0;
        }
        fprintf(stderr, "SG_IO status scsi=%d host=%d driver=%d sense:",
                h.status, h.host_status, h.driver_status);
        for (int i = 0; i < h.sb_len_wr; i++)
            fprintf(stderr, " %02x", sense[i]);
        fprintf(stderr, "\n");
        return -1;
    }
    return 0;
}

static int read16_fua(int fd, uint64_t lba, void *buf)
{
    unsigned char cdb[16] = {0};

    cdb[0] = 0x88;
    cdb[1] = 0x08;
    for (int i = 0; i < 8; i++)
        cdb[2 + i] = (uint8_t)(lba >> (8 * (7 - i)));
    cdb[13] = 1;
    return sgio(fd, cdb, 16, buf, SECTOR, SG_DXFER_FROM_DEV, NULL);
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <device> <lba_512> <page_offset 0..4095> <pattern_hex>\n",
                argv[0]);
        return 2;
    }
    const char *dev = argv[1];
    uint64_t lba = strtoull(argv[2], NULL, 0);
    unsigned off = strtoul(argv[3], NULL, 0) & 4095;
    unsigned pat = strtoul(argv[4], NULL, 16) & 0xff;

    int fd = open(dev, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", dev, strerror(errno));
        return 2;
    }

    unsigned char cur[SECTOR];
    if (read16_fua(fd, lba, cur) < 0)
        return 2;

    long pg = sysconf(_SC_PAGESIZE);
    unsigned char *map = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return 2;
    }
    unsigned char *payload = map + off;
    memcpy(payload, cur, SECTOR);
    memset(payload + SECTOR, pat, SECTOR);

    unsigned char cdb[16] = {0};
    cdb[0] = 0x89;                    /* COMPARE AND WRITE, FUA */
    cdb[1] = 0x08;
    for (int i = 0; i < 8; i++)
        cdb[2 + i] = (uint8_t)(lba >> (8 * (7 - i)));
    cdb[13] = 1;
    int mc = 0;
    if (sgio(fd, cdb, 16, payload, 2 * SECTOR, SG_DXFER_TO_DEV, &mc) < 0) {
        printf("PROBE off=%u pat=%02x CAW-ERROR\n", off, pat);
        return 2;
    }
    if (mc) {
        printf("PROBE off=%u pat=%02x MISCOMPARE (racer changed sector)\n",
               off, pat);
        return 2;
    }

    unsigned char got[SECTOR];
    if (read16_fua(fd, lba, got) < 0)
        return 2;

    int good = 0, zero = 0, other = 0, first_bad = -1;
    for (int i = 0; i < SECTOR; i++) {
        if (got[i] == pat) {
            good++;
        } else {
            if (first_bad < 0)
                first_bad = i;
            if (got[i] == 0)
                zero++;
            else
                other++;
        }
    }
    if (good == SECTOR) {
        printf("PROBE off=%u pat=%02x OK (512/512 pattern)\n", off, pat);
        return 0;
    }
    printf("PROBE off=%u pat=%02x CORRUPT good=%d zero=%d other=%d first_bad=%d "
           "bytes@bad: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           off, pat, good, zero, other, first_bad,
           got[first_bad < 504 ? first_bad + 0 : 504],
           got[first_bad < 504 ? first_bad + 1 : 505],
           got[first_bad < 504 ? first_bad + 2 : 506],
           got[first_bad < 504 ? first_bad + 3 : 507],
           got[first_bad < 504 ? first_bad + 4 : 508],
           got[first_bad < 504 ? first_bad + 5 : 509],
           got[first_bad < 504 ? first_bad + 6 : 510],
           got[first_bad < 504 ? first_bad + 7 : 511]);
    return 1;
}
