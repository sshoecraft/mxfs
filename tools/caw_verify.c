/*
 * caw_verify — verify SCSI COMPARE AND WRITE (opcode 0x89) cross-initiator
 * persistence on a multi-initiator iSCSI/LIO stack.
 *
 * Sess24 finding: MXFS DLM CAW slot writes succeed locally on the writing
 * initiator (verify-read sees what was written) but the same FUA-read from
 * a peer initiator returns stale or empty content.  This test isolates that
 * behavior from the rest of MXFS.
 *
 * Usage on two nodes T1 and T2 sharing /dev/sda (or another device):
 *
 *   T1: ./caw_verify write /dev/sda <lba_512> <pattern_byte>
 *        - Reads LBA via SCSI READ(16) FUA.
 *        - Issues SCSI COMPARE AND WRITE (opcode 0x89) with FUA:
 *            compare = current content, write = 512 bytes of <pattern_byte>.
 *        - Re-reads LBA via SCSI READ(16) FUA.  Reports whether the disk
 *          content matches what we wrote.
 *
 *   T2: ./caw_verify read  /dev/sda <lba_512> [expected_byte]
 *        - Reads LBA via SCSI READ(16) FUA.
 *        - If [expected_byte] is given, reports match/mismatch.
 *
 * If CAW works cross-initiator, T2's read after T1's write should see
 * the pattern byte uniformly.  If T2 sees something else, the LIO target
 * is not propagating CAW writes to other initiators despite FUA semantics.
 *
 * Pick an LBA outside any filesystem to avoid corruption.
 *
 * Copyright (c) 2026
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
#include <scsi/sg.h>

#define SECTOR_SIZE 512
#define TIMEOUT_MS  30000
#define UA_MAX_RETRY 6           /* bounded retries on UNIT ATTENTION */

/* --retry-ua: retry a command that returns UNIT ATTENTION (sense key 0x06).
 * A UA (e.g. ASC 0x29 power-on/reset) is a transient "state changed, reissue"
 * condition — the FIRST command down a dm-multipath path after (re)selection
 * gets one.  A correct SG_IO issuer retries; without this, a lone UA looks like
 * a hard CAW failure.  Off by default (single-path behaviour unchanged). */
static int g_retry_ua = 0;

static int do_scsi_io(int fd, unsigned char *cdb, int cdb_len,
                      void *buf, int len, int dxfer_dir, int *miscompare)
{
    sg_io_hdr_t hdr;
    unsigned char sense[64];
    int attempt;

    for (attempt = 0; ; attempt++) {
        memset(&hdr, 0, sizeof(hdr));
        memset(sense, 0, sizeof(sense));
        if (miscompare)
            *miscompare = 0;

        hdr.interface_id = 'S';
        hdr.cmd_len = cdb_len;
        hdr.cmdp = cdb;
        hdr.dxferp = buf;
        hdr.dxfer_len = len;
        hdr.dxfer_direction = dxfer_dir;
        hdr.sbp = sense;
        hdr.mx_sb_len = sizeof(sense);
        hdr.timeout = TIMEOUT_MS;

        if (ioctl(fd, SG_IO, &hdr) < 0) {
            fprintf(stderr, "SG_IO ioctl failed: %s\n", strerror(errno));
            return -1;
        }
        if (hdr.status != 0 || hdr.host_status != 0 || hdr.driver_status != 0) {
            /* MISCOMPARE sense key = 0x0E */
            if (hdr.sb_len_wr > 2 && (sense[2] & 0x0F) == 0x0E) {
                if (miscompare)
                    *miscompare = 1;
                return 0;
            }
            /* UNIT ATTENTION sense key = 0x06 — transient; retry if enabled */
            if (g_retry_ua && attempt < UA_MAX_RETRY &&
                hdr.sb_len_wr > 2 && (sense[2] & 0x0F) == 0x06) {
                fprintf(stderr, "UNIT ATTENTION (key 0x06) — retry %d/%d\n",
                        attempt + 1, UA_MAX_RETRY);
                usleep(200000);
                continue;
            }
            fprintf(stderr,
                    "SG_IO bad status: scsi=%d host=%d driver=%d sense_len=%d\n",
                    hdr.status, hdr.host_status, hdr.driver_status, hdr.sb_len_wr);
            if (hdr.sb_len_wr > 0) {
                fprintf(stderr, "sense:");
                for (int i = 0; i < hdr.sb_len_wr; i++)
                    fprintf(stderr, " %02x", sense[i]);
                fprintf(stderr, "\n");
            }
            return -1;
        }
        return 0;
    }
}

static int scsi_read16_fua(int fd, uint64_t lba, void *buf, uint32_t blocks)
{
    unsigned char cdb[16] = {0};
    cdb[0]  = 0x88;                  /* READ(16) */
    cdb[1]  = 0x08;                  /* FUA */
    cdb[2]  = (uint8_t)(lba >> 56);
    cdb[3]  = (uint8_t)(lba >> 48);
    cdb[4]  = (uint8_t)(lba >> 40);
    cdb[5]  = (uint8_t)(lba >> 32);
    cdb[6]  = (uint8_t)(lba >> 24);
    cdb[7]  = (uint8_t)(lba >> 16);
    cdb[8]  = (uint8_t)(lba >> 8);
    cdb[9]  = (uint8_t)(lba);
    cdb[10] = (uint8_t)(blocks >> 24);
    cdb[11] = (uint8_t)(blocks >> 16);
    cdb[12] = (uint8_t)(blocks >> 8);
    cdb[13] = (uint8_t)(blocks);
    return do_scsi_io(fd, cdb, sizeof(cdb), buf,
                      blocks * SECTOR_SIZE, SG_DXFER_FROM_DEV, NULL);
}

/* Compare buf is sectors[0..n), write buf is sectors[n..2n). */
static int scsi_compare_and_write(int fd, uint64_t lba,
                                  void *cmp_buf, void *write_buf,
                                  int *miscompare)
{
    unsigned char cdb[16] = {0};
    unsigned char data[2 * SECTOR_SIZE];
    cdb[0]  = 0x89;                  /* COMPARE AND WRITE */
    cdb[1]  = 0x08;                  /* FUA */
    cdb[2]  = (uint8_t)(lba >> 56);
    cdb[3]  = (uint8_t)(lba >> 48);
    cdb[4]  = (uint8_t)(lba >> 40);
    cdb[5]  = (uint8_t)(lba >> 32);
    cdb[6]  = (uint8_t)(lba >> 24);
    cdb[7]  = (uint8_t)(lba >> 16);
    cdb[8]  = (uint8_t)(lba >> 8);
    cdb[9]  = (uint8_t)(lba);
    cdb[13] = 0x01;                  /* number of logical blocks = 1 */
    memcpy(data, cmp_buf, SECTOR_SIZE);
    memcpy(data + SECTOR_SIZE, write_buf, SECTOR_SIZE);
    return do_scsi_io(fd, cdb, sizeof(cdb), data, sizeof(data),
                      SG_DXFER_TO_DEV, miscompare);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s [--retry-ua] write <device> <lba_512> <pattern_byte_hex>\n"
            "  %s [--retry-ua] read  <device> <lba_512> [expected_byte_hex]\n"
            "\n"
            "  pattern_byte_hex / expected_byte_hex: 00..ff\n"
            "  --retry-ua: retry on UNIT ATTENTION (needed on dm-multipath)\n",
            prog, prog);
    exit(2);
}

int main(int argc, char **argv)
{
    /* pull the optional --retry-ua flag out of argv, keep positional parsing */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--retry-ua") == 0) {
            g_retry_ua = 1;
            for (int j = i; j < argc - 1; j++)
                argv[j] = argv[j + 1];
            argc--;
            i--;
        }
    }

    if (argc < 4)
        usage(argv[0]);

    const char *mode = argv[1];
    const char *path = argv[2];
    uint64_t lba = strtoull(argv[3], NULL, 0);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return 1;
    }

    if (strcmp(mode, "write") == 0) {
        if (argc < 5)
            usage(argv[0]);
        unsigned int pat = strtoul(argv[4], NULL, 16) & 0xff;
        unsigned char cur[SECTOR_SIZE];
        unsigned char want[SECTOR_SIZE];
        unsigned char got[SECTOR_SIZE];

        printf("[write] LBA=%llu pattern=0x%02x\n",
               (unsigned long long)lba, pat);

        if (scsi_read16_fua(fd, lba, cur, 1) < 0) {
            fprintf(stderr, "pre-read failed\n");
            return 1;
        }
        printf("[write] pre-read first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
               cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7]);

        memset(want, pat, SECTOR_SIZE);
        int miscompare = 0;
        if (scsi_compare_and_write(fd, lba, cur, want, &miscompare) < 0) {
            fprintf(stderr, "CAW failed\n");
            return 1;
        }
        if (miscompare) {
            fprintf(stderr, "CAW MISCOMPARE — disk content changed during pre-read+CAW\n");
            return 1;
        }
        printf("[write] CAW success\n");

        if (scsi_read16_fua(fd, lba, got, 1) < 0) {
            fprintf(stderr, "post-read failed\n");
            return 1;
        }
        printf("[write] post-read first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
               got[0], got[1], got[2], got[3], got[4], got[5], got[6], got[7]);

        int match = 1;
        for (int i = 0; i < SECTOR_SIZE; i++) {
            if (got[i] != pat) {
                match = 0;
                break;
            }
        }
        if (match)
            printf("[write] OK: post-read matches written pattern\n");
        else
            printf("[write] LOCAL DIVERGENCE: post-read != written pattern\n");
        return match ? 0 : 1;
    }

    if (strcmp(mode, "read") == 0) {
        unsigned char buf[SECTOR_SIZE];
        if (scsi_read16_fua(fd, lba, buf, 1) < 0) {
            fprintf(stderr, "read failed\n");
            return 1;
        }
        printf("[read] LBA=%llu first 16 bytes:",
               (unsigned long long)lba);
        for (int i = 0; i < 16; i++)
            printf(" %02x", buf[i]);
        printf("\n");

        if (argc >= 5) {
            unsigned int expect = strtoul(argv[4], NULL, 16) & 0xff;
            int match = 1;
            for (int i = 0; i < SECTOR_SIZE; i++) {
                if (buf[i] != expect) {
                    match = 0;
                    break;
                }
            }
            if (match)
                printf("[read] OK: matches expected 0x%02x\n", expect);
            else
                printf("[read] CROSS-INITIATOR DIVERGENCE: expected 0x%02x not found uniformly\n",
                       expect);
            return match ? 0 : 1;
        }
        return 0;
    }

    usage(argv[0]);
    return 2;
}
