/*
 * fua_verify — synthetic verification of SCSI READ(16)/WRITE(16) FUA
 * semantics on a multi-initiator iSCSI/LIO stack.
 *
 * Sess21/sess22 hypothesis: even with the FUA bit set in READ(16) CDB,
 * the iSCSI/LIO target may serve from a per-initiator read cache that
 * does not see another initiator's prior FUA writes.  This test proves
 * or disproves that.
 *
 * Usage on two nodes T1 and T2, sharing /dev/sda:
 *
 *   T1: ./fua_verify write /dev/sda <lba_512> <byte_pattern>
 *   T2: ./fua_verify read  /dev/sda <lba_512>
 *
 * If FUA works, T2's read returns the written pattern.  If not,
 * T2 may see whatever was at <lba_512> previously (its own initiator
 * read cache, or the pre-write disk content).
 *
 * Pick a sector well outside any filesystem to avoid corruption.
 * 1 sector = 512 bytes.
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

static int do_scsi_io(int fd, unsigned char *cdb, int cdb_len,
                      void *buf, int len, int dxfer_dir)
{
    sg_io_hdr_t hdr;
    unsigned char sense[64];

    memset(&hdr, 0, sizeof(hdr));
    memset(sense, 0, sizeof(sense));
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

static int scsi_write16_fua(int fd, uint64_t lba, void *buf, uint32_t blocks)
{
    unsigned char cdb[16] = {0};
    cdb[0]  = 0x8A;                 /* WRITE(16) */
    cdb[1]  = 0x08;                 /* FUA bit set */
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
    return do_scsi_io(fd, cdb, sizeof(cdb), buf, blocks * SECTOR_SIZE,
                      SG_DXFER_TO_DEV);
}

static int scsi_read16_fua(int fd, uint64_t lba, void *buf, uint32_t blocks)
{
    unsigned char cdb[16] = {0};
    cdb[0]  = 0x88;                 /* READ(16) */
    cdb[1]  = 0x08;                 /* FUA bit set */
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
    return do_scsi_io(fd, cdb, sizeof(cdb), buf, blocks * SECTOR_SIZE,
                      SG_DXFER_FROM_DEV);
}

static int scsi_synchronize_cache16(int fd)
{
    unsigned char cdb[16] = {0};
    cdb[0] = 0x91;                  /* SYNCHRONIZE CACHE(16), ALL blocks */
    return do_scsi_io(fd, cdb, sizeof(cdb), NULL, 0, SG_DXFER_NONE);
}

int main(int argc, char **argv)
{
    if (argc < 4) {
usage:
        fprintf(stderr,
                "usage:\n"
                "  %s write <device> <lba_512> <byte_pattern_hex>\n"
                "  %s read  <device> <lba_512>\n"
                "  %s sync  <device>\n",
                argv[0], argv[0], argv[0]);
        return 2;
    }

    const char *op = argv[1];
    const char *dev = argv[2];
    int fd = open(dev, O_RDWR | O_DIRECT);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", dev, strerror(errno));
        return 1;
    }

    if (strcmp(op, "sync") == 0) {
        if (scsi_synchronize_cache16(fd) < 0) {
            close(fd);
            return 1;
        }
        printf("SYNCHRONIZE CACHE 16: OK\n");
        close(fd);
        return 0;
    }

    if (argc < 4)
        goto usage;
    uint64_t lba = strtoull(argv[3], NULL, 0);

    /* Use a 512-byte aligned buffer */
    void *buf;
    if (posix_memalign(&buf, 4096, SECTOR_SIZE) != 0) {
        close(fd);
        return 1;
    }

    if (strcmp(op, "write") == 0) {
        if (argc < 5) goto usage;
        int pattern = strtol(argv[4], NULL, 0);
        memset(buf, pattern & 0xff, SECTOR_SIZE);
        /* Stamp a header so we can identify ours */
        snprintf((char *)buf, 64, "FUATEST pattern=0x%02x lba=%llu pid=%d\n",
                 pattern & 0xff, (unsigned long long)lba, getpid());
        if (scsi_write16_fua(fd, lba, buf, 1) < 0) {
            free(buf);
            close(fd);
            return 1;
        }
        printf("WRITE(16) FUA: lba=%llu pattern=0x%02x OK\n",
               (unsigned long long)lba, pattern & 0xff);
    } else if (strcmp(op, "read") == 0) {
        memset(buf, 0xCC, SECTOR_SIZE);
        if (scsi_read16_fua(fd, lba, buf, 1) < 0) {
            free(buf);
            close(fd);
            return 1;
        }
        printf("READ(16) FUA: lba=%llu first_64=\"", (unsigned long long)lba);
        char *s = buf;
        for (int i = 0; i < 64 && s[i] && s[i] != '\n'; i++)
            putchar(s[i]);
        printf("\"\nfirst_byte=0x%02x byte_at_64=0x%02x byte_at_511=0x%02x\n",
               ((unsigned char *)buf)[0], ((unsigned char *)buf)[64],
               ((unsigned char *)buf)[511]);
    } else {
        goto usage;
    }

    free(buf);
    close(fd);
    return 0;
}
