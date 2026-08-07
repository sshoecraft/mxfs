/*
 * prprobe — SG_IO probe for the D-PR-FENCE-PREEMPT-WITHOUT-ABORT step-4
 * in-flight exclusion harness.
 *
 * Why this exists instead of sg_persist(8): the sess133 RULE-5 ruling requires
 * the harness to control sg_io_hdr.timeout itself (sg_persist 0.67 has no such
 * option, and the sysfs per-device timeout does NOT govern SG_IO), and to
 * report SCSI status, sense, host_status, driver_status, errno, residual and
 * duration so a run can be INVALIDATED rather than misread.  It also emits
 * CLOCK_MONOTONIC timestamps around every ioctl so userspace events sit on the
 * same timeline as ftrace with trace_clock=mono.
 *
 * All output is key=value on one line per event, prefixed with the subcommand,
 * so the shell harness can parse it without regex fragility.
 *
 * Subcommands:
 *   prout   <dev> <sa_hex> <rk_hex> <sark_hex> <type> [timeout_ms] [aptpl]
 *   prin    <dev> <sa_hex> [alloc_len]
 *   write   <dev> <lba> <nblocks> <pattern_byte> [timeout_ms] [blocksize]
 *   poll    <dev> <byteoff> <len> <pattern_byte> <duration_ms> <interval_ms>
 *   dwrite  <dev> <byteoff> <len> <pattern_byte>
 *   dread   <dev> <byteoff> <len>
 *   fiemap  <file> <byteoff> <len>
 *
 * PROUT service actions: 00 REGISTER, 01 RESERVE, 02 RELEASE, 03 CLEAR,
 *                        04 PREEMPT, 05 PREEMPT AND ABORT, 06 REGISTER-IGNORE.
 * PRIN  service actions: 00 READ KEYS, 01 READ RESERVATION,
 *                        02 REPORT CAPABILITIES, 03 READ FULL STATUS.
 * Type 5 = Write Exclusive - Registrants Only (what MXFS's fence takes).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

#define SENSE_LEN 64

static double mono(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void put_be64(uint8_t *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static uint64_t get_be64(const uint8_t *p)
{
	uint64_t v = 0; int i;
	for (i = 0; i < 8; i++) v = (v << 8) | p[i];
	return v;
}

static uint32_t get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

/* Print the full outcome of one SG_IO, in the shape the validity predicate
 * needs.  Returns 0 only for an unambiguous GOOD status. */
static int report(const char *tag, struct sg_io_hdr *io, int rc, int saved_errno,
		  double t0, double t1, const uint8_t *sense)
{
	int i, good;

	good = (rc == 0 && io->status == 0 && io->host_status == 0 &&
		io->driver_status == 0);

	printf("%s t_submit=%.6f t_return=%.6f dur_ms=%.3f rc=%d errno=%d(%s) "
	       "scsi_status=0x%02x host_status=0x%02x driver_status=0x%02x "
	       "resid=%d sb_len=%u duration_ms=%u good=%d",
	       tag, t0, t1, (t1 - t0) * 1000.0, rc, saved_errno,
	       rc ? strerror(saved_errno) : "-",
	       io->status, io->host_status, io->driver_status,
	       io->resid, io->sb_len_wr, io->duration, good);

	if (io->status == 0x18)
		printf(" RESERVATION_CONFLICT=1");
	if (io->status == 0x02 && io->sb_len_wr >= 3) {
		unsigned sk, asc = 0, ascq = 0;
		if ((sense[0] & 0x7e) == 0x72) {          /* descriptor format */
			sk = sense[1] & 0x0f; asc = sense[2]; ascq = sense[3];
		} else {                                   /* fixed format */
			sk = sense[2] & 0x0f;
			if (io->sb_len_wr >= 14) { asc = sense[12]; ascq = sense[13]; }
		}
		printf(" sense_key=0x%x asc=0x%02x ascq=0x%02x", sk, asc, ascq);
	}
	if (io->sb_len_wr) {
		printf(" sense_hex=");
		for (i = 0; i < io->sb_len_wr && i < SENSE_LEN; i++)
			printf("%02x", sense[i]);
	}
	printf("\n");
	fflush(stdout);
	return good ? 0 : 1;
}

static int do_prout(int argc, char **argv)
{
	uint8_t cdb[10], parm[24], sense[SENSE_LEN];
	struct sg_io_hdr io;
	unsigned sa, type, aptpl = 0, tmo = 120000;
	uint64_t rk, sark;
	int fd, rc, se;
	double t0, t1;

	if (argc < 7) {
		fprintf(stderr, "usage: prprobe prout <dev> <sa_hex> <rk_hex> <sark_hex> <type> [timeout_ms] [aptpl]\n");
		return 2;
	}
	sa   = strtoul(argv[3], NULL, 16);
	rk   = strtoull(argv[4], NULL, 16);
	sark = strtoull(argv[5], NULL, 16);
	type = strtoul(argv[6], NULL, 0);
	if (argc > 7) tmo   = strtoul(argv[7], NULL, 0);
	if (argc > 8) aptpl = strtoul(argv[8], NULL, 0);

	fd = open(argv[2], O_RDWR);
	if (fd < 0) { fprintf(stderr, "open %s: %s\n", argv[2], strerror(errno)); return 2; }

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x5f;                       /* PERSISTENT RESERVE OUT */
	cdb[1] = sa & 0x1f;
	cdb[2] = ((0 & 0x0f) << 4) | (type & 0x0f);   /* scope 0 = LU_SCOPE */
	put_be32(&cdb[5], 24);               /* parameter list length */

	memset(parm, 0, sizeof(parm));
	put_be64(&parm[0],  rk);
	put_be64(&parm[8],  sark);
	parm[20] = aptpl ? 0x01 : 0x00;      /* bit0 APTPL */

	memset(&io, 0, sizeof(io));
	memset(sense, 0, sizeof(sense));
	io.interface_id    = 'S';
	io.dxfer_direction = SG_DXFER_TO_DEV;
	io.cmd_len         = sizeof(cdb);
	io.cmdp            = cdb;
	io.dxfer_len       = sizeof(parm);
	io.dxferp          = parm;
	io.sbp             = sense;
	io.mx_sb_len       = sizeof(sense);
	io.timeout         = tmo;

	printf("prout_issue dev=%s sa=0x%02x rk=0x%016llx sark=0x%016llx type=%u "
	       "aptpl=%u sgio_timeout_ms=%u t_pre=%.6f\n",
	       argv[2], sa, (unsigned long long)rk, (unsigned long long)sark,
	       type, aptpl, tmo, mono());
	fflush(stdout);

	t0 = mono();
	rc = ioctl(fd, SG_IO, &io);
	se = errno;
	t1 = mono();
	close(fd);
	return report("prout_done", &io, rc, se, t0, t1, sense);
}

static int do_prin(int argc, char **argv)
{
	uint8_t cdb[10], sense[SENSE_LEN];
	uint8_t *buf;
	struct sg_io_hdr io;
	unsigned sa, alloc = 8192;
	int fd, rc, se, ret;
	double t0, t1;

	if (argc < 4) {
		fprintf(stderr, "usage: prprobe prin <dev> <sa_hex> [alloc_len]\n");
		return 2;
	}
	sa = strtoul(argv[3], NULL, 16);
	if (argc > 4) alloc = strtoul(argv[4], NULL, 0);

	buf = calloc(1, alloc);
	if (!buf) return 2;

	fd = open(argv[2], O_RDWR);
	if (fd < 0) { fprintf(stderr, "open %s: %s\n", argv[2], strerror(errno)); free(buf); return 2; }

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x5e;                       /* PERSISTENT RESERVE IN */
	cdb[1] = sa & 0x1f;
	cdb[7] = (alloc >> 8) & 0xff;
	cdb[8] = alloc & 0xff;

	memset(&io, 0, sizeof(io));
	memset(sense, 0, sizeof(sense));
	io.interface_id    = 'S';
	io.dxfer_direction = SG_DXFER_FROM_DEV;
	io.cmd_len         = sizeof(cdb);
	io.cmdp            = cdb;
	io.dxfer_len       = alloc;
	io.dxferp          = buf;
	io.sbp             = sense;
	io.mx_sb_len       = sizeof(sense);
	io.timeout         = 60000;

	t0 = mono();
	rc = ioctl(fd, SG_IO, &io);
	se = errno;
	t1 = mono();

	ret = report("prin_done", &io, rc, se, t0, t1, sense);

	if (ret == 0) {
		uint32_t gen = get_be32(&buf[0]);
		uint32_t len = get_be32(&buf[4]);
		printf("prin_hdr dev=%s sa=0x%02x generation=%u addl_len=%u\n",
		       argv[2], sa, gen, len);
		if (sa == 0x00) {                       /* READ KEYS */
			uint32_t i, n = len / 8;
			printf("prin_keys count=%u", n);
			for (i = 0; i < n && (8 + i * 8 + 8) <= alloc; i++)
				printf(" k%u=0x%016llx", i,
				       (unsigned long long)get_be64(&buf[8 + i * 8]));
			printf("\n");
		} else if (sa == 0x01) {                /* READ RESERVATION */
			if (len >= 16)
				printf("prin_rsv key=0x%016llx scope=%u type=%u\n",
				       (unsigned long long)get_be64(&buf[8]),
				       (buf[21] >> 4) & 0x0f, buf[21] & 0x0f);
			else
				printf("prin_rsv none=1\n");
		} else if (sa == 0x02) {                /* REPORT CAPABILITIES */
			printf("prin_cap len=%u crh=%u sip_c=%u atp_c=%u ptpl_c=%u "
			       "tmv=%u ptpl_a=%u type_mask=0x%02x%02x\n",
			       (buf[0] << 8) | buf[1],
			       (buf[2] >> 4) & 1, (buf[2] >> 3) & 1, (buf[2] >> 2) & 1,
			       buf[2] & 1, (buf[3] >> 7) & 1, buf[3] & 1,
			       buf[4], buf[5]);
		} else if (sa == 0x03) {                /* READ FULL STATUS */
			uint32_t off = 8;
			int idx = 0;
			while (off + 24 <= 8 + len && off + 24 <= alloc) {
				uint64_t k = get_be64(&buf[off]);
				unsigned all_tg_pt = (buf[off + 12] >> 1) & 1;
				unsigned r_holder  = buf[off + 12] & 1;
				unsigned scope     = (buf[off + 13] >> 4) & 0x0f;
				unsigned type      = buf[off + 13] & 0x0f;
				uint16_t rtpi      = (buf[off + 18] << 8) | buf[off + 19];
				uint32_t adl       = get_be32(&buf[off + 20]);
				uint32_t tid_off   = off + 24;
				printf("prin_full i=%d key=0x%016llx all_tg_pt=%u holder=%u "
				       "scope=%u type=%u rel_tgt_port=%u tid_len=%u tid=",
				       idx, (unsigned long long)k, all_tg_pt, r_holder,
				       scope, type, rtpi, adl);
				/* TransportID: for iSCSI (protocol id 5) the name is
				 * ASCII starting at byte 4 of the descriptor. */
				if (adl && tid_off + adl <= alloc) {
					if ((buf[tid_off] & 0x0f) == 0x05 && adl > 4) {
						uint32_t j;
						for (j = 4; j < adl && buf[tid_off + j]; j++)
							putchar(buf[tid_off + j]);
					} else {
						uint32_t j;
						for (j = 0; j < adl; j++)
							printf("%02x", buf[tid_off + j]);
					}
				} else {
					printf("-");
				}
				printf("\n");
				off += 24 + adl;
				idx++;
			}
			printf("prin_full_count n=%d\n", idx);
		}
		fflush(stdout);
	}
	free(buf);
	close(fd);
	return ret;
}

/* Drain pending Unit Attentions on a nexus.  PROUT CLEAR/PREEMPT posts
 * RESERVATIONS PREEMPTED / REGISTRATIONS PREEMPTED to every other I_T nexus,
 * and the next command on that nexus returns CHECK CONDITION instead of doing
 * its job.  MXFS's own fence path keeps a UA-retry loop for exactly this
 * reason; the harness needs the same before it can trust a setup step. */
static int do_clearua(int argc, char **argv)
{
	uint8_t cdb[6], sense[SENSE_LEN];
	struct sg_io_hdr io;
	int fd, rc, tries = 8, i;

	if (argc < 3) {
		fprintf(stderr, "usage: prprobe clearua <dev> [tries]\n");
		return 2;
	}
	if (argc > 3) tries = atoi(argv[3]);

	fd = open(argv[2], O_RDWR);
	if (fd < 0) { fprintf(stderr, "open %s: %s\n", argv[2], strerror(errno)); return 2; }

	for (i = 0; i < tries; i++) {
		memset(cdb, 0, sizeof(cdb));      /* TEST UNIT READY */
		memset(&io, 0, sizeof(io));
		memset(sense, 0, sizeof(sense));
		io.interface_id    = 'S';
		io.dxfer_direction = SG_DXFER_NONE;
		io.cmd_len         = sizeof(cdb);
		io.cmdp            = cdb;
		io.sbp             = sense;
		io.mx_sb_len       = sizeof(sense);
		io.timeout         = 30000;

		rc = ioctl(fd, SG_IO, &io);
		if (rc == 0 && io.status == 0 && io.host_status == 0 &&
		    io.driver_status == 0) {
			printf("clearua dev=%s cleared_after=%d t=%.6f\n",
			       argv[2], i, mono());
			fflush(stdout);
			close(fd);
			return 0;
		}
		printf("clearua_pending dev=%s try=%d scsi_status=0x%02x\n",
		       argv[2], i, io.status);
		fflush(stdout);
	}
	printf("clearua dev=%s FAILED_TO_CLEAR tries=%d\n", argv[2], tries);
	fflush(stdout);
	close(fd);
	return 1;
}

static int do_write(int argc, char **argv)
{
	uint8_t cdb[16], sense[SENSE_LEN];
	uint8_t *buf;
	struct sg_io_hdr io;
	uint64_t lba;
	unsigned nblk, pat, tmo = 120000, bs = 512;
	size_t len;
	int fd, rc, se;
	double t0, t1;

	if (argc < 6) {
		fprintf(stderr, "usage: prprobe write <dev> <lba> <nblocks> <pattern_byte> [timeout_ms] [blocksize]\n");
		return 2;
	}
	lba  = strtoull(argv[3], NULL, 0);
	nblk = strtoul(argv[4], NULL, 0);
	pat  = strtoul(argv[5], NULL, 0);
	if (argc > 6) tmo = strtoul(argv[6], NULL, 0);
	if (argc > 7) bs  = strtoul(argv[7], NULL, 0);
	len = (size_t)nblk * bs;

	if (posix_memalign((void **)&buf, 4096, len)) return 2;
	memset(buf, pat & 0xff, len);

	fd = open(argv[2], O_RDWR);
	if (fd < 0) { fprintf(stderr, "open %s: %s\n", argv[2], strerror(errno)); return 2; }

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x8a;                       /* WRITE(16) */
	put_be64(&cdb[2], lba);
	put_be32(&cdb[10], nblk);

	memset(&io, 0, sizeof(io));
	memset(sense, 0, sizeof(sense));
	io.interface_id    = 'S';
	io.dxfer_direction = SG_DXFER_TO_DEV;
	io.cmd_len         = sizeof(cdb);
	io.cmdp            = cdb;
	io.dxfer_len       = len;
	io.dxferp          = buf;
	io.sbp             = sense;
	io.mx_sb_len       = sizeof(sense);
	io.timeout         = tmo;

	printf("write_issue dev=%s lba=%llu nblocks=%u bs=%u bytes=%zu pattern=0x%02x "
	       "sgio_timeout_ms=%u t_pre=%.6f\n",
	       argv[2], (unsigned long long)lba, nblk, bs, len, pat & 0xff, tmo, mono());
	fflush(stdout);

	t0 = mono();
	rc = ioctl(fd, SG_IO, &io);
	se = errno;
	t1 = mono();
	close(fd);
	free(buf);
	return report("write_done", &io, rc, se, t0, t1, sense);
}

/* Aligned O_DIRECT observation of the device immediately below dm-delay.
 * Buffered reads are unsound here — up to five cache aliases sit between the
 * target and the backing file (sess132 ruling). */
static int do_poll(int argc, char **argv)
{
	uint8_t *buf;
	unsigned pat, dur_ms, iv_ms;
	size_t len;
	off_t off;
	int fd, n_obs = 0, seen = 0;
	double t_start, t_last_absent = -1.0, t_first_present = -1.0;

	if (argc < 8) {
		fprintf(stderr, "usage: prprobe poll <dev> <byteoff> <len> <pattern_byte> <duration_ms> <interval_ms>\n");
		return 2;
	}
	off    = (off_t)strtoull(argv[3], NULL, 0);
	len    = (size_t)strtoull(argv[4], NULL, 0);
	pat    = strtoul(argv[5], NULL, 0) & 0xff;
	dur_ms = strtoul(argv[6], NULL, 0);
	iv_ms  = strtoul(argv[7], NULL, 0);

	if (posix_memalign((void **)&buf, 4096, len)) return 2;

	fd = open(argv[2], O_RDONLY | O_DIRECT);
	if (fd < 0) { fprintf(stderr, "open O_DIRECT %s: %s\n", argv[2], strerror(errno)); return 2; }

	printf("poll_start dev=%s byteoff=%llu len=%zu pattern=0x%02x "
	       "duration_ms=%u interval_ms=%u t=%.6f\n",
	       argv[2], (unsigned long long)off, len, pat, dur_ms, iv_ms, mono());
	fflush(stdout);

	t_start = mono();
	while ((mono() - t_start) * 1000.0 < dur_ms) {
		ssize_t r;
		double t;
		size_t i;
		int present;
		struct timespec sl;

		t = mono();
		r = pread(fd, buf, len, off);
		if (r != (ssize_t)len) {
			printf("poll_err t=%.6f r=%zd errno=%d(%s)\n",
			       t, r, errno, strerror(errno));
			fflush(stdout);
			break;
		}
		present = 1;
		for (i = 0; i < len; i++)
			if (buf[i] != pat) { present = 0; break; }

		n_obs++;
		if (present) {
			if (t_first_present < 0) {
				t_first_present = t;
				printf("poll_first_present t=%.6f obs=%d\n", t, n_obs);
				fflush(stdout);
			}
			seen = 1;
		} else if (!seen) {
			t_last_absent = t;
		}

		sl.tv_sec  = iv_ms / 1000;
		sl.tv_nsec = (long)(iv_ms % 1000) * 1000000L;
		nanosleep(&sl, NULL);
	}

	printf("poll_end observations=%d present=%d t_last_absent=%.6f "
	       "t_first_present=%.6f t=%.6f\n",
	       n_obs, seen, t_last_absent, t_first_present, mono());
	fflush(stdout);
	close(fd);
	free(buf);
	return seen ? 0 : 1;
}

static int do_dwrite(int argc, char **argv)
{
	uint8_t *buf;
	unsigned pat;
	size_t len;
	off_t off;
	int fd;
	ssize_t w;
	double t0, t1;

	if (argc < 6) {
		fprintf(stderr, "usage: prprobe dwrite <dev> <byteoff> <len> <pattern_byte>\n");
		return 2;
	}
	off = (off_t)strtoull(argv[3], NULL, 0);
	len = (size_t)strtoull(argv[4], NULL, 0);
	pat = strtoul(argv[5], NULL, 0) & 0xff;

	if (posix_memalign((void **)&buf, 4096, len)) return 2;
	memset(buf, pat, len);

	fd = open(argv[2], O_WRONLY | O_DIRECT);
	if (fd < 0) { fprintf(stderr, "open O_DIRECT %s: %s\n", argv[2], strerror(errno)); return 2; }

	t0 = mono();
	w = pwrite(fd, buf, len, off);
	fsync(fd);
	t1 = mono();
	printf("dwrite dev=%s byteoff=%llu len=%zu pattern=0x%02x w=%zd errno=%d "
	       "t_submit=%.6f t_return=%.6f\n",
	       argv[2], (unsigned long long)off, len, pat, w,
	       w == (ssize_t)len ? 0 : errno, t0, t1);
	fflush(stdout);
	close(fd);
	free(buf);
	return w == (ssize_t)len ? 0 : 1;
}

static int do_dread(int argc, char **argv)
{
	uint8_t *buf;
	size_t len, i;
	off_t off;
	int fd, uniform = 1;
	ssize_t r;

	if (argc < 5) {
		fprintf(stderr, "usage: prprobe dread <dev> <byteoff> <len>\n");
		return 2;
	}
	off = (off_t)strtoull(argv[3], NULL, 0);
	len = (size_t)strtoull(argv[4], NULL, 0);

	if (posix_memalign((void **)&buf, 4096, len)) return 2;

	fd = open(argv[2], O_RDONLY | O_DIRECT);
	if (fd < 0) { fprintf(stderr, "open O_DIRECT %s: %s\n", argv[2], strerror(errno)); return 2; }

	r = pread(fd, buf, len, off);
	if (r != (ssize_t)len) {
		printf("dread_err r=%zd errno=%d(%s)\n", r, errno, strerror(errno));
		close(fd); free(buf); return 1;
	}
	for (i = 1; i < len; i++)
		if (buf[i] != buf[0]) { uniform = 0; break; }
	printf("dread dev=%s byteoff=%llu len=%zu first=0x%02x uniform=%d t=%.6f\n",
	       argv[2], (unsigned long long)off, len, buf[0], uniform, mono());
	fflush(stdout);
	close(fd);
	free(buf);
	return 0;
}

/*
 * fiemap — translate a byte range inside a FILE into the physical byte offset
 * of the block device that holds it.
 *
 * Stage (ii) of the ruled plan runs the A/B against the SHIPPED SCST handler,
 * vdisk_fileio, whose backing store is a file on a real filesystem rather than
 * the dm device itself.  The observation point is still the device immediately
 * BELOW dm-delay, so the harness has to know which sector of that device the
 * victim's LBA actually lands on.  The ruling requires this mapping to be
 * obtained PROGRAMMATICALLY (not by parsing filefrag output), and to be
 * rejected unless the whole tested range sits inside ONE extent that is
 * already initialized and cannot move or be shared underneath us.
 *
 * Every flag refused below would break the observation in a different way:
 * UNWRITTEN reads back as zeroes regardless of what was written, DELALLOC has
 * no physical block at all yet, ENCODED/DATA_INLINE/DATA_TAIL mean the bytes
 * on disk are not the bytes in the file, SHARED means a reflink copy could
 * divert the write elsewhere, UNKNOWN/NOT_ALIGNED mean the answer itself is
 * not trustworthy.
 */
#define FIEMAP_REFUSED (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | \
			FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_DATA_ENCRYPTED | \
			FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE | \
			FIEMAP_EXTENT_DATA_TAIL | FIEMAP_EXTENT_UNWRITTEN | \
			FIEMAP_EXTENT_SHARED)

static int do_fiemap(int argc, char **argv)
{
	struct { struct fiemap f; struct fiemap_extent e[32]; } q;
	const struct fiemap_extent *ex = NULL;
	unsigned long long off, len, phys;
	unsigned i;
	int fd;

	if (argc < 5) {
		fprintf(stderr, "usage: prprobe fiemap <file> <byteoff> <len>\n");
		return 2;
	}
	off = strtoull(argv[3], NULL, 0);
	len = strtoull(argv[4], NULL, 0);

	fd = open(argv[2], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", argv[2], strerror(errno));
		return 2;
	}
	/* Sync first: a range still only in the page cache can be reported as
	 * DELALLOC, and an extent map read before writeback is not the map the
	 * target will write through. */
	if (fsync(fd)) {
		fprintf(stderr, "fsync %s: %s\n", argv[2], strerror(errno));
		close(fd);
		return 2;
	}

	memset(&q, 0, sizeof(q));
	q.f.fm_start = off;
	q.f.fm_length = len;
	q.f.fm_flags = FIEMAP_FLAG_SYNC;
	q.f.fm_extent_count = 32;
	if (ioctl(fd, FS_IOC_FIEMAP, &q.f) < 0) {
		fprintf(stderr, "FS_IOC_FIEMAP %s: %s\n", argv[2], strerror(errno));
		close(fd);
		return 2;
	}
	close(fd);

	if (q.f.fm_mapped_extents != 1) {
		printf("fiemap_err file=%s byteoff=%llu len=%llu extents=%u — the "
		       "range is not covered by exactly one extent\n",
		       argv[2], off, len, q.f.fm_mapped_extents);
		for (i = 0; i < q.f.fm_mapped_extents && i < 32; i++)
			printf("fiemap_extent i=%u logical=%llu physical=%llu "
			       "length=%llu flags=0x%08x\n", i,
			       (unsigned long long)q.e[i].fe_logical,
			       (unsigned long long)q.e[i].fe_physical,
			       (unsigned long long)q.e[i].fe_length,
			       q.e[i].fe_flags);
		return 1;
	}
	ex = &q.e[0];

	/* Wholly inside, not merely overlapping. */
	if (off < ex->fe_logical ||
	    off + len > ex->fe_logical + ex->fe_length) {
		printf("fiemap_err file=%s byteoff=%llu len=%llu — range is not "
		       "wholly inside the extent logical=%llu length=%llu\n",
		       argv[2], off, len,
		       (unsigned long long)ex->fe_logical,
		       (unsigned long long)ex->fe_length);
		return 1;
	}
	if (ex->fe_flags & FIEMAP_REFUSED) {
		printf("fiemap_err file=%s byteoff=%llu len=%llu flags=0x%08x — "
		       "extent is not an initialized, unshared, directly-mapped "
		       "extent (refused=0x%08x)\n",
		       argv[2], off, len, ex->fe_flags,
		       ex->fe_flags & (unsigned)FIEMAP_REFUSED);
		return 1;
	}

	phys = ex->fe_physical + (off - ex->fe_logical);
	printf("fiemap file=%s byteoff=%llu len=%llu phys=%llu phys_lba512=%llu "
	       "ext_logical=%llu ext_physical=%llu ext_length=%llu flags=0x%08x "
	       "aligned4k=%d\n",
	       argv[2], off, len, phys, phys / 512,
	       (unsigned long long)ex->fe_logical,
	       (unsigned long long)ex->fe_physical,
	       (unsigned long long)ex->fe_length, ex->fe_flags,
	       (phys % 4096) == 0);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			"prprobe — SG_IO probe for the PR in-flight exclusion harness\n"
			"  prout  <dev> <sa_hex> <rk_hex> <sark_hex> <type> [timeout_ms] [aptpl]\n"
			"  prin   <dev> <sa_hex> [alloc_len]\n"
			"  write  <dev> <lba> <nblocks> <pattern_byte> [timeout_ms] [blocksize]\n"
			"  poll   <dev> <byteoff> <len> <pattern_byte> <duration_ms> <interval_ms>\n"
			"  dwrite <dev> <byteoff> <len> <pattern_byte>\n"
			"  dread  <dev> <byteoff> <len>\n"
			"  fiemap <file> <byteoff> <len>\n");
		return 2;
	}
	if (!strcmp(argv[1], "prout"))  return do_prout(argc, argv);
	if (!strcmp(argv[1], "prin"))   return do_prin(argc, argv);
	if (!strcmp(argv[1], "write"))  return do_write(argc, argv);
	if (!strcmp(argv[1], "poll"))   return do_poll(argc, argv);
	if (!strcmp(argv[1], "dwrite")) return do_dwrite(argc, argv);
	if (!strcmp(argv[1], "dread"))  return do_dread(argc, argv);
	if (!strcmp(argv[1], "fiemap")) return do_fiemap(argc, argv);
	if (!strcmp(argv[1], "clearua")) return do_clearua(argc, argv);
	fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
	return 2;
}
