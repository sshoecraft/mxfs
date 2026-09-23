/*
 * tests/d0532_uring_nowait.c — drive MXFS's IOMAP_NOWAIT mapping paths.
 *
 * D-RECYCLE-DEFERRED-FREE-CORPSE-ILOCK-END-UNPAIRED-EX-HOLDER-UNDERFLOW-0532.
 * MXFS never sets FMODE_NOWAIT, so preadv2/pwritev2(RWF_NOWAIT) are refused
 * with EOPNOTSUPP before reaching the filesystem.  io_uring is different: it
 * treats any file opened O_NONBLOCK as nowait-capable and issues its FIRST
 * attempt of a read or write with IOCB_NOWAIT (punting to a worker only if
 * that attempt returns -EAGAIN).  IOCB_NOWAIT becomes IOMAP_NOWAIT in iomap,
 * and xfs_ilock_for_iomap then takes the ILOCK with xfs_ilock_nowait.
 *
 * No liburing: raw io_uring_setup / io_uring_enter, one SQE in flight.
 *
 *   d0532_uring_nowait <file> <mode> <ops>
 *     mode  bufw  buffered IORING_OP_WRITE, file opened O_NONBLOCK
 *           dior  O_DIRECT IORING_OP_READ, O_NONBLOCK
 *           diow  O_DIRECT IORING_OP_WRITE over existing blocks, O_NONBLOCK
 *           dsyncw diow with O_DSYNC: the completion's sync tail runs after
 *                 inode_dio_end and takes the ILOCK on its own (D-0971)
 *           diou  O_DIRECT IORING_OP_WRITE, O_NONBLOCK, into blocks
 *                 preallocated unwritten past the first 64 KiB (fallocate of
 *                 ops blocks first): every completion converts an unwritten
 *                 extent under ILOCK_EXCL, the work the release pipeline's
 *                 direct-I/O wait must admit (D-0971)
 *           diox  O_DIRECT IORING_OP_WRITE, O_NONBLOCK, one block past EOF
 *                 each op: every completion converts and moves the size
 *                 under ILOCK_EXCL (D-0971)
 *           iopoll O_DIRECT IORING_OP_READ on an IORING_SETUP_IOPOLL ring:
 *                 a clustered mount refuses polled direct I/O (D-0971), so
 *                 every op is expected to fail EOPNOTSUPP; err counts only
 *                 other outcomes and refused= reports the refusals
 *           ctl-* the same with no O_NONBLOCK (first attempt blocks normally)
 * Prints: URING mode=<m> ops=<n> ok=<n> short=<n> err=<n> last_err=<errno>
 *         nocqe=<n> [refused=<n>]
 * The file must already exist and be at least 64 KiB; diou and diox grow it
 * by ops blocks.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct ring {
	int fd;
	unsigned *sq_head, *sq_tail, *sq_mask, *sq_array;
	unsigned *cq_head, *cq_tail, *cq_mask;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
};

static int ring_init(struct ring *r, unsigned setup_flags)
{
	struct io_uring_params p;
	void *sq, *cq;
	size_t sqsz, cqsz;

	memset(&p, 0, sizeof(p));
	p.flags = setup_flags;
	r->fd = syscall(__NR_io_uring_setup, 4, &p);
	if (r->fd < 0)
		return -errno;
	sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	sq = mmap(NULL, sqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		  r->fd, IORING_OFF_SQ_RING);
	cq = mmap(NULL, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		  r->fd, IORING_OFF_CQ_RING);
	r->sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
		       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		       r->fd, IORING_OFF_SQES);
	if (sq == MAP_FAILED || cq == MAP_FAILED || r->sqes == MAP_FAILED)
		return -errno;
	r->sq_head = (unsigned *)((char *)sq + p.sq_off.head);
	r->sq_tail = (unsigned *)((char *)sq + p.sq_off.tail);
	r->sq_mask = (unsigned *)((char *)sq + p.sq_off.ring_mask);
	r->sq_array = (unsigned *)((char *)sq + p.sq_off.array);
	r->cq_head = (unsigned *)((char *)cq + p.cq_off.head);
	r->cq_tail = (unsigned *)((char *)cq + p.cq_off.tail);
	r->cq_mask = (unsigned *)((char *)cq + p.cq_off.ring_mask);
	r->cqes = (struct io_uring_cqe *)((char *)cq + p.cq_off.cqes);
	return 0;
}

static int nocqe;	/* ops whose completion never appeared (2 s) */

/*
 * Submit one read/write and wait for its completion; returns cqe->res.
 * On an IOPOLL ring io_uring_enter(GETEVENTS) returns with no event when
 * the request was punted to a worker before this task polled (the poll
 * loop breaks on an empty iopoll list), and MXFS punts every first attempt
 * because it sets no FMODE_NOWAIT; so wait for the completion the way any
 * ring user does, re-entering until it is there, bounded at 2 s.
 */
static int ring_rw(struct ring *r, int op, int fd, void *buf, unsigned len,
		   uint64_t off)
{
	unsigned tail = *r->sq_tail, idx = tail & *r->sq_mask, head;
	struct io_uring_sqe *sqe = &r->sqes[idx];
	int res, tries = 0;

	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = op;
	sqe->fd = fd;
	sqe->addr = (uint64_t)(uintptr_t)buf;
	sqe->len = len;
	sqe->off = off;
	r->sq_array[idx] = idx;
	__atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
	if (syscall(__NR_io_uring_enter, r->fd, 1, 1, IORING_ENTER_GETEVENTS,
		    NULL, 0) < 0)
		return -errno;
	for (;;) {
		head = __atomic_load_n(r->cq_head, __ATOMIC_ACQUIRE);
		if (head != __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE))
			break;
		if (++tries > 2000) {
			nocqe++;
			return -ETIMEDOUT;
		}
		usleep(1000);
		if (syscall(__NR_io_uring_enter, r->fd, 0, 1,
			    IORING_ENTER_GETEVENTS, NULL, 0) < 0 &&
		    errno != EINTR)
			return -errno;
	}
	res = r->cqes[head & *r->cq_mask].res;
	__atomic_store_n(r->cq_head, head + 1, __ATOMIC_RELEASE);
	return res;
}

int main(int argc, char **argv)
{
	const char *path, *mode;
	int ops, i, fd, flags, op, res, ok = 0, shrt = 0, err = 0, last = 0;
	int ctl, iopoll, grow, refused = 0;
	unsigned setup = 0;
	uint64_t base = 0;
	struct ring r;
	void *buf;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <file> <bufw|dior|diow|dsyncw|iopoll|ctl-*> <ops>\n",
			argv[0]);
		return 2;
	}
	path = argv[1];
	mode = argv[2];
	ops = atoi(argv[3]);
	ctl = strncmp(mode, "ctl-", 4) == 0;
	if (ctl)
		mode += 4;
	iopoll = strcmp(mode, "iopoll") == 0;
	grow = !strcmp(mode, "diou") || !strcmp(mode, "diox");
	if (strcmp(mode, "bufw") && strcmp(mode, "dior") && strcmp(mode, "diow") &&
	    strcmp(mode, "dsyncw") && !grow && !iopoll) {
		fprintf(stderr, "unknown mode %s\n", argv[2]);
		return 2;
	}
	flags = O_RDWR | ((ctl || iopoll) ? 0 : O_NONBLOCK) |
		(strcmp(mode, "bufw") ? O_DIRECT : 0) |
		(strcmp(mode, "dsyncw") ? 0 : O_DSYNC);
	op = (strcmp(mode, "dior") && !iopoll) ? IORING_OP_WRITE : IORING_OP_READ;
	if (iopoll)
		setup = IORING_SETUP_IOPOLL;
	if (posix_memalign(&buf, 4096, 4096))
		return 2;
	memset(buf, ctl ? 'c' : 'n', 4096);
	fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 2;
	}
	res = ring_init(&r, setup);
	if (res) {
		fprintf(stderr, "io_uring_setup: %s\n", strerror(-res));
		return 2;
	}
	if (grow) {
		/* fresh blocks past the current end: unwritten for diou (a
		 * plain fallocate leaves them unwritten and moves EOF), absent
		 * for diox (each write extends EOF by one block) */
		base = (uint64_t)lseek(fd, 0, SEEK_END);
		if (!strcmp(mode, "diou") &&
		    fallocate(fd, 0, base, (uint64_t)ops * 4096)) {
			fprintf(stderr, "fallocate: %s\n", strerror(errno));
			return 2;
		}
	}
	for (i = 0; i < ops; i++) {
		res = ring_rw(&r, op, fd, buf, 4096,
			      grow ? base + (uint64_t)i * 4096
				   : (uint64_t)(i % 16) * 4096);
		if (res == 4096)
			ok++;
		else if (res >= 0)
			shrt++;
		else if (iopoll && res == -EOPNOTSUPP)
			refused++;
		else {
			err++;
			last = -res;
		}
	}
	close(fd);
	if (iopoll) {
		/* the expected outcome is every op refused; anything that
		 * completed, or failed otherwise, is the failure here */
		if (ok || shrt)
			err += ok + shrt;
		printf("URING mode=iopoll ops=%d ok=%d short=%d err=%d last_err=%d nocqe=%d refused=%d\n",
		       ops, ok, shrt, err, last, nocqe, refused);
		return err ? 1 : 0;
	}
	printf("URING mode=%s%s ops=%d ok=%d short=%d err=%d last_err=%d nocqe=%d\n",
	       ctl ? "ctl-" : "", mode, ops, ok, shrt, err, last, nocqe);
	return err ? 1 : 0;
}
