/*
 * tests/delalloc_dirty_tail_race.c — produce the state that
 * D-THE-DELALLOC-RELEASE-SHIM-PUNCHES-UNDER-DIRTY-FOLIOS-BELOW-6-12 is about:
 * a SHORT buffered write over a NEWLY allocated delalloc extent, with a folio
 * in the unwritten tail dirtied while the write is still in flight.
 *
 * WHY EACH PIECE IS THE WAY IT IS.  xfs_buffered_write_iomap_end() only punches
 * when all of these hold, and the program is built backwards from that list:
 *
 *   iomap->type == IOMAP_DELALLOC   -> write into a HOLE, so the mapping is
 *                                      delayed-allocation rather than real
 *   iomap->flags & IOMAP_F_NEW      -> the extent must be created BY THIS
 *                                      WRITE.  Anything that touches the range
 *                                      first (including the mmap store, if it
 *                                      lands early) allocates the delalloc
 *                                      itself, the mapping is then not NEW, and
 *                                      iomap_end returns at its first guard
 *                                      having punched nothing.  That is the
 *                                      main way this test goes quiet, and it is
 *                                      why the toucher chases the writer rather
 *                                      than leading it.
 *   written < length                -> the write must be SHORT
 *
 * HOW THE SHORT WRITE IS MADE DETERMINISTIC.  Not by a signal, not by filling
 * the disk: the source buffer is one mapping whose first page is readable and
 * whose remainder is PROT_NONE.  iomap copies the readable page and then
 * copy_page_from_iter_atomic() returns 0; iomap_write_iter tries
 * fault_in_iov_iter_readable(), which cannot make a PROT_NONE page readable, and
 * gives up with -EFAULT.  write() returns the one page it copied.  So every
 * call is short by construction, at a boundary we choose, with no race.
 *
 * WHAT THE OTHER THREAD DOES.  It stores one byte into the first byte of pages
 * inside the tail the writer is about to have punched — the region
 * [offset + PAGE, offset + REQ).  A store into a page backed by the delalloc
 * that the writer just created dirties the folio without allocating anything,
 * which is exactly the "dirty data still pending in the page cache" upstream's
 * comment says must keep its reservation.
 *
 * THE ORACLE.  The two threads write disjoint pages and the expected first byte
 * of a page is a pure function of its index:
 *
 *   even page i   the writer's page, filled by write(), first byte (i & 0xff)
 *   odd  page i   the toucher's page, first byte (i & 0xff) via the mmap
 *
 * Every even page below VERIFY_HI is written by the closing pass, always.  An
 * odd page is expected ONLY IF THE TOUCHER ACTUALLY STORED TO IT during the
 * closing pass, and that is recorded, page by page, in a manifest written next
 * to the data file as <path>.touched: one byte per page, 1 = stored.  The first
 * version of this program assumed the toucher covers every odd page and had no
 * manifest.  It does not cover them: when the closing pass begins the toucher
 * is still finishing the previous pass's last window at the far end of the
 * file, and by the time it re-reads the writer's position the writer is at
 * page N, so it never stores to odd pages 1..N-1 in this pass and those pages
 * legitimately hold zeros after the punch.  Four laps on native 6.8 XFS
 * (s139a,b,d-g) and one on MXFS (s138b2) each reported exactly that set as
 * "lost" — 1..9, 1..13, 1..23 — with the boundary landing wherever the writer
 * was when the toucher caught up, and the kernel-side trace of the folio
 * (tests/delalloc_dirty_tail_kprobe.sh) showed every one of its blocks dirty,
 * submitted and written.  An odd page the toucher can also miss mid-file, when
 * its window slides past one while it is blocked behind the writer's punch.
 *
 * After the run everything is msync'd and fsync'd.  A page in the manifest (or
 * any even page) whose first byte is not (i & 0xff) afterwards is data this
 * filesystem accepted and did not keep.  The checking is deliberately NOT done
 * here — it is done after an unmount and remount by the harness, because a
 * read from the live page cache would return the bytes whether or not anything
 * reached the platter.
 *
 * Usage: delalloc_dirty_tail_race <path> <seconds> [req_kb] [check]
 * Prints one summary line:
 *   SHORT=<n> FULL=<n> TOUCHED=<n> TOUCHED_FINAL=<n> PAGES=<n> VERIFY_HI=<bytes> ERR=<n>
 * VERIFY_HI is the offset below which the file is fully determined by the
 * closing pass; the caller checks pages below it and nothing above it.
 * TOUCHED_FINAL is the number of distinct odd pages the manifest marks; a
 * caller should refuse to read a verdict from a run where it is small.
 *
 * THE LIVE CHECKER (4th argument "check") is a third thread that, during the
 * closing pass only, keeps pread()ing the odd pages the manifest already marks
 * (pread copies from the page cache and installs no PTE, so it disturbs neither
 * the fault path nor the mapping).  The first time one reads back wrong it
 * writes a marker into the kernel trace ring (/sys/kernel/tracing/trace_marker)
 * so the kernel events immediately before that instant can be read from the
 * same trace, and prints ZERO_AT=<page> ZERO_GOT=<byte> ZERO_CHECKS=<n> on the
 * summary line.  The toucher's first store of the closing pass and the pass
 * start are marked the same way.  Without "check" nothing here runs.
 *
 * Build: gcc -O2 -pthread -o <bin> delalloc_dirty_tail_race.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/falloc.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096UL

static volatile int running = 1;
static volatile unsigned long writer_at;   /* the offset the writer is on now */
static unsigned long req_bytes;            /* the length each write asks for */
static unsigned long file_bytes;
static int fd = -1;
static unsigned char *filemap;

static unsigned long shortw, fullw, touched, errs;

/* the manifest: one byte per page, set by the toucher during the closing pass */
static volatile unsigned char *stored;
static volatile int in_final;                 /* the closing pass has begun */
static volatile unsigned long touched_hi;     /* highest odd offset stored in it */

/* the live checker (see the header): armed by "check", live in the closing pass */
static int checking;
static int markfd = -1;
static unsigned long zero_at = ~0UL, zero_got, zero_checks;

static void mark(const char *fmt, unsigned long a, unsigned long b)
{
	char buf[96];
	int n;

	if (markfd < 0)
		return;
	n = snprintf(buf, sizeof(buf), fmt, a, b);
	if (n > 0 && write(markfd, buf, (size_t)n) < 0)
		errs++;
}

static double now_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/*
 * The toucher.  It reads the writer's current offset and dirties odd pages
 * inside that write's tail.  It deliberately does NOT run ahead: a store to a
 * page the writer has not yet mapped would allocate the delalloc itself and
 * cost the write its IOMAP_F_NEW, which is the one flag the whole case needs.
 */
static void *toucher(void *arg)
{
	int first_final = 1;

	(void)arg;
	while (running) {
		unsigned long base = writer_at;
		unsigned long off;

		if (base + req_bytes > file_bytes)
			continue;
		for (off = base + PAGE; off < base + req_bytes; off += PAGE) {
			unsigned long idx = off / PAGE;

			if (!(idx & 1UL))
				continue;          /* even pages belong to the writer */
			if (off + 1 > file_bytes)
				break;
			filemap[off] = (unsigned char)(idx & 0xff);
			touched++;
			if (in_final) {
				/*
				 * The store is in the page; only now may the
				 * manifest say so.  The compiler may not reorder
				 * the two (both are volatile), and the checker
				 * reads the page through the kernel, so there is
				 * no CPU ordering to arrange.
				 */
				stored[idx] = 1;
				if (first_final) {
					mark("DDTR-TOUCH-FIRST page=%lu base=%lu\n", idx, base / PAGE);
					first_final = 0;
				}
				if (off > touched_hi)
					touched_hi = off;
			}
		}
	}
	return NULL;
}

/*
 * The checker.  Reads back, through the page cache and without touching the
 * mapping, every odd page the manifest marks as stored in the closing pass,
 * and marks the kernel trace the first time one is wrong.
 */
static void *checker(void *arg)
{
	(void)arg;
	while (running) {
		unsigned long hi = touched_hi, off;

		if (!in_final || !hi)
			continue;
		for (off = PAGE; off <= hi && running; off += 2 * PAGE) {
			unsigned char b;
			unsigned long idx = off / PAGE;

			if (!stored[idx])
				continue;
			if (pread(fd, &b, 1, (off_t)off) != 1) {
				errs++;
				continue;
			}
			zero_checks++;
			if (b != (unsigned char)(idx & 0xff)) {
				mark("DDTR-ZERO page=%lu got=%lu\n", idx, (unsigned long)b);
				zero_at = idx;
				zero_got = b;
				return NULL;   /* one witness is the point; stop */
			}
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	const char *path;
	double secs, t0;
	unsigned char *src;
	unsigned long off, touched_final_out = 0;
	int final_pass = 0;
	pthread_t th, ck;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <path> <seconds> [req_kb] [check]\n", argv[0]);
		return 2;
	}
	path = argv[1];
	secs = atof(argv[2]);
	req_bytes = (argc > 3 ? (unsigned long)atol(argv[3]) : 256UL) * 1024UL;
	if (req_bytes < 2 * PAGE)
		req_bytes = 2 * PAGE;
	if (argc > 4 && strcmp(argv[4], "check") == 0) {
		checking = 1;
		markfd = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
		if (markfd < 0)
			perror("trace_marker (markers disabled)");
	}

	/*
	 * The source buffer: one readable page followed by PROT_NONE.  The
	 * write asks for req_bytes and can only ever deliver the first page.
	 */
	src = mmap(NULL, req_bytes, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src == MAP_FAILED) { perror("mmap src"); return 2; }
	memset(src, 0, req_bytes);
	if (mprotect(src + PAGE, req_bytes - PAGE, PROT_NONE) != 0) {
		perror("mprotect"); return 2;
	}

	/*
	 * The file is sized up front so the toucher's mmap has somewhere to
	 * land, but ftruncate allocates no blocks — every offset is still a
	 * hole, which is what makes each write's mapping NEW.
	 */
	file_bytes = req_bytes * 64;
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { perror("open"); return 2; }
	if (ftruncate(fd, (off_t)file_bytes) != 0) { perror("ftruncate"); return 2; }
	filemap = mmap(NULL, file_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (filemap == MAP_FAILED) { perror("mmap file"); return 2; }
	stored = calloc(file_bytes / PAGE, 1);
	if (!stored) { perror("calloc"); return 2; }

	writer_at = 0;
	if (pthread_create(&th, NULL, toucher, NULL) != 0) {
		perror("pthread_create"); return 2;
	}
	if (checking && pthread_create(&ck, NULL, checker, NULL) != 0) {
		perror("pthread_create checker"); return 2;
	}

	/*
	 * TWO PHASES, AND THE SECOND ONE IS WHAT MAKES THE FILE AN ORACLE.
	 * The timed phase wraps the file many times a second, punching it back
	 * to holes each pass, so whatever it leaves behind is a partial pass at
	 * an arbitrary offset and cannot be checked against anything.  When the
	 * time is up the loop therefore stops taking new work and runs ONE more
	 * complete pass from zero, with the toucher still live, so the final
	 * contents are fully determined: every even page below
	 * file_bytes - req_bytes was written by this pass, and every odd page
	 * below it was touched while the writer went past.
	 */
	t0 = now_s();
	off = 0;
	while (1) {
		ssize_t n;
		unsigned long idx = off / PAGE;

		if (!final_pass && now_s() - t0 >= secs) {
			final_pass = 1;
			if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				      0, (off_t)file_bytes) != 0) {
				perror("fallocate punch"); errs++; break;
			}
			off = 0;
			writer_at = 0;
			in_final = 1;
			mark("DDTR-FINAL-PASS pages=%lu req=%lu\n", file_bytes / PAGE,
			     req_bytes / PAGE);
			continue;
		}

		if (off + req_bytes > file_bytes) {
			if (final_pass)
				break;          /* the closing pass is complete */
			/*
			 * Start over.  Every offset has to be a HOLE again or
			 * the next pass writes over real blocks, the mapping is
			 * not IOMAP_F_NEW and nothing is ever punched.
			 *
			 * PUNCH_HOLE, not ftruncate.  Truncating to 0 while the
			 * file is still mapped tears the mapping down under the
			 * toucher and its next store takes SIGBUS — which is
			 * how the first version of this program died.  Punching
			 * keeps i_size and the mapping, drops the blocks, and
			 * the toucher's pages simply refault.
			 */
			if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				      0, (off_t)file_bytes) != 0) {
				perror("fallocate punch");
				errs++; break;
			}
			off = 0;
			writer_at = 0;
			continue;
		}
		memset(src, (int)(idx & 0xff), PAGE);
		writer_at = off;

		n = pwrite(fd, src, req_bytes, (off_t)off);
		if (n < 0) {
			if (errno != EFAULT) errs++;
			/* EFAULT with nothing copied is not the case we want,
			 * but it is not an error either — step on. */
		} else if ((unsigned long)n < req_bytes) {
			shortw++;
		} else {
			fullw++;
		}
		/* even pages only: step by two pages so the toucher owns the odd ones */
		off += 2 * PAGE;
	}

	running = 0;
	pthread_join(th, NULL);
	if (checking)
		pthread_join(ck, NULL);
	mark("DDTR-PASS-DONE touched_hi=%lu zero_at=%lu\n", touched_hi / PAGE, zero_at);

	if (msync(filemap, file_bytes, MS_SYNC) != 0) { perror("msync"); errs++; }
	if (fsync(fd) != 0) { perror("fsync"); errs++; }
	mark("DDTR-SYNCED err=%lu x=%lu\n", errs, 0UL);

	/*
	 * The manifest, for the harness's post-remount check.  Written and
	 * fsync'd through its own descriptor so a remount cannot lose it, and
	 * counted here so the summary says how much of the file it covers.
	 */
	{
		char mpath[4096];
		unsigned long i, npages = file_bytes / PAGE, tfinal = 0;
		int mfd;

		for (i = 0; i < npages; i++)
			tfinal += stored[i];
		snprintf(mpath, sizeof(mpath), "%s.touched", path);
		mfd = open(mpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (mfd < 0 || write(mfd, (const void *)stored, npages) != (ssize_t)npages ||
		    fsync(mfd) != 0) {
			perror("manifest"); errs++;
		}
		if (mfd >= 0)
			close(mfd);
		touched_final_out = tfinal;
	}

	/*
	 * VERIFY_HI is the byte offset below which the file is fully
	 * determined by the closing pass.  The harness checks pages below it
	 * and nothing above it: the last req_bytes of the file are never the
	 * start of a write, so its even pages are still holes.
	 */
	printf("SHORT=%lu FULL=%lu TOUCHED=%lu TOUCHED_FINAL=%lu PAGES=%lu VERIFY_HI=%lu ERR=%lu",
	       shortw, fullw, touched, touched_final_out, file_bytes / PAGE,
	       file_bytes - req_bytes, errs);
	if (checking)
		printf(" ZERO_AT=%ld ZERO_GOT=%lu ZERO_CHECKS=%lu",
		       zero_at == ~0UL ? -1L : (long)zero_at, zero_got, zero_checks);
	printf("\n");
	munmap(filemap, file_bytes);
	close(fd);
	return errs ? 1 : 0;
}
