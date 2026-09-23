/*
 * d512_ref_matrix.c — D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512
 * cycle-1 long-lived-reference matrix helper (sess414).
 *
 * Runs ON a test node against a file on the mxfs mount.  Exercises the
 * sess413 design-consult ruling's long-lived-ref set against a debug-forced
 * incarnation poison (module param dbg_incarn_poison_ino, self-clearing,
 * fires at open) and asserts every old reference fails SAFELY:
 *
 *   phase 1 (pre-poison references):
 *     - rw fd, baseline content written + fsync'd (platter-durable)
 *     - O_DIRECT fd (skipped if the mount refuses O_DIRECT)
 *     - rw mmap, page made resident AND dirtied through the mapping
 *       (this page is the "dirty G1" the ruling says must be DISCARDED,
 *       never flushed — its bmap may map another file's blocks by now)
 *     prints "READY ino=<n>" then waits for the trigger file the driver
 *     creates after arming the knob.
 *
 *   phase 2 (post-poison assertions), each prints ASSERT <name> PASS/FAIL:
 *     open_estale    re-open of the path fails ESTALE (the open itself
 *                    fires the armed poison, then the open gate refuses)
 *     read_estale    read(2) on the old rw fd fails ESTALE
 *     pwrite_estale  pwrite(2) on the old rw fd fails ESTALE
 *     fsync_estale   fsync(2) on the old rw fd fails ESTALE (never
 *                    stale durability, and never a flush through the
 *                    dead bmap)
 *     dio_estale     pread(2) on the O_DIRECT fd fails ESTALE (skipped
 *                    if no dio fd)
 *     mmap_sigbus    a forked child dereferencing the old mapping dies
 *                    SIGBUS within the revocation window (polled: reads
 *                    that still succeed beforehand are the resident-PTE
 *                    hazard the revocation worker exists to close)
 *     reopen_fresh   after dropping every old ref, a fresh open succeeds
 *                    and the content is the fsync'd BASELINE — the page
 *                    dirtied through the dead incarnation's mapping was
 *                    discarded, not written back
 *
 * Exit 0 iff every (non-skipped) assertion passed.
 *
 * Usage: d512_ref_matrix <file-on-mxfs> <trigger-file>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

static int failures;

static void
check(const char *name, int ok, const char *detail)
{
	printf("ASSERT %s %s%s%s\n", name, ok ? "PASS" : "FAIL",
	       detail ? " " : "", detail ? detail : "");
	fflush(stdout);
	if (!ok)
		failures++;
}

static void
msleep_(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
}

int
main(int argc, char **argv)
{
	const char *path, *trigger;
	char baseline[4096], buf[4096], detail[256];
	int fd, dfd = -1, rc, i;
	long pgsz = sysconf(_SC_PAGESIZE);
	volatile char *map;
	struct stat st;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <file-on-mxfs> <trigger-file>\n",
			argv[0]);
		return 2;
	}
	path = argv[1];
	trigger = argv[2];
	unlink(trigger);

	memset(baseline, 'B', sizeof(baseline));

	/* ---- phase 1: establish the long-lived references ---- */
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("SETUP open");
		return 2;
	}
	if (pwrite(fd, baseline, sizeof(baseline), 0) !=
	    (ssize_t)sizeof(baseline) || fsync(fd) != 0) {
		perror("SETUP baseline write+fsync");
		return 2;
	}
	if (fstat(fd, &st) != 0) {
		perror("SETUP fstat");
		return 2;
	}

	dfd = open(path, O_RDWR | O_DIRECT);	/* optional leg */

	map = mmap(NULL, pgsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("SETUP mmap");
		return 2;
	}
	if (map[0] != 'B') {
		fprintf(stderr, "SETUP resident read got 0x%02x\n", map[0]);
		return 2;
	}
	map[0] = 'D';	/* the dirty-G1 page: must be discarded, not flushed */

	printf("READY ino=%llu\n", (unsigned long long)st.st_ino);
	fflush(stdout);

	/* driver arms dbg_incarn_poison_ino, then creates the trigger */
	for (i = 0; i < 600; i++) {
		if (access(trigger, F_OK) == 0)
			break;
		msleep_(100);
	}
	if (i == 600) {
		fprintf(stderr, "TIMEOUT waiting for trigger file\n");
		return 2;
	}

	/* ---- phase 2: the poisoning open, then the matrix ---- */
	errno = 0;
	rc = open(path, O_RDWR);
	snprintf(detail, sizeof(detail), "rc=%d errno=%d", rc, errno);
	check("open_estale", rc < 0 && errno == ESTALE, detail);
	if (rc >= 0)
		close(rc);

	errno = 0;
	rc = (int)pread(fd, buf, sizeof(buf), 0);
	snprintf(detail, sizeof(detail), "rc=%d errno=%d", rc, errno);
	check("read_estale", rc < 0 && errno == ESTALE, detail);

	errno = 0;
	rc = (int)pwrite(fd, baseline, 512, 0);
	snprintf(detail, sizeof(detail), "rc=%d errno=%d", rc, errno);
	check("pwrite_estale", rc < 0 && errno == ESTALE, detail);

	errno = 0;
	rc = fsync(fd);
	snprintf(detail, sizeof(detail), "rc=%d errno=%d", rc, errno);
	check("fsync_estale", rc < 0 && errno == ESTALE, detail);

	if (dfd >= 0) {
		errno = 0;
		rc = (int)pread(dfd, buf, 512, 0);
		snprintf(detail, sizeof(detail), "rc=%d errno=%d", rc, errno);
		check("dio_estale", rc < 0 && errno == ESTALE, detail);
	} else {
		printf("ASSERT dio_estale SKIP no-odirect-fd\n");
	}

	/*
	 * The revocation worker is asynchronous: poll the mapping with a
	 * sacrificial child until the PTE zap lands (SIGBUS), bounded 15s.
	 * A child that reads the page successfully beforehand demonstrates
	 * the resident-PTE window the worker closes.
	 */
	{
		int sigbus = 0, resident_reads = 0;

		for (i = 0; i < 150 && !sigbus; i++) {
			pid_t pid = fork();

			if (pid == 0) {
				char c = map[0];
				_exit((unsigned char)c);
			}
			if (pid > 0) {
				int ws;

				waitpid(pid, &ws, 0);
				if (WIFSIGNALED(ws) &&
				    WTERMSIG(ws) == SIGBUS)
					sigbus = 1;
				else
					resident_reads++;
			}
			if (!sigbus)
				msleep_(100);
		}
		snprintf(detail, sizeof(detail),
			 "resident_reads_before_zap=%d polls=%d",
			 resident_reads, i);
		check("mmap_sigbus", sigbus, detail);
	}

	/* ---- drop every old reference, then prove the fresh path ---- */
	munmap((void *)map, pgsz);
	close(fd);
	if (dfd >= 0)
		close(dfd);

	/* the retire arm may need a lookup or two to re-iget the live
	 * incarnation; the -ESTALE contract is revalidate-and-retry */
	rc = -1;
	for (i = 0; i < 50 && rc < 0; i++) {
		errno = 0;
		rc = open(path, O_RDWR);
		if (rc < 0 && errno != ESTALE)
			break;
		if (rc < 0)
			msleep_(100);
	}
	snprintf(detail, sizeof(detail), "rc=%d errno=%d retries=%d", rc,
		 errno, i);
	check("reopen_fresh", rc >= 0, detail);
	if (rc >= 0) {
		memset(buf, 0, sizeof(buf));
		errno = 0;
		i = (int)pread(rc, buf, sizeof(buf), 0);
		snprintf(detail, sizeof(detail),
			 "nread=%d first_byte=0x%02x (0x42=discarded-correct 0x44=G1-FLUSHED-DEFECT)",
			 i, (unsigned char)buf[0]);
		check("dirty_g1_discarded",
		      i == (int)sizeof(buf) && buf[0] == 'B', detail);
		close(rc);
	} else {
		printf("ASSERT dirty_g1_discarded FAIL no-fresh-fd\n");
		failures++;
	}

	printf("MATRIX %s failures=%d\n", failures ? "FAIL" : "PASS",
	       failures);
	return failures ? 1 : 0;
}
