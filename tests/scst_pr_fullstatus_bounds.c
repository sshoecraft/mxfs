/*
 * scst_pr_fullstatus_bounds.c — deterministic proof of the SCST
 * PERSISTENT RESERVE IN / READ FULL STATUS buffer overflow that took clyde
 * down on 2026-08-21, and of the fix (+caw-abort-reclaim.4).
 *
 * WHY THIS EXISTS
 * ---------------
 * The defect is a signed/unsigned comparison in
 * scst/src/scst_pres.c::scst_pr_read_full_status():
 *
 *     int offset, size, size_max;                  <- signed
 *     const uint32_t rec_len = 24 + ts;            <- UNSIGNED
 *     if (size_max - size > rec_len) { ...write... }
 *
 * `size` accumulates EVERY registrant, including the ones that were skipped
 * for not fitting.  The moment one does not fit, `size` passes `size_max`,
 * `size_max - size` goes negative, and because the other operand is uint32_t
 * the comparison is performed UNSIGNED — the negative int promotes to ~4e9,
 * the test passes, and every remaining registrant is memcpy()'d past the end
 * of the command's data buffer.
 *
 * On the rig that buffer is a single order-0 page belonging to the SCSI
 * command, so the overflow lands in whatever physical page follows it.  On
 * 2026-08-21 that was a live QEMU page-table page: two PTEs were found
 * holding the little-endian ASCII "st16-mxf" and "s-node,i" — consecutive
 * 8-byte chunks of an iSCSI TransportID, the exact payload of the
 * memcpy().  print_bad_pte -> Oops in a vCPU thread with irqs disabled ->
 * stop_machine never completed -> RCU stall -> unrecoverable host wedge.
 *
 * The trigger is structural, not exotic: MXFS probes READ FULL STATUS with a
 * 4096-byte buffer and resizes on the reported ADDITIONAL LENGTH.  Any time
 * the registrant list outgrows the probe buffer (~53 iSCSI registrants, i.e.
 * ~27 dual-path nodes) the first non-fitting registrant arms the bug.  The
 * 32-node rig runs 64 registrants.
 *
 * WHAT THIS PROGRAM DOES
 * ----------------------
 * Reproduces both loop variants verbatim against a buffer that is followed by
 * a PROT_NONE guard page, so an out-of-bounds write is a deterministic
 * SIGSEGV rather than silent corruption.  Each variant runs in a forked child
 * so the harness survives the fault.
 *
 * Expected:
 *   OLD (uint32_t rec_len, bound vs `size`)  -> SIGSEGV: writes past the end.
 *   NEW (int rec_len, bound vs `offset`)     -> clean: stops at the first
 *                                               descriptor that does not fit,
 *                                               and still reports the FULL
 *                                               ADDITIONAL LENGTH so the
 *                                               initiator can resize.
 *
 * Build/run:  tests/scst_pr_bounds_check.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define PAGE 4096

/*
 * One registrant, modelled on the real rig: an iSCSI TransportID whose
 * scst_tid_size() is 4 + the padded initiator-name length.
 * "iqn.2004-10.com.ubuntu:01:testNN-mxfs-node,i,0x00023d020000"
 */
struct reg {
	uint8_t	tid[128];
	int	tid_size;
};

static struct reg *build_registrants(int n)
{
	struct reg *r = calloc(n, sizeof(*r));
	int i;

	for (i = 0; i < n; i++) {
		char name[96];
		int len, padded;

		snprintf(name, sizeof(name),
			 "iqn.2004-10.com.ubuntu:01:test%d-mxfs-node,i,0x0002%04x0000",
			 (i / 2) + 1, i);
		len = (int)strlen(name) + 1;		/* SCST NUL-terminates */
		padded = (len + 3) & ~3;		/* SPC: multiple of 4 */

		r[i].tid[0] = 0x05;			/* PROTOCOL ID = iSCSI */
		r[i].tid[2] = (uint8_t)(padded >> 8);
		r[i].tid[3] = (uint8_t)padded;
		memcpy(&r[i].tid[4], name, (size_t)len);
		r[i].tid_size = 4 + padded;		/* == scst_tid_size() */
	}
	return r;
}

/* Buffer of `size` bytes, immediately followed by an unmapped guard page. */
static uint8_t *guarded_buffer(int size)
{
	size_t span = (size_t)PAGE * 2;
	uint8_t *base = mmap(NULL, span, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (base == MAP_FAILED) {
		perror("mmap");
		exit(2);
	}
	if (mprotect(base + PAGE, PAGE, PROT_NONE) != 0) {
		perror("mprotect");
		exit(2);
	}
	/* End the writable region exactly at `size`. */
	return base + (PAGE - size);
}

/* ---- the loop as it shipped in +caw-abort-reclaim.3 and earlier ---- */
static int loop_old(uint8_t *buffer, int buffer_size, int bufflen,
		    struct reg *regs, int n, int *reported_addl)
{
	int offset = 0, size, size_max, i;

	(void)bufflen;
	if (buffer_size < 8)
		return 0;

	offset += 8;
	size = 0;
	size_max = buffer_size - 8;

	for (i = 0; i < n; i++) {
		const uint32_t ts = (uint32_t)regs[i].tid_size;
		const uint32_t rec_len = 24 + ts;

		if (size_max - size > rec_len) {	/* UNSIGNED comparison */
			memset(&buffer[offset], 0, rec_len);
			memcpy(&buffer[offset + 24], regs[i].tid, ts);
			offset += (int)rec_len;
		}
		size += (int)rec_len;
	}
	*reported_addl = size;
	return offset;
}

/* ---- the loop as fixed in +caw-abort-reclaim.4 ---- */
static int loop_new(uint8_t *buffer, int buffer_size, int bufflen,
		    struct reg *regs, int n, int *reported_addl)
{
	int offset = 0, size, size_max, i;
	bool truncated = false;

	if (buffer_size < 8)
		return 0;

	offset += 8;
	size = 0;
	size_max = buffer_size < bufflen ? buffer_size : bufflen;

	for (i = 0; i < n; i++) {
		const int ts = regs[i].tid_size;
		const int rec_len = 24 + ts;

		if (!truncated && rec_len <= size_max - offset) {
			memset(&buffer[offset], 0, (size_t)rec_len);
			memcpy(&buffer[offset + 24], regs[i].tid, (size_t)ts);
			offset += rec_len;
		} else {
			truncated = true;
		}
		size += rec_len;
	}
	*reported_addl = size;
	return offset;
}

struct outcome {
	int	signalled;
	int	sig;
	int	offset;
	int	addl;
};

static struct outcome run_child(int which, int buffer_size, int bufflen,
				struct reg *regs, int n)
{
	int fd[2];
	pid_t pid;
	struct outcome o = { 0, 0, 0, 0 };
	int status;
	int got[2] = { 0, 0 };

	if (pipe(fd) != 0) {
		perror("pipe");
		exit(2);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(2);
	}
	if (pid == 0) {
		uint8_t *buf = guarded_buffer(buffer_size);
		int addl = 0, off;

		close(fd[0]);
		off = which ? loop_new(buf, buffer_size, bufflen, regs, n, &addl)
			    : loop_old(buf, buffer_size, bufflen, regs, n, &addl);
		got[0] = off;
		got[1] = addl;
		if (write(fd[1], got, sizeof(got)) != (ssize_t)sizeof(got))
			_exit(3);
		_exit(0);
	}

	close(fd[1]);
	if (read(fd[0], got, sizeof(got)) == (ssize_t)sizeof(got)) {
		o.offset = got[0];
		o.addl = got[1];
	}
	close(fd[0]);
	waitpid(pid, &status, 0);
	if (WIFSIGNALED(status)) {
		o.signalled = 1;
		o.sig = WTERMSIG(status);
	}
	return o;
}

int main(int argc, char **argv)
{
	int n = (argc > 1) ? atoi(argv[1]) : 64;	/* 32 nodes x 2 paths */
	int buffer_size = (argc > 2) ? atoi(argv[2]) : PAGE;
	struct reg *regs = build_registrants(n);
	struct outcome old_o, new_o;
	int required = 8, i, rc = 0;

	for (i = 0; i < n; i++)
		required += 24 + regs[i].tid_size;

	printf("registrants=%d  buffer_size=%d  full response would need %d bytes\n",
	       n, buffer_size, required);

	old_o = run_child(0, buffer_size, buffer_size, regs, n);
	new_o = run_child(1, buffer_size, buffer_size, regs, n);

	printf("\nOLD (+caw-abort-reclaim.3 and earlier):\n");
	if (old_o.signalled)
		printf("  WROTE PAST THE END OF THE BUFFER  (killed by signal %d "
		       "at the guard page)\n", old_o.sig);
	else
		printf("  offset=%d addl=%d  (offset > buffer_size means it "
		       "overran: %s)\n", old_o.offset, old_o.addl,
		       old_o.offset > buffer_size ? "YES" : "no");

	printf("\nNEW (+caw-abort-reclaim.4):\n");
	if (new_o.signalled) {
		printf("  WROTE PAST THE END OF THE BUFFER (signal %d) — FIX IS "
		       "WRONG\n", new_o.sig);
		rc = 1;
	} else {
		printf("  offset=%d (<= buffer_size %d)  addl reported=%d "
		       "(full required=%d)\n",
		       new_o.offset, buffer_size, new_o.addl, required - 8);
		if (new_o.offset > buffer_size) {
			printf("  FAIL: offset exceeds the buffer\n");
			rc = 1;
		}
		if (new_o.addl != required - 8) {
			printf("  FAIL: ADDITIONAL LENGTH must report the FULL "
			       "size so the initiator can resize\n");
			rc = 1;
		}
	}

	printf("\nVERDICT: %s\n",
	       rc == 0 && old_o.signalled ?
	       "old loop overruns, new loop is bounded and still reports the full length — PASS" :
	       rc == 0 ?
	       "new loop bounded (old loop did not fault at this size — try more registrants)" :
	       "FAIL");
	free(regs);
	return rc;
}
