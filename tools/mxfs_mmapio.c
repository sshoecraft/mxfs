/*
 * mxfs_mmapio — perform one mmap'd access against a file, reporting how the
 * fault path disposed of it.  Built for the D-512 fault race leg
 * (tests/d512_race_verify.sh): the racer's page fault enters the
 * xfs_filemap_fault post-gate window (P-D512-RACEWIN site=fault) and the
 * harness publishes the incarnation poison mid-window; the access must then
 * either complete from the same (pre-poison) incarnation or SIGBUS — never
 * hang, never oops, never read another incarnation's bytes.
 *
 * usage: mxfs_mmapio r <file> <offset>
 *        mxfs_mmapio w <file> <offset> <byte 0-255>
 *
 * exit codes:
 *   0  access completed (r: prints "read=0xNN"; w: prints "wrote=0xNN msync=RC")
 *   42 SIGBUS during the access (the mmap-path shape of -ESTALE)
 *   43 SIGSEGV during the access
 *   2  usage / open / fstat / mmap failure (perror'd)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/stat.h>

static sigjmp_buf jb;
static volatile sig_atomic_t sigcaught;

static void on_sig(int sig)
{
	sigcaught = sig;
	siglongjmp(jb, 1);
}

int main(int argc, char **argv)
{
	struct sigaction sa;
	struct stat st;
	unsigned char *map;
	unsigned long off;
	size_t maplen;
	int fd, wr;

	if (argc < 4 || (argv[1][0] != 'r' && argv[1][0] != 'w') ||
	    (argv[1][0] == 'w' && argc < 5)) {
		fprintf(stderr, "usage: %s r|w <file> <offset> [byte]\n", argv[0]);
		return 2;
	}
	wr = argv[1][0] == 'w';
	off = strtoul(argv[3], NULL, 0);

	fd = open(argv[2], wr ? O_RDWR : O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 2;
	}
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return 2;
	}
	if ((off_t)off >= st.st_size) {
		fprintf(stderr, "offset %lu beyond size %lld\n", off,
			(long long)st.st_size);
		return 2;
	}
	maplen = st.st_size;
	map = mmap(NULL, maplen, wr ? PROT_READ | PROT_WRITE : PROT_READ,
		   MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		return 2;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sig;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);

	if (sigsetjmp(jb, 1)) {
		printf("sig=%s\n", sigcaught == SIGBUS ? "SIGBUS" : "SIGSEGV");
		fflush(stdout);
		return sigcaught == SIGBUS ? 42 : 43;
	}

	if (wr) {
		unsigned char b = (unsigned char)strtoul(argv[4], NULL, 0);
		int mrc;

		map[off] = b;
		mrc = msync(map, maplen, MS_SYNC);
		printf("wrote=0x%02x msync=%d\n", b, mrc);
	} else {
		printf("read=0x%02x\n", map[off]);
	}
	return 0;
}
