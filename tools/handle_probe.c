// SPDX-License-Identifier: GPL-2.0
/*
 * handle_probe — name_to_handle_at / open_by_handle_at probe for MXFS.
 *
 * (D-0527): xfs_nfs_get_inode decodes a file handle with an
 * XFS_IGET_UNTRUSTED iget, whose xfs_imap_lookup consults this node's cached
 * AGI/inobt WITHOUT the AG DLM lock.  A handle minted on the node that
 * allocated the inode therefore decodes on a peer only if the peer's cached
 * inobt already shows the allocation.  This tool makes that measurable:
 *
 *   handle_probe encode <path>            -> prints "<type> <hex-bytes>"
 *   handle_probe open <mount-dir> <type> <hex-bytes> [repeat] [sleep_ms]
 *        -> per attempt: "attempt=N rc=<0|-1> errno=<n> (<name>) ino=<n>"
 *
 * Exit status of `open`: 0 when every attempt opened, 1 when any failed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int do_encode(const char *path)
{
	unsigned char buf[sizeof(struct file_handle) + MAX_HANDLE_SZ];
	struct file_handle *fh = (struct file_handle *)buf;
	int mount_id = 0;
	unsigned int i;

	fh->handle_bytes = MAX_HANDLE_SZ;
	if (name_to_handle_at(AT_FDCWD, path, fh, &mount_id, 0) != 0) {
		printf("encode rc=-1 errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("%d ", fh->handle_type);
	for (i = 0; i < fh->handle_bytes; i++)
		printf("%02x", fh->f_handle[i]);
	printf("\n");
	return 0;
}

static int do_open(const char *mnt, int type, const char *hex, int repeat,
		   int sleep_ms)
{
	unsigned char buf[sizeof(struct file_handle) + MAX_HANDLE_SZ];
	struct file_handle *fh = (struct file_handle *)buf;
	size_t n = strlen(hex);
	unsigned int i;
	int mfd, failed = 0, a;

	if (n % 2 || n / 2 > MAX_HANDLE_SZ) {
		fprintf(stderr, "bad hex handle\n");
		return 2;
	}
	fh->handle_bytes = n / 2;
	fh->handle_type = type;
	for (i = 0; i < n / 2; i++) {
		int h = hexval(hex[2 * i]), l = hexval(hex[2 * i + 1]);

		if (h < 0 || l < 0) {
			fprintf(stderr, "bad hex handle\n");
			return 2;
		}
		fh->f_handle[i] = (unsigned char)((h << 4) | l);
	}
	mfd = open(mnt, O_RDONLY | O_DIRECTORY);
	if (mfd < 0) {
		printf("mount open rc=-1 errno=%d (%s)\n", errno, strerror(errno));
		return 2;
	}
	for (a = 1; a <= repeat; a++) {
		int fd = open_by_handle_at(mfd, fh, O_RDONLY);

		if (fd < 0) {
			printf("attempt=%d rc=-1 errno=%d (%s) ino=0\n", a, errno,
			       strerror(errno));
			failed = 1;
		} else {
			struct stat st;

			if (fstat(fd, &st) == 0)
				printf("attempt=%d rc=0 errno=0 (ok) ino=%llu nlink=%lu size=%lld\n",
				       a, (unsigned long long)st.st_ino,
				       (unsigned long)st.st_nlink,
				       (long long)st.st_size);
			else
				printf("attempt=%d rc=0 errno=0 (ok) ino=? fstat_errno=%d\n",
				       a, errno);
			close(fd);
		}
		fflush(stdout);
		if (a < repeat && sleep_ms > 0) {
			struct timespec ts = { sleep_ms / 1000,
					       (sleep_ms % 1000) * 1000000L };
			nanosleep(&ts, NULL);
		}
	}
	close(mfd);
	return failed;
}

int main(int argc, char **argv)
{
	if (argc >= 3 && strcmp(argv[1], "encode") == 0)
		return do_encode(argv[2]);
	if (argc >= 5 && strcmp(argv[1], "open") == 0)
		return do_open(argv[2], atoi(argv[3]), argv[4],
			       argc > 5 ? atoi(argv[5]) : 1,
			       argc > 6 ? atoi(argv[6]) : 0);
	fprintf(stderr,
		"usage: handle_probe encode <path>\n"
		"       handle_probe open <mount-dir> <type> <hex> [repeat] [sleep_ms]\n");
	return 2;
}
