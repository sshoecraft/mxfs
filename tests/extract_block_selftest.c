// SPDX-License-Identifier: GPL-2.0
/*
 * Self-test input for scripts/extract_block.py.
 *
 * work() is built from the constructs the tool must move without changing
 * behaviour: a local written through a macro argument, one whose address is
 * taken, a function-local static, member stores, arrays, a return with a
 * value, a goto out of a block, a macro that names its argument twice
 * (one written reference, two AST references), and loops whose break/continue stay inside
 * the moved block.  tests/extract_block_selftest.sh extracts each block
 * below, compiles, runs, and compares the output with the untouched file.
 * The blocks marked REFUSE must be refused.
 */
#include <stdio.h>
#include <string.h>

/* as in xfs/xfs_mxfs_dlm_priv.h */
enum {
	MXFS_BLOCK_NEXT = 0,
	MXFS_BLOCK_RETURN = 1,
	MXFS_BLOCK_GOTO = 2,
};

struct acc {
	int sum;
	int hits[4];
};

#define BUMP(v, n)	((v) += (n))
#define SETMAX(a, b)	do { if ((b) > (a)) (a) = (b); } while (0)
#define PEEK(x)		(*(volatile int *)&(x))
#define TWICE(x)	((x) + (x))

static int sink(int *p, int v)
{
	*p += v;
	return *p;
}

static int work(int n, const int *in, struct acc *out)
{
	int total = 0, best = -1, i, err = 0;
	int shadow = 7;
	int *alias = &shadow;
	struct acc local = { 0 };
	int buf[8];
	static int calls;

	memset(buf, 0, sizeof(buf));
	calls++;

	/* block A: writes through a macro argument and a member store */
	{
		for (i = 0; i < n; i++) {
			BUMP(total, in[i]);
			SETMAX(best, in[i]);
			local.hits[in[i] & 3]++;
		}
		local.sum = total;
	}

	/* block B: a local whose address is taken elsewhere, read via the alias */
	if (n > 2) {
		shadow += n;
		*alias += 1;
		total += TWICE(shadow);
	}

	/* block C: a return with a value, and an array written in place */
	if (total > 1000) {
		buf[0] = total;
		return buf[0] - calls;
	}

	/* block D: a goto out of the block */
	{
		int j;

		for (j = 0; j < n; j++) {
			if (in[j] < 0) {
				err = -j - 1;
				goto fail;
			}
			if (in[j] == 0)
				continue;
			buf[j & 7] += in[j];
			if (buf[j & 7] > 50)
				break;
		}
	}

	/* block E: the function-local static and a callee writing through & */
	{
		sink(&err, calls);
		calls += PEEK(shadow) & 1;
	}

	/* block F: a switch whose cases stay inside the block */
	switch (best & 3) {
	case 0:
		total += 1;
		break;
	case 1:
		total += 10;
		break;
	default:
		total += 100;
	}

	out->sum = total + local.sum + err;
	memcpy(out->hits, local.hits, sizeof(local.hits));
	return total + buf[1] + best;
fail:
	out->sum = err;
	return err;
}

static int refusals(int n)
{
	int x = n;

	for (int k = 0; k < 3; k++) {
		/* REFUSE: the break leaves the moved block for the loop outside */
		if (x > 4) {
			x--;
			break;
		}
	}
	/* REFUSE: names __func__ */
	if (x == 99) {
		printf("%s\n", __func__);
	}
	return x;
}

int main(void)
{
	static const int sets[][6] = {
		{ 1, 2, 3, 4, 5, 6 }, { 0, 0, 9, 9, 9, 9 }, { 5, -1, 3, 0, 0, 0 },
		{ 400, 400, 400, 0, 1, 2 }, { 17, 0, 23, 42, 8, 1 }, { 3, 3, 3, 3, 3, 3 },
	};
	struct acc out;

	for (unsigned s = 0; s < sizeof(sets) / sizeof(sets[0]); s++) {
		for (int n = 0; n <= 6; n++) {
			memset(&out, 0, sizeof(out));
			int r = work(n, sets[s], &out);

			printf("%u %d -> %d sum=%d hits=%d,%d,%d,%d\n", s, n, r, out.sum,
			       out.hits[0], out.hits[1], out.hits[2], out.hits[3]);
		}
	}
	printf("refusals %d %d\n", refusals(9), refusals(99));
	return 0;
}
