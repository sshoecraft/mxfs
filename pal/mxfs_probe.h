/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS diagnostic probes
 *
 * A probe is an instrumentation line ("mxfs: P12-DLMTR ...") that the test
 * harness reads back out of the kernel log.  Probes are dynamic debug: they
 * print nothing, and their arguments are not evaluated, unless enabled --
 *
 *   insmod mxfs.ko dyndbg=+p                                    every probe
 *   echo 'module mxfs +p' > /proc/dynamic_debug/control         at run time
 *   echo 'module mxfs format "P-AGIFC" +p' > /proc/dynamic_debug/control
 *
 * Messages an operator must see (errors, lifecycle, a refusal or a loss) are
 * not probes and keep their pr_err/pr_warn/pr_info level.  docs/log-levels.md
 * says which is which and why.
 */
#ifndef __MXFS_PROBE_H__
#define __MXFS_PROBE_H__

#ifdef __KERNEL__
#include <linux/printk.h>
#include <linux/dynamic_debug.h>

/*
 * mxfs_probe_on(): true where probes are enabled.  It is a dynamic-debug
 * site of its own (format "mxfs: probe site"), so `module mxfs +p` turns it
 * on with everything else.  Guards the work a probe does beyond printing:
 * a stack dump, or a rate limit that would otherwise report suppressions
 * of a line that never prints.
 */
#if defined(CONFIG_DYNAMIC_DEBUG) || \
	(defined(CONFIG_DYNAMIC_DEBUG_CORE) && defined(DYNAMIC_DEBUG_MODULE))
#define mxfs_probe_on()							\
	({								\
		DEFINE_DYNAMIC_DEBUG_METADATA(mxfs_probe_site,		\
					      "mxfs: probe site");	\
		DYNAMIC_DEBUG_BRANCH(mxfs_probe_site);			\
	})
#else
#define mxfs_probe_on()			(0)
#endif
#define mxfs_probe_stack()						\
	do {								\
		if (mxfs_probe_on())					\
			dump_stack();					\
	} while (0)

/*
 * mxfs_xfs_probe(mp, fmt, ...): a probe written where XFS code would use
 * xfs_notice(mp, ...).  Same "XFS (<dev>): " prefix and appended newline as
 * xfs_printk, so the line reads the same when probes are on.
 */
#define mxfs_xfs_probe(mp, fmt, ...)					\
	pr_debug("XFS (%s): " fmt "\n",					\
		 ((mp) && (mp)->m_super) ? (mp)->m_super->s_id : "?",	\
		 ##__VA_ARGS__)

#define mxfs_probe(fmt, ...)		pr_debug(fmt, ##__VA_ARGS__)
#define mxfs_probe_ratelimited(fmt, ...) pr_debug_ratelimited(fmt, ##__VA_ARGS__)
#define mxfs_probe_once(fmt, ...)					\
	do {								\
		static bool mxfs_probe_fired;				\
									\
		if (!mxfs_probe_fired) {				\
			mxfs_probe_fired = true;			\
			pr_debug(fmt, ##__VA_ARGS__);			\
		}							\
	} while (0)
#else
/* user-mode builds of dlm/ print probes at the PAL's debug level */
#define mxfs_probe_on()			(0)
#define mxfs_probe(fmt, ...)		mxfs_pal_log(MXFS_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define mxfs_probe_ratelimited(fmt, ...) mxfs_pal_log(MXFS_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define mxfs_probe_once(fmt, ...)	mxfs_pal_log(MXFS_LOG_DEBUG, fmt, ##__VA_ARGS__)
#endif

#endif /* __MXFS_PROBE_H__ */
