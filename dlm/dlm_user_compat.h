/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Usermode shims for the kernel idioms the DLM engine's instrumented probe lines
 * use directly (capped counters, pr_warn).  Architectural invariant 4 (no
 * direct kernel API outside pal/) is honoured for everything that carries
 * semantics — locks, I/O, threads, time go through mxfs_pal_*; these are
 * only the diagnostic counters and printk aliases, and this header lets
 * tests/tauth/dlm_ledger_test build the engine against pal/linux/user.c.
 */
#ifndef MXFS_DLM_USER_COMPAT_H
#define MXFS_DLM_USER_COMPAT_H

#ifndef __KERNEL__

#include <stdio.h>

typedef struct { volatile int counter; } atomic_t;
#define ATOMIC_INIT(i)  { (i) }

static inline int atomic_inc_return(atomic_t *v)
{
    return __sync_add_and_fetch(&v->counter, 1);
}

static inline int atomic_read(const atomic_t *v)
{
    return v->counter;
}

static inline void atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}

/*
 * Module parameters are the knobs the test harnesses arm at runtime; user
 * mode has no /sys, so the knobs are plain globals here and the
 * declarations expand to nothing.  A knob with a set-callback (one that
 * resets its counter when armed) keeps the callback compiled — it is
 * ordinary C over the same global — so that the user-mode build checks it.
 */
struct kernel_param { void *arg; };
struct kernel_param_ops {
    int (*set)(const char *val, const struct kernel_param *kp);
    int (*get)(char *buffer, const struct kernel_param *kp);
};
static inline int param_set_ullong(const char *val, const struct kernel_param *kp)
{
    return sscanf(val, "%llu", (unsigned long long *)kp->arg) == 1 ? 0 : -1;
}
static inline int param_get_ullong(char *buffer, const struct kernel_param *kp)
{
    return sprintf(buffer, "%llu", *(unsigned long long *)kp->arg);
}
#define module_param_named(name, var, type, perm)
#define module_param_cb(name, ops, arg, perm) \
    static const struct kernel_param_ops *const mxfs_param_ref_##name \
        __attribute__((unused)) = (ops)
#define MODULE_PARM_DESC(name, desc)

#ifndef pr_warn
#define pr_warn(fmt, ...)               mxfs_pal_log(MXFS_LOG_WARN, fmt, ##__VA_ARGS__)
#endif
#ifndef pr_warn_ratelimited
#define pr_warn_ratelimited(fmt, ...)   mxfs_pal_log(MXFS_LOG_WARN, fmt, ##__VA_ARGS__)
#endif
#ifndef pr_info
#define pr_info(fmt, ...)               mxfs_pal_log(MXFS_LOG_INFO, fmt, ##__VA_ARGS__)
#endif
#ifndef pr_err
#define pr_err(fmt, ...)                mxfs_pal_log(MXFS_LOG_ERR, fmt, ##__VA_ARGS__)
#endif
#ifndef READ_ONCE
#define READ_ONCE(x)                    (*(volatile __typeof__(x) *)&(x))
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v)                (*(volatile __typeof__(x) *)&(x) = (v))
#endif
#ifndef unlikely
#define unlikely(x)                     (x)
#endif
#ifndef likely
#define likely(x)                       (x)
#endif

#endif /* !__KERNEL__ */
#endif /* MXFS_DLM_USER_COMPAT_H */
