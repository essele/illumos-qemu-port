/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "sysemu.h"
#include "net.h"
#include "monitor.h"
#include "console.h"
#include "trace.h"

#include "hw/hw.h"

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>
#ifdef __FreeBSD__
#include <sys/param.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <mmsystem.h>
#endif

#include "qemu-timer.h"

/***********************************************************/
/* timers */

#define QEMU_CLOCK_REALTIME 0
#define QEMU_CLOCK_VIRTUAL  1
#define QEMU_CLOCK_HOST     2

struct QEMUClock {
    int type;
    int enabled;

    QEMUTimer *active_timers;

    NotifierList reset_notifiers;
    int64_t last;
};

struct QEMUTimer {
    QEMUClock *clock;
    int64_t expire_time;	/* in nanoseconds */
    int64_t interval;
    int scale;
    QEMUTimerCB *cb;
    void *opaque;
    void *source;
    struct QEMUTimer *next;
};

struct qemu_alarm_timer {
    char const *name;
    int (*start)(struct qemu_alarm_timer *t);
    void (*stop)(struct qemu_alarm_timer *t);
    void (*rearm)(struct qemu_alarm_timer *t, int64_t nearest_delta_ns);
#if defined(__linux__) || defined(__sun__)
    int fd;
    timer_t timer;
#elif defined(_WIN32)
    HANDLE timer;
#endif
#if defined(__sun__)
    void *priv;
#endif
    char expired;
    char pending;
};

static struct qemu_alarm_timer *alarm_timer;

static bool qemu_timer_expired_ns(QEMUTimer *timer_head, int64_t current_time)
{
    return timer_head && (timer_head->expire_time <= current_time);
}

int qemu_alarm_pending(void)
{
    return alarm_timer->pending;
}

static inline int alarm_has_dynticks(struct qemu_alarm_timer *t)
{
    return !!t->rearm;
}

static int64_t qemu_next_alarm_deadline(struct QEMUTimer **tp)
{
    int64_t delta;
    int64_t rtdelta;
    struct QEMUTimer *t;

    if (tp == NULL)
        tp = &t;

    if (!use_icount && vm_clock->active_timers) {
        delta = vm_clock->active_timers->expire_time -
                     qemu_get_clock_ns(vm_clock);
        *tp = vm_clock->active_timers;
    } else {
        delta = INT32_MAX;
        *tp = NULL;
    }
    if (host_clock->active_timers) {
        int64_t hdelta = host_clock->active_timers->expire_time -
                 qemu_get_clock_ns(host_clock);
        if (hdelta < delta) {
            delta = hdelta;
            *tp = host_clock->active_timers;
        }
    }
    if (rt_clock->active_timers) {
        rtdelta = (rt_clock->active_timers->expire_time -
                 qemu_get_clock_ns(rt_clock));
        if (rtdelta < delta) {
            delta = rtdelta;
            *tp = rt_clock->active_timers;
        }
    }

    return delta;
}

static void qemu_rearm_alarm_timer(struct qemu_alarm_timer *t)
{
    int64_t nearest_delta_ns;
    assert(alarm_has_dynticks(t));
    if (!rt_clock->active_timers &&
        !vm_clock->active_timers &&
        !host_clock->active_timers) {
        return;
    }
    nearest_delta_ns = qemu_next_alarm_deadline(NULL);
    t->rearm(t, nearest_delta_ns);
}

/* TODO: MIN_TIMER_REARM_NS should be optimized */
#define MIN_TIMER_REARM_NS 250000

#ifdef _WIN32

static int mm_start_timer(struct qemu_alarm_timer *t);
static void mm_stop_timer(struct qemu_alarm_timer *t);
static void mm_rearm_timer(struct qemu_alarm_timer *t, int64_t delta);

static int win32_start_timer(struct qemu_alarm_timer *t);
static void win32_stop_timer(struct qemu_alarm_timer *t);
static void win32_rearm_timer(struct qemu_alarm_timer *t, int64_t delta);

#else

static int unix_start_timer(struct qemu_alarm_timer *t);
static void unix_stop_timer(struct qemu_alarm_timer *t);
static void unix_rearm_timer(struct qemu_alarm_timer *t, int64_t delta);

#if defined(__sun__)
static int multiticks_start_timer(struct qemu_alarm_timer *t);
static void multiticks_stop_timer(struct qemu_alarm_timer *t);
static void multiticks_rearm_timer(struct qemu_alarm_timer *t, int64_t delta);
#endif

#if defined(__linux__) || defined(__sun__)

static int dynticks_start_timer(struct qemu_alarm_timer *t);
static void dynticks_stop_timer(struct qemu_alarm_timer *t);
static void dynticks_rearm_timer(struct qemu_alarm_timer *t, int64_t delta);

#endif /* __linux__ */

#endif /* _WIN32 */

static struct qemu_alarm_timer alarm_timers[] = {
#ifndef _WIN32
#if defined(__sun__)
    {"multiticks", multiticks_start_timer,
     multiticks_stop_timer, multiticks_rearm_timer},
#endif
#if defined(__linux__) || defined(__sun__)
    {"dynticks", dynticks_start_timer,
     dynticks_stop_timer, dynticks_rearm_timer},
#endif
    {"unix", unix_start_timer, unix_stop_timer, unix_rearm_timer},
#else
    {"mmtimer", mm_start_timer, mm_stop_timer, mm_rearm_timer},
    {"dynticks", win32_start_timer, win32_stop_timer, win32_rearm_timer},
#endif
    {NULL, }
};

static void show_available_alarms(void)
{
    int i;

    printf("Available alarm timers, in order of precedence:\n");
    for (i = 0; alarm_timers[i].name; i++)
        printf("%s\n", alarm_timers[i].name);
}

void configure_alarms(char const *opt)
{
    int i;
    int cur = 0;
    int count = ARRAY_SIZE(alarm_timers) - 1;
    char *arg;
    char *name;
    struct qemu_alarm_timer tmp;

    if (!strcmp(opt, "?")) {
        show_available_alarms();
        exit(0);
    }

    arg = g_strdup(opt);

    /* Reorder the array */
    name = strtok(arg, ",");
    while (name) {
        for (i = 0; i < count && alarm_timers[i].name; i++) {
            if (!strcmp(alarm_timers[i].name, name))
                break;
        }

        if (i == count) {
            fprintf(stderr, "Unknown clock %s\n", name);
            goto next;
        }

        if (i < cur)
            /* Ignore */
            goto next;

	/* Swap */
        tmp = alarm_timers[i];
        alarm_timers[i] = alarm_timers[cur];
        alarm_timers[cur] = tmp;

        cur++;
next:
        name = strtok(NULL, ",");
    }

    g_free(arg);

    if (cur) {
        /* Disable remaining timers */
        for (i = cur; i < count; i++)
            alarm_timers[i].name = NULL;
    } else {
        show_available_alarms();
        exit(1);
    }
}

QEMUClock *rt_clock;
QEMUClock *vm_clock;
QEMUClock *host_clock;

static QEMUClock *qemu_new_clock(int type)
{
    QEMUClock *clock;

    clock = g_malloc0(sizeof(QEMUClock));
    clock->type = type;
    clock->enabled = 1;
    clock->last = INT64_MIN;
    notifier_list_init(&clock->reset_notifiers);
    return clock;
}

void qemu_clock_enable(QEMUClock *clock, int enabled)
{
    bool old = clock->enabled;
    clock->enabled = enabled;
    if (enabled && !old) {
        qemu_rearm_alarm_timer(alarm_timer);
    }
}

int64_t qemu_clock_has_timers(QEMUClock *clock)
{
    return !!clock->active_timers;
}

int64_t qemu_clock_expired(QEMUClock *clock)
{
    return (clock->active_timers &&
            clock->active_timers->expire_time < qemu_get_clock_ns(clock));
}

int64_t qemu_clock_deadline(QEMUClock *clock)
{
    /* To avoid problems with overflow limit this to 2^32.  */
    int64_t delta = INT32_MAX;

    if (clock->active_timers) {
        delta = clock->active_timers->expire_time - qemu_get_clock_ns(clock);
    }
    if (delta < 0) {
        delta = 0;
    }
    return delta;
}

QEMUTimer *qemu_new_timer(QEMUClock *clock, int scale,
                          QEMUTimerCB *cb, void *opaque)
{
    QEMUTimer *ts;

    ts = g_malloc0(sizeof(QEMUTimer));
    ts->clock = clock;
    ts->cb = cb;
    ts->opaque = opaque;
    ts->scale = scale;
    return ts;
}

void qemu_free_timer(QEMUTimer *ts)
{
    g_free(ts);
}

/* stop a timer, but do not dealloc it */
void qemu_del_timer(QEMUTimer *ts)
{
    QEMUTimer **pt, *t;

    /* NOTE: this code must be signal safe because
       qemu_timer_expired() can be called from a signal. */
    pt = &ts->clock->active_timers;
    for(;;) {
        t = *pt;
        if (!t)
            break;
        if (t == ts) {
            *pt = t->next;
            break;
        }
        pt = &t->next;
    }
}

/* modify the current timer so that it will be fired when current_time
   >= expire_time. The corresponding callback will be called. */
void qemu_mod_timer_ns(QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimer **pt, *t;

    qemu_del_timer(ts);

    /* add the timer in the sorted list */
    /* NOTE: this code must be signal safe because
       qemu_timer_expired() can be called from a signal. */
    pt = &ts->clock->active_timers;
    for(;;) {
        t = *pt;
        if (!qemu_timer_expired_ns(t, expire_time)) {
            break;
        }
        pt = &t->next;
    }

    if (ts->expire_time && expire_time > ts->expire_time) {
        ts->interval = expire_time - ts->expire_time;
    } else {
        ts->interval = 0;
    }

    ts->expire_time = expire_time;
    ts->next = *pt;
    *pt = ts;

    trace_qemu_mod_timer(ts, expire_time, ts->interval);

    /* Rearm if necessary  */
    if (pt == &ts->clock->active_timers) {
        if (!alarm_timer->pending) {
            qemu_rearm_alarm_timer(alarm_timer);
        }
        /* Interrupt execution to force deadline recalculation.  */
        qemu_clock_warp(ts->clock);
        if (use_icount) {
            qemu_notify_event();
        }
    }
}

void qemu_mod_timer(QEMUTimer *ts, int64_t expire_time)
{
    qemu_mod_timer_ns(ts, expire_time * ts->scale);
}

int qemu_timer_pending(QEMUTimer *ts)
{
    QEMUTimer *t;
    for (t = ts->clock->active_timers; t != NULL; t = t->next) {
        if (t == ts)
            return 1;
    }
    return 0;
}

int qemu_timer_expired(QEMUTimer *timer_head, int64_t current_time)
{
    return qemu_timer_expired_ns(timer_head, current_time * timer_head->scale);
}

void qemu_run_timers(QEMUClock *clock)
{
    QEMUTimer **ptimer_head, *ts;
    int64_t current_time;
   
    if (!clock->enabled)
        return;

    current_time = qemu_get_clock_ns(clock);
    ptimer_head = &clock->active_timers;
    for(;;) {
        ts = *ptimer_head;
        if (!qemu_timer_expired_ns(ts, current_time)) {
            break;
        }

        trace_qemu_run_timer(ts, ts->expire_time, current_time);

        /* remove timer from the list before calling the callback */
        *ptimer_head = ts->next;
        ts->next = NULL;

        /* run the callback (the timer list can be modified) */
        ts->cb(ts->opaque);
    }
}

int64_t qemu_get_clock_ns(QEMUClock *clock)
{
    int64_t now, last;

    switch(clock->type) {
    case QEMU_CLOCK_REALTIME:
        return get_clock();
    default:
    case QEMU_CLOCK_VIRTUAL:
        if (use_icount) {
            return cpu_get_icount();
        } else {
            return cpu_get_clock();
        }
    case QEMU_CLOCK_HOST:
        now = get_clock_realtime();
        last = clock->last;
        clock->last = now;
        if (now < last) {
            notifier_list_notify(&clock->reset_notifiers, &now);
        }
        return now;
    }
}

void qemu_register_clock_reset_notifier(QEMUClock *clock, Notifier *notifier)
{
    notifier_list_add(&clock->reset_notifiers, notifier);
}

void qemu_unregister_clock_reset_notifier(QEMUClock *clock, Notifier *notifier)
{
    notifier_remove(notifier);
}

void init_clocks(void)
{
    rt_clock = qemu_new_clock(QEMU_CLOCK_REALTIME);
    vm_clock = qemu_new_clock(QEMU_CLOCK_VIRTUAL);
    host_clock = qemu_new_clock(QEMU_CLOCK_HOST);
}

uint64_t qemu_timer_expire_time_ns(QEMUTimer *ts)
{
    return qemu_timer_pending(ts) ? ts->expire_time : -1;
}

void qemu_run_all_timers(void)
{
    alarm_timer->pending = 0;

    /* vm time timers */
    qemu_run_timers(vm_clock);
    qemu_run_timers(rt_clock);
    qemu_run_timers(host_clock);

    /* rearm timer, if not periodic */
    if (alarm_timer->expired) {
        alarm_timer->expired = 0;
        qemu_rearm_alarm_timer(alarm_timer);
    }
}

#ifdef _WIN32
static void CALLBACK host_alarm_handler(PVOID lpParam, BOOLEAN unused)
#else
static void host_alarm_handler(int host_signum)
#endif
{
    struct qemu_alarm_timer *t = alarm_timer;
    if (!t)
	return;

    if (alarm_has_dynticks(t) ||
        qemu_next_alarm_deadline (NULL) <= 0) {
        t->expired = alarm_has_dynticks(t);
        t->pending = 1;
        qemu_notify_event();
    }
}

#if defined(__sun__)

#define QEMU_MULTITICKS_NSOURCES 8

int multiticks_enabled = 1;
int multiticks_tolerance_jitter = 20000;
int64_t multiticks_tolerance_interval = 200000;
int64_t multiticks_reap_threshold = NANOSEC;
int multiticks_reap_multiplier = 4;

struct multitick_source {
    timer_t source;
    QEMUTimer *timer;
    int64_t armed;
    int64_t interval;
    int64_t initial;
};

struct qemu_alarm_multiticks {
    int64_t reaped;
    struct multitick_source sources[QEMU_MULTITICKS_NSOURCES];
};

/*
 * Many QEMU timer consumers seek to create interval timers, but QEMU only has
 * a one-shot timer facility.  This forces the consumer to effect their own
 * intervals, an annoying (but not necessarily difficult) task. However, the
 * problem with using one-shots to implement interval timers is the overhead
 * of programming the underlying timer (e.g., timer_settime()):  even at
 * moderate frequencies (e.g., 1 KHz) this overhead can become significant at
 * modest levels of tenancy.  Given that the underlying POSIX timer facility
 * is in fact capable of providing interval timers (and given that using the
 * interval timers is more accurate than effecting the same with a one-shot),
 * and given that one can have multiple timers in a process, there is an
 * opportunity to significantly reduce timer programming overhead while
 * increasing timer accuracy by making better use of POSIX timers.  The
 * multiticks alarm timer does exactly this via a cache of interval timers,
 * associating a timer in a one-to-one manner with an underlying source.
 */
static int multiticks_start_timer(struct qemu_alarm_timer *t)
{
    struct sigevent ev;
    struct sigaction act;
    struct qemu_alarm_multiticks *multiticks;
    struct multitick_source *sources;
    struct itimerspec timeout;
    struct timespec res;
    int64_t resolution, found;
    int i;

    if (!multiticks_enabled) {
        fprintf(stderr, "multiticks: programmatically disabled\n");
        return -1;
    }

    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = host_alarm_handler;

    sigaction(SIGALRM, &act, NULL);

    multiticks = g_malloc0(sizeof (struct qemu_alarm_multiticks));
    sources = multiticks->sources;
    t->priv = multiticks;

    memset(&ev, 0, sizeof(ev));
    ev.sigev_value.sival_int = 0;
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGALRM;

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++)
        sources[i].source = -1;

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
        if (timer_create(CLOCK_MONOTONIC, &ev, &sources[i].source) != 0) {
            perror("multiticks: timer_create");
            fprintf(stderr, "multiticks: could not create timer; disabling\n");
            multiticks_stop_timer(t);
            return -1;
        }
    }

    /*
     * Check that the implementation properly honors an arbitrary interval --
     * and in particular, an interval that is explicitly not evenly divided
     * by the resolution.  (Multiticks very much relies on interval timers
     * being properly implemented; even small errors in the interval can
     * add up quickly when frequencies are high.)
     */
    if (clock_getres(CLOCK_MONOTONIC, &res) != 0) {
        perror("multiticks: clock_getres");
        fprintf(stderr, "multiticks: could not get resolution; disabling\n");
        multiticks_stop_timer(t);
        return -1;
    }

    resolution = (res.tv_sec * NANOSEC + res.tv_nsec) * 60 * NANOSEC + 1;

    timeout.it_value.tv_sec = resolution / NANOSEC;
    timeout.it_value.tv_nsec = resolution % NANOSEC;
    timeout.it_interval.tv_sec = resolution / NANOSEC;
    timeout.it_interval.tv_nsec = resolution % NANOSEC;

    if (timer_settime(sources[0].source, TIMER_RELTIME, &timeout, NULL) != 0) {
        perror("multiticks: timer_settime");
        fprintf(stderr, "multiticks: could not set test timer; disabling\n");
        multiticks_stop_timer(t);
        return -1;
    }

    if (timer_gettime(sources[0].source, &timeout) != 0) {
        perror("multiticks: timer_gettime");
        fprintf(stderr, "multiticks: could not get test timer; disabling\n");
        multiticks_stop_timer(t);
        return -1;
    }

    found = timeout.it_interval.tv_sec * NANOSEC + timeout.it_interval.tv_nsec;

    if (resolution != found) {
        fprintf(stderr, "multitics: interval not properly honored "
            "(set to %lld; found %lld); disabling\n",
            (long long)resolution, (long long)found);
        multiticks_stop_timer(t);
        return -1;
    }

    memset(&timeout, 0, sizeof (timeout));
    (void) timer_settime(sources[0].source, TIMER_RELTIME, &timeout, NULL);

    return 0;
}

static void multiticks_stop_timer(struct qemu_alarm_timer *t)
{
    struct qemu_alarm_multiticks *multiticks = t->priv;
    struct multitick_source *sources = multiticks->sources;
    int i;

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
        if (sources[i].source != -1)
            timer_delete(sources[i].source); 
    }

    qemu_vfree(multiticks);
    t->priv = NULL;
}

static struct multitick_source *multiticks_source(struct qemu_alarm_timer *t,
                                                  QEMUTimer *timer)
{
    struct qemu_alarm_multiticks *multiticks = t->priv;
    struct multitick_source *sources = multiticks->sources, *source;
    int64_t oldest = INT64_MAX;
    int i;

    /*
     * We have a dynamic check here against multiticks_enabled to allow it
     * to be dynamically disabled after the multiticks alarm timer has been
     * configured.  When disabled, multiticks should degenerate to an
     * implementation approximating that of dynticks, allowing for behavior
     * comparisons to be made without restarting guests.
     */
    if (!multiticks_enabled) {
        source = &sources[0];
        source->interval = 0;
    } else {
        if ((source = timer->source) != NULL && source->timer == timer) {
            /*
             * This timer still owns its source -- it wasn't stolen since last
             * being armed.
             */
            return (source);
        }

        /*
         * The source has either been stolen from the timer, or it was never
         * assigned; find a source and assign it.
         */
        for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
            if (sources[i].armed < oldest) {
                oldest = sources[i].armed;
                source = &sources[i];
            }
        }
    }

    trace_multiticks_assign(source->timer, source->source);

    assert(source != NULL);
    source->timer = timer;
    timer->source = source;

    return (source);
}

static void multiticks_reap(struct qemu_alarm_timer *t, int64_t now)
{
    struct qemu_alarm_multiticks *multiticks = t->priv;
    struct multitick_source *sources = multiticks->sources, *source;
    int multiplier = multiticks_reap_multiplier;
    struct itimerspec timeout;
    int64_t interval;
    int i;

    if (now - multiticks->reaped < multiticks_reap_threshold)
        return;

    memset(&timeout, 0, sizeof (timeout));

    for (i = 0; i < QEMU_MULTITICKS_NSOURCES; i++) {
        if (!(interval = sources[i].interval))
            continue;

        if (sources[i].armed + (multiplier * interval) > now)
            continue;

        source = &sources[i];
        trace_multiticks_reap(source->source, source->armed, interval);

        source->interval = 0;

        if (timer_settime(source->source, TIMER_RELTIME, &timeout, NULL) != 0) {
            perror("timer_settime");
            fprintf(stderr, "multiticks: internal reaping error; aborting\n");
            exit(1);
        }
    }

    multiticks->reaped = now;
}

static void multiticks_rearm_timer(struct qemu_alarm_timer *t, 
                                   int64_t nearest_delta_ns)
{
    struct multitick_source *source;
    struct itimerspec timeout;
    QEMUTimer *timer;
    int64_t when, interval;
    int64_t delta, low, high, now;

    assert(alarm_has_dynticks(t));

    /*
     * First we need to find the next timer to fire.
     */
    low = get_clock();
    // LEE - TODO: this is called previously, but we need the timer???
    delta = qemu_next_alarm_deadline(&timer);
    now = high = get_clock();

    if (delta < MIN_TIMER_REARM_NS)
        delta = MIN_TIMER_REARM_NS;

    multiticks_reap(t, now);

    if (timer == NULL)
        return;

    low += delta;
    high += delta;

    if (timer->clock->type == QEMU_CLOCK_REALTIME) {
        interval = timer->interval * 1000000;
    } else {
        interval = timer->interval;
    }

    if (interval < multiticks_tolerance_interval)
        interval = 0;

    source = multiticks_source(t, timer);

    if (interval && source->interval) {
        int64_t offset, fire;

        if (low < source->initial && source->initial < high) {
            /*
             * Our timer has not yet had its initial firing, which is already
             * scheduled to be within band; we have nothing else to do.
             */
            trace_multiticks_inband(source->timer, low, high, source->initial);
            source->armed = now;
            return;
        }

        offset = (low - source->initial) % source->interval;
        fire = low + (source->interval - offset);

        if (fire < high) {
            /*
             * Our timer is going to fire within our band of expectation; we
             * have nothing else to do.
             */
            trace_multiticks_inband(source->timer, low, high, fire);
            source->armed = now;
            return;
        }

        if (fire - high < multiticks_tolerance_jitter) {
            /*
             * Our timer is going to fire out of our band of expection, but
             * within our jitter tolerance; we'll let it ride.
             */
            trace_multiticks_inband(source->timer, low, high, fire);
            source->armed = now;
            return;
        }

        trace_multiticks_outofband(source->timer, low, high, fire);
    }

    /*
     * We don't actually know the precise (absolute) time to fire, so we'll
     * take the middle of the band.
     */
    when = low + (high - low) / 2;

    trace_multiticks_program(source->timer, when, interval);

    source->interval = interval;
    source->armed = interval ? now : 0;
    source->initial = when;
    timeout.it_value.tv_sec = when / NANOSEC;
    timeout.it_value.tv_nsec = when % NANOSEC;
    timeout.it_interval.tv_sec = interval / NANOSEC;
    timeout.it_interval.tv_nsec = interval % NANOSEC;

    if (timer_settime(source->source, TIMER_ABSTIME, &timeout, NULL) != 0) {
        perror("timer_settime");
        fprintf(stderr, "multiticks: internal timer error; aborting\n");
        exit(1);
    }
}
#endif /* defined(__sun__) */

#if defined(__linux__) || defined(__sun__)

#include "compatfd.h"

static int dynticks_start_timer(struct qemu_alarm_timer *t)
{
    struct sigevent ev;
    timer_t host_timer;
    struct sigaction act;

    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = host_alarm_handler;

    sigaction(SIGALRM, &act, NULL);

    /* 
     * Initialize ev struct to 0 to avoid valgrind complaining
     * about uninitialized data in timer_create call
     */
    memset(&ev, 0, sizeof(ev));
    ev.sigev_value.sival_int = 0;
    ev.sigev_notify = SIGEV_SIGNAL;
#ifdef SIGEV_THREAD_ID
    if (qemu_signalfd_available()) {
        ev.sigev_notify = SIGEV_THREAD_ID;
        ev._sigev_un._tid = qemu_get_thread_id();
    }
#endif /* SIGEV_THREAD_ID */
    ev.sigev_signo = SIGALRM;

#if defined(__sun__)
    if (timer_create(CLOCK_HIGHRES, &ev, &host_timer)) {
#else
    if (timer_create(CLOCK_REALTIME, &ev, &host_timer)) {
#endif
        perror("timer_create");

        /* disable dynticks */
        fprintf(stderr, "Dynamic Ticks disabled\n");

        return -1;
    }

    t->timer = host_timer;

    return 0;
}

static void dynticks_stop_timer(struct qemu_alarm_timer *t)
{
    timer_t host_timer = t->timer;

    timer_delete(host_timer);
}

static void dynticks_rearm_timer(struct qemu_alarm_timer *t,
                                 int64_t nearest_delta_ns)
{
    timer_t host_timer = t->timer;
    struct itimerspec timeout;
    int64_t current_ns;

    if (nearest_delta_ns < MIN_TIMER_REARM_NS)
        nearest_delta_ns = MIN_TIMER_REARM_NS;

    /* check whether a timer is already running */
    if (timer_gettime(host_timer, &timeout)) {
        perror("gettime");
        fprintf(stderr, "Internal timer error: aborting\n");
        exit(1);
    }
    current_ns = timeout.it_value.tv_sec * 1000000000LL + timeout.it_value.tv_nsec;
    if (current_ns && current_ns <= nearest_delta_ns)
        return;

    timeout.it_interval.tv_sec = 0;
    timeout.it_interval.tv_nsec = 0; /* 0 for one-shot timer */
    timeout.it_value.tv_sec =  nearest_delta_ns / 1000000000;
    timeout.it_value.tv_nsec = nearest_delta_ns % 1000000000;
    if (timer_settime(host_timer, 0 /* RELATIVE */, &timeout, NULL)) {
        perror("settime");
        fprintf(stderr, "Internal timer error: aborting\n");
        exit(1);
    }
}

#endif /* defined(__linux__) || defined(__sun__) */

#if !defined(_WIN32)

static int unix_start_timer(struct qemu_alarm_timer *t)
{
    struct sigaction act;

    /* timer signal */
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = host_alarm_handler;

    sigaction(SIGALRM, &act, NULL);
    return 0;
}

static void unix_rearm_timer(struct qemu_alarm_timer *t,
                             int64_t nearest_delta_ns)
{
    struct itimerval itv;
    int err;

    if (nearest_delta_ns < MIN_TIMER_REARM_NS)
        nearest_delta_ns = MIN_TIMER_REARM_NS;

    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 0; /* 0 for one-shot timer */
    itv.it_value.tv_sec =  nearest_delta_ns / 1000000000;
    itv.it_value.tv_usec = (nearest_delta_ns % 1000000000) / 1000;
    err = setitimer(ITIMER_REAL, &itv, NULL);
    if (err) {
        perror("setitimer");
        fprintf(stderr, "Internal timer error: aborting\n");
        exit(1);
    }
}

static void unix_stop_timer(struct qemu_alarm_timer *t)
{
    struct itimerval itv;

    memset(&itv, 0, sizeof(itv));
    setitimer(ITIMER_REAL, &itv, NULL);
}

#endif /* !defined(_WIN32) */


#ifdef _WIN32

static MMRESULT mm_timer;
static unsigned mm_period;

static void CALLBACK mm_alarm_handler(UINT uTimerID, UINT uMsg,
                                      DWORD_PTR dwUser, DWORD_PTR dw1,
                                      DWORD_PTR dw2)
{
    struct qemu_alarm_timer *t = alarm_timer;
    if (!t) {
        return;
    }
    if (alarm_has_dynticks(t) || qemu_next_alarm_deadline(NULL) <= 0) {
        t->expired = alarm_has_dynticks(t);
        t->pending = 1;
        qemu_notify_event();
    }
}

static int mm_start_timer(struct qemu_alarm_timer *t)
{
    TIMECAPS tc;
    UINT flags;

    memset(&tc, 0, sizeof(tc));
    timeGetDevCaps(&tc, sizeof(tc));

    mm_period = tc.wPeriodMin;
    timeBeginPeriod(mm_period);

    flags = TIME_CALLBACK_FUNCTION;
    if (alarm_has_dynticks(t)) {
        flags |= TIME_ONESHOT;
    } else {
        flags |= TIME_PERIODIC;
    }

    mm_timer = timeSetEvent(1,                  /* interval (ms) */
                            mm_period,          /* resolution */
                            mm_alarm_handler,   /* function */
                            (DWORD_PTR)t,       /* parameter */
                            flags);

    if (!mm_timer) {
        fprintf(stderr, "Failed to initialize win32 alarm timer: %ld\n",
                GetLastError());
        timeEndPeriod(mm_period);
        return -1;
    }

    return 0;
}

static void mm_stop_timer(struct qemu_alarm_timer *t)
{
    timeKillEvent(mm_timer);
    timeEndPeriod(mm_period);
}

static void mm_rearm_timer(struct qemu_alarm_timer *t, int64_t delta)
{
    int nearest_delta_ms = (delta + 999999) / 1000000;
    if (nearest_delta_ms < 1) {
        nearest_delta_ms = 1;
    }

    timeKillEvent(mm_timer);
    mm_timer = timeSetEvent(nearest_delta_ms,
                            mm_period,
                            mm_alarm_handler,
                            (DWORD_PTR)t,
                            TIME_ONESHOT | TIME_CALLBACK_FUNCTION);

    if (!mm_timer) {
        fprintf(stderr, "Failed to re-arm win32 alarm timer %ld\n",
                GetLastError());

        timeEndPeriod(mm_period);
        exit(1);
    }
}

static int win32_start_timer(struct qemu_alarm_timer *t)
{
    HANDLE hTimer;
    BOOLEAN success;

    /* If you call ChangeTimerQueueTimer on a one-shot timer (its period
       is zero) that has already expired, the timer is not updated.  Since
       creating a new timer is relatively expensive, set a bogus one-hour
       interval in the dynticks case.  */
    success = CreateTimerQueueTimer(&hTimer,
                          NULL,
                          host_alarm_handler,
                          t,
                          1,
                          alarm_has_dynticks(t) ? 3600000 : 1,
                          WT_EXECUTEINTIMERTHREAD);

    if (!success) {
        fprintf(stderr, "Failed to initialize win32 alarm timer: %ld\n",
                GetLastError());
        return -1;
    }

    t->timer = hTimer;
    return 0;
}

static void win32_stop_timer(struct qemu_alarm_timer *t)
{
    HANDLE hTimer = t->timer;

    if (hTimer) {
        DeleteTimerQueueTimer(NULL, hTimer, NULL);
    }
}

static void win32_rearm_timer(struct qemu_alarm_timer *t,
                              int64_t nearest_delta_ns)
{
    HANDLE hTimer = t->timer;
    int nearest_delta_ms;
    BOOLEAN success;

    nearest_delta_ms = (nearest_delta_ns + 999999) / 1000000;
    if (nearest_delta_ms < 1) {
        nearest_delta_ms = 1;
    }
    success = ChangeTimerQueueTimer(NULL,
                                    hTimer,
                                    nearest_delta_ms,
                                    3600000);

    if (!success) {
        fprintf(stderr, "Failed to rearm win32 alarm timer: %ld\n",
                GetLastError());
        exit(-1);
    }

}

#endif /* _WIN32 */

static void quit_timers(void)
{
    struct qemu_alarm_timer *t = alarm_timer;
    alarm_timer = NULL;
    t->stop(t);
}

int init_timer_alarm(void)
{
    struct qemu_alarm_timer *t = NULL;
    int i, err = -1;

    for (i = 0; alarm_timers[i].name; i++) {
        t = &alarm_timers[i];

        err = t->start(t);
        if (!err)
            break;
    }

    if (err) {
        err = -ENOENT;
        goto fail;
    }

    /* first event is at time 0 */
    atexit(quit_timers);
    t->pending = 1;
    alarm_timer = t;

    return 0;

fail:
    return err;
}

int qemu_calculate_timeout(void)
{
    return 1000;
}

