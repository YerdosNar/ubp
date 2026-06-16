/*
 * cc.h - UBP Congestion Control (the pluggable vtable).
 *
 * This is the architectural firewall of the library. core/ depends ONLY on the
 * types declared here; each algorithm (stub, reno, cubic, bbr, or a caller's
 * own) is a `const ubp_cc_ops_t` that implements them. Neither side changes
 * when the other does.
 *
 * Key properties:
 *      - Congestion Control is SENDER-LOCAL and never negotiated. The two peers
 *        may run entirely different algorithms; the receiver only sends ACKs and
 *        does not know or care which algorithm the sender uses.
 *      - The algorithm owns an opaque per-connection state blob. THe core never
 *        looks inside it; it only passes it back to each op.
 *      - The even structs carry UNION of what any algorithm needs, so the
 *        contract does not change when a new algorithm is added. Reno/CUBIC use
 *        the ack/loss byte counts; BBR additionally uses the delivery-rate sample
 *        and the min-RTT. Fields an algorithms does not need are simply ignored.
 *
 * This header contains NO logic - only types and the vtable
 */

#ifndef UBP_CC_H
#define UBP_CC_H

#include <stddef.h>
#include "typedefs.h"

/* SENTINELS */

/*
 * Returned by pacing_rate() to mean "do not pace" - send as fast as CWND allows.
 * Loss-based algorithms (Reno, CUBIC) are not rate-paced and return this;
 * BBR returns a real bytes/second rate.
 */
#define UBP_PACING_UNLIMITED    UINT64_MAX

/* EVENT: an ACK newly acknowledged some data */

/*
 * Delivered to on_ack() once per processed ACK that advances acknowledgement.
 * The core computes these from its reliability state and the ACK body.
 *
 * RTT fields:
 *      - rtt_ms is the latest raw sample for THIS ack, already corrected by the
 *        peer's reported ack_delay. It is 0 if no clean sample was available this
 *        event (e.g. only retransmitted packets were acked - Karn's algorithm
 *        see `rtt_valid`).
 *      - rtt_valid is 0 precisely when Karn's algorithm suppressed the sample
 *        (the acked packet had been retransmitted, so its RTT is ambiguous). An
 *        algorithms MUST NOT update its RTT estimators from an event with
 *        rtt_valid == 0.
 *      - srtt_ms / min_rtt_ms are the core's smoothed and windowed-minimum RTTs,
*        provided for convenience (BBR's RTprop tracking can use min_rtt_ms).
 *
 * Delivery-rate same (for BBR; ignore in loss-based algorithms):
 *      - delivered_bytes is the number of bytes the peer newly acknowledged over
 *        the sameple interval, and sample_interval_us is that interval's duration.
 *        delivery_rate = delivered_bytes / sample_interval (bytes/sec). The
 *        sample is valid only if sample_interval_us > 0.
 */
typedef struct {
        u64     now_ms;            /* current monotonic time (ms)             */
        u64     bytes_acked;       /* newly acked bytes this event            */
        u64     bytes_in_flight;   /* in flight BEFORE applying this ack      */
        u32     rtt_ms;            /* latest sample (ack_delay-corrected)     */
        u32     srtt_ms;           /* core's smoothed                         */
        u32     min_rtt_ms;        /* core's windowed-min RTT(RTprop input)   */
        u8      rtt_valid;         /* 0 => Karn suppressed; do not sample RTT */
        u64     delivered_bytes;   /* bytes delivered over the sample windows */
        u64     sample_interval_us;/* duration of that windows (us); 0 => none*/
} ubp_cc_ack_event_t;

/* EVENT: loss was detected */

/*
 * Delivered to on_loss() when the reliability layer one or more packets
 * lost, whether by fast-retransmit (3 higher seq_ids acked past a hole) or by
 * RTO expiry. An algorithm reacts by reducing CWND / changing state.
 */
typedef struct {
        i64     now_ms;
        u64     bytes_lost;      /* bytes in the packets just declared lost    */
        u64     bytes_in_flight; /* in flight at the moment of detection       */
        u64     largest_lost_seq;/* highest seq_id among the lost packets      */
        u8      is_rto;          /* 1 => RTO timeout, 0 => fast restransmit    */
} ubp_cc_loss_event_t;

/* VTABLE */

/*
 * One instance per algorithm, exported as a `const ubp_cc_ops_t`. A connection
 * selects it at creation via config. All function pointers except on_tick are
 * REQUIRED (must be non-NULL); on_tick may be NULL for algorithms with no
 * periodic behaviour (Reno, CUBIC). The stub and BBR use it.
 *
 * Lifecycle:
 *      st = create(cfg)                once, at connection setup
 *      on_ack / on_loss / on_tick      many times, during the connection
 *      cwnd / pacing_rate              consulted by the core before each send
 *      destroy(st)                     once, at connection teardown
 *
 * Threading: all calls for one connection happen on that connection's single owning thread. Implementations need no internal locking.
 */
typedef struct ub_cc_ops {
        /*
         * Allocate and initialize per-connection state. `cfg` is the
         * algorithm-specific config pointer from ubp_config_t.cc_cfg (may be
         * NULL for algorithms that take defaults). Returns the state pointer,
         * or NULL or allocation failure.
         */
        void   *(*create)(const void *cfg);

        /* React to newly acked data */
        void    (*on_ack)(void *st, const ubp_cc_ack_event_t *ev);

        /* React to detected loss */
        void    (*on_loss)(void *st, const ubp_cc_loss_event_t *ev);

        /*
         * Current congestion window: the maximum bytes the sender may keep in
         * flight, as far as the NETWORK is concerned. The core additionally
         * clamps to the receiver's flow-control window and the retransmit-
         * buffer capacity; the effective cap is the max of all three.
         */
        u64     (*cwnd)(void *st);

        /*
         * Desired pacing rate in bytes/second, or UBP_PACING_UNLIMITED to send
         * as fast as cwnd permits. BBR returns a real rate; loss-based algorithms
         * return UBP_PACING_UNLIMITED.
         */
        u64     (*pacing_rate)(void *st);

        /*
         * Optional periodic hook, called from the core's tick() at (at least)
         * the cadence implied by next_tick_in_ms(). Used by BBR for PROBE_RTT
         * scheduling. MAY be NULL.
         */
        void    (*on_tick)(void *st, i64 now_ms);

        /*
         * Optional: how long until on_tick next needs to run, in ms from now_ms,
         * or a negative value if no timer is pending. Lets the core fold.
         * CC timers into tis overall next_timeout computation. MAY be NULL
         * (treated as "no pending CC timer").
         */
        i64     (*next_tick_in_ms)(void *st, i64 now_ms);

        /* Free state allocated by create(). */
        void    (*destroy)(void *st);
} ubp_cc_ops_t;

/* Built-in algorithms (exported by their respective .c files) */

/*
 * Fixed-window stub: always advertises a constant cwnd, never paces, ingores
 * loss. Exists to bring the whole data path up (and for determinstic tests)
 * before a real algorithms is wired in. NOT for production use.
 */
extern const ubp_cc_ops_t ub_cc_stub;

/* Classic loss-based algorithms */
extern const ubp_cc_ops_t ubp_cc_reno;
/* extern const ubp_cc_ops_t ubp_cc_cubic;*/
/* extern const ubp_cc_ops_t ubp_cc_bbr;*/

/*
 * Passed as ubp_config_t.cc_cfg when the stub is selected. NULL => default of
 * UBP_CC_STUB_DEFAULT_CWND bytes.
 */
#define UBP_CC_STUB_DEFAULT_CWND (64u * 1024u)

typedef struct {
        u64     fixed_cwnd;     /* bytes; 0 => UBP_CC_STUB_DEFAULT_CWND         */
} ubp_cc_stub_cfg_t;

/*
 * Passed as cc_cfg when a Reno is selected. NULL => sane defaults. All sizes are
 * in bytes; the algorithms works in byte units (not packets) to stay agnostic
 * to payload size.
 */
typedef struct {
        u64     init_cwnd;      /* initial window; 0 => 10 * mss-ish            */
        u64     min_cwnd;       /* floow; 0 => 2 * miss-ish                     */
        u32     mss;            /* segment size used for growth; 0 => 1200      */
} ubp_cc_reno_cfg_t;

#endif /* UBP_CC_H */
