# UBP (UDP Based Protocol) — Reliable Datagram Transport Library Specification

**Version:** draft 1
**Scope:** A single-threaded, POSIX, reliable-unordered, multiplexed datagram
transport engine. It guarantees that every byte handed to it is delivered to the
peer uncorrupted and eventually, with per-stream reassembly and pluggable,
sender-local congestion control.

It is *only* a delivery engine. It does **not** own sockets, perform NAT
traversal, encrypt, or compute file hashes. Those are the caller's
responsibility (or the responsibility of a separate library built on top).

---

## 1. Design principles

1. **The library is a pure transport engine.** It transforms application
   messages into wire datagrams and back, manages reliability and congestion,
   and nothing else. All I/O, NAT traversal, socket options (`SO_REUSEPORT`,
   binding, hole punching), and key management live above it.

2. **No internal threads, no internal clock, no internal allocation in steady
   state.** The caller drives time via `tick(now)` and drives I/O via a
   `send_fn` callback and `recv()` entry point. The library is single-threaded
   *per connection*.

3. **Pluggable, sender-local congestion control via a vtable.** Congestion
   control is a struct of function pointers (`cc_ops_t`). Each algorithm
   (Reno, CUBIC, BBR, or user-supplied) is one such struct. The choice is
   per-connection and **never negotiated** — the receiver does not know or care
   which algorithm the sender runs.

4. **Encryption is the caller's responsibility, but the header is
   authenticated.** The library calls caller-supplied `seal`/`open` callbacks
   and passes the fixed header as Associated Data (AAD). A no-op seal/open gives
   a pure-cleartext mode for testing.

5. **Reliable, not ordered.** Every byte arrives, and corruption is caught (by
   the caller's AEAD tag). Bytes are reassembled per stream by offset, so a loss
   in one stream never head-of-line-blocks another. End-to-end integrity (e.g. a
   SHA-256 over a completed file) is an application concern, not the library's.

---

## 2. Threading and ownership model

### 2.1 One connection, one thread

A `conn_t` is owned by exactly one thread at a time. The library uses **no
locks**. Concurrency is achieved by running **N connections across N threads**,
each connection touched by a single thread (a sharded / thread-per-connection
model). Calling any function on the same `conn_t` from two threads concurrently
is undefined behavior.

This is the precise meaning of "thread-agnostic": the library imposes no
threading, but the caller must honor the one-connection-one-thread contract.

### 2.2 The event loop the caller runs

The library never blocks and never sleeps. The caller's loop drives it:

```c
for (;;) {
    int64_t now    = monotonic_ms();
    int64_t deadline = ubp_next_timeout(conn);   /* ms until next timer, or -1 */

    int timeout = clamp_to_poll(deadline - now);
    poll(&pfd, 1, timeout);                       /* caller owns the fd */

    if (pfd.revents & POLLIN) {
        n = recvfrom(fd, buf, sizeof buf, 0, ...);
        ubp_recv(conn, buf, n);                    /* feed inbound datagram */
    }

    ubp_tick(conn, now);                           /* fire due timers */

    /* drain app-level received messages */
    ubp_event_t ev;
    while (ubp_poll_event(conn, &ev) == UBP_OK) { handle(ev); }
}
```

- `ubp_next_timeout` returns when the library next needs `tick()` (the minimum of
  RTO, keepalive, idle, and any CC-internal timer such as BBR PROBE_RTT).
- `ubp_tick(now)` fires retransmissions, keepalives, and CC timers. `now` is a
  caller-supplied monotonic millisecond clock — which makes the whole library
  testable by advancing a fake clock, with no real sleeping.
- Outbound datagrams (ACKs, retransmits, keepalives, and the caller's own
  `send`s) are emitted through the `send_fn` callback, never by the library
  touching a socket.

---

## 3. The four boundaries (callbacks)

All caller integration happens through a `ubp_callbacks_t` passed at connection
creation. The library holds an opaque `void *user_ctx` it passes back to each.

```c
typedef int (*ubp_send_fn)(void *ctx,
                           const uint8_t *datagram, size_t len);

/* AEAD seal: encrypt `pt` with `aad` authenticated, write to `out`.
 * out has room for pt_len + caller's tag overhead. Returns 0 on success. */
typedef int (*ubp_seal_fn)(void *ctx,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt,  size_t pt_len,
                           uint8_t *out, size_t *out_len);

/* AEAD open: verify+decrypt `ct` with `aad`, write plaintext to `out`.
 * Returns 0 on success, nonzero if authentication fails (packet dropped). */
typedef int (*ubp_open_fn)(void *ctx,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct,  size_t ct_len,
                           uint8_t *out, size_t *out_len);

typedef struct {
    ubp_send_fn send;
    ubp_seal_fn seal;
    ubp_open_fn open;
    void       *user_ctx;
} ubp_callbacks_t;
```

Notes:

- **`send`** is how *all* outbound datagrams leave the library. The library never
  calls `sendto`. This keeps it transport-agnostic (could run over anything that
  carries datagrams) and testable (mock the wire).
- **`seal`/`open`** receive the **fixed header as AAD** (§5.3). The caller's
  implementation derives its own nonce — recommended: from `conn_id` +
  `seq_id` + a direction bit + an epoch, so nonces never repeat under one key
  (see §8). The library guarantees `seq_id` is unique and monotonic per
  connection, which is what makes a `seq_id`-derived nonce safe.
- **Tag overhead is the caller's.** The library asks `seal` how many bytes it
  produced (`out_len`) and budgets payload accordingly using a configured
  `crypto_overhead` value (§7).

---

## 4. Connection lifecycle

```
            send HELLO
  CLOSED  ───────────────▶  HELLO_SENT
                                 │ recv HELLO-ACK
                                 ▼
  recv HELLO            ┌── ESTABLISHED ──┐
  CLOSED ──▶ send       │  data + acks    │
            HELLO-ACK   │  flow / cc      │
                        └────────┬────────┘
                                 │ local close → send BYE (half-close: stop
                                 ▼              sending DATA, keep ACKing)
                            CLOSING
                                 │ recv BYE (peer acks the close)
                                 ▼
                              CLOSED
```

### 4.1 HELLO / HELLO-ACK

The initiator sends `HELLO` carrying:

- protocol `version`
- the `conn_id` it assigns to this connection (4 bytes, §1)
- its initial **flow-control window** (receive-buffer bytes it will accept)

The responder replies `HELLO-ACK` echoing `version` and `conn_id` and
advertising **its** initial flow-control window. After HELLO-ACK the connection
is `ESTABLISHED`.

Congestion control is **not** in the handshake — it is sender-local. `stream_id`
and `seq_id` spaces start fresh per connection.

### 4.2 Graceful close (half-close, TCP-style)

`BYE` is a control-stream message. Peer A sends `BYE` and half-closes: it stops
sending new DATA but continues to receive and ACK so in-flight data from B can
still be acknowledged and retransmitted. When B has finished, B sends its own
`BYE`. Once a peer has both sent and received a `BYE`, it transitions to
`CLOSED`.

### 4.3 Liveness — KEEPALIVE (core, not CC)

KEEPALIVE detects a peer that died without a `BYE`. It lives in the **core** so
it works regardless of which CC algorithm is loaded.

- If no datagram has been *received* for `keepalive_idle` ms, send a
  `KEEPALIVE`.
- If, after sending, no datagram arrives within `keepalive_timeout` ms (across
  `keepalive_max_probes` probes), the connection is declared dead and reported
  via an error event.

Both timers are configurable (§7). **PROBE_RTT is a separate, BBR-internal
mechanism (§6.4) and must not be confused with KEEPALIVE.**

---

## 5. Wire format

### 5.1 MTU budget

Fixed conservative MTU, **no Path-MTU discovery**:

```
MAX_DATAGRAM = 1280 bytes   (safe minimum IPv6 MTU)
```

The library never emits a datagram larger than 1280 bytes. Messages larger than
the per-packet payload budget are fragmented across DATA packets by offset
(§5.4). The caller does not have to pre-chunk, though for files it typically
already does at the application layer.

### 5.2 Fixed header (authenticated as AAD)

Every datagram begins with the same fixed header. It is sent in **network byte
order (big-endian)** and the **exact wire bytes are fed as AAD** to `seal`/`open`.

```
 offset  size  field        notes
 ───────────────────────────────────────────────────────────────
   0       8   seq_id       connection-global packet number.
                            Monotonic. The nonce source. The unit ACKed.
   8       4   conn_id      connection/session id for state lookup.
  12       2   stream_id    logical stream. 0 = control stream.
  14       1   type         packet type (§5.5).
  15       1   flags        bit0 STREAM_FIN, others reserved = 0.
  16       2   length       total datagram length in bytes (header+body).
                            Cross-checked against the datagram actually
                            received; mismatches are dropped before crypto.
  18       2   reserved     = 0 (alignment / future use).
 ───────────────────────────────────────────────────────────────
        20  bytes header (= AAD span)
```

After the header comes the **sealed body**: `seal(aad = these 20 bytes,
pt = body_plaintext)`. The body's plaintext layout depends on `type` (§5.4–5.6).

Endianness/AAD invariant (learned the hard way): **the bytes serialized to the
wire are exactly the bytes fed as AAD.** Serialize all multi-byte fields to
big-endian *before* sealing; on receive, feed the raw wire header to `open`
*before* converting any field back to host order. One-byte fields (`type`,
`flags`) are never swapped.

### 5.3 What is encrypted vs. authenticated

- **Header (20 bytes):** cleartext on the wire, **authenticated** as AAD. It must
  be readable before `open` (it carries `conn_id` for state/key lookup and
  `seq_id` for the nonce), so it cannot itself be encrypted — but tampering is
  detected because the body's tag covers it as AAD.
- **Body:** **encrypted and authenticated** by the caller's AEAD.

### 5.4 DATA body

`type = DATA`. The per-stream byte offset lives **inside the encrypted body**,
not in the header — it is only meaningful for DATA, and keeping it out of the
header keeps the header fixed-size for every packet type.

```
 encrypted body plaintext:
   offset  8   stream_offset   byte position of this chunk within its stream
   ...     N   payload         application bytes (N = up to payload budget)
```

The receiver demultiplexes by `stream_id`, then places `payload` at
`stream_offset` in that stream's sparse reassembly buffer. A `STREAM_FIN` flag
on the final DATA packet of a stream marks its total length.

**Payload budget per DATA packet:**

```
payload_max = MAX_DATAGRAM (1280)
            - HEADER (20)
            - STREAM_OFFSET (8)
            - crypto_overhead     (caller's AEAD tag, e.g. 16 for Poly1305)
```

With a 16-byte tag: `1280 - 20 - 8 - 16 = 1236` payload bytes per packet.

### 5.5 Packet types

```
HELLO       connection open (initiator)        control stream
HELLO_ACK   connection open ack (responder)    control stream
BYE         graceful half-close                control stream
KEEPALIVE   liveness probe                     control stream
ACK         acknowledgement (§5.6)             control stream
DATA        stream payload (§5.4)              any stream >= 1
```

Exact numeric values are assigned in `protocol.h`; they are not
wire-order-sensitive (single byte).

### 5.6 ACK body — QUIC-style ranges, varint-encoded

ACKs use **ascending-described, descending-encoded ranges** rather than a
fixed-width bitmask. This removes any window ceiling: a bitmask would cap
outstanding packets at 64, throttling throughput before congestion control ever
engaged — fatal for a protocol whose purpose is high-BDP performance. Ranges
describe arbitrary gap patterns compactly.

All ACK fields are **QUIC-style variable-length integers** (1/2/4/8 bytes by
magnitude) to keep ACKs small, since they compete with data on the return path.

```
 encrypted ACK body plaintext (all varint unless noted):
   largest_acked       highest seq_id received
   ack_delay           microseconds between receiving largest_acked and
                       sending this ACK (for RTT correction)
   recv_window         bytes free in receiver's reassembly buffer
                       (flow control — see §6.5)
   range_count         number of additional ranges that follow
   first_range_len     contiguous run of acked seq_ids ending at largest_acked
   repeat range_count times, walking downward:
       gap             count of missing (unacked) seq_ids
       range_len       count of acked seq_ids before the gap
```

- The decoder reconstructs acked/missing spans by walking down from
  `largest_acked`.
- **Max ranges per ACK: 64.** If loss is so fragmented that more than 64 holes
  exist, the top 64 (nearest `largest_acked`) are encoded; the rest are reported
  in subsequent ACKs. 64 ranges fits comfortably within the 1280-byte budget.
- `ack_delay` lets the sender subtract receiver-side processing latency from its
  RTT sample (§6.2).
- `recv_window` is the receiver-advertised flow-control window (§6.5).

### 5.7 ACK transmission policy

The receiver does not ACK every packet. An ACK is sent when any of:

1. **Threshold:** every 2 received DATA packets, or
2. **Gap:** immediately when an out-of-order arrival creates or extends a hole
   (so the sender learns of loss fast), or
3. **Idle flush:** if a packet arrived and no further packet arrives within
   `ack_idle_flush` ms (default 20), flush an ACK to release sender state.

---

## 6. Reliability and congestion engine (core)

### 6.1 Sender state

- **Retransmit buffer:** a bounded pool of in-flight packets (§7). Each entry
  holds the **already-sealed datagram bytes** plus metadata (`seq_id`, send
  timestamp, retransmit count, the `stream_id`/`stream_offset` it carries).
- **Encrypt-once rule:** a packet is sealed exactly once; retransmission resends
  the **identical cached bytes**. The library never re-seals a retransmit. This
  guarantees the caller's nonce (derived from `seq_id`) is never reused with
  differing plaintext — the single most important crypto-safety invariant, and
  the reason sealing is the library's job to *schedule* even though the crypto
  is the caller's.
- **In-flight cap:** `bytes_in_flight <= min(cwnd, retransmit_buffer_capacity)`.
  `cwnd` is dynamic (CC-owned, §6.3). The buffer capacity is a fixed configured
  ceiling. If the buffer is smaller than the bandwidth-delay product, **the
  buffer, not CC, caps throughput** — the config documents this so users size it
  deliberately.

### 6.2 RTT estimation (Jacobson/Karels)

On each ACK that newly acknowledges a packet:

```
rtt      = now - send_time(largest_newly_acked) - ack_delay
srtt     = (1 - 1/8) * srtt   + (1/8) * rtt
rttvar   = (1 - 1/4) * rttvar + (1/4) * |srtt - rtt|
rto      = srtt + 4 * rttvar          (clamped: min 10 ms, max 2000 ms)
```

`ack_delay` (from §5.6) removes receiver processing time from the sample.
Karn's algorithm applies: do not take RTT samples from retransmitted packets.

### 6.3 Congestion-control vtable

CC is a struct of function pointers. The core calls these; the algorithm owns
its private state. The contract is stable — adding an algorithm never changes
core code.

```c
typedef struct {
    int64_t   now_ms;             /* current time */
    uint64_t  bytes_acked;        /* newly acked bytes this event */
    uint64_t  bytes_in_flight;    /* before applying this ack */
    uint32_t  rtt_ms;             /* latest sample (0 if none this event) */
    uint32_t  srtt_ms;
    /* delivery-rate sample (for BBR); valid if delivered_bytes > 0 */
    uint64_t  delivered_bytes;    /* bytes delivered over the sample interval */
    int64_t   sample_interval_us; /* duration of that interval */
} cc_ack_event_t;

typedef struct {
    int64_t   now_ms;
    uint64_t  bytes_lost;
    uint64_t  bytes_in_flight;
    uint64_t  largest_lost_seq;
} cc_loss_event_t;

typedef struct cc_ops {
    /* allocate + init private state; return it (or NULL on failure) */
    void    *(*create)(const void *cfg);
    void     (*on_ack) (void *st, const cc_ack_event_t *ev);
    void     (*on_loss)(void *st, const cc_loss_event_t *ev);
    /* the core consults these to decide how much / how fast to send */
    uint64_t (*cwnd)        (void *st);  /* in-flight cap in bytes */
    uint64_t (*pacing_rate) (void *st);  /* bytes/sec; UINT64_MAX = unpaced */
    /* optional periodic hook (e.g. BBR PROBE_RTT); may be NULL */
    void     (*on_tick)(void *st, int64_t now_ms);
    void     (*destroy)(void *st);
} cc_ops_t;
```

The `cc_ack_event_t` carries the **union** of what any algorithm needs:
Reno/CUBIC use `bytes_acked` + loss signals; BBR additionally uses the
delivery-rate sample (`delivered_bytes` / `sample_interval_us`) and the min-RTT.
Designing this event to satisfy every algorithm is what makes the vtable a clean
seam rather than a leaky one.

A connection picks its ops at creation: `cfg.cc = &bbr_ops;` (or `&cubic_ops`,
`&reno_ops`, or a user struct). Two peers may run different algorithms; neither
needs to know the other's choice.

### 6.4 BBR specifics (lives entirely inside `bbr.c`)

- **Delivery rate:** `delivered_bytes / sample_interval` over a recent window of
  ACKs. The core supplies the raw sample in `cc_ack_event_t`; BBR maintains the
  windowed max.
- **RTprop:** the minimum RTT observed over a sliding window (~10 s) — the
  physical path delay without queue.
- **BDP target:** `bytes_in_flight` capped at `delivery_rate * RTprop`.
- **PROBE_RTT:** periodically (~every 10 s) BBR drops the in-flight target to a
  minimal value for a short interval to re-measure RTprop without standing
  queue. This is driven from `on_tick`, is internal to BBR, and has nothing to
  do with KEEPALIVE.

Reno/CUBIC implement the same vtable but return `UINT64_MAX` from `pacing_rate`
(unpaced) and ignore the delivery-rate fields.

### 6.5 Flow control (distinct from congestion control)

Congestion control protects the *network*; flow control protects the *receiver's
buffer*. They are independent and both apply:

```
bytes_in_flight <= min(cwnd, recv_window, retransmit_buffer_capacity)
```

`recv_window` is advertised by the receiver in every ACK (§5.6) as the free
bytes in its reassembly buffer. A sender must not send data that would exceed the
peer's advertised window even if its cwnd is larger. The receiver re-advertises a
larger window as the application drains delivered data.

### 6.6 Loss detection and fast retransmit

A packet is considered lost (without waiting for its RTO) when an ACK shows it
unacked while at least 3 packets with **higher** `seq_id` have been acked
(packet-reordering-threshold = 3, QUIC-style). On detection:

- mark the packet lost, feed `on_loss`,
- re-queue its **cached sealed bytes** for transmission with a fresh send
  timestamp (a retransmit reuses the original `seq_id` — see the encrypt-once
  rule; the nonce is therefore identical, but so are the bytes, so this is safe).

If no ACK arrives at all, the RTO timer (§6.2) triggers retransmission of the
oldest unacked packet and signals `on_loss`.

> **Retransmit & `seq_id` note.** Because a retransmit reuses the original
> `seq_id` (and thus the original nonce and the original sealed bytes), the
> ACK accounting must treat "received" as a property of the `seq_id`, not of a
> physical transmission. This is consistent with reusing `seq_id` as the nonce.
> (An alternative QUIC-style design assigns a *new* packet number to each
> retransmission and never reuses a number; that decouples the nonce from
> retransmission entirely but requires a separate frame-level notion of "which
> stream bytes" independent of packet number. UBP draft 1 chooses
> seq-reuse + byte-identity for simplicity; revisit if you later want
> per-transmission RTT samples on retransmits.)

---

## 7. Configuration

All knobs are set at connection creation via a `ubp_config_t`. Defaults chosen
for general use; documented formulas let users tune deliberately.

```c
typedef struct {
    /* identity */
    uint32_t conn_id;                 /* initiator assigns; 0 = auto */
    uint8_t  version;

    /* congestion control (sender-local) */
    const cc_ops_t *cc;               /* &bbr_ops by default */
    const void     *cc_cfg;           /* algorithm-specific config, may be NULL */

    /* crypto budgeting (the library does not encrypt; this is the tag size) */
    size_t   crypto_overhead;         /* bytes seal() adds; e.g. 16 */

    /* memory ceilings (hybrid: pools hot, heap cold) */
    size_t   retransmit_buffer_bytes; /* default 4 MiB; range 256 KiB–64 MiB */
    size_t   recv_buffer_bytes;       /* default 2 MiB; bounds flow-control win */
    uint16_t max_streams;             /* default 256; max 65535 */
    uint8_t  max_ack_ranges;          /* default 64 */

    /* timers (ms) */
    uint32_t ack_idle_flush_ms;       /* default 20 */
    uint32_t keepalive_idle_ms;       /* default 15000 */
    uint32_t keepalive_timeout_ms;    /* default 5000 */
    uint8_t  keepalive_max_probes;    /* default 3 */
    uint32_t rto_min_ms;              /* default 10 */
    uint32_t rto_max_ms;              /* default 2000 */
} ubp_config_t;
```

**Sizing the retransmit buffer (the throughput knob).**

```
retransmit_buffer_bytes  >=  target_bandwidth (bytes/s) * max_RTT (s)
```

Examples:

| Link target              | BDP            | Recommended buffer |
|--------------------------|----------------|--------------------|
| 100 Mbps @ 100 ms RTT    | ~1.25 MB       | 4 MB (default) ✓   |
| 1 Gbps @ 50 ms RTT       | ~6.25 MB       | 8–16 MB            |
| 1 Gbps @ 200 ms RTT      | ~25 MB         | 32 MB              |
| embedded / low-rate      | small          | 256–512 KB         |

If this is set below the BDP, it — not the CC algorithm — becomes the throughput
ceiling, which would invalidate any Reno-vs-CUBIC-vs-BBR comparison.

**Memory model (hybrid).**

| Resource                         | Allocation                         |
|----------------------------------|------------------------------------|
| Retransmit buffer (in-flight)    | pool, sized at create from config  |
| Per-stream reassembly (sparse)   | heap, bounded by `recv_buffer_bytes`|
| Stream table                     | small pool, grows to heap to max   |
| ACK range scratch                | fixed, `max_ack_ranges`            |

---

## 8. Nonce guidance for the caller (informative)

The library guarantees `seq_id` is unique and monotonic per connection and never
re-seals differing bytes under the same `seq_id`. To exploit that safely, the
caller's `seal`/`open` should build the AEAD nonce so it never repeats under one
key — e.g. for a 24-byte XChaCha nonce:

```
nonce = [ 1B direction | 7B conn_epoch | 8B seq_id | 8B zero ]
```

- `direction` distinguishes the two peers, which share a session key but each
  start `seq_id` at 0.
- `conn_epoch` changes on rekey/re-establishment under the same long-term key.
- `seq_id` is the per-packet counter from the header.

The trailing bytes must be **set to zero**, not left uninitialized — the AEAD
reads the full nonce width on both sides and they must match exactly. The nonce
must be reconstructed identically by sender and receiver; build it from the
**host-order** `seq_id` on both sides.

This is guidance, not library code — the library only passes the header as AAD
and trusts the caller's seal/open.

---

## 9. Public API (sketch)

```c
/* lifecycle */
int  ubp_create(ubp_conn_t **out, const ubp_config_t *cfg,
                const ubp_callbacks_t *cb, ubp_role_t role);
int  ubp_connect(ubp_conn_t *c);          /* initiator: send HELLO */
int  ubp_close(ubp_conn_t *c);            /* begin graceful BYE */
void ubp_destroy(ubp_conn_t *c);

/* streams */
int  ubp_stream_open(ubp_conn_t *c, uint16_t *out_stream_id);
int  ubp_send(ubp_conn_t *c, uint16_t stream_id,
              const uint8_t *data, size_t len, int fin);
              /* copies into retransmit buffer; returns UBP_EWOULDBLOCK if
                 the send window (cwnd/recv_window/buffer) is full */

/* inbound datagram from the caller's socket */
int  ubp_recv(ubp_conn_t *c, const uint8_t *datagram, size_t len);

/* drive time; returns ms until next needed tick, or -1 if none */
int64_t ubp_next_timeout(ubp_conn_t *c);
int  ubp_tick(ubp_conn_t *c, int64_t now_ms);

/* drain delivered data / events (borrowed buffers, valid until next call) */
typedef enum { UBP_EV_DATA, UBP_EV_STREAM_FIN, UBP_EV_CLOSED, UBP_EV_ERROR } ubp_ev_kind_t;
typedef struct {
    ubp_ev_kind_t kind;
    uint16_t      stream_id;
    const uint8_t *data;   /* borrowed; copy if needed past next call */
    size_t        len;
    int           error;   /* UBP_EV_ERROR: an error code from §10 */
} ubp_event_t;
int  ubp_poll_event(ubp_conn_t *c, ubp_event_t *out);  /* UBP_OK / UBP_EAGAIN */

/* observability (for measuring BBR vs CUBIC) */
typedef struct {
    uint64_t bytes_in_flight, cwnd, pacing_rate;
    uint32_t srtt_ms, rttvar_ms, rto_ms, min_rtt_ms;
    uint64_t delivery_rate;        /* bytes/s, BBR */
    uint64_t pkts_sent, pkts_acked, pkts_lost, pkts_retransmitted;
    uint32_t recv_window;
} ubp_stats_t;
int  ubp_get_stats(ubp_conn_t *c, ubp_stats_t *out);
```

### Buffer ownership

- **Send:** the library **copies** the payload into the retransmit buffer (which
  it must hold until ACKed anyway), so the caller's buffer is free the instant
  `ubp_send` returns. No borrow footgun on the send path.
- **Receive:** `ubp_poll_event` hands a **borrowed** pointer valid only until the
  next `ubp_poll_event`/`ubp_recv`/`ubp_tick` call on that connection. The caller
  copies it out if it needs it longer. This is the one place a borrow saves a
  real copy on the hot path.

---

## 10. Error handling

All entry points return an `int`: `UBP_OK` (0), `UBP_EAGAIN`/`UBP_EWOULDBLOCK`
for non-error retry conditions, or a negative `ubp_err_t`. Errors are *reported*,
never silently swallowed.

```c
typedef enum {
    UBP_OK              =  0,
    UBP_EAGAIN          =  1,   /* no event ready (poll), non-error */
    UBP_EWOULDBLOCK     =  2,   /* send window full, retry later, non-error */

    UBP_ERR_INVAL       = -1,   /* bad argument */
    UBP_ERR_NOMEM       = -2,   /* allocation / pool exhausted */
    UBP_ERR_STATE       = -3,   /* operation invalid in current conn state */
    UBP_ERR_TOO_LARGE   = -4,   /* message exceeds limits */
    UBP_ERR_STREAMS     = -5,   /* max_streams reached */
    UBP_ERR_AUTH        = -6,   /* open() rejected a datagram (also dropped) */
    UBP_ERR_PROTO       = -7,   /* malformed datagram / length mismatch */
    UBP_ERR_CLOSED      = -8,   /* connection closed */
    UBP_ERR_TIMEOUT     = -9,   /* keepalive/idle: peer declared dead */
    UBP_ERR_CALLBACK    = -10,  /* a user callback returned failure */
} ubp_err_t;

const char *ubp_strerror(int err);
```

Datagram-level faults that should not kill the connection (`UBP_ERR_AUTH` on a
single forged/corrupt packet, `UBP_ERR_PROTO` on a malformed one) cause the
packet to be **dropped** and, where relevant, surfaced as an `UBP_EV_ERROR`
event without tearing down the connection. Fatal conditions (`UBP_ERR_TIMEOUT`,
peer `BYE`) move the connection to `CLOSED` and emit `UBP_EV_CLOSED`.

---

## 11. Out of scope (explicit non-goals)

- **NAT traversal / hole punching / STUN / rendezvous.** The caller (or a
  separate library) does this and hands UBP a working `send_fn` plus inbound
  datagrams.
- **Socket ownership & options** (`SO_REUSEPORT`, bind, connect). Caller's.
- **Encryption & key management.** Caller's, via seal/open.
- **File hashing / end-to-end integrity proof.** Application's (e.g. SHA-256 over
  the reassembled file). The library guarantees byte-faithful delivery; the app
  verifies the whole artifact.
- **Path MTU discovery.** Fixed 1280-byte datagrams.
- **Ordered cross-stream delivery.** Deliberately not provided; per-stream
  reassembly avoids head-of-line blocking.

---

## 12. Module layout (suggested)

```
core/
  conn.c        connection state machine, lifecycle, dispatch
  wire.c        header serialize/parse, AAD assembly, seal/open invocation
  reliability.c retransmit buffer, ACK range encode/decode, loss detection, RTO
  stream.c      stream table, sparse reassembly, flow-control accounting
  timers.c      next_timeout / tick: RTO, keepalive, ack-flush, cc on_tick
cc/
  cc.h          cc_ops_t, cc_ack_event_t, cc_loss_event_t (the stable contract)
  reno.c        reno_ops
  cubic.c       cubic_ops
  bbr.c         bbr_ops  (delivery rate, RTprop, PROBE_RTT)
include/
  ubp.h         public API (§9)
  protocol.h    wire constants, types, sizes
```

The `cc/cc.h` contract is the firewall: `core/` depends on it, the algorithms
implement it, and neither side changes when the other does. That is the
structural answer to "I don't want to untangle spaghetti on every change."
