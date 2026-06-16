/*
 * protocol.h - UBP (UDP Based Protocol) wire contract.
 *
 * This header defines the on-wire format and the constants every other module
 * depends on. It contains NO logic - only types, sizes, and the packet header.
 *
 */

#ifndef UBP_PROTOCOL_H
#define UBP_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* TYPEDEFS for ease of use */
typedef uint64_t        u64;
typedef uint32_t        u32;
typedef uint16_t        u16;
typedef uint8_t         u8;

typedef int64_t         i64;
typedef int32_t         i32;
typedef int16_t         i16;
typedef int8_t          i8;

/* Protocol version */
#define UBP_VERSION             0x01

/* DATAGRAM AND HEADER SIZING */

/*
 * Fixed conservative MTU. No Path-MTU discovery is performed; the library never
 * emits a datagram larger than this. 1280 is the guaranteed minimum IPv6 MTU,
 * so a UBP datagram survives any conformat IPv6 path without fragmentation.
 */
#define UBP_MAX_DATAGRAM        1280

/* Fixed header length, in bytes. This is also the AAD span. */
#define UBP_HEADER_SZ           20

/*
 * Per-DATA-packet prefix inside the encrypted body: the 8-byte stream_offset
 * (see ubp_data_body below). It lives INSIDE the sealed body, not in the header,
 * because it is only meaningful for DATA and keeps the header fixed-size for
 * every packet type.
 */
#define UBP_DATA_PREFIX_SZ

/*
 * Maximum application payload carried by a single DATA packet, given a caller
 * AEAD tag of `overhead` bytes. Use the macro with the configured
 * crypto_overhead; UBP_MAX_PAYLOAD_TAG16 is the common case (Poly1305/GCM).
 *
 * payload = MTU - header - data_prefix - aead_tag
 */
#define UBP_MAX_PAYLOAD(overhead) \
        (UBP_MAX_DATAGRAM - UBP_HEADER_SZ - UBP_DATA_PREFIX_SZ - (overhead))

#define UBP_MAX_PAYLOAD_TAG16   UBP_MAX_PAYLOAD(16) /* == 1236 */

/* STREAM IDENTIFIERS */

/*
 * stream_id 0 is reserved for the control stream: HELLO, HELLO_ACK, BYE,
 * KEEPALIVE, and ACK all ride on it. Application data streams are >= 1.
 */
#define UBP_STREAM_CONTROL      0
#define UBP_STREAM_FIRST_APP    1
#define UBP_STREAM_MAX          0xFFFF

/* PACKET TYPES */
typedef enum {
        UBP_PKT_HELLO           = 0x01, /* initiator: open connection   */
        UBP_PKT_HELLO_ACK       = 0x02, /* responder: accept connection */
        UBP_PKT_BYE             = 0x03, /* graceful half-close          */
        UBP_PKT_KEEPALIVE       = 0x04, /* liveness probe (core, not CC)*/
        UBP_PKT_ACK             = 0x05, /* ack (QUIC-style ranges)      */
        UBP_PKT_DATA            = 0x06  /* stream payload               */
} ubp_pkt_type_t;

/* HEADER FLAGS */
#define UBP_FLAG_STREAM_FIN     0x01 /* final DATA packet of its stream */
/* bits 0x02..0x80 reserved, MUST be zero on send, ignored on receive for now */

/* FIXED PACKET HEADER (20 bytes, network byte order on the wire)       */

/*
 * offset   size  field         meaning
 * -----------------------------------------
 *      0   8     seq_id        connection-global packet number. Monotonic
 *                              NONCE source. The unit that gets ACKed.
 *      8   4     conn_id       connection/session id for state lookup.
 *     12   2     stream_id     logical stream (0 = control).
 *     14   1     type          ubp_pkt_type_t.
 *     15   1     flags         UBP_FlAG_* bitfield
 *     16   2     length        total datagram length (header + sealed body),
 *                              cross-checked against bytes actually received
 *                              and rejected on mismatch BEFORE crypto.
 *     18   2     reserved      MUST be zero (future use / alignment).
 * -----------------------------------------
 *              20 bytes total = AAD span
 *
 * The struct is packed and field order matches wire order so that, once fields
 * are byte-swapped to big-endian in place, the struct's bytes are the wire bytes
 * and can be passed directly as AAD. A static assert guards the size.
 */
typedef struct __attribute__((packed)) {
        u64             seq_id;
        u32             conn_id;
        u16             stream_id;
        u8              type;
        u8              flags;
        u16             length;
        u16             reserved;
} ubp_header_t;

_Static_assert(sizeof(ubp_header_t) == UBP_HEADER_SZ,
               "ubp_header_t must be exactly 20 packed bytes");

/* CONNECTION ROLE */
typedef enum {
        UBP_ROLE_INITIATOR      = 0, /* sends HELLO             */
        UBP_ROLE_RESPONDER      = 1  /* answers with HELLO_ACK  */
} ubp_role_t;

/* ERROR / STATUS CODES */

/*
 * Non-negative values are non-error statuses; negative values are errors.
 * Every public entry point returns one of these. Single-packet faults
 * (UBP_ERR_AUTH, UBP_ERR_PROTO) cause the datagram to be dropped without
 * tearing down the connection; fatal faults move the connection to CLOSED.
 */
typedef enum {
        UBP_OK                  = 0,  /* success                             */
        UBP_EAGAIN              = 1,  /* no even ready (poll); not an error  */
        UBP_EWOULDBLOCK         = 2,  /* send windows full; retry later      */

        UBP_ERR_INVAL           = -1, /* bad args                            */
        UBP_ERR_NOMEM           = -2, /* allocation / pool exhausted         */
        UBP_ERR_STATE           = -3, /* invalid in current connection state */
        UBP_ERR_TOO_LARGE       = -4, /* message exceeds a limit             */
        UBP_ERR_STREAMS         = -5, /* max_streams reached                 */
        UBP_ERR_AUTH            = -6, /* open() rejected a datagram (dropped)*/
        UBP_ERR_PROTO           = -7, /* malformed datagram / length mismatch*/
        UBP_ERR_CLOSED          = -8, /* connection is closed                */
        UBP_ERR_TIMEOUT         = -9, /* peer declared dead (keepalive/idle) */
        UBP_ERR_CALLBACK        = -10,/* a caller reported failure          */
} ubp_status_t;

/* WIRE CONSTANTS for the ACK */

/*
 * ACK bodies use QUIC-style variable-length integers and descending ranges
 * (see reliability layer). The fixed default cap on ranges per ACK lives in the
 * config, but the protocol ceiling that always fits a 1280-byte datagram is:
 */
#define UBP_ACK_MAX_RANGES_CEIL 64

/*
 * QUIC-style varINT: the two most significant bits of the first byte select the
 * encoded length (1, 2, 4, 8 bytes), leaving 6/14/20/62 usable value bits.
 * The codec lives in the wire module; these are the shared limits.
 */
#define UBP_VARINT_MAX_1B       0x3FULL                 /* 6-bit  */
#define UBP_VARINT_MAX_2B       0x3FFFULL               /* 14-bit */
#define UBP_VARINT_MAX_4B       0x3FFFFFFFULL           /* 30-bit */
#define UBP_VARINT_MAX_8B       0x3FFFFFFFFFFFFFFFULL   /* 62-bit */

#endif /* UBP_PROTOCOL_H */
