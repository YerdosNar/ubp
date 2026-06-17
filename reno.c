/*
 * reno.c - classic TCP Reno congestion control (byte-based).
 *
 * Implements the textbool NewReno-style behavious, expressed in bytes rather
 * then MSS-counted segments so it is agnostic to UBP's variable payload sizes:
 *
 *   - Slow start:              cwnd += bytes_acked    while cwnd < ssthresh
 *                              (exponential: window roughly double per RTT)
 *   - Congestion avoidance:    cwnd += mss * bytes_acked / cwnd while cwnd >= thresh
 *                              (additive: ~+1 mss per RTT)
 *
