# Implementation Conformity Notes

This note records where the CS 168 Project 3 spec intentionally narrows RFC TCP into a smaller, stageable subset. The project is explicit that you are implementing only a subset of TCP, but it is useful to spell out which corners are being cut so lab-oriented behavior is not confused with full RFC conformance.

## Sources

- RFC 793: base TCP state machine, sequence-space rules, close semantics, event processing.
- RFC 1122: host requirements and later clarifications for TCP behavior.
- RFC 6298: retransmission timeout estimation.
- CS 168 Project 3 spec: staged subset with unit-test-driven grading.

## High-level cuts

### The project implements only a subset of TCP

The course spec says so directly. It covers handshake, ordered delivery, advertised-window flow control, graceful close, retransmission, and a basic RTT/RTO estimator, but it explicitly omits congestion control and leaves large parts of RFC 793 and RFC 1122 untouched.

### The grading target is staged behavior, not whole-protocol conformance

The autograder checks specific traces and state transitions. That makes the assignment teachable, but it also means many RFC requirements are outside scope unless a stage explicitly asks for them.

## Concrete places the spec cuts corners

### No passive open/listen implementation

The starter code says it does not support or implement `LISTEN` and `SYN_RECEIVED` in the student path. That removes a large part of RFC 793's connection-establishment and event-processing logic:

- passive open
- simultaneous open
- recovery paths involving `SYN_RECEIVED`
- many reset-handling branches that depend on synchronized vs non-synchronized states

### No full reset, security, precedence, or option handling

RFC 793 event processing spends a lot of effort on:

- when to generate RSTs
- when to ignore or validate them
- security and precedence checks
- source route, record route, timestamp, and other IP/TCP options
- urgent data handling
- PUSH semantics

The course spec does not ask for these. The project therefore cuts away much of RFC 793's robustness machinery and keeps only the minimum needed for the tested data/close paths.

### Close semantics are simplified to the lab's state traces

RFC 793 treats `CLOSE` as a user-level operation meaning "I have no more data to send." In the full spec, FIN is conceptually queued after earlier sends, the connection remains half-open for reading, and there is a broader user/TCP interface around success, failure, and asynchronous notification.

The course spec simplifies this into a smaller socket-level model:

- use `fin_ctrl.set_pending(...)` to defer FIN until queued transmit data is gone
- transition through `CLOSE_WAIT`, `LAST_ACK`, `FIN_WAIT_1`, `FIN_WAIT_2`, `CLOSING`, and `TIME_WAIT` only along the tested paths
- focus on observable packet/state traces rather than the full RFC user-interface contract

One subtle gap is that the project spec does not really force a position on the RFC question of whether `CLOSE` conceptually enters `FIN_WAIT_1` immediately when the FIN is queued, or only once the FIN is actually emitted. The tests care about the staged behavior they describe, not the full user-call semantics in RFC 793 section 3.5/3.9.

### Flow control is only advertised-window flow control

Stage 5 says the project uses the peer's advertised window and explicitly notes that real TCP would also use congestion control, which the project skips. So the spec intentionally omits:

- congestion window (`cwnd`)
- slow start
- congestion avoidance
- fast retransmit / fast recovery
- proper interaction between retransmission and congestion control

That is a major conformance cut relative to RFC 1122-era TCP expectations.

### Persist and zero-window probing are effectively out of scope

RFC 793 and RFC 1122 require a sender to cope with zero-window conditions and probe to discover reopening of the window. The course spec teaches send-window honoring in Stage 5, but it does not ask for the full persist/zero-window machinery from RFC 1122.

If the implementation happens to work in some zero-window cases, that is incidental; it is not the project's actual target.

### Retransmission is intentionally simplified in Stage 8

The stage-8 model is much simpler than production TCP:

- fixed timeout of 1 second before retransmission
- only the earliest queued segment is checked each timer tick
- only SYN, FIN, and payload-bearing packets are retransmitted
- ACK-only packets are not retransmitted
- no fast retransmit
- no loss recovery coupled to congestion response

This is a teaching simplification, not a faithful implementation of RFC 793 plus RFC 1122 transport behavior.

### RTO estimation is only the core RFC 6298 formula set

Stage 9 focuses on the arithmetic for `srtt`, `rttvar`, and `rto`, plus exponential backoff. That is useful, but it is still narrower than full TCP retransmission behavior because the project does not ask for the surrounding pieces that RFC 1122 expects in a full stack:

- congestion-control interaction
- broader failure handling policy
- full sender behavior under prolonged loss or zero-window conditions

The starter structure does implicitly lean toward Karn-style sampling by only updating RTT on non-retransmitted packets, but the assignment is still only covering the estimator core.

### Receiver behavior is simplified to byte-stream correctness plus a basic queue

Stages 2 and 3 teach ordered data delivery and out-of-order holding, which is the right core idea, but the spec avoids a lot of real TCP receiver complexity:

- no SACK
- no window scaling
- no urgent-mode delivery
- no PUSH-visible API behavior
- no richer duplicate-segment policy beyond what the queue and overlap trimming need

### No whole-protocol interface conformance

RFC 793 and RFC 1122 describe a much richer user/TCP interface than this project exposes. The assignment reduces that to a small socket-like object with:

- `connect`
- `send`
- `recv`
- `close`
- `shutdown` left unimplemented

This means the project skips or compresses:

- passive-open semantics
- asynchronous error reporting
- full status reporting
- abort behavior
- half-close API nuances

### Timer behavior is trimmed to what the assignment teaches

The project includes retransmission and `TIME_WAIT`, but it does not aim at full RFC timer behavior across all events and states. For example, the spec focuses on a single `TIME_WAIT` helper and a retransmission timer path, not the broader RFC handling around persist, user timeout policy, keep-alives, or richer failure policy.

## What this means in practice

If the goal is to pass the course autograder, optimize for the project spec first. If the goal is to reason about RFC conformance, treat the course spec as a pedagogical slice of TCP rather than a normative TCP implementation plan.

The safest framing is:

- the project teaches important TCP invariants
- the project does not implement all RFC-required edge cases
- some lab behaviors are deliberately simplified so they are easy to test and debug
- passing all 9 stages does not mean the implementation is a fully conformant TCP