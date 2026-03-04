# CS168 Project 1B — Practical Spec Summary

This file is a boiled-down checklist of **behavioral requirements** for `traceroute.py` (Part B), focused on what affects correctness.
The full spec is at https://sp26.cs168.io/proj1/proj1b/ ; this is a distilled version of it.

## Core Loop Requirements
- Probe TTLs from `1` to `TRACEROUTE_MAX_TTL` inclusive.
- For each TTL, send exactly `PROBE_ATTEMPT_COUNT` probes.
- Collect routers seen at this TTL into one sublist.
- No duplicate IPs within a TTL sublist.
- Call `util.print_result(routers_for_ttl, ttl)` once per TTL.
- Stop early and return once destination IP is observed at current TTL.
- If destination is never observed, return results up to max TTL.

## Response Acceptance Rules
Process only packets that are valid traceroute replies:
- Outer packet must parse as IPv4.
- Outer IPv4 protocol must be ICMP.
- ICMP type must be:
  - `11` (Time Exceeded), code must be `0` (TTL exceeded in transit), or
  - `3` (Destination Unreachable) (for final host behavior).
- ICMP payload must include parsable embedded IPv4 + embedded UDP headers.
- Embedded destination IP must match current traceroute target IP.
- Embedded UDP destination port must match traceroute probe port.

Ignore packet if any validation step fails.

## Error-Handling Requirements (Part B themes)
Your implementation should tolerate and ignore without crashing:
- Invalid ICMP types/codes.
- Wrong outer IP protocol (not ICMP).
- Unparseable/truncated packets.
- Irrelevant UDP responses.
- IP headers with options (header length > 20) while still parsing correctly.

## Timeouts / Receive Strategy
- Avoid unnecessary extra `recv_select()` timeouts in clean paths.
- Do not blindly drain receive queue forever.
- Handle drops/silence by allowing missing responses and continuing.

## Duplicates & Stale Traffic
- Ignore duplicate responses (same router duplicated for a probe/TTL).
- Avoid carrying stale/duplicate traffic into incorrect TTL results.
- Filter out replies not belonging to this traceroute run via embedded destination/port checks.

## Output Shape Expectations
- Return type: `list[list[str]]`.
- Index `i` corresponds to TTL `i+1`.
- Empty list is valid for silent/lost hops.
- Looping routes may repeat across different TTLs.

## Non-Requirements
- Pretty-print/debug packet rendering format.
- Internal parser architecture, as long as behavior above is correct.

## Final sanity checks before submit
- No crashes on malformed input packets.
- Correct early stop at destination.
- No duplicate IPs inside same TTL list.
- Correct behavior with missing replies (empty hop lists).
- Submission includes only `traceroute.py`.

## Short Checklist

### Core Loop
- [x] TTL loop runs from `1..TRACEROUTE_MAX_TTL`.
- [x] Sends `PROBE_ATTEMPT_COUNT` probes per TTL.
- [x] Deduplicates routers within each TTL sublist.
- [x] Calls `util.print_result(...)` once per TTL.
- [x] Stops early when destination IP is discovered.
- [x] Returns all collected hops up to stop/max TTL.

### Validation Rules
- [x] Outer packet must parse as IPv4.
- [x] Outer IPv4 protocol must be ICMP.
- [x] ICMP payload must include embedded IPv4 + UDP for matching.
- [x] Embedded destination IP must match traceroute target.
- [x] Embedded UDP destination port must match traceroute probe port.
- [x] For ICMP Time Exceeded (`type=11`), enforce `code=0`.

### Robustness
- [x] Ignore unparseable/truncated packets without crashing.
- [x] Handle IPv4 options via `header_len` parsing.
- [x] Handle missing replies (timeouts) by continuing.
- [x] Correctly handle duplicate/delayed packets without contaminating later TTLs.
- [x] Fully handle wrong-traceroute/wrong-TTL replies (B16-hard behavior).

### Output Contract
- [x] Returns `list[list[str]]`.
- [x] Index `i` corresponds to TTL `i+1`.
- [x] Allows empty lists for silent hops.

## Test-by-Test Checklist

Use this section as a Gradescope tracking sheet.

### B1 — Avoiding Unnecessary Timeouts
- [x] In clean/no-error topology, no extra timeout from unnecessary queue-draining.
  - Reasoning: receive loop exits as soon as all per-TTL probe ports are satisfied; no unconditional drain loop.
  - Evidence: `traceroute.py` lines `468-471`, `481-485`.
- [x] Move to next TTL once 3 relevant replies are processed for 3 probes.
  - Reasoning: exactly 3 probes are sent, and completion is tracked via `pending_probe_ports` for those 3 ports.
  - Evidence: `traceroute.py` lines `463-466`, `468-469`.

### B2 — Invalid ICMP Type
- [x] Ignore ICMP packets whose `type` is neither Time Exceeded (`11`) nor Destination Unreachable (`3`).
  - Reasoning: non-`3/11` ICMP types are rejected in validation.
  - Evidence: `traceroute.py` lines `428-430`.

### B3 — Invalid ICMP Code
- [x] If ICMP `type=11`, accept only `code=0` (TTL exceeded in transit); ignore other codes.
  - Reasoning: ICMP Time Exceeded with nonzero code is explicitly filtered.
  - Evidence: `traceroute.py` lines `431-432`.

### B4 — Invalid IP Protocol
- [x] Ignore response packets whose outer IPv4 `proto` is not ICMP.
  - Reasoning: outer IPv4 protocol must equal ICMP or packet is dropped.
  - Evidence: `traceroute.py` lines `417-420`.

### B5 — Unparseable Response
- [x] Ignore packets with unparseable payloads (garbage body) without crashing.
  - Reasoning: parser returns `None`/`unknown` on parse failures and validation drops nonconforming trees.
  - Evidence: `traceroute.py` lines `167-176`, `184-191`, `196-203`, `417-426`, `475-476`.

### B6 — Truncated Buffer
- [x] Ignore too-short/truncated packets safely (no exceptions/crashes).
  - Reasoning: minimum-length checks and guarded parsing reject short IPv4/ICMP/UDP payloads.
  - Evidence: `traceroute.py` lines `169-170`, `185-186`, `197-198`, `177-181`.

### B7 — Irrelevant UDP Response
- [x] Ignore UDP response packets from routers when expecting ICMP traceroute errors.
  - Reasoning: outer protocol must be ICMP, so standalone UDP responses are ignored.
  - Evidence: `traceroute.py` lines `419-420`, `475-476`.

### B8 — IP Options
- [x] Correctly parse IPv4 header length (`IHL`) and handle headers with options (`header_len > 20`).
  - Reasoning: IPv4 parser computes `header_len` from IHL and advances parse boundary by that length.
  - Evidence: `traceroute.py` lines `45`, `177-181`.

### B9 — Router Loops
- [x] If path loops and destination is unreachable, continue probing until max TTL.
  - Reasoning: outer TTL loop always runs to `TRACEROUTE_MAX_TTL` unless destination is actually observed.
  - Evidence: `traceroute.py` lines `456`, `493-496`.
- [x] Return repeated loop hops across TTLs (no premature termination).
  - Reasoning: each TTL independently appends discovered routers; repeats across TTLs are allowed.
  - Evidence: `traceroute.py` lines `459-461`, `486-491`.

### B10 — Missing Host
- [x] If destination never responds, continue to max TTL and return collected results.
  - Reasoning: return occurs only on destination match; otherwise function returns after max TTL loop ends.
  - Evidence: `traceroute.py` lines `456`, `493-496`.
- [x] Include empty lists for TTLs with no replies.
  - Reasoning: `ttl_routers` starts empty and is appended every TTL regardless of responses.
  - Evidence: `traceroute.py` lines `459`, `490-491`.

### B11 — Silent Routers
- [x] Allow silent intermediate hops (`[]` for that TTL) and still continue to later TTLs.
  - Reasoning: timeout breaks per-TTL receive loop, then empty list is recorded and next TTL proceeds.
  - Evidence: `traceroute.py` lines `469-471`, `490-491`, `456`.

### B12 — Occasional Drops
- [x] Tolerate dropped probes/replies; return hop if at least one probe yields valid response.
  - Reasoning: responses are optional per probe; any valid response adds router while missing replies simply time out.
  - Evidence: `traceroute.py` lines `469-471`, `486-488`.
- [x] Return `[]` for TTL if all probes for that TTL are dropped/silent.
  - Reasoning: if no valid response arrives before timeout, `ttl_routers` remains empty and is still appended.
  - Evidence: `traceroute.py` lines `459`, `469-471`, `490-491`.

### B13 — Duplicate Responses
- [x] Ignore duplicate ICMP replies to a single probe/TTL.
  - Reasoning: once a probe port is matched, it is removed from `pending_probe_ports`; further same-port replies are ignored.
  - Evidence: `traceroute.py` lines `481-485`.
- [x] Do not duplicate router IPs within a TTL sublist.
  - Reasoning: `seen_routers` set guards list insertion per TTL.
  - Evidence: `traceroute.py` lines `460`, `486-488`.

### B14 — Duplicate Probes
- [x] Ignore extra replies caused by duplicated outbound probes.
  - Reasoning: duplicated probe replies use already-consumed destination port and are rejected.
  - Evidence: `traceroute.py` lines `481-485`.
- [x] Keep one logical result per intended probe stream for the current TTL.
  - Reasoning: per-TTL unique probe-port set defines exactly which responses count for completion.
  - Evidence: `traceroute.py` lines `461-466`, `468-469`.

### B15 — Delayed Duplicates
- [x] Ignore delayed duplicate packets from prior probes/TTLs.
  - Reasoning: delayed replies with old ports fail membership in current `pending_probe_ports`.
  - Evidence: `traceroute.py` lines `463-465`, `481-482`.
- [x] Prevent stale replies from contaminating later TTL results.
  - Reasoning: each TTL uses disjoint destination ports, so old responses cannot be attributed to new TTL probes.
  - Evidence: `traceroute.py` lines `464-465`, `468`, `481-482`.

### B16 — Irrelevant TTL Response (Wrong Traceroute)
- [x] Ignore otherwise-valid ICMP replies not generated by this traceroute run.
  - Reasoning: responses must match this run’s destination IP and this TTL’s expected probe ports.
  - Evidence: `traceroute.py` lines `478-482`.
- [x] Validate embedded destination IP + embedded UDP destination port to match current run/probe set.
  - Reasoning: validation extracts embedded destination/port, then receive loop enforces both checks.
  - Evidence: `traceroute.py` lines `446-448`, `478-482`.
