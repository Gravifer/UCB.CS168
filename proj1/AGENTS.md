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

## Implementation Checklist (current status)

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
- [ ] For ICMP Time Exceeded (`type=11`), enforce `code=0`.

### Robustness
- [x] Ignore unparseable/truncated packets without crashing.
- [x] Handle IPv4 options via `header_len` parsing.
- [x] Handle missing replies (timeouts) by continuing.
- [ ] Correctly handle duplicate/delayed packets without contaminating later TTLs.
- [ ] Fully handle wrong-traceroute/wrong-TTL replies (B16-hard behavior).

### Output Contract
- [x] Returns `list[list[str]]`.
- [x] Index `i` corresponds to TTL `i+1`.
- [x] Allows empty lists for silent hops.
