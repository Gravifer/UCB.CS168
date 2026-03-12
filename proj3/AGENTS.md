# UCB CS168 Project 3: Transport

Official spec: https://sp26.cs168.io/proj3

This workflow is strict and lockstep.

Primary rule:
Do not consider, discuss, design, or implement any later stage or subtask until the current subtask is fully complete and validated.

Scope rule:
Only edit ext/cs168p2/student_socket.py.
Do not modify any other file, add files, add imports, or edit outside the marked stage blocks.

## Enforcement Protocol (Hard Gate)

1. Active unit of work is exactly one subtask at a time (for example 1.1, then 1.2, then 1.3).
   - Your current session only cares about the topmost incomplete subtask in the current stage. Do not implement ahead.
2. For the active subtask, do only:
    - Read the corresponding spec subsection.
    - Hand over to the user: let they write relevant code for that subtask.
    - Run the relevant stage tests.
3. If any test fails, stop and debug only that subtask. No progression allowed.
    - See if you can fix bugs the user made
    - If you need to change code outside the current subtask's code blocks, stop and debug only that subtask. No progression allowed.
    - Report to the user if you find making changes elsewhere highly advisable, but do not make those changes yourself. Let the user decide how to proceed.
4. Progression to next subtask is allowed only when:
    - Current subtask implementation is complete.
    - Relevant tests pass.
    - User explicitly confirms readiness to continue, and have checked or let you checked it in the list.
5. Progression to next stage is allowed only when:
    - All subtasks in current stage are complete.
    - python3 autograder.py sN passes.
    - python3 autograder.py all N passes.
    - `python3 autograder.py all ${n} 2>&1 | grep  -Ev '##|\\x1b\[' | grep -E "(FAIL|ERROR|ok|FAILED|test_s)"` is a good way to deflate test output; grep can also take a `--line-buffered` flag if you need it.
    - `../../pox.py config=./tests/s${n}_t${m}.cfg tcpip.pcap --node=r1 --no-tx` is a good way to focus on a specific subtask
    - User explicitly confirms readiness to continue.
6. Never pre-implement future stages for convenience.
7. If future-stage behavior seems required, add a note and defer it; do not implement it early.

## Standard Working Loop Per Subtask

1. Confirm current stage and subtask.
2. Read only that spec subsection.
3. Identify exact code block markers in student_socket.py for that subtask.
4. Implement minimal required logic.
5. Run stage tests:
- python autograder.py sN
- If needed, run specific scenario from the spec.
6. Verify no regressions with:
- python autograder.py all N
7. Ask user for explicit approval before moving to next subtask.

## Stage Checklist (Strict Order)

### Stage 1: Three-Way Handshake
- [x] 1.1 Sending SYN complete and tested
- [x] 1.2 Receiving packets in SYN_SENT complete and tested
- [x] 1.3 Processing SYN-ACK and sending ACK complete and tested
- [x] Gate passed: python autograder.py s1
- [x] Gate passed: python autograder.py all 1
- [x] User approval to continue
- User complains about still lacking understanding of the bigger picture

### Stage 2: Receiving In-Order Data
- [x] 2.1 Raw receive logic complete and tested
- [x] 2.2 Accepted segment handling complete and tested
- [x] 2.3 Accepted payload handling complete and tested
- [x] Gate passed: python autograder.py s2
- [x] Gate passed: python autograder.py all 2
- [x] User approval to continue
- L713: a lot of doubt about the size of rx_data

### Stage 3: Receiving Out-of-Order Data
- [x] 3.1 Insert packets into receive queue complete and tested
- [x] 3.2 Process receive queue in order (including overlap handling path) complete and tested
- [x] Gate passed: python autograder.py s3
- [x] Gate passed: python autograder.py all 3
- [x] User approval to continue

### Stage 4: Simple Sending of Data
- [x] 4.1 ACK validation logic complete and tested
- [x] 4.2 Accepted ACK processing complete and tested
- [x] 4.3 Segment creation and send-window honoring complete and tested
- [x] 4.4 Transmit-side sequence-space updates complete and tested
- [x] Gate passed: python autograder.py s4
- [x] Gate passed: python autograder.py all 4
- [x] User approval to continue

### Stage 5: Honoring Advertised Window
- [x] 5.1 update_window uses advertised seg.win complete and tested
- [x] Gate passed: python autograder.py s5
- [x] Gate passed: python autograder.py all 5
- [x] User approval to continue
- [x] Project 3A checkpoint ready

### Stage 6: Passive Close
- [x] 6.1 Receive FIN path complete and tested
- [x] 6.2 close() from CLOSE_WAIT sends FIN path complete and tested
- [x] 6.3 LAST_ACK ACK-of-our-FIN handling complete and tested
- [x] Gate passed: python autograder.py s6
- [x] Gate passed: python autograder.py all 6
- [x] User approval to continue

### Stage 7: Active Close
- [ ] 7.1 close() from ESTABLISHED sends FIN path complete and tested
- [ ] 7.2 FIN handling transitions (FIN_WAIT_1/FIN_WAIT_2/CLOSING paths) complete and tested
- [ ] 7.3 ACK handling transitions (FIN_WAIT_1 and CLOSING) complete and tested
- [ ] Gate passed: python autograder.py s7
- [ ] Gate passed: python autograder.py all 7
- [ ] User approval to continue

### Stage 8: Retransmitting Packets
- [ ] 8.1 First-transmission timestamping and queue insertion complete and tested
- [ ] 8.2 Remove acked packets from retransmit queue complete and tested
- [ ] 8.3 Retransmit expired earliest packet complete and tested
- [ ] Gate passed: python autograder.py s8
- [ ] Gate passed: python autograder.py all 8
- [ ] User approval to continue

### Stage 9: Updating RTO by Estimating RTT
- [ ] 9.1 RFC6298 RTO update logic complete and tested
- [ ] 9.2 ACK processing wired to update_rto complete and tested
- [ ] 9.3 RTO backoff on retransmission complete and tested
- [ ] Gate passed: python autograder.py s9
- [ ] Gate passed: python autograder.py all 9
- [ ] User approval to continue
- [ ] Project 3B ready for submission

## Non-Negotiable Stop Conditions

Stop immediately and do not proceed if any of the following is true:
- Current stage tests are failing.
- all N regression tests are failing.
- User has not approved moving forward.
- Requested change touches future-stage logic.

## Progress Logging Template

For each subtask, log:
- Subtask ID:
- Spec section read:
- Code blocks edited:
- Tests run:
- Result:
- Blockers:
- Next action (must be same subtask unless gate passed):
- Comments to the user (e.g. if you find a bug, or have a suggestion on how to proceed, but let them decide how to proceed):
