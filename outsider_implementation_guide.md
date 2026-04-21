# SecureLAN Monitor: Detailed Outsider Implementation Guide

## 0. How to Use This Document

This guide explains the entire project for readers who do not have code access.
It is written as a step-by-step implementation narrative, not just a user manual.

Read in this order:
1. Project mission and boundaries
2. Architecture and data movement
3. Module-by-module implementation details
4. Setup, runtime behavior, and operations
5. Security model, limitations, and extension paths

## 1. Section Build Plan (Incremental)

This document is being populated section-by-section.

- [x] 0. How to Use This Document
- [x] 2. Project Mission, Scope, and Non-Goals
- [x] 3. End-to-End Architecture
- [x] 4. Data Model and Persistence Design
- [x] 5. Cryptographic Logging Design
- [x] 6. Serial Connectivity and Command Pipeline
- [x] 7. Detection and Auto-Defense Engine
- [x] 8. Streamlit Application Layer
- [x] 9. Operational Runbook (Lab and Production-Like Use)
- [x] 10. Troubleshooting Decision Tree
- [x] 11. Known Limitations and Safe Future Enhancements
- [x] 12. Glossary and Quick Reference

## 2. Project Mission, Scope, and Non-Goals

### 2.1 Mission Statement

SecureLAN Monitor is a hardware-oriented network security monitoring and response prototype.
It demonstrates how to combine:
- real switch console automation,
- live attack signal detection,
- automatic defensive command execution, and
- tamper-evident security audit logging

inside one operator-facing dashboard.

The project is intentionally educational and demonstrative, but built with practical engineering patterns:
- isolated modules,
- event-driven worker/UI separation,
- durable storage,
- cryptographic integrity checks,
- bounded error handling and retries.

### 2.2 What This Project Detects and Responds To

The system currently implements two detection classes:
1. MAC Flood behavior
2. ARP Spoof behavior

When these conditions are detected, it can issue predefined switch CLI defense commands automatically.

### 2.3 Why Hardware-Only Mode Was Chosen

This codebase intentionally runs in hardware mode only.

Reasoning:
- The objective is to demonstrate direct switch interaction through serial console.
- Detection-to-defense timing should be observed against real control plane behavior.
- Audit records should reflect real command output from actual infrastructure.

Simulation support is intentionally disabled to avoid confusing mixed behavior in the core submission build.

### 2.4 Explicit In-Scope Features

The implemented scope includes:
- Streamlit UI with three pages:
	- LIVE MONITOR
	- SWITCH CONSOLE
	- AUDIT TRAIL
- Worker loop that polls switch state and sniffs ARP traffic
- Manual command dispatch from UI to switch
- Auto-defense dispatch on triggered detections
- SQLite persistence for events, snapshots, and audit entries
- Cryptographic audit protections:
	- Fernet encryption of audit payloads
	- SHA-256 hash chaining across records
	- HMAC-SHA256 command signatures

### 2.5 Explicit Out-of-Scope / Non-Goals

The project does not attempt to be a complete enterprise SIEM or NAC platform.

Non-goals include:
- broad IDS signature libraries,
- full packet analytics and long-term PCAP retention,
- distributed multi-switch fleet orchestration,
- role-based access control and user management,
- reverse-command rollback guarantees on network devices,
- autonomous policy optimization.

This focus keeps the implementation concise enough for lab evaluation while still covering real-world security engineering concepts.

### 2.6 Core Engineering Principles Used

The implementation reflects these design principles:
1. Separate observation and presentation paths (worker thread vs UI thread).
2. Prefer append-only evidence over mutable state.
3. Log both command intent and command output.
4. Fail visibly: errors are surfaced in the UI and written to audit where possible.
5. Use deterministic cryptographic checks for post-incident trust validation.

## 3. End-to-End Architecture

### 3.1 Logical Components

The system is composed of six major implementation layers:

1. UI Layer (Streamlit App)
- Presents dashboards and operator controls.
- Pulls processed state from session memory and database.
- Pushes operator commands and synthetic triggers into command queue.

2. Monitor Worker Layer
- Runs continuously in a background thread.
- Polls switch MAC table on interval.
- Sniffs ARP replies from configured interface.
- Emits structured events and command records.

3. Serial Engine Layer
- Manages serial port lifecycle.
- Performs login handshake and startup preparation commands.
- Sends CLI commands and returns full raw output text.
- Signs command strings with HMAC.

4. Persistence Layer (SQLite)
- Stores detected events.
- Stores MAC time-series snapshots.
- Stores audit chain entries with cryptographic linkage fields.

5. Cryptography Layer
- Encrypts audit payload descriptions.
- Computes hash chain links across audit rows.
- Verifies entire chain integrity on demand.

6. Configuration Layer
- Supplies runtime mode, serial credentials, thresholds, and interface settings.

### 3.2 Runtime Topology (Conceptual)

At runtime, there are two long-lived execution contexts:

1. Main Streamlit process/thread
- Handles page rendering, session state, database writes from queue-drained events.

2. Worker thread
- Handles external I/O (serial and packet sniffing) and detection logic.

Communication is asynchronous and queue-based:
- command_queue: UI to worker commands
- event_queue: worker to UI/persistence events

This avoids blocking the UI on switch/network I/O while preserving deterministic processing flow.

### 3.3 Startup Sequence

When the app starts, initialization proceeds in this order:

1. Load YAML configuration from disk.
2. Enforce hardware-only mode gate.
3. Initialize session state containers if missing.
4. Open or initialize SQLite schema.
5. Load or create Fernet and HMAC key material files.
6. Create in-memory queues for worker communication.
7. Start worker thread if not already running.
8. Enable periodic Streamlit autorefresh.
9. Drain worker events into UI state and database.
10. Render selected page.

This order ensures key dependencies (database and crypto state) exist before event processing begins.

### 3.4 Event Contract Between Worker and UI

Worker publishes event envelopes in the format:
- kind: event category
- data: event payload object

Supported event kinds:
1. CMD_RECORD
- Represents one executed command and output.

2. ATTACK_EVENT
- Represents one normalized detection event.

3. MAC_METRIC
- Point-in-time MAC metric sample for dashboard/time series.

4. ARP_METRIC
- Point-in-time ARP mapping metric state.

5. ERROR_EVENT
- Recoverable or transient runtime error details.

6. UNKNOWN_EVENT
- Fallback audit category created by UI when it receives unrecognized kind.

### 3.5 Primary Data and Control Flows

#### Flow A: Manual Command Execution

1. Operator submits command in SWITCH CONSOLE form.
2. UI writes command object into command_queue.
3. Worker dequeues message and executes through serial engine.
4. Worker emits CMD_RECORD containing timestamp, source, command, output, and HMAC signature.
5. UI drains event, appends command history, and writes COMMAND audit entry.

#### Flow B: MAC Flood Detection and Defense

1. Worker periodically executes show mac-address.
2. Serial output is parsed into current MAC count.
3. Delta is computed from previous sample.
4. If delta exceeds configured threshold, worker emits ATTACK_EVENT (MAC_FLOOD).
5. Worker executes defense command port security max-mac-count 5.
6. Defense command appears as CMD_RECORD and is persisted/audited by UI drain path.

#### Flow C: ARP Spoof Detection and Defense

1. Worker sniffs ARP reply packets on configured interface.
2. It tracks IP to MAC mapping history.
3. If the same IP appears with a changed MAC, it emits ATTACK_EVENT (ARP_SPOOF).
4. Worker executes defense command ip arp inspection vlan 1.
5. UI persists event and audit records identically to Flow B.

#### Flow D: Synthetic Demo Trigger Path

1. Operator clicks Inject MAC Flood or Inject ARP Spoof.
2. UI pushes a control action into command_queue.
3. Worker generates synthetic ATTACK_EVENT payload (no real attack traffic produced).
4. Worker still executes corresponding defense command, allowing full demonstration of response and audit flows.

### 3.6 Reliability and Recovery Behavior

The architecture includes practical recovery safeguards:

1. Serial reconnect attempts
- If serial is not open, worker retries opening and emits ERROR_EVENT on failure.

2. Login preparation idempotence
- After reconnect, startup prepare sequence is re-run before regular operations.

3. Bounded queue drain per refresh
- UI processes a capped number of queue events each cycle to avoid freeze under burst load.

4. ARP error throttling
- Repeated sniffing failures are rate-limited so logs remain readable.

5. SQLite lock retries
- Persistence helper retries on transient lock conditions.

6. Non-fatal audit write fallback
- If audit write fails while processing an event, UI remains operational and surfaces error context.

## 4. Data Model and Persistence Design

### 4.1 Why SQLite Was Chosen

SQLite is used because the project is designed for single-node lab execution with low operational complexity.

Advantages for this use case:
1. Zero external database service dependency.
2. Simple file-based portability for demonstrations.
3. Sufficient write throughput for moderate event and snapshot rates.
4. Easy inspection for viva/reporting.

The connection is configured with:
- WAL journal mode for better concurrent read/write behavior.
- NORMAL synchronous mode for balanced durability/performance.

### 4.2 Table Inventory

The database uses three primary tables.

#### 4.2.1 events

Purpose:
- Store normalized attack detections.

Columns:
1. id (auto-increment primary key)
2. timestamp (ISO text)
3. attack_type (for example, MAC_FLOOD, ARP_SPOOF)
4. severity (string)
5. details_json (JSON string with detector-specific payload)

Write trigger:
- Inserted when UI drains ATTACK_EVENT from event_queue.

Read usage:
- LIVE MONITOR fetches most recent events for operator timeline display.

#### 4.2.2 mac_snapshots

Purpose:
- Persist MAC count time-series points for trend charting and snapshots.

Columns:
1. id
2. timestamp
3. mac_count
4. delta

Write trigger:
1. On each MAC_METRIC event.
2. On user-triggered Take Snapshot action.

Read usage:
- LIVE MONITOR line chart generation.

#### 4.2.3 audit_log

Purpose:
- Immutable-style audit evidence with tamper-evident cryptographic chain.

Columns:
1. id
2. timestamp
3. action_type
4. description (canonical JSON plaintext)
5. encrypted_blob (Fernet ciphertext of description)
6. prev_hash (hash pointer to previous row or GENESIS)
7. entry_hash (current row SHA-256 digest)
8. hmac_sig (optional command signature context)

Write trigger:
- On command records, attack events, error events, snapshots, and undo actions.

Read usage:
- AUDIT TRAIL table view, entry inspection, and chain verification.

### 4.3 Write Path Design

All persistent writes are performed in the Streamlit/UI context after queue drain.

This design choice means:
1. Worker remains focused on I/O and detection, not DB concerns.
2. Persistence order follows queue processing order.
3. UI and audit are synchronized from one event consumer.

Potential tradeoff:
- Very high event rates could delay writes until next refresh cycles.

For this project scale, that tradeoff is acceptable and keeps architecture simpler.

### 4.4 Retry Strategy for Locked Database States

SQLite operational lock errors are handled by bounded retry logic.

Behavior:
1. Up to 5 attempts.
2. Small delay between attempts.
3. Retry only for recognized lock messages.
4. Raise exception immediately for unrelated operational errors.

This prevents occasional lock contention from collapsing runtime processing.

### 4.5 Query and Ordering Patterns

The project uses predictable retrieval patterns:

1. Recent views
- Queries pull latest N rows in descending order then reverse client-side when chronological display is required.

2. Audit verification
- Full audit list fetched in ascending id order to validate chain from genesis to newest entry.

3. Last hash lookup
- Constant-time style query (ORDER BY id DESC LIMIT 1) for chain append.

### 4.6 Data Retention Characteristics

Current implementation is append-heavy and does not include pruning or archival automation.

Implications:
1. Database file grows over time.
2. Suitable for lab and short-lived demos.
3. Long-term deployment should add:
- retention policy,
- periodic export,
- optional compressed archive strategy.

## 5. Cryptographic Logging Design

### 5.1 Security Objectives in This Project

The audit subsystem targets three complementary goals:

1. Confidentiality of structured audit payload copies.
2. Integrity of each command signature context.
3. Tamper evidence across the full chronological log.

It does not claim non-repudiation with PKI identity or external notarization.

### 5.2 Key Material and Local Storage

Two key artifacts are used:

1. Fernet key file
- Used for symmetric encryption/decryption of audit payload text.

2. HMAC secret file
- Used to compute HMAC-SHA256 over command strings.

Lifecycle behavior:
1. If key file exists: load it.
2. If key file missing: generate and persist it.

Operational consequence:
- Reusing key files preserves ability to decrypt old entries.
- Deleting/replacing key files breaks decryption continuity for past data.

### 5.3 Canonical Payload Construction

Before encryption and hashing, audit payload dictionaries are serialized as canonical JSON:
- sorted keys
- compact separators

Why this matters:
1. Deterministic serialization prevents accidental hash divergence due to key order formatting differences.
2. Repeat verification recomputes the same byte-level content.

### 5.4 Command Signing with HMAC

When commands are executed, the command text is signed via HMAC-SHA256 using the shared secret.

Stored result:
- Hex digest string per command record.

What it gives:
- Ability to detect accidental or malicious command-text tampering in records where signature context is preserved.

What it does not give:
- It does not authenticate which person entered the command.

### 5.5 Hash Chain Construction

Each audit row links to the prior row via prev_hash and derives entry_hash over a concatenated field payload.

Conceptually:
1. prev_hash starts as GENESIS for first entry.
2. entry_hash = SHA256(prev_hash + timestamp + action_type + description + encrypted_blob + hmac_sig)
3. Next row stores previous row's entry_hash as its prev_hash.

Security effect:
- Editing any historical row breaks all downstream verification links.

### 5.6 Dual Storage of Plaintext and Ciphertext

The design stores both:
- description (plaintext canonical JSON)
- encrypted_blob (ciphertext of same description)

Rationale in this educational build:
1. Plaintext enables transparent operator debugging and easy audit table readability.
2. Ciphertext demonstrates confidentiality mechanism and key-dependent recovery.
3. Hash chain still binds both values, so unauthorized edits are detectable.

For stricter production security, plaintext would typically be minimized or access-restricted.

### 5.7 Chain Verification Process

Verification is performed over rows in ascending order:

1. Check each row prev_hash equals expected previous entry_hash (or GENESIS for first row).
2. Recompute entry_hash from stored row fields.
3. Compare recomputed hash to stored entry_hash.
4. Stop at first mismatch and report exact failing row id.

Possible failure semantics:
1. Broken prev_hash link: sequence or insertion tampering.
2. Entry hash mismatch: row field modification.

### 5.8 Cryptographic Boundaries and Assumptions

Important assumptions outsiders should know:
1. Local host file security is trusted for key files and DB file.
2. No external trusted timestamping authority is integrated.
3. No hardware security module is used.
4. Key rotation policy is not implemented in this version.

Given these assumptions, the system provides strong local tamper evidence for educational and lab contexts.

## 6. Serial Connectivity and Command Pipeline

### 6.1 Responsibilities of the Serial Engine

The serial engine is the only module that directly talks to the switch console.

It is responsible for:
1. Opening and closing serial connection.
2. Synchronizing command writes and reads.
3. Running login/prepare sequence.
4. Returning raw command output.
5. Wrapping command execution metadata (timestamp, source, signature).

### 6.2 Connection Lifecycle

The engine tracks an internal serial object and exposes:
- is_open check
- open attempt
- close action

Open behavior:
1. Uses configured port, baudrate, and timeout.
2. Returns success/failure with message.

Failure examples include:
- wrong COM port,
- cable unplugged,
- permission/driver errors.

### 6.3 Thread Safety Model

A re-entrant lock guards command send/read operations.

Reason:
- Even if future updates introduce multiple command producers, write/read transaction boundaries remain serialized.

Current architecture mostly routes command execution via worker, but lock-protected engine is still a robust design choice.

### 6.4 Prompt and Login Pattern Handling

Regex patterns are used to interpret console text:
1. Prompt detector for shell endings (greater-than or hash prompt).
2. Username/login prompt detector.
3. Password prompt detector.
4. Authentication-failure detector.

Login flow sequence:
1. Read startup buffer.
2. If login prompt found, send username.
3. If password prompt found, send password.
4. Reject if prompts persist or auth-fail pattern appears.
5. Record login sequence output as system command record.
6. Execute startup preparation commands:
- enable
- skip-page-display

This ensures operational session state is normalized before detection loop begins.

### 6.5 Command Execution Transaction

A single command execution follows this transaction:
1. Ensure serial is open.
2. Write command plus line ending.
3. Read until prompt/timeout behavior.
4. Build record object:
- timestamp
- source (SYSTEM/AUTO/MANUAL)
- command
- raw output
- hmac signature
5. Return record to caller.

The worker forwards these records to UI as CMD_RECORD events.

### 6.6 Output Reading Strategy

Reading is implemented as timed loop with incremental byte collection:
1. Drain available input chunks while within timeout.
2. Decode with utf-8, ignore malformed fragments.
3. Stop when prompt is detected and stream has gone briefly idle.
4. Return concatenated output text.

This strategy balances responsiveness with practical terminal-output completeness.

### 6.7 MAC Count Parsing Strategy

MAC parsing logic scans command output line-by-line:
1. Skip empty/header/prompt lines.
2. Match known MAC address patterns.
3. Count lines containing valid MAC shapes.

Count output drives detector delta computation.

Because switch CLI formats vary, this parser is intentionally heuristic but sufficient for controlled lab output.

### 6.8 Failure and Recovery Paths

When command send/read fails:
1. Worker catches exception.
2. Emits ERROR_EVENT with context.
3. Loop continues and reconnect logic can retry.

When login sequence fails:
1. Worker reports error.
2. Sleeps briefly.
3. Attempts open/login again in subsequent iterations.

This makes transient console disruptions survivable without app restart.

## 7. Detection and Auto-Defense Engine

### 7.1 Monitor Loop Role

The monitor loop is the continuous runtime brain of the system.

It executes the following responsibilities in one recurring cycle:
1. Ensure serial session availability.
2. Ensure login/prepare sequence is complete.
3. Process pending manual/synthetic commands.
4. Poll MAC table on configured interval.
5. Sniff ARP replies for spoof anomalies.
6. Publish metric and event updates.
7. Sleep briefly and repeat.

### 7.2 Internal Runtime State

The worker tracks short-lived in-memory state:
1. previous_mac_count
2. last_mac_poll timestamp
3. arp_map (IP to MAC dictionary)
4. last_arp_packet details
5. last_suspicious mapping details
6. last_arp_error timestamp for error-throttle logic

This state is enough to derive detector behavior without expensive persistent reads.

### 7.3 Command Queue Handling

Worker drains command_queue in non-blocking mode.

Supported command message types:
1. action messages (synthetic demo controls)
2. command messages (manual CLI commands)

For action messages, worker executes pre-defined synthetic flow.
For manual messages, worker executes exact command text through serial engine.

### 7.4 MAC Flood Detection Logic

Polling schedule:
- Runs every detection.mac_poll_interval_sec seconds.

Pipeline:
1. Execute show mac-address.
2. Parse current MAC count from output.
3. Compute delta:
- delta = current_count - previous_mac_count
4. Emit MAC_METRIC event for dashboard and snapshot persistence.
5. If previous exists and delta exceeds threshold:
- Emit ATTACK_EVENT with MAC_FLOOD details.
- Execute defense command port security max-mac-count 5.
- Emit CMD_RECORD for defense execution.

Detection payload includes:
- current, previous, delta, threshold.

### 7.5 ARP Spoof Detection Logic

Sniff schedule:
- Repeated short-duration sniff windows using configured interface and timeout.

Pipeline per ARP reply packet:
1. Extract source IP and source MAC.
2. Lookup prior MAC for that IP in arp_map.
3. If prior MAC exists and differs from current MAC:
- Emit ATTACK_EVENT with ARP_SPOOF details.
- Execute defense command ip arp inspection vlan 1.
- Emit CMD_RECORD for defense execution.
4. Update arp_map with latest IP to MAC mapping.

Metrics emitted:
- tracked_ip_count,
- last_arp_packet,
- last_suspicious_mapping.

### 7.6 Synthetic Attack Injection Path

For safe classroom demonstration, two synthetic controls exist:
1. INJECT_MAC_FLOOD
2. INJECT_ARP_SPOOF

Behavior:
1. Worker constructs synthetic ATTACK_EVENT payload (explicitly marked as UI button demo).
2. Worker still executes corresponding defense command.
3. Full downstream persistence and audit path remains identical to real detections.

This allows complete workflow demonstration without generating harmful network traffic.

### 7.7 Event Normalization Pattern

Both real and synthetic detections are normalized into same ATTACK_EVENT schema:
- timestamp
- attack_type
- severity
- details object

This uniformity simplifies UI rendering, DB persistence, and audit reporting.

### 7.8 Error Handling and Loop Continuity

Error handling is layered:
1. Local try/except around command and action handling to isolate failures.
2. ARP sniff failures throttled to reduce log spam.
3. Outer loop exception handler emits ERROR_EVENT, closes engine, pauses, then retries.

Design outcome:
- The worker is resilient by default and attempts self-recovery for transient faults.

### 7.9 Defense Command Philosophy

Auto-defense actions are intentionally simple and deterministic.

Benefits:
1. Easy to explain and validate in lab evaluation.
2. Reproducible behavior under repeated tests.
3. Clear forensic audit trail linking detection to response command.

Tradeoff:
- Static defense commands are less adaptive than policy engines, but significantly easier to reason about for first implementation stage.

## 8. Streamlit Application Layer

### 8.1 Why Streamlit Was Used

Streamlit provides a fast way to expose real-time monitoring behavior to non-developer users.

It fits this project because:
1. UI development overhead stays low.
2. State handling is straightforward for one-page-app patterns.
3. Operators can interact through forms/buttons without custom frontend code.

### 8.2 Session State Initialization Strategy

On startup, app initializes a stable session contract containing:
1. config object
2. db connection
3. fernet instance
4. hmac secret
5. event queue
6. command queue
7. stop event
8. worker thread handle
9. command_records list
10. live_events list
11. errors list
12. mac_metric snapshot
13. arp_metric snapshot

This avoids re-creating resources on every Streamlit rerun.

### 8.3 Worker Bootstrap and Refresh Model

The UI calls a start-if-needed routine to avoid duplicate worker threads.

Then autorefresh executes at configured interval.
Each refresh cycle:
1. Drains a bounded number of worker events.
2. Updates in-memory session state.
3. Persists relevant records to database.
4. Writes audit entries.
5. Renders current page.

### 8.4 Queue Drain as Integration Hub

Queue drain logic is the central integration point between worker and UI/persistence.

By event kind, it performs these actions:
1. CMD_RECORD
- append command history list
- write COMMAND audit entry

2. ATTACK_EVENT
- append live event list
- insert into events table
- write ATTACK_EVENT audit entry

3. MAC_METRIC
- update session metric object
- insert mac snapshot

4. ARP_METRIC
- update session metric object

5. ERROR_EVENT
- append error list
- write ERROR_EVENT audit entry

6. Unknown kind
- write UNKNOWN_EVENT audit entry for diagnostics

### 8.5 Page 1: LIVE MONITOR

Purpose:
- Immediate security posture visibility.

Displays:
1. mode and monitor status
2. MAC detector counters
3. ARP detector state
4. MAC trend chart
5. recent attack events
6. synthetic trigger controls

Operator interactions:
- Inject MAC Flood button
- Inject ARP Spoof button

Both buttons send control actions to worker queue, not direct DB inserts.

### 8.6 Page 2: SWITCH CONSOLE

Purpose:
- Operational command center and command evidence view.

Displays:
1. terminal-like output panel built from recent command records
2. full command history dataframe

Operator interactions:
1. manual command form submit
2. Undo Last Command (UI/DB log action only)
3. Take Snapshot

Important nuance:
- Undo does not send reverse switch command; it only removes one manual record from UI history and logs audit note.

### 8.7 Page 3: AUDIT TRAIL

Purpose:
- Trust validation and forensic review.

Displays:
1. audit rows with chain fields
2. verify chain action
3. selected entry encrypted blob
4. selected entry decrypted plaintext
5. tamper-demo button

Tamper demo behavior:
- Creates in-memory modified copy of first row description and runs verification.
- Expected result is chain failure detection.

### 8.8 Error Visibility Pattern

Most recent error is surfaced in sidebar for immediate operator awareness.

Error origin examples:
1. serial open/login failures
2. ARP sniff exceptions
3. queue processing errors
4. audit persistence issues

This visibility pattern reduces silent failure risk during demos.

### 8.9 Why This UI Structure Works for Outsiders

The three-page split mirrors operational roles:
1. detect (LIVE MONITOR)
2. control (SWITCH CONSOLE)
3. verify (AUDIT TRAIL)

That mental model makes project behavior easy to explain during review, viva, and external handover.

## 9. Operational Runbook (Lab and Production-Like Use)

### 9.1 Pre-Deployment Checklist

Before first run, ensure:
1. Python 3.10+ is available.
2. Required dependencies are installed from requirements file.
3. Switch console cable is physically connected.
4. Serial port path is known and configured.
5. Switch credentials are valid.
6. ARP sniff interface is correct.
7. On Windows, packet capture backend (Npcap) is installed.

### 9.2 Configuration Procedure

Populate YAML configuration in this order:
1. mode
- keep as hardware
2. database path
- local writable file path
3. crypto key paths
- stable local files for continuity
4. serial block
- port, baudrate, timeout, username, password
5. detection block
- MAC threshold and poll interval
6. arp block
- interface name and sniff window timeout

Recommended validation after edit:
1. confirm no YAML indentation mistakes
2. confirm serial port exists on host
3. confirm interface name matches OS listing exactly

### 9.3 First-Run Bring-Up Sequence

1. Launch Streamlit app.
2. Observe startup without config-load errors.
3. Confirm monitor status becomes RUNNING.
4. Open SWITCH CONSOLE and verify startup commands appeared.
5. Open AUDIT TRAIL and verify entries are being appended.

If startup command outputs are absent, prioritize serial/login troubleshooting before detector validation.

### 9.4 Live Operation Procedure

Normal operation loop for operator:
1. Keep LIVE MONITOR open for posture tracking.
2. Use SWITCH CONSOLE for manual checks (show commands).
3. Periodically verify audit chain from AUDIT TRAIL.
4. Use snapshot action before and after demonstrations for reportability.

### 9.5 Demonstration Procedure (Safe)

For presentations/viva:
1. Trigger Inject MAC Flood.
2. Verify attack event appears.
3. Verify defense command appears.
4. Repeat with Inject ARP Spoof.
5. Verify both are reflected in audit table.

Because triggers are synthetic, this demonstrates response pipeline without creating harmful traffic.

### 9.6 Post-Run Evidence Collection

For external reporting and reproducibility:
1. Capture screenshots of all three pages.
2. Export or copy recent command records (with outputs and HMAC).
3. Export or copy recent audit rows (with prev_hash and entry_hash).
4. Record Verify Chain result.
5. Record active config (credentials redacted).

### 9.7 Shutdown Procedure

1. Stop Streamlit process gracefully.
2. Ensure DB file and key files are retained together.
3. Do not rotate/delete keys if historical decryption is still required.

### 9.8 Lightweight Hardening Recommendations

For deployments beyond pure lab context:
1. Restrict filesystem permissions on database and key files.
2. Avoid default/weak switch credentials.
3. Keep host patched and dedicated for monitoring role.
4. Add periodic DB backup process.
5. Add key rotation and re-encryption strategy in next project phase.

## 10. Troubleshooting Decision Tree

### 10.1 App Fails to Start

Symptoms:
- Streamlit launch error
- immediate config parse failure

Decision path:
1. Does config file parse as valid YAML?
- No: fix indentation/formatting.
- Yes: continue.

2. Is mode set to hardware?
- No: set hardware.
- Yes: continue.

3. Are required Python packages installed?
- No: reinstall dependencies.
- Yes: inspect traceback for specific module/runtime issue.

### 10.2 Monitor Status Not RUNNING

Symptoms:
- UI loads, but monitor shows STOPPED or persistent error.

Decision path:
1. Check sidebar latest error text.
2. If serial open failed:
- verify cable and COM/tty path
- verify no other app owns the port
3. If login failed:
- verify username/password
- verify prompt behavior on direct console session
4. Restart app after corrections.

### 10.3 Commands Not Returning Output

Symptoms:
- Command appears sent but output is empty/unexpected.

Decision path:
1. Confirm switch prompt style matches expected delimiters.
2. Confirm skip-page-display startup command succeeded.
3. Try simple known-safe command (show arp, show interfaces brief).
4. If still unstable, inspect serial timeout and increase cautiously.

### 10.4 MAC Detector Not Triggering

Symptoms:
- MAC chart updates, but no MAC_FLOOD event appears.

Decision path:
1. Is previous_mac_count initialized (after at least one poll)?
2. Is delta actually above threshold?
3. For demo, reduce threshold temporarily.
4. Confirm parser can count MAC lines from switch output format.

### 10.5 ARP Detector Not Triggering

Symptoms:
- No ARP metrics or no ARP_SPOOF events.

Decision path:
1. Is interface name correct and active?
2. Is packet capture permission sufficient (admin/root)?
3. Is packet capture backend installed on Windows?
4. Is there observable ARP reply traffic on that interface?

### 10.6 Frequent ARP Sniff Errors

Symptoms:
- Repeating ARP sniff failed messages.

Decision path:
1. Validate capture backend and driver state.
2. Validate interface visibility to capture library.
3. Run process with elevated privilege.
4. Verify no endpoint security policy blocks sniffing APIs.

### 10.7 Audit Chain Verification Fails

Symptoms:
- Verify Chain reports broken link or hash mismatch.

Decision path:
1. Confirm audit DB was not edited manually.
2. Confirm row ordering for verification is ascending by id.
3. Confirm key files and DB correspond to same project history.
4. Treat failure as potential integrity incident until disproven.

### 10.8 Database Locked Errors

Symptoms:
- intermittent persistence failures mentioning locked database.

Decision path:
1. Ensure no external tool is holding long write locks.
2. Rely on built-in retry behavior for transient locks.
3. If persistent, close external viewers and restart app.
4. Consider reducing concurrent external reads during demo.

### 10.9 Minimal Incident Report Template

When escalating issues externally, report:
1. timestamp and environment details
2. exact step where failure occurred
3. latest sidebar error message
4. last 10 command records
5. last 10 audit rows
6. chain verification result

## 11. Known Limitations and Safe Future Enhancements

### 11.1 Current Limitations

1. Single-switch focus
- Current design targets one serial-connected switch session at a time.

2. Limited detector set
- Only MAC flood and ARP spoof logic are implemented.

3. Heuristic parser dependency
- MAC count parser depends on expected CLI formatting patterns.

4. Local trust boundary
- Key files and DB remain on local host with no external attestation.

5. No RBAC/user identity
- Manual commands are source-tagged but not identity-authenticated.

6. No true command rollback framework
- Undo in UI is historical record adjustment, not network state reversal.

7. No retention management
- Database grows without automatic pruning/archival.

8. Non-distributed runtime
- No horizontal scaling, failover coordination, or remote collector fabric.

### 11.2 Why These Limits Are Acceptable for This Stage

Given project objectives (lab demonstration and educational clarity), these constraints are intentional:
1. Keep control flow auditable end-to-end.
2. Minimize operational moving parts.
3. Prioritize deterministic behavior for evaluation and teaching.

### 11.3 Safe Enhancement Path (Phase 2)

Recommended next enhancements in practical order:

1. Harden secret handling
- introduce environment-based secret injection or protected key store.

2. Add identity-aware command accountability
- capture operator identity/session metadata with each manual command.

3. Expand detection library
- include DHCP anomalies, port scan indicators, and unauthorized VLAN shifts.

4. Improve parser resilience
- switch to template-driven parser profiles per firmware variant.

5. Add retention and archival controls
- rolling windows, compressed export, and integrity-preserving archive verification.

6. Add notification integrations
- webhook/email/SIEM forwarding for attack events and integrity failures.

7. Introduce policy abstraction for responses
- map attack classes to configurable response profiles rather than fixed commands.

### 11.4 High-Assurance Enhancement Path (Phase 3)

For stronger production readiness:
1. Signed audit anchoring to external trust service.
2. Periodic immutable snapshotting to append-only storage.
3. HSM-backed key custody and scheduled rotation.
4. Multi-device collector architecture with secure message bus.
5. Test harness with replayable traffic traces and conformance checks.

### 11.5 Backward Compatibility Considerations

When extending project, preserve:
1. existing event kinds and baseline payload fields,
2. audit chain append semantics,
3. operator mental model of detect -> control -> verify.

This protects documentation continuity and lowers handover friction for external adopters.

## 12. Glossary and Quick Reference

### 12.1 Glossary

1. MAC Flood
- Abnormal surge in observed MAC entries, often associated with switch CAM table pressure.

2. ARP Spoof
- Condition where a known IP is observed with a different MAC mapping than previously learned.

3. CMD_RECORD
- Worker-to-UI event carrying executed command metadata and output.

4. ATTACK_EVENT
- Normalized detection event payload used for persistence and UI display.

5. MAC_METRIC
- Periodic MAC measurement sample for trend and threshold logic.

6. ARP_METRIC
- Current ARP observation summary including tracked mapping stats.

7. ERROR_EVENT
- Structured runtime fault report emitted by worker/UI processing.

8. HMAC Signature
- SHA-256 keyed digest over command text to support integrity checking.

9. Hash Chain
- Linked digest sequence where each entry references the previous entry hash.

10. GENESIS
- Special prev_hash marker used for the first audit row.

### 12.2 Module-to-Responsibility Map

1. app.py
- Streamlit orchestration, queue drain, page rendering, audit writing.

2. monitor.py
- Worker loop, detectors, command queue handling, auto-defense dispatch.

3. serial_engine.py
- Serial session handling, login/prepare, command send/read, MAC parser.

4. db.py
- SQLite schema setup, inserts, recent queries, audit hash retrieval.

5. crypto_log.py
- Fernet/HMAC key handling, payload encryption, hash chain computation/verification.

6. config.yaml
- Runtime parameters for mode, serial, detection, and ARP behavior.

7. simulator.py
- Explicit disabled placeholder for non-hardware mode.

### 12.3 Event Kind Quick Matrix

1. CMD_RECORD
- Produced by: worker after any command execution
- Consumed by: UI history + audit

2. ATTACK_EVENT
- Produced by: worker detectors or synthetic actions
- Consumed by: events table + audit + live event display

3. MAC_METRIC
- Produced by: worker MAC polling
- Consumed by: metric state + mac_snapshots table

4. ARP_METRIC
- Produced by: worker ARP observation loop
- Consumed by: metric state only

5. ERROR_EVENT
- Produced by: worker and queue-processing exception paths
- Consumed by: sidebar error state + audit

### 12.4 Key Defensive Commands Reference

1. port security max-mac-count 5
- Triggered on MAC_FLOOD path.

2. ip arp inspection vlan 1
- Triggered on ARP_SPOOF path.

### 12.5 End-to-End Validation Checklist (External Reviewer)

An external reviewer can validate implementation quality by confirming:
1. app starts and worker remains running,
2. startup commands are visible in command history,
3. manual command execution produces signed command records,
4. synthetic triggers generate attack events and defense commands,
5. audit entries are appended for command/event/error actions,
6. chain verification passes for untampered data,
7. tamper demo produces expected verification failure.

---

Document completion note:
This guide was intentionally built in incremental sections so each concern (scope, architecture, data, crypto, serial, detection, UI, operations) could be validated independently before final handover.
