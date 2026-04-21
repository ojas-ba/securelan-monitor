# SecureLAN Monitor: Outsider Implementation Guide (Refactored Build)

This document explains the current implementation for evaluators who want a
technical understanding without reading source code first.

## 1. Project Objective

SecureLAN Monitor is a hardware-only security monitoring and response prototype for
Ruckus ICX 7150. It demonstrates:

- Real serial console automation
- Live attack signal detection
- Automatic containment (quarantine VLAN)
- Operator-approved port recovery
- Cryptographic audit proof

## 2. Scope and Boundaries

Implemented attack classes:
- MAC_FLOOD
- ARP_SPOOF

Implemented response class:
- Port quarantine into configured quarantine VLAN

Implemented operator action:
- Recover quarantined port back to configured access VLAN

Not implemented:
- Full SIEM functionality
- Multi-switch orchestration
- Role-based access control
- Production policy engine

## 3. Runtime Components

1. UI layer (app.py)
- Streamlit pages
- Session state and queue drain
- Writes to database and audit log

2. Worker layer (monitor.py)
- Switch polling and ARP sniffing
- Detection and auto-defense
- Manual command and recovery handling

3. Serial layer (serial_engine.py)
- Serial lifecycle and login sequence
- Command execution and output capture
- HMAC signature creation for command records

4. Persistence layer (db.py)
- events table
- mac_snapshots table
- audit_log table

5. Crypto layer (crypto_log.py)
- Fernet payload encryption
- SHA-256 chain hashing
- Chain verification

## 4. Concurrency Model

Two long-running execution contexts:

1. Streamlit context
- Drains worker events
- Updates UI state
- Persists events and audit entries

2. Worker thread
- Handles serial and sniff I/O
- Emits structured events to event_queue
- Consumes operator commands from command_queue

This design keeps UI responsive during switch/network operations.

## 5. Event Contract

Worker emits envelopes with:
- kind
- data

Current kinds:
- CMD_RECORD
- ATTACK_EVENT
- MAC_METRIC
- ARP_METRIC
- BASELINE_EVENT
- PORT_RECOVERY_EVENT
- ERROR_EVENT

## 6. Startup Pipeline

At runtime start:

1. App loads config and enforces hardware mode.
2. App initializes DB, crypto keys, queues, and worker thread.
3. Worker opens serial and executes login sequence.
4. Worker sends startup commands:
   - enable
   - skip-page-display
5. Worker runs baseline hardening:
   - show arp and preload ARP map
   - show interfaces brief and harden active ports
   - ip arp inspection vlan 1

Port hardening command sequence for each UP port:
- configure terminal
- interface ethernet <id>
- port security
- port security max-mac-count 1
- port security violation shutdown
- exit
- exit

## 7. Detection and Containment Logic

### 7.1 MAC Flood Path

1. Worker polls show port security on interval detection.poll_interval_sec.
2. Parser extracts violated ports where shutdown is active and violation_count > 0.
3. For each new offending port, worker runs quarantine sequence:
   - configure terminal
   - vlan <quarantine_vlan> untagged <port>
   - exit
4. ATTACK_EVENT is emitted with action_taken.

### 7.2 ARP Spoof Path

1. Worker sniffs ARP replies on arp.interface.
2. If same IP appears with different MAC from baseline map, ARP_SPOOF is detected.
3. Worker looks up attacker port with show mac-address <attacker_mac>.
4. If port is found, worker runs quarantine sequence.
5. ATTACK_EVENT is emitted with attacker details and action_taken.

## 8. Recovery Logic

Operator triggers recovery from ATTACK CONSOLE.
Worker executes strict recovery sequence:

- configure terminal
- vlan <access_vlan> untagged <port>
- interface ethernet <port_id>
- enable
- exit
- exit

Only if all commands are accepted:
- port is removed from quarantine state
- PORT_RECOVERY_EVENT is emitted

If any command is rejected:
- quarantine remains
- ERROR_EVENT is emitted

## 9. Command Validation and Error Handling

The worker validates command outputs using CLI error patterns (invalid input,
incomplete command, unknown command, syntax error, and related forms).

Behavior:
- Strict paths (hardening, quarantine, recovery) fail on CLI rejection.
- Manual command path still records output, but emits ERROR_EVENT if rejected.

This prevents false success states in UI.

## 10. UI Pages (Current)

1. NETWORK STATUS
- Connection and hardening state cards
- MAC chart
- Live event feed

2. ATTACK CONSOLE
- Terminal-style command history
- Manual command input (Run Command)
- Quarantine panel with Authorize Port Recovery button

3. AUDIT & PROOF
- Chain status banner
- Verify Now button
- Per-entry encrypted and decrypted views

Sidebar utility:
- Load Mock Data button for layout/demo content

## 11. Database and Evidence

Tables:
- events: attack events and details_json
- mac_snapshots: timeline chart data
- audit_log: cryptographic chain evidence

Audit entry fields:
- action_type
- description
- encrypted_blob
- prev_hash
- entry_hash
- hmac_sig

Chain validation:
- Verify Now recomputes and validates hash chain from genesis to latest row

## 12. Lab Demonstration Recipe

Topology for one-console-port plus two PCs:

- PC1 Defender:
  - console cable to switch
  - data cable to switch
  - runs streamlit app
- PC2 Attacker:
  - data cable to switch
  - runs attack scripts

Demo sequence:

1. Launch app on PC1 and confirm startup hardening completes.
2. On PC2 run MAC flood script and show quarantine event on PC1.
3. On PC2 run ARP spoof script and show attacker-port quarantine on PC1.
4. On PC1 run Authorize Port Recovery for quarantined port.
5. On PC1 verify audit chain in AUDIT & PROOF.

## 13. Active Configuration Keys

Authoritative config schema:

- mode
- streamlit_refresh_ms
- db_path
- crypto.fernet_key_path
- crypto.hmac_key_path
- serial.port
- serial.baudrate
- serial.timeout
- serial.username
- serial.password
- detection.poll_interval_sec
- network.quarantine_vlan
- network.access_vlan (optional)
- arp.interface
- arp.sniff_timeout_sec

Notes:
- detection.mac_flood_threshold is legacy and not used.
- detection.mac_poll_interval_sec is legacy and not used.

## 14. Known Operational Risks

- Wrong arp.interface produces no useful ARP visibility.
- Missing Npcap or no admin privileges can break sniffing on Windows.
- If switch rejects VLAN/CLI syntax, quarantine or recovery is blocked and
  surfaced as ERROR_EVENT.
- Console prompt variations may require serial login tuning on different firmware.

## 15. Safety and Compliance

Run attack scripts only in an authorized lab environment.
Do not execute this workflow on production networks.
Keep switch credentials and local key files protected.
