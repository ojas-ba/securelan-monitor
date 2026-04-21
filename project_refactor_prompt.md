# SecureLAN Monitor — Full Refactor Prompt

> Archived engineering prompt.
> This file is historical context for the refactor task, not the active runbook.
> For current setup and execution, use README.md, setup.md, and student_experiment_guide.md.

## Context for the AI Agent

You are refactoring an existing project called **SecureLAN Monitor**. It is a hardware-oriented network security monitoring and auto-response system running on Python with a Streamlit frontend. It connects to a **Ruckus ICX 7150 12-port switch** via serial console, detects Layer 2 attacks, issues defense commands, and logs everything with a cryptographic audit chain.

The existing codebase has the following files:
- `app.py` — Streamlit UI, session state, queue drain, page rendering, audit writes
- `monitor.py` — Background worker thread, detection logic, command queue handling, auto-defense dispatch
- `serial_engine.py` — Serial port lifecycle, login/prepare handshake, command send/read, MAC parser
- `db.py` — SQLite schema, inserts, queries (DO NOT MODIFY)
- `crypto_log.py` — Fernet encryption, HMAC signing, SHA-256 hash chain (DO NOT MODIFY)
- `config.yaml` — Runtime config for mode, serial, detection, ARP settings
- `simulator.py` — Disabled placeholder, ignore

The existing architecture uses:
- Two queues: `command_queue` (UI → worker) and `event_queue` (worker → UI)
- Worker runs in a background thread, never touches DB directly
- All DB writes happen in UI thread after queue drain
- Event envelope format: `{ "kind": <string>, "data": <dict> }`
- Existing event kinds: CMD_RECORD, ATTACK_EVENT, MAC_METRIC, ARP_METRIC, ERROR_EVENT
- SQLite tables: `events`, `mac_snapshots`, `audit_log` (schema unchanged)
- Crypto: Fernet for payload encryption, HMAC-SHA256 for command signing, SHA-256 hash chain across audit rows

**DO NOT modify `db.py` or `crypto_log.py` under any circumstances.**

---

## Environment

- OS: Windows 11
- Python 3.10+
- Npcap installed (packet capture backend for Scapy)
- Hardware: Ruckus ICX 7150 (12-port switch)
- Serial console cable physically connected
- Two devices connected to switch for demo: Defender PC (runs SecureLAN Monitor) + Attacker PC (runs attack scripts)
- VLAN 99 already created manually on switch before app starts: `vlan 99 name QUARANTINE`

---

## Files to Modify

### 1. `config.yaml`

**Remove these fields entirely:**
- `detection.mac_threshold` (or whatever the threshold field is named)
- Any baseline poll count or baseline gap fields

**Add these fields:**
- `detection.poll_interval_sec: 10` — interval between `show port security` polls
- `network.quarantine_vlan: 99` — VLAN ID to isolate attacker ports

**Keep all existing fields:** mode, database path, crypto key paths, serial block (port, baudrate, timeout, username, password), arp block (interface, sniff timeout)

---

### 2. `monitor.py`

#### 2A. Add New Worker State Variables

Add these to worker internal state (alongside existing `arp_map`, `last_arp_error`, etc.):
- `arp_map` — already exists, keep it, but populate it at startup (see 2B)
- `hardening_done` — boolean flag, False at start
- `quarantined_ports` — list of port strings currently in quarantine e.g. `["e 1/1/3"]`

#### 2B. Add Startup Baseline Builder

This runs ONCE before the monitor loop begins, after serial login/prepare completes. Execute in this exact order:

**Step 1 — Pre-load ARP map from switch:**
- Execute command: `show arp`
- Parse output line by line
- Extract IP and MAC from each valid ARP entry line
- Ruckus ICX `show arp` output format per line: `<index> <IP> <MAC> <interface> <type> <age>`
- MAC format in output: `xxxx.xxxx.xxxx` (Ruckus dot-notation) — convert to `xx:xx:xx:xx:xx:xx` for storage in `arp_map`
- Store as `arp_map[ip] = mac`
- Emit one `BASELINE_EVENT` with payload: `{ "arp_entries_loaded": <count>, "step": "arp_map_preloaded" }`

**Step 2 — Apply port hardening on all active ports:**
- Execute `show interfaces brief` to get list of active ports
- Parse output to find all port identifiers that are in UP state (format: `e 1/1/1`, `e 1/1/2`, etc.)
- For each active port, fire these three commands in sequence via serial engine with source=SYSTEM:
  ```
  interface ethernet 1/1/X
  port security
  port security max-mac-count 1
  port security violation shutdown
  exit
  ```
- Emit CMD_RECORD for each command block
- After all ports done, emit one `BASELINE_EVENT` with payload: `{ "ports_hardened": <count>, "step": "port_hardening_complete" }`

**Step 3 — Enable DAI:**
- Execute command: `ip arp inspection vlan 1`
- Emit CMD_RECORD for this command
- Emit `BASELINE_EVENT` with payload: `{ "step": "dai_enabled" }`

**Step 4 — Mark hardening complete:**
- Set `hardening_done = True`
- Emit final `BASELINE_EVENT` with payload:
  ```json
  {
    "step": "hardening_complete",
    "arp_entries": <count>,
    "ports_hardened": <count>,
    "dai_enabled": true
  }
  ```

All BASELINE_EVENTs are emitted to `event_queue`.

#### 2C. Replace MAC Flood Detection Logic

**Remove entirely:**
- All delta computation
- All threshold comparison
- All references to `previous_mac_count` and threshold config value
- The `show mac-address` polling loop used for detection

**Add — Port Security Violation Monitoring:**

Poll `show port security` every `detection.poll_interval_sec` seconds.

Parse output to find any port in `shutdown` state with violation count > 0.

Ruckus ICX `show port security` output format per port:
```
Port    Status           Violation-count   Last-Violation-MAC
e1/1/3  Shutdown(Psec)   47                ff:ee:dd:cc:bb:aa
```

When a port in shutdown state is found AND it is not already in `quarantined_ports`:

1. Extract: offending port identifier, violation count, last violator MAC
2. Fire quarantine command: `vlan 99 untagged <port>` via serial engine with source=AUTO_DEFENSE
3. Add port to `quarantined_ports` list
4. Emit `ATTACK_EVENT` with payload:
   ```json
   {
     "attack_type": "MAC_FLOOD",
     "severity": "HIGH",
     "details": {
       "offending_port": "<port>",
       "violation_count": <count>,
       "attacker_mac": "<mac>",
       "action_taken": "port_quarantined_vlan99",
       "quarantine_vlan": 99
     }
   }
   ```

**Keep MAC_METRIC events:**
- Still poll `show mac-address` on the same interval for the chart only
- Still emit `MAC_METRIC` with current count for dashboard display
- Do NOT use MAC count for detection anymore — chart display only

#### 2D. Update ARP Spoof Detection Logic

**Existing logic to keep:** sniff ARP reply packets, compare `psrc` IP to `arp_map`, detect mismatch.

**Add attacker fingerprinting when mismatch detected:**

From the ARP packet extract:
- `attacker_mac` = packet `hwsrc` (the real NIC MAC of attacker — cannot be faked at this layer)
- `impersonated_ip` = packet `psrc` (IP attacker is pretending to be)
- `victim_ip` = packet `pdst`
- `victim_mac` = packet `hwdst`
- `legitimate_mac` = `arp_map[impersonated_ip]` (what the IP should map to per baseline)

Then immediately fire: `show mac-address <attacker_mac>` via serial engine.
Parse output to extract physical port the attacker is connected on.
Ruckus ICX `show mac-address <mac>` output format:
```
MAC-Address    Port    VLAN    Type
ffee.ddcc.bbaa  e1/1/3   1      Dynamic
```
Extract port identifier from this output.

Then fire quarantine: `vlan 99 untagged <port>` via serial engine with source=AUTO_DEFENSE.
Add port to `quarantined_ports` list.

Emit `ATTACK_EVENT` with payload:
```json
{
  "attack_type": "ARP_SPOOF",
  "severity": "HIGH",
  "details": {
    "attacker_mac": "<hwsrc>",
    "attacker_port": "<port from show mac-address>",
    "impersonated_ip": "<psrc>",
    "victim_ip": "<pdst>",
    "victim_mac": "<hwdst>",
    "legitimate_mac": "<from arp_map>",
    "action_taken": "port_quarantined_vlan99",
    "quarantine_vlan": 99
  }
}
```

Continue to emit `ARP_METRIC` as before.

#### 2E. Add New Event Kind: BASELINE_EVENT

Add to worker event emission: `{ "kind": "BASELINE_EVENT", "data": <payload> }`
This is consumed by UI to update hardening status display.

#### 2F. Add Port Recovery Command Handler

In the command queue handler, support a new message type:
- Message format: `{ "type": "RECOVER_PORT", "port": "e 1/1/3" }`
- When received: execute `interface ethernet 1/1/X` then `enable` via serial engine with source=MANUAL
- Remove port from `quarantined_ports` list
- Emit `CMD_RECORD` for the recovery commands
- Emit a new event kind `PORT_RECOVERY_EVENT` with payload: `{ "port": "<port>", "action": "operator_authorized_recovery" }`

#### 2G. Synthetic Demo Triggers — Keep Both

Keep existing `INJECT_MAC_FLOOD` and `INJECT_ARP_SPOOF` synthetic triggers exactly as they are. They must still work. Label them clearly as simulation in their event payloads by adding `"synthetic": true` to the details dict.

---

### 3. `app.py`

#### 3A. Session State — Add New Keys

Add to session state initialization (alongside existing keys):
- `hardening_status` — dict: `{ "done": False, "arp_entries": 0, "ports_hardened": 0, "dai_enabled": False }`
- `quarantined_ports` — list of port strings currently quarantined
- `last_attack_details` — dict storing the most recent ATTACK_EVENT payload for timeline display

#### 3B. Queue Drain — Add New Event Handlers

Add handlers for new event kinds:

**BASELINE_EVENT:**
- Update `hardening_status` in session state based on `step` field in payload
- Write audit entry with action_type = "BASELINE_EVENT"

**PORT_RECOVERY_EVENT:**
- Remove port from `quarantined_ports` in session state
- Write audit entry with action_type = "PORT_RECOVERY"

**For existing CMD_RECORD handler — add filtering:**
- If command text contains `show mac-address` AND source is SYSTEM (polling): route to a separate `polling_records` list, NOT to `command_records`
- If command text contains `show arp` AND source is SYSTEM (polling): same, route to `polling_records`
- All other CMD_RECORDs go to `command_records` as before
- Cap `polling_records` at 10 entries (FIFO, drop oldest)

#### 3C. Page 1: Network Status (rename from LIVE MONITOR)

**Top row — 4 metric cards using `st.columns(4)`:**

Card 1 — Switch Connection:
- Green if serial connected, Red if not
- Show: "CONNECTED" / "DISCONNECTED"
- Sub-label: serial port name from config

Card 2 — Hardening Status:
- Green if `hardening_status["done"]` is True, Yellow if in progress, Red if not started
- Show: "HARDENED" / "HARDENING..." / "NOT HARDENED"
- Sub-label: "X ports secured · DAI active" when done

Card 3 — MAC Flood Status:
- Green if no MAC_FLOOD in `quarantined_ports` context, Red if active attack
- Show: "CLEAN" / "ATTACK DETECTED"
- Sub-label: current MAC count from latest MAC_METRIC

Card 4 — ARP Spoof Status:
- Green if no recent ARP_SPOOF event, Red if active
- Show: "CLEAN" / "ATTACK DETECTED"
- Sub-label: "X mappings tracked" from latest ARP_METRIC

Use `st.markdown` with inline CSS for card colors. Do not use `st.metric` delta arrows — use custom styled containers.

**Middle — MAC Count Chart:**
- Line chart of MAC count over time from `mac_snapshots` table
- X-axis: timestamp, Y-axis: MAC count
- Use Plotly via `st.plotly_chart`
- No threshold line, no baseline line — clean single line only
- Points where an ATTACK_EVENT occurred should be marked as red dots on the line

**Below chart — Event Feed:**
- Display `live_events` list as a styled feed, NOT a dataframe table
- Each entry is a colored row:
  - 🔴 RED background: attack events
  - 🟡 YELLOW background: warnings/errors
  - 🟢 GREEN background: system/baseline events
  - 🔵 BLUE background: manual operator actions
- Each row shows: `[timestamp] [type] [one-line summary] [action taken]`
- Clicking a row (use `st.expander`) reveals full details_json
- Show maximum 20 most recent events

**Bottom — Simulation Controls:**
- Two buttons side by side: `[🧪 Simulate MAC Flood]` and `[🧪 Simulate ARP Spoof]`
- Below the buttons, add a note in grey italic text: "Simulation mode — no real attack traffic generated"
- These push to command_queue exactly as before

#### 3D. Page 2: Attack Console (rename from SWITCH CONSOLE)

**Layout: two columns — 60% left, 40% right**

**Left column — Action Terminal:**
- Render `command_records` list as a styled terminal panel
- Dark background: `background-color: #1a1a1a`
- Monospace font: `font-family: 'Courier New', monospace`
- Color code each line by source field:
  - source = SYSTEM → color: `#888888` (grey)
  - source = AUTO_DEFENSE → color: `#ff4444` (red)
  - source = MANUAL → color: `#44aaff` (cyan)
- Each line format: `[HH:MM:SS] [SOURCE] command_text`
- On hover show HMAC badge — use `title` attribute in HTML: `✓ HMAC: <first 12 chars of hmac_sig>`
- Render using `st.markdown` with `unsafe_allow_html=True`
- Fixed height scrollable container: `height: 400px; overflow-y: auto`
- Scroll to bottom by default

**Below terminal — Polling Log (collapsed):**
- `st.expander("📊 Polling Log (last 10 polls)", expanded=False)`
- Inside: render `polling_records` list in same terminal style but smaller font
- Grey text only, no color coding needed

**Below polling log — Manual Command Input:**
- `st.text_input` for command
- `st.button("Run Command")`
- On submit: push `{ "type": "command", "command": <text> }` to command_queue

**Right column — Attack Timeline:**
- Header: "Last Incident"
- If `last_attack_details` is None: show grey italic "No attacks detected — system monitoring"
- If `last_attack_details` is populated: render a numbered step-by-step card:

  For MAC_FLOOD:
  ```
  ① Detection
     Type: MAC_FLOOD
     Port: <offending_port>
     Violations: <violation_count>

  ② Attacker Identified
     MAC: <attacker_mac>
     Port: <offending_port>

  ③ Defense Executed
     Command: port security violation shutdown
     Status: Already active (hardware)

  ④ Port Quarantined
     Port <offending_port> → VLAN 99

  ⑤ Audit Written
     Chain entry logged
  ```

  For ARP_SPOOF:
  ```
  ① Detection
     Type: ARP_SPOOF
     IP Mapping Changed

  ② Attacker Identified
     MAC: <attacker_mac>
     Port: <attacker_port>
     Pretending to be: <impersonated_ip>
     Targeting: <victim_ip> (<victim_mac>)
     Legitimate mapping: <legitimate_mac>

  ③ Defense Executed
     Command: ip arp inspection vlan 1

  ④ Port Quarantined
     Port <attacker_port> → VLAN 99

  ⑤ Audit Written
     Chain entry logged
  ```

**Below right column — Quarantine Panel:**
- Show for each port in `quarantined_ports` session state:
  ```
  ⚠️ Port e 1/1/X — QUARANTINED
  Reason: <attack_type>  Since: <timestamp>
  [✅ Authorize Port Recovery]
  ```
- Recovery button: push `{ "type": "RECOVER_PORT", "port": "e 1/1/X" }` to command_queue

#### 3E. Page 3: Audit & Proof (rename from AUDIT TRAIL)

**Top — Chain Health Banner:**
- Run chain verification on page load
- If verified: green banner: `✅ CHAIN INTEGRITY VERIFIED — X entries — Last checked: HH:MM:SS`
- If broken: red banner: `❌ CHAIN INTEGRITY BROKEN — Tampered at row #X`
- Two buttons side by side: `[🔍 Verify Now]` and `[🧪 Run Tamper Demo]`

**Middle — Audit Entries as Cards:**
- Fetch all audit_log rows in descending order
- For each row render a card using `st.expander`:
  - Expander label: `#<id>  <action_type>  •  <timestamp>`
  - Color the expander label based on action_type:
    - ATTACK_EVENT → red label
    - COMMAND → blue label
    - BASELINE_EVENT / PORT_RECOVERY → green label
    - ERROR_EVENT → yellow label
  - Inside expander:
    - Show: `Prev Hash: <first 16 chars>... → Entry Hash: <first 16 chars>...`
    - Two columns: `[View Encrypted Blob]` and `[View Decrypted]` buttons
    - On View Encrypted: show `encrypted_blob` in a code block
    - On View Decrypted: decrypt using fernet instance and show plaintext in a code block

**Bottom — Tamper Demo Result (shown only after clicking Run Tamper Demo):**
- Take first audit row's description field
- Modify it in memory (e.g., append "_TAMPERED" to one value)
- Re-run chain verification with this modification injected
- Show two columns:
  - Left: original description (green border)
  - Right: tampered description (red border)
- Show verification result below: which row number failed, with row highlighted in red

---

### 4. New File: `mac_flood_attack.py`

Standalone script. Uses Scapy only. Runs on Windows with Npcap.

**Usage:** `python mac_flood_attack.py --iface "Ethernet"`

**Behavior:**
- Accept one argument: `--iface` (network interface name as shown in Windows)
- In a loop:
  - Generate a random 6-byte MAC address
  - Construct an Ethernet frame: `Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff")`
  - Send via `sendp` with `verbose=False`
  - Increment counter
  - Every 100 packets: print `Sent <total> fake MACs — <rate>/sec`
- On Ctrl+C: print summary `Stopped. Total sent: <count>` and exit cleanly

**Requirements:** `scapy` only. No other dependencies.

---

### 5. New File: `arp_spoof_attack.py`

Standalone script. Uses Scapy only. Runs on Windows with Npcap.

**Usage:** `python arp_spoof_attack.py --iface "Ethernet" --target 192.168.1.10 --gateway 192.168.1.1`

**Behavior:**
- Accept arguments: `--iface`, `--target` (victim IP), `--gateway` (gateway IP)
- Resolve target MAC and gateway MAC using `getmacbyip()` at startup. If either fails, print error and exit.
- In a loop:
  - Send ARP reply to target: claiming gateway IP is at attacker's MAC
    `Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)`
  - Send ARP reply to gateway: claiming target IP is at attacker's MAC
    `Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)`
  - Print: `[HH:MM:SS] Poisoning <target_ip> — telling them <gateway_ip> is at <our_mac>`
  - Sleep 1 second
- On Ctrl+C:
  - Send 5 corrective ARP replies to restore original mappings for both target and gateway
  - Print: `Stopped. ARP caches restored.`
  - Exit cleanly

**Requirements:** `scapy` only. No other dependencies.

---

## What NOT to Change

- `db.py` — do not touch. Schema stays identical.
- `crypto_log.py` — do not touch. Crypto logic stays identical.
- `serial_engine.py` — do not touch except: add a method `send_command_raw(cmd, source)` if one doesn't exist for single-command dispatch used by startup hardening. Existing methods unchanged.
- Existing event kinds CMD_RECORD, ATTACK_EVENT, MAC_METRIC, ARP_METRIC, ERROR_EVENT — all keep their existing schema. Only add new fields where specified. Never remove existing fields.
- Existing queue architecture — worker never writes to DB, UI thread handles all persistence. This does not change.
- SQLite table schemas — unchanged.
- Crypto chain — unchanged. New event kinds (BASELINE_EVENT, PORT_RECOVERY_EVENT) get audit entries written via the same existing `write_audit_entry` path.

---

## Ruckus ICX 7150 CLI Reference for Parsers

### `show arp` output format:
```
    IP Address      MAC Address       Type    Age  Interface
1   192.168.1.1     0011.2233.4455    Dynamic  0    e 1/1/1
2   192.168.1.10    ffee.ddcc.bbaa    Dynamic  2    e 1/1/3
```
Parse: split each data line by whitespace, index 1 = IP, index 2 = MAC (convert xxxx.xxxx.xxxx → xx:xx:xx:xx:xx:xx)

### `show mac-address <mac>` output format:
```
MAC-Address        Port      VLAN     Type
ffee.ddcc.bbaa     e1/1/3    1        Dynamic
```
Parse: find line containing the MAC, extract second token as port identifier.

### `show port security` output format:
```
Port      MAC            Shutdown   Violation-Count   Last-Violation-MAC
e1/1/1    0011.2233.4455  No         0                 None
e1/1/3    ffee.ddcc.bbaa  Yes        47                ffee.ddcc.bbaa
```
Parse: for each line where shutdown = Yes and violation count > 0, extract port, violation count, last violator MAC.

### `show interfaces brief` output format:
```
Port    Link    State    Speed    Trunk    Tag    Pvid    Pri    MAC              Name
e1/1/1  Up      Forward  1G       None     No     1       0      0011.2233.4455
e1/1/2  Down    None     None     None     No     1       0      0011.2233.4456
```
Parse: lines where second token = "Up" → extract first token as active port identifier.

### Port hardening command sequence for port `e 1/1/3`:
```
interface ethernet 1/1/3
port security
port security max-mac-count 1
port security violation shutdown
exit
```

### VLAN quarantine command for port `e 1/1/3`:
```
vlan 99 untagged e 1/1/3
```

### Port recovery command for port `e 1/1/3`:
```
interface ethernet 1/1/3
enable
exit
```

---

## Summary of Files to Create/Modify

| File | Action |
|---|---|
| `config.yaml` | Modify — remove threshold, add poll_interval_sec and quarantine_vlan |
| `monitor.py` | Modify — startup hardening, new detection logic, fingerprinting, quarantine, recovery handler |
| `app.py` | Modify — full UI redesign, new session state keys, new queue drain handlers |
| `serial_engine.py` | Modify minimally — verify single-command dispatch method exists |
| `mac_flood_attack.py` | Create new |
| `arp_spoof_attack.py` | Create new |
| `db.py` | DO NOT MODIFY |
| `crypto_log.py` | DO NOT MODIFY |
| `simulator.py` | DO NOT MODIFY |
