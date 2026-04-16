# SecureLAN Monitor (Hardware-Only)

SecureLAN Monitor is a Python mini-project for hardware operation with a Ruckus ICX 7150 switch.

This build is intentionally hardware-only.

## 1. Supported Scope

- Mode: hardware only
- Serial communication: Python `pyserial` only
- Detections: MAC Flooding and ARP Spoofing only
- Defense commands:
  - `port security max-mac-count 5`
  - `ip arp inspection vlan 1`
- UI: Streamlit with three logical pages in `app.py`
- Cryptographic audit:
  - Fernet encrypted audit payloads
  - SHA-256 hash chain
  - HMAC-SHA256 command signatures

## 2. Project Structure

- `app.py`: Streamlit app and queue drain orchestration
- `monitor.py`: worker loop for detection and auto-defense
- `serial_engine.py`: serial login/command/read wrapper
- `crypto_log.py`: encryption, HMAC, hash chain verification
- `db.py`: SQLite setup and helper methods
- `simulator.py`: disabled placeholder only
- `config.yaml`: editable runtime settings
- `requirements.txt`: pinned dependencies
- `README.md`: setup and operations guide

## 3. System Requirements

- Python 3.10 or newer
- Serial access to Ruckus ICX 7150 management console
- Administrator/root privileges for ARP sniffing
- Windows users: Npcap installed for Scapy packet capture

## 4. Installation

### Windows

1. Create a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Install Npcap (required for Scapy):
- Download from https://npcap.com/
- Install with default options
- Restart terminal/VS Code after install

### Linux

1. Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run Streamlit with privileges if ARP sniffing requires it:

```bash
sudo .venv/bin/streamlit run app.py
```

## 5. Hardware Prerequisites

- Connect console cable to switch and host system.
- Confirm serial settings match switch:
  - Port: `COMx` on Windows or `/dev/ttyUSB0` on Linux
  - Baudrate: typically `9600`
  - Timeout: default `2`
- Ensure valid switch credentials in `config.yaml`.

### How to find serial port

Windows:

```powershell
mode
```

Linux:

```bash
ls /dev/ttyUSB*
```

## 6. Configuration Reference

Edit `config.yaml`:

- `mode`: must stay `hardware`
- `streamlit_refresh_ms`: UI refresh interval in milliseconds
- `db_path`: SQLite DB file path

`crypto`:
- `fernet_key_path`: Fernet key file path
- `hmac_key_path`: HMAC secret file path

`serial`:
- `port`: COM port or tty path
- `baudrate`: serial speed
- `timeout`: read timeout
- `username`: switch username
- `password`: switch password

`detection`:
- `mac_flood_threshold`: delta threshold for MAC flooding
- `mac_poll_interval_sec`: `show mac-address` polling interval

`arp`:
- `interface`: NIC interface name for sniffing
- `sniff_timeout_sec`: per-cycle sniff timeout

## 7. First Run (Quickstart)

1. Activate environment
2. Install requirements
3. Set `config.yaml` serial and interface values
4. Start app:

```bash
streamlit run app.py
```

5. Open browser URL shown by Streamlit

## 8. Runtime Workflow

### Page 1: LIVE MONITOR

Shows:
- Current mode and monitor status
- MAC detector values: current, previous, delta, threshold
- ARP detector values: tracked IP count, last ARP packet, suspicious mapping
- MAC count line chart
- Last 10 attack events
- Demo trigger buttons:
  - Inject MAC Flood
  - Inject ARP Spoof

The demo trigger buttons are safe synthetic triggers. They do not generate real attack traffic.
They directly invoke the corresponding detector event path so defenses and logging can be demonstrated.

### Page 2: SWITCH CONSOLE

Shows:
- Live terminal output (commands and exact switch responses)
- Manual command input
- Command history table:
  - timestamp
  - source (SYSTEM/AUTO/MANUAL)
  - command
  - output
  - HMAC signature
- Recovery controls:
  - Undo Last Command (UI/DB only)
  - Take Snapshot

### Page 3: AUDIT TRAIL

Shows:
- Audit table:
  - timestamp
  - action_type
  - description
  - prev_hash
  - entry_hash
- `Verify Chain` button
- Selected entry inspector:
  - encrypted blob
  - decrypted plaintext
- Demo tamper test button

## 9. Supported Switch Commands

Startup/system:
- `enable`
- `skip-page-display`

Detection polling:
- `show mac-address`

Supported manual commands (at minimum):
- `show arp`
- `show interfaces brief`

Defense actions:
- `port security max-mac-count 5`
- `ip arp inspection vlan 1`

Manual console:
- Any CLI command you type in the SWITCH CONSOLE page

## 10. Detection Logic

### MAC Flooding

- Poll `show mac-address`
- Parse valid MAC entries
- Compute `delta = current_count - previous_count`
- If `delta > mac_flood_threshold`, trigger `MAC_FLOOD`

### ARP Spoofing

- Sniff ARP replies using Scapy
- Track IP to MAC mapping
- If same IP appears with a different MAC, trigger `ARP_SPOOF`

## 11. Defense Actions

On `MAC_FLOOD`:
- Send `port security max-mac-count 5`

On `ARP_SPOOF`:
- Send `ip arp inspection vlan 1`

All defense commands are logged in command history and audit trail.

## 12. Error Handling

App catches and logs:
- Serial port unavailable
- Login failure patterns
- Switch timeout/output issues
- ARP sniff permission or interface errors
- SQLite locked errors (bounded retries)

Errors are shown in UI sidebar and written into `audit_log`.

## 13. Troubleshooting Matrix

### Serial open failed
- Likely cause: wrong port or cable disconnected
- Verify:
  - Windows: `mode`
  - Linux: `ls /dev/ttyUSB*`
- Fix: update `serial.port` in `config.yaml`

### Login does not progress
- Likely cause: credentials mismatch or prompt format mismatch
- Verify: check latest `SYSTEM` command outputs in SWITCH CONSOLE
- Fix: correct username/password; test manually on console

### No ARP events appear
- Likely cause: wrong interface or missing privileges
- Verify:
  - Confirm `arp.interface` value
  - Run with elevated privileges
- Fix: set correct interface and run as admin/root

### ARP sniff failed on Windows
- Likely cause: Npcap missing
- Verify: check sidebar error messages
- Fix: install Npcap and restart terminal

### Database locked errors
- Likely cause: external process holding DB
- Verify: check audit error logs
- Fix: close other DB viewers and retry

## 14. AI Debug Pack (Share This For Fast Help)

When asking AI to debug, share:

1. OS and Python version:

```bash
python --version
```

2. Dependency install output:

```bash
pip install -r requirements.txt
```

3. Startup command and first error traceback:

```bash
streamlit run app.py
```

4. `config.yaml` with password redacted
5. Last 20 command history records (timestamp/source/command/output/hmac)
6. Last 20 audit rows (`timestamp`, `action_type`, `prev_hash`, `entry_hash`)
7. Verify Chain result from AUDIT TRAIL page
8. Exact reproduction steps as numbered list

## 15. Reproducibility Checklist

- Fresh virtual environment used
- Requirements installed without conflicts
- Serial port and interface configured correctly
- App starts and worker remains running
- Commands and outputs visible in SWITCH CONSOLE
- Audit chain verifies successfully

## 16. Security and Safety Notes

- Use only authorized test environment and switch.
- Keep credentials private.
- Do not run active attack tools from this project.
- This project is for monitoring and response demonstration.

## 17. Known Limitations

- Prompt parsing is best-effort and may vary by switch firmware prompt style.
- ARP detection quality depends on interface visibility and privileges.
- Undo command is UI/DB action only; no reverse switch command is sent.
- Hardware-only build does not include simulation runtime.
