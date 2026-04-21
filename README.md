# SecureLAN Monitor (Refactored Hardware Build)

SecureLAN Monitor is a hardware-only lab project for Ruckus ICX 7150.
The current implementation uses verified command execution, startup hardening,
automatic quarantine, operator recovery, and cryptographic audit logging.

## 1. What Is Implemented

- Hardware mode only
- Serial communication through pyserial
- Attack detection:
  - MAC flood from port-security violation output
  - ARP spoof from live ARP reply mismatch
- Defense action:
  - Move attacker or offending port into quarantine VLAN
- Recovery action:
  - Operator authorizes restoration back to access VLAN
- Audit and proof:
  - Fernet encrypted payloads
  - SHA-256 hash chain
  - HMAC command signatures

## 2. Runtime Architecture

- app.py:
  - UI pages
  - queue draining
  - DB writes and audit writes
- monitor.py:
  - worker loop
  - detection and auto-defense
  - recovery command handling
- serial_engine.py:
  - serial open/login
  - command send and output capture
- db.py:
  - SQLite schema and inserts
- crypto_log.py:
  - encryption, signatures, chain verification

## 3. Required Lab Topology

For real attack demonstration with one console port and two PCs:

- Switch: ICX 7150
- PC1 (Defender Console):
  - USB-to-serial cable to switch console port
  - Ethernet to switch data port
  - Runs streamlit app.py
- PC2 (Attacker):
  - Ethernet to switch data port
  - Runs attack scripts

You need the serial cable for control and at least one data path for ARP observation.

## 4. Installation

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Install Npcap for Scapy sniffing on Windows:
- https://npcap.com/

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 5. Configuration (Authoritative Keys)

Edit config.yaml with these active keys:

- mode: must be hardware
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
- network.access_vlan (optional, defaults to 1)
- arp.interface
- arp.sniff_timeout_sec

Note:
- Old keys like detection.mac_flood_threshold and detection.mac_poll_interval_sec
  are not used by the refactored monitor loop.

## 6. Start the App

```powershell
streamlit run app.py
```

Expected pages:
- NETWORK STATUS
- ATTACK CONSOLE
- AUDIT & PROOF

## 7. Startup Sequence (What You Should See)

After worker starts and serial login succeeds:

1. SYSTEM startup commands
   - enable
   - skip-page-display
2. Baseline preload
   - show arp
3. Port hardening
   - show interfaces brief
   - for each UP port:
     - port security
     - port security max-mac-count 1
     - port security violation shutdown
4. DAI enable
   - ip arp inspection vlan 1

If any strict command is rejected by switch CLI, an ERROR_EVENT is emitted.

## 8. Real Attack Demonstration

### 8.1 MAC Flood Demo (PC2)

On PC2:

```powershell
python mac_flood_attack.py --iface "YourAttackerInterface"
```

Expected response on PC1 UI:
- ATTACK_EVENT with attack_type MAC_FLOOD
- AUTO_DEFENSE command sequence:
  - configure terminal
  - vlan <quarantine_vlan> untagged <offending_port>
  - exit
- Port appears in quarantine panel

### 8.2 ARP Spoof Demo (PC2)

Use PC1 as victim and switch SVI as gateway (or your real gateway).

On PC2:

```powershell
python arp_spoof_attack.py --iface "YourAttackerInterface" --target <PC1_IP> --gateway <Gateway_IP>
```

Expected response on PC1 UI:
- ATTACK_EVENT with attack_type ARP_SPOOF
- Attacker MAC lookup through show mac-address <attacker_mac>
- AUTO_DEFENSE quarantine sequence for attacker port

## 9. Recovery Showcase

From ATTACK CONSOLE on PC1:

1. In Quarantine Panel, click Authorize Port Recovery for the target port.
2. Worker sends strict recovery sequence:
   - configure terminal
   - vlan <access_vlan> untagged <port>
   - interface ethernet <port_id>
   - enable
   - exit
   - exit
3. UI receives PORT_RECOVERY_EVENT if all commands are accepted.

If any recovery command is rejected, port stays quarantined and ERROR_EVENT is shown.

## 10. Audit Demonstration

Go to AUDIT & PROOF page:

1. Click Verify Now
2. Open latest ATTACK_EVENT and PORT_RECOVERY entries
3. View encrypted blob and decrypted payload

This proves end-to-end detection, response, and tamper-evident logging.

## 11. Troubleshooting

### Serial open failed
- Check COM port or tty path
- Confirm cable and adapter driver
- Ensure no other terminal app is holding the port

### Login fails
- Verify serial.username and serial.password
- Verify switch prompt and baudrate

### ARP sniff errors
- Windows: install Npcap and run elevated terminal
- Verify arp.interface name exactly matches active NIC

### No quarantine despite event
- Check ERROR_EVENT in UI for command rejection text
- Verify quarantine VLAN exists on switch

## 12. Safety Notes

- Run attacks only in authorized lab environment.
- Do not run these scripts on production networks.
- Keep keys and credentials private.
