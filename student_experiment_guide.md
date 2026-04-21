# SecureLAN Monitor: Student Experiment Guide (Refactored, Real Attacks)

This is the correct guide for the refactored build.
It is designed for your lab case with one switch console port, PC1, and PC2.

## A. What You Will Demonstrate

1. Detection of MAC flood and ARP spoof on real traffic.
2. Automatic quarantine defense on the offending switch port.
3. Operator-approved port recovery from quarantine.
4. Cryptographic audit proof of all actions.

## B. Lab Roles and Connections

Use this exact mapping:

1. Switch: Ruckus ICX7150
2. PC1 (Defender + Operator):
   - USB-to-serial cable to switch console port
   - Ethernet cable to a switch access port
   - Runs app.py
3. PC2 (Attacker):
   - Ethernet cable to another switch access port
   - Runs attack scripts

Why:
- PC1 needs console for control and data NIC for ARP observation.
- PC2 generates attack traffic into the same VLAN.

## C. PC1 Software Setup

Open PowerShell as Administrator on PC1.

1. Go to project folder

```powershell
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"
```

2. Create and activate virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies

```powershell
pip install -r requirements.txt
```

4. Install Npcap if not already installed
- https://npcap.com/

5. Verify imports

```powershell
python -c "import streamlit, serial, scapy, cryptography, pandas, yaml, plotly; print('All imports OK')"
```

## D. Discover Correct Interface Values

1. Find console COM port

```powershell
mode
```

2. Find active NIC name

```powershell
Get-NetAdapter | Select-Object Name, Status, InterfaceDescription
```

## E. Configure config.yaml

Set active keys like this:

```yaml
mode: hardware
streamlit_refresh_ms: 3000
db_path: securelan.db

crypto:
  fernet_key_path: .securelan_fernet.key
  hmac_key_path: .securelan_hmac.key

serial:
  port: COM3
  baudrate: 9600
  timeout: 2
  username: your_switch_user
  password: your_switch_password

detection:
  poll_interval_sec: 10

network:
  quarantine_vlan: 99
  access_vlan: 1

arp:
  interface: Ethernet
  sniff_timeout_sec: 2
```

Important:
- Use your real COM port and NIC name.
- Do not use old keys mac_flood_threshold or mac_poll_interval_sec.

## F. Start the App on PC1

```powershell
streamlit run app.py
```

Open the URL shown in terminal (usually http://localhost:8501).

## G. Verify Startup Baseline (Must Pass)

On ATTACK CONSOLE and NETWORK STATUS pages, verify these startup actions happened:

1. enable
2. skip-page-display
3. show arp
4. show interfaces brief
5. Per active port hardening:
   - port security
   - port security max-mac-count 1
   - port security violation shutdown
6. ip arp inspection vlan 1

If these fail, fix serial credentials and port settings first.

## H. Manual Sanity Check (Before Attack)

In ATTACK CONSOLE, run these commands from the manual command box:

1. show arp
2. show interfaces brief
3. show port security

Confirm each command appears with output and HMAC signature.

## I. Real MAC Flood Demonstration (PC2)

On PC2, open terminal in project folder and run:

```powershell
python mac_flood_attack.py --iface "<PC2_Interface_Name>"
```

Watch PC1 UI and confirm:

1. ATTACK_EVENT appears with type MAC_FLOOD.
2. AUTO_DEFENSE sequence appears:
   - configure terminal
   - vlan 99 untagged <offending_port> (or your configured quarantine VLAN)
   - exit
3. Offending port appears in Quarantine Panel.

Stop attack with Ctrl+C on PC2.

## J. Real ARP Spoof Demonstration (PC2)

Recommended mapping:
- target: PC1 IP
- gateway: switch SVI IP (or actual gateway IP)

On PC2 run:

```powershell
python arp_spoof_attack.py --iface "<PC2_Interface_Name>" --target <PC1_IP> --gateway <Gateway_IP>
```

Watch PC1 UI and confirm:

1. ATTACK_EVENT appears with type ARP_SPOOF.
2. Command record shows lookup: show mac-address <attacker_mac>.
3. AUTO_DEFENSE quarantine command sequence runs for attacker port.
4. Quarantine panel includes attacker port.

Stop attack with Ctrl+C on PC2.

## K. Recovery Demonstration (PC1)

In ATTACK CONSOLE Quarantine Panel:

1. Click Authorize Port Recovery on one quarantined port.
2. Confirm recovery sequence appears:
   - configure terminal
   - vlan <access_vlan> untagged <port>
   - interface ethernet <id>
   - enable
   - exit
   - exit
3. Confirm PORT_RECOVERY_EVENT appears.
4. Confirm port is removed from quarantined list.

If recovery command is rejected by switch, port remains quarantined and ERROR_EVENT is shown.

## L. Audit Proof Demonstration

Go to AUDIT & PROOF page:

1. Click Verify Now.
2. Confirm chain verification success.
3. Open latest ATTACK_EVENT and PORT_RECOVERY entries.
4. Click View Encrypted Blob and View Decrypted.

This completes end-to-end proof: detection -> defense -> recovery -> audit integrity.

## M. Suggested Viva Flow (5-8 Minutes)

1. Show topology and role split: PC1 defender, PC2 attacker.
2. Show startup hardening commands in ATTACK CONSOLE.
3. Run MAC flood from PC2 and show auto quarantine on PC1.
4. Run ARP spoof from PC2 and show attacker port quarantine.
5. Perform Authorize Port Recovery on PC1.
6. Verify chain in AUDIT & PROOF.

## N. Troubleshooting

### 1) Serial open failed
- Check console cable and COM port.
- Ensure no other program owns the COM port.

### 2) Login failure
- Recheck username and password.
- Recheck baudrate.

### 3) ARP sniff failed
- Run elevated terminal.
- Ensure Npcap installed.
- Verify arp.interface value exactly.

### 4) Event detected but quarantine failed
- Check ERROR_EVENT details in UI.
- Verify quarantine VLAN exists on switch and command syntax is accepted.

### 5) Recovery did not release port
- Check ERROR_EVENT for CLI rejection.
- Ensure access_vlan is correct for your lab VLAN.

## O. Quick Command Block (PC1)

```powershell
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m py_compile app.py monitor.py serial_engine.py crypto_log.py db.py simulator.py
streamlit run app.py
```
