# SecureLAN Monitor Lab Setup Guide (Refactored)

This guide is for the current refactored hardware workflow.
It is written for the exact lab case with one ICX7150 console port and two PCs.

## 1. Required Physical Connections

Use this topology:

- Switch: ICX7150
- PC1 (Defender):
  - USB-to-serial cable to switch console port
  - Ethernet cable to switch data port
  - Runs app.py
- PC2 (Attacker):
  - Ethernet cable to switch data port
  - Runs attack scripts

Why this works:
- Console cable gives command/control channel to the monitor worker.
- Data ports carry live ARP and MAC behavior for detection.

## 2. Windows Setup on PC1 (Defender)

Open PowerShell as Administrator:

1. Move to project folder
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"

2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

3. Install dependencies
pip install -r requirements.txt

4. Verify imports
python -c "import streamlit, serial, scapy, cryptography, pandas, yaml, plotly; print('Imports OK')"

5. Find serial COM port
mode

6. Find active NIC name for sniffing
Get-NetAdapter | Select-Object Name, Status, InterfaceDescription

7. Edit config.yaml with correct values

Required active keys:
- mode: hardware
- serial.port: your COM port
- serial.baudrate: usually 9600
- serial.username and serial.password
- detection.poll_interval_sec
- network.quarantine_vlan
- network.access_vlan (optional; default is 1)
- arp.interface: exact NIC Name from Get-NetAdapter
- arp.sniff_timeout_sec

8. Start app
streamlit run app.py

## 3. Linux Setup (If Needed)

1. cd /path/to/NS_Project
2. python3 -m venv .venv
3. source .venv/bin/activate
4. pip install -r requirements.txt
5. ls /dev/ttyUSB*
6. update config.yaml serial.port and arp.interface
7. run with privileges if sniffing needs it:
sudo .venv/bin/streamlit run app.py

## 4. Startup Validation on PC1

After streamlit starts, verify:

- Page NETWORK STATUS shows switch connection and hardening progress.
- ATTACK CONSOLE shows SYSTEM startup commands and outputs.

Expected startup command flow:
- enable
- skip-page-display
- show arp
- show interfaces brief
- port security max-mac-count 1 and port security violation shutdown per active port
- ip arp inspection vlan 1

## 5. Real Attack Demo on PC2

### 5.1 MAC Flood Demo

On PC2, run:

python mac_flood_attack.py --iface "<PC2_Interface_Name>"

Expected on PC1:
- ATTACK_EVENT of type MAC_FLOOD
- AUTO_DEFENSE quarantine sequence in command history
- port appears in Quarantine Panel

### 5.2 ARP Spoof Demo

On PC2, run:

python arp_spoof_attack.py --iface "<PC2_Interface_Name>" --target <PC1_IP> --gateway <Gateway_IP>

Recommended:
- Target is PC1 IP.
- Gateway is switch SVI IP for that VLAN, or your real gateway.

Expected on PC1:
- ATTACK_EVENT of type ARP_SPOOF
- show mac-address <attacker_mac> lookup record
- attacker port quarantine action

## 6. Recovery Demo on PC1

In ATTACK CONSOLE:

1. Locate quarantined port in Quarantine Panel.
2. Click Authorize Port Recovery.
3. Verify recovery sequence in command history:
   - configure terminal
   - vlan <access_vlan> untagged <port>
   - interface ethernet <id>
   - enable
4. Verify PORT_RECOVERY_EVENT appears.

If switch rejects any recovery command, the port stays quarantined and an ERROR_EVENT is shown.

## 7. Audit and Proof Demo on PC1

Go to AUDIT & PROOF:

1. Click Verify Now.
2. Open ATTACK_EVENT and PORT_RECOVERY entries.
3. Click View Encrypted Blob and View Decrypted.

This demonstrates cryptographic chain plus readable forensic details.

## 8. Fast Troubleshooting

1. Serial open failed
- Check COM port and cable.
- Ensure no other tool has locked console.

2. Login failure
- Recheck serial.username and serial.password.
- Recheck baudrate.

3. ARP sniff failed
- Run terminal as Administrator.
- Verify Npcap installed.
- Verify arp.interface matches active NIC exactly.

4. Event appears but no quarantine
- Inspect ERROR_EVENT for CLI rejection.
- Ensure quarantine VLAN exists and command syntax is accepted on switch.

## 9. Useful Validation Commands

Compile check:
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"; python -m py_compile app.py monitor.py serial_engine.py crypto_log.py db.py simulator.py

Dependency check:
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"; .\.venv\Scripts\Activate.ps1; python -c "import streamlit, serial, scapy, cryptography, pandas, yaml, plotly; print('All deps OK')"
