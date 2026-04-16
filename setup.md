# SecureLAN Monitor Lab Setup Guide

This guide gives exact commands for running the project on a lab PC with hardware mode.

## 1. Recommended Lab Topology

- PC USB to serial adapter connected to switch console port.
- Switch powered on and reachable through console.
- Run this project from the lab PC terminal.

## 2. Windows Lab Setup (PowerShell)

Open PowerShell in the project folder and run:

1. Move to project folder
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"

2. Check Python
python --version

3. Create virtual environment
python -m venv .venv

4. Activate virtual environment
.\.venv\Scripts\Activate.ps1

5. Upgrade pip
python -m pip install --upgrade pip

6. Install dependencies
pip install -r requirements.txt

7. Verify key imports
python -c "import streamlit, serial, scapy, cryptography, pandas, yaml, plotly; print('Imports OK')"

8. Find COM ports
mode

9. Edit config.yaml values before start
- mode: hardware
- serial.port: COMx from mode output
- serial.baudrate: usually 9600
- serial.username and serial.password: your switch credentials
- arp.interface: NIC name used for sniffing

10. Start app
streamlit run app.py

## 3. Linux Lab Setup (if needed)

1. Move to project folder
cd /path/to/NS_Project

2. Check Python
python3 --version

3. Create virtual environment
python3 -m venv .venv

4. Activate virtual environment
source .venv/bin/activate

5. Upgrade pip
python -m pip install --upgrade pip

6. Install dependencies
pip install -r requirements.txt

7. Discover serial ports
ls /dev/ttyUSB*

8. Update config.yaml
- serial.port: /dev/ttyUSB0 (or correct one)
- arp.interface: correct interface name

9. Start app with privileges if required for sniffing
sudo .venv/bin/streamlit run app.py

## 4. First Successful Run Checklist

- Live monitor page shows mode as HARDWARE.
- Monitor status shows RUNNING.
- Switch console page shows SYSTEM startup commands:
  - enable
  - skip-page-display
- Command output is visible in the console panel.
- Audit trail page shows entries and Verify Chain passes.

## 4A. Safe Demo Trigger Flow

Use LIVE MONITOR buttons for demo:
- Inject MAC Flood
- Inject ARP Spoof

These buttons trigger synthetic detector events only. They do not generate real attack packets.
When clicked, expected behavior is:
1. Attack event appears in LIVE MONITOR.
2. Defense command appears in SWITCH CONSOLE.
3. Audit entries appear in AUDIT TRAIL.

## 5. Quick Validation Commands

Run compile check:
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"; python -m py_compile app.py monitor.py serial_engine.py crypto_log.py db.py simulator.py

Run dependency check:
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"; .\.venv\Scripts\Activate.ps1; python -c "import streamlit, serial, scapy, cryptography, pandas, yaml, plotly; print('All deps OK')"

## 6. Common Lab Issues and Fast Fixes

1. Serial open failed
- Verify cable and adapter driver.
- Re-check COM port with mode.
- Ensure no other app is holding the same COM port.

2. Login not progressing
- Confirm username and password in config.yaml.
- Confirm switch console prompt appears when pressing Enter in terminal emulator test.
- Confirm baudrate in config.yaml matches switch console setting.

3. ARP sniff errors
- On Windows, install Npcap and reopen terminal.
- Run terminal as Administrator.
- Verify arp.interface value is correct.

4. No command output in UI
- Check SWITCH CONSOLE page for latest error.
- Check AUDIT TRAIL for ERROR_EVENT entries.

## 7. AI Debug Bundle to Collect

Before asking AI for help, collect:

1. OS and Python version
python --version

2. Dependency installation output
pip install -r requirements.txt

3. Compile output
python -m py_compile app.py monitor.py serial_engine.py crypto_log.py db.py simulator.py

4. Redacted config.yaml

5. Last 20 command records from SWITCH CONSOLE page

6. Last 20 audit rows with prev_hash and entry_hash

7. Verify Chain result from AUDIT TRAIL page

8. Exact reproduction steps in numbered order
