# SecureLAN Monitor: Student Experiment Guide (Step-by-Step)

This guide is written for first-time students.
If you follow every step in order, you can run the project in a lab environment.

## A. Goal of This Experiment

You will run a hardware-only network monitoring app that:
- Connects to a switch through serial console
- Monitors MAC table growth (MAC flooding detector)
- Monitors ARP mapping changes (ARP spoof detector)
- Auto-runs defense commands when detection triggers
- Stores cryptographic audit logs
- Shows all activity in a Streamlit UI

## B. What You Need Before Starting

1. A lab PC (Windows preferred for this guide)
2. Python 3.10 or newer
3. USB-to-Serial adapter and console cable
4. Access to Ruckus ICX 7150 console port
5. Switch username and password
6. Local admin rights on PC (needed for packet sniffing setup)
7. Project folder available on lab PC

## C. Physical Setup (Do This First)

1. Power on the switch.
2. Connect USB-to-Serial adapter to lab PC.
3. Connect adapter cable to switch console port.
4. Connect PC network interface to lab network where ARP traffic can be observed.

Important:
- Console cable is for serial commands.
- Network interface is for ARP sniffing.
- You need both for full experiment behavior.

## D. Open Terminal in Project Folder

Open PowerShell and run:

```powershell
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"
```

Check files exist:

```powershell
Get-ChildItem
```

You should see app.py, monitor.py, serial_engine.py, db.py, crypto_log.py, config.yaml, requirements.txt.

## E. Create Python Environment and Install Packages

1. Check Python:

```powershell
python --version
```

2. Create virtual environment:

```powershell
python -m venv .venv
```

3. Activate virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

4. Upgrade pip:

```powershell
python -m pip install --upgrade pip
```

5. Install project requirements:

```powershell
pip install -r requirements.txt
```

6. Confirm imports:

```powershell
python -c "import streamlit, serial, scapy, cryptography, pandas, yaml, plotly; print('All imports OK')"
```

## F. Install Npcap (Windows Required for ARP Sniffing)

1. Download from https://npcap.com/
2. Install with default options.
3. Close and reopen terminal after install.
4. Re-activate venv:

```powershell
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"
.\.venv\Scripts\Activate.ps1
```

## G. Find Correct COM Port and Network Interface

### 1) Find COM Port

Run:

```powershell
mode
```

Look for COM entries (example COM3, COM4).
Use the actual console adapter COM port in config.yaml.

### 2) Find NIC Interface Name for ARP

Run:

```powershell
Get-NetAdapter | Select-Object Name, Status, InterfaceDescription
```

Choose the active interface connected to your lab network.
Use this exact name in config.yaml arp.interface.

## H. Edit config.yaml Correctly

Open config.yaml and set values:

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
  username: admin
  password: admin

detection:
  mac_flood_threshold: 50
  mac_poll_interval_sec: 15

arp:
  interface: Ethernet
  sniff_timeout_sec: 2
```

Replace:
- COM3 with your real COM port
- username/password with your real switch credentials
- Ethernet with your real NIC name

## I. Pre-Run Health Check

1. Compile project files:

```powershell
python -m py_compile app.py monitor.py serial_engine.py crypto_log.py db.py simulator.py
```

2. If no output appears, compile check passed.

## J. Run the Application

Start Streamlit:

```powershell
streamlit run app.py
```

Open the URL shown in terminal (usually http://localhost:8501).

## K. Verify Startup Works (Must Pass)

On LIVE MONITOR page:
1. Current mode should show HARDWARE.
2. Monitor status should show RUNNING.

On SWITCH CONSOLE page:
1. You should see SYSTEM startup command records.
2. You should see command and output text for:
- enable
- skip-page-display

If these are not visible, check troubleshooting section below.

## L. Manual Command Test (Basic Functionality)

In SWITCH CONSOLE manual command box, run each command one by one:

1. show mac-address
2. show arp
3. show interfaces brief

For each command, confirm table shows:
- timestamp
- source
- command
- output
- HMAC signature

## M. Detector Observation Steps

### 1) MAC Flood Detector Observation

What it uses:
- Repeated show mac-address output
- Current MAC count, previous MAC count, delta, threshold

Where to see:
- LIVE MONITOR page (MAC Flood detector block)
- MAC count line chart

For classroom demo:
- You can lower detection.mac_flood_threshold in config.yaml (example 5) to observe trigger faster in active lab traffic.
- Restart app after config changes.

### 2) ARP Spoof Detector Observation

What it uses:
- ARP replies captured on arp.interface
- Tracks IP to MAC mapping
- Flags if same IP appears with a different MAC

Where to see:
- LIVE MONITOR ARP detector block
- Last suspicious mapping field

Note:
- If no ARP traffic is visible on selected interface, detector will remain quiet.
- Pick the correct active network interface.

## M1. Button-Based Safe Demo Trigger (Recommended for Viva)

On LIVE MONITOR page:
1. Click Inject MAC Flood.
2. Wait for next refresh.
3. Confirm MAC_FLOOD event appears.
4. Confirm defense command appears on SWITCH CONSOLE:
  - port security max-mac-count 5

Then:
1. Click Inject ARP Spoof.
2. Wait for next refresh.
3. Confirm ARP_SPOOF event appears.
4. Confirm defense command appears on SWITCH CONSOLE:
  - ip arp inspection vlan 1

These demo buttons are safe synthetic triggers and do not send attack packets.

## N. Defense Command Validation

When detection happens, verify on SWITCH CONSOLE page:

For MAC_FLOOD:
- command should appear: port security max-mac-count 5

For ARP_SPOOF:
- command should appear: ip arp inspection vlan 1

Both must show output text and HMAC signature.

## O. Audit Trail Validation

Go to AUDIT TRAIL page:

1. Confirm rows exist with:
- timestamp
- action_type
- description
- prev_hash
- entry_hash

2. Click Verify Chain.
- Expected: Chain verified.

3. Select any audit id.
- Confirm encrypted blob is shown.
- Confirm decrypted plaintext is shown.

4. Optional: click Demo Tamper Test.
- Expected: tamper detected message.

## P. Save Artifacts for Report Submission

Collect these for your lab record:

1. Screenshot of LIVE MONITOR showing detector stats
2. Screenshot of SWITCH CONSOLE showing command/output and HMAC
3. Screenshot of AUDIT TRAIL with Verify Chain success
4. Copy of config.yaml with password redacted
5. Terminal output of:

```powershell
python --version
pip install -r requirements.txt
python -m py_compile app.py monitor.py serial_engine.py crypto_log.py db.py simulator.py
```

## Q. Stop the Experiment Safely

1. In terminal running Streamlit, press Ctrl+C.
2. Keep DB and key files for later review:
- securelan.db
- .securelan_fernet.key
- .securelan_hmac.key

## R. Troubleshooting (Student-Friendly)

### Problem 1: Serial open failed

Checks:
1. Cable connected properly
2. Correct COM port in config.yaml
3. No other app using same COM port

Fix:
- Update serial.port and restart app.

### Problem 2: Login not successful

Checks:
1. Correct username/password
2. Correct baudrate
3. Switch prompt appears on console connection

Fix:
- Correct credentials and restart app.

### Problem 3: ARP sniff error

Checks:
1. Npcap installed
2. Terminal has admin rights
3. arp.interface is correct active NIC

Fix:
- Install Npcap, run terminal as admin, correct interface name.

### Problem 4: No events showing

Checks:
1. Monitor status is RUNNING
2. show mac-address works manually
3. Interface receives ARP traffic

Fix:
- Reduce threshold for demo visibility and verify traffic source.

### Problem 5: Verify Chain fails

Checks:
1. Ensure DB file is not externally modified
2. Do not edit rows manually

Fix:
- Restart with fresh DB if needed for clean run.

## S. Quick Command Block (Copy-Paste)

```powershell
Set-Location "c:\RV UNIVERSITY STUFF\NS_Project"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m py_compile app.py monitor.py serial_engine.py crypto_log.py db.py simulator.py
streamlit run app.py
```

This is the minimum sequence to get the experiment running.
