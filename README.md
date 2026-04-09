# Authentication Detection Engine

## Overview

This project demonstrates authentication-focused detection engineering techniques across Linux security telemetry environments.

The goal of this lab is to simulate realistic attacker behavior and implement detection logic based on authentication events collected from Linux systems and structured SQL telemetry tables.

The detectors correlate:

- failed authentication attempts
- successful login activity
- privilege escalation behavior
- persistence indicators
- geographic login anomalies
- multi-stage attack chains

This project reflects hands-on experience with:

- Linux authentication logs (auth.log)
- SQL-based telemetry normalization
- pandas-based detection correlation
- behavioral authentication analytics
- privilege escalation detection
- persistence detection logic

--- 

## Detection Coverage

### Linux — Brute Force Detection

Detects:

multiple failed login attempts from the same IP address
repeated authentication failures within a defined time window

File:

detectors/brute_force_detector.py

Telemetry source:

auth_events (parsed from Linux auth.log)

---

### Linux — Password Spray Detection

Detects:

authentication attempts using one password across multiple user accounts from the same source IP

File:

detectors/password_spray_detector.py

Telemetry source:

auth_events

--- 

### Linux — Foreign Login Detection

Detects:

authentication attempts originating from unusual geographic locations

Uses IP enrichment logic to identify suspicious login origins.

File:

detectors/foreign_login_detector.py

Telemetry source:

auth_events + IP enrichment

--- 

### Linux — SSH Attack Chain Detection

Detects a realistic attacker sequence:

Invalid login attempts
→ Successful login
→ sudo privilege escalation
→ New user creation

This represents credential compromise followed by privilege escalation and persistence establishment.

File:

detectors/ssh_attack_chain_detector.py

Telemetry source:

auth_events

--- 

### Jupyter Detection Workflow

Authentication telemetry is ingested from a SQL security table using SQLAlchemy:

SELECT * FROM auth_events

The dataset is analyzed using pandas to identify suspicious authentication behavior such as:

repeated failed login attempts from the same IP
failed-to-success authentication transitions
privilege escalation sequences
persistence creation events

Example correlation logic implemented in the notebook:

failed ×3
→ success
→ sudo
→ create_user

Alerts are generated and exported as structured JSON output.

### Detection Pipeline

The detection workflow simulates a simplified SIEM-style authentication telemetry pipeline:

Linux auth.log
→ parsing into structured telemetry
→ SQL security table (auth_events)
→ pandas detection correlation
→ JSON alert generation

This reflects a realistic authentication telemetry detection workflow.

### Sample Logs

Example telemetry datasets are included:

logs/linux_auth_attack.log
logs/detection_practice_logs.json
logs/detection_time_logs.json
logs/impossible_travel_logs.json
logs/sample_security_logs.json

These allow running detectors locally without requiring external infrastructure.

Example Alert Output

Example correlated attack-chain alert:

failed login ×3
→ successful login
→ sudo execution
→ create_user event

Example output:

outputs/alerts.json

### Skills Demonstrated

This lab demonstrates practical detection engineering skills:

- authentication telemetry parsing
- SQL-based security data normalization
- pandas-based behavioral detection logic
- time-window correlation detection
- attack-chain sequence reconstruction
- privilege escalation detection
- persistence detection techniques
- modular Python detector development
