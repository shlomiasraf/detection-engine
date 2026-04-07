Authentication Detection Engine
Overview

This project implements a behavioral authentication detection engine that analyzes Linux authentication telemetry using:

Python
pandas
SQL

Raw authentication logs are parsed into structured telemetry and stored in a relational database before being analyzed using sequence-based detection logic.

The engine identifies attacker behavior patterns such as:

brute-force login attempts
password spraying activity
foreign login anomalies
privilege escalation
persistence creation via attack-chain correlation

This project simulates a simplified SIEM-style authentication detection pipeline.

Detection Pipeline
Linux auth.log
→ parsing into structured telemetry
→ SQL security table (auth_events)
→ pandas detection correlation
→ JSON alert generation

This reflects a realistic authentication telemetry detection workflow.

Detection Coverage
Brute-Force Detection

Detects multiple failed login attempts from the same IP or user within a defined time window.

File:

detectors/brute_force_detector.py

Telemetry source:

auth_events
Password Spray Detection

Detects authentication attempts using one password across multiple user accounts from the same source IP.

File:

detectors/password_spray_detector.py

Telemetry source:

auth_events
Foreign Login Detection

Detects authentication attempts originating from unusual geographic locations using IP enrichment logic.

File:

detectors/foreign_login_detector.py

Telemetry source:

auth_events + IP enrichment
SSH Attack-Chain Detection

Detects a realistic attacker sequence:

failed login ×3
→ successful login
→ sudo privilege escalation
→ create_user event

This represents credential compromise followed by privilege escalation and persistence creation.

File:

detectors/ssh_attack_chain_detector.py

Telemetry source:

auth_events
Detection Techniques Used

This project demonstrates practical detection engineering techniques:

authentication telemetry analysis
time-window correlation
multi-event sequence detection
privilege escalation detection
persistence detection
failed-to-success login transition analytics
SQL security telemetry ingestion
pandas-based event grouping and filtering
Data Sources

Authentication telemetry is parsed from Linux:

/var/log/auth.log

and normalized into a structured SQL security table:

auth_events

Example telemetry fields:

timestamp
host
user
ip
action
status

These fields enable reconstruction of attacker behavior across authentication workflows.

Example Alert Output

Example correlated attack-chain alert:

{
  "host": "server1",
  "user": "root",
  "ip": "10.0.0.5",
  "severity": "HIGH",
  "attack_chain": "failed×3 → success → sudo → create_user"
}

Alerts are exported to:

outputs/alerts.json
Project Structure
detection-engine/
│
├── detectors/
│   brute_force_detector.py
│   password_spray_detector.py
│   foreign_login_detector.py
│   ssh_attack_chain_detector.py
│
├── enrichment/
│   ip_enrichment.py
│
├── parsing/
│
├── logs/
│
├── outputs/
│
└── attack_chain_detection.ipynb
Skills Demonstrated

This project demonstrates hands-on detection engineering skills:

Linux authentication log analysis
security telemetry normalization
SQL-based event ingestion
behavioral authentication analytics
privilege escalation detection
persistence detection techniques
attack-chain correlation logic
pandas-based detection workflows
modular Python detector development
