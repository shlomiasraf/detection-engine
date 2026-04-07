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
