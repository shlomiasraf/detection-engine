import re
from datetime import datetime
def parse_auth_log_line(line):
    line = line.strip()

    ssh_failed_pattern = r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+)"
    ssh_success_pattern = r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from (\S+)"
    sudo_pattern = r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo:\s+(\S+)\s+: .*COMMAND=(.+)$"
    useradd_pattern = r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+useradd\[\d+\]: new user: name=(\S+),"
    passwd_pattern = r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+passwd\[\d+\]: password changed for (\S+)$"

    m = re.match(ssh_failed_pattern, line)
    if m:
        ts, host, user, ip = m.groups()
        dt = datetime.strptime(f"2026 {ts}", "%Y %b %d %H:%M:%S")

        return {
            "timestamp": dt,
            "host": host,
            "service": "sshd",
            "action": "ssh_failed",
            "user": user,
            "ip": ip
        }

    m = re.match(ssh_success_pattern, line)
    if m:
        ts, host, user, ip = m.groups()
        dt = datetime.strptime(f"2026 {ts}", "%Y %b %d %H:%M:%S")

        return {
            "timestamp": dt,
            "host": host,
            "service": "sshd",
            "action": "ssh_success",
            "user": user,
            "ip": ip
        }

    m = re.match(sudo_pattern, line)
    if m:
        ts, host, user, command = m.groups()
        dt = datetime.strptime(f"2026 {ts}", "%Y %b %d %H:%M:%S")

        return {
            "timestamp": dt,
            "host": host,
            "service": "sudo",
            "action": "sudo_command",
            "user": user,
            "command": command
        }

    m = re.match(useradd_pattern, line)
    if m:
        ts, host, new_user = m.groups()
        dt = datetime.strptime(f"2026 {ts}", "%Y %b %d %H:%M:%S")

        return {
            "timestamp": dt,
            "host": host,
            "service": "useradd",
            "action": "create_user",
            "new_user": new_user
        }

    m = re.match(passwd_pattern, line)
    if m:
        ts, host, user = m.groups()
        dt = datetime.strptime(f"2026 {ts}", "%Y %b %d %H:%M:%S")

        return {
            "timestamp": dt,
            "host": host,
            "service": "passwd",
            "action": "password_change",
            "user": user
        }

    return None