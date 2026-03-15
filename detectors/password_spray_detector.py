
from datetime import datetime
def detector_password_spray(logs):
    alerts = []
    failed_logs_by_ip = {}
    for log in logs:
        if log["action"] == "login_failed":
            ip = log["ip"]
            t = datetime.fromisoformat(log["timestamp"])
            event = {
                "user": log["user"],
                "time": t
            }
            if ip not in failed_logs_by_ip:
                failed_logs_by_ip[ip] = [event]
            else:
                failed_logs_by_ip[ip].append(event)

    for ip, events in failed_logs_by_ip.items():
        for i in range(len(events)-2):
            users = {events[i]["user"], events[i+1]["user"], events[i+2]["user"]}
            if len(users) >= 3 and (events[i+2]["time"]-events[i]["time"]).seconds < 60:
                alerts.append({
                    "type": "password_spray",
                    "ip": ip,
                    "users": list(users),
                    "message": "Password spray detected"
                })
                break

    return alerts