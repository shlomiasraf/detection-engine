
def detector_brute_force(logs):
    alerts = []
    logs_by_ip = {}
    for log in logs:
        ip = log["ip"]
        if ip not in logs_by_ip:
            logs_by_ip[ip] = [log]
        else:
            logs_by_ip[ip].append(log)
    for ip,logs in logs_by_ip.items():
        count_failed = 0
        for log in logs:
            if log["action"] == "login_failed":
                count_failed+=1

            elif log["action"] == "login_success":
                if count_failed >= 3:
                    alerts.append({
                        "type": "brute_force",
                        "ip": ip,
                        "failed_count": count_failed,
                        "message": "Brute force detected"
                    })
                    break
                count_failed = 0

        return alerts