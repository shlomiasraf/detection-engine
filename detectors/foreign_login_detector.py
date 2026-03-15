
def detector_foreign_login(logs):
    alerts = []
    for log in logs:
        if log["action"] == "login_success":
            country = log.get("country")
            if country and country != "IL":
                alerts.append({
                    "type": "foreign_login",
                    "user": log.get("user"),
                    "ip": log.get("ip"),
                    "country": country,
                    "message": "Foreign login detected"
                })
    return alerts