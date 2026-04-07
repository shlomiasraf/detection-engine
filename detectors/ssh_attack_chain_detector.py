def detector_attack_chain(events):
    alerts = []
    events_by_host = {}

    for event in events:
        host = event.get("host")
        events_by_host.setdefault(host, []).append(event)

    for host, host_events in events_by_host.items():

        # חשוב!
        host_events.sort(key=lambda e: e["timestamp"])

        count_failed = 0
        success_after_failed = False
        sudo_after_success = False
        user_after_sudo = False
        attack_ip = None
        success_time = None

        for event in host_events:

            if event["action"] == "ssh_failed":
                if count_failed == 0:
                    attack_ip = event.get("ip")

                if event.get("ip") == attack_ip:
                    count_failed += 1

            elif event["action"] == "ssh_success" and count_failed >= 3:
                if event.get("ip") == attack_ip:
                    success_after_failed = True
                    success_time = event["timestamp"]

            elif event["action"] == "sudo_command" and success_after_failed:
                sudo_after_success = True

            elif event["action"] == "create_user" and sudo_after_success:
                user_after_sudo = True

            elif (
                event["action"] == "password_change"
                and user_after_sudo
                and success_time
                and (event["timestamp"] - success_time).total_seconds() <= 300
            ):
                alerts.append({
                    "type": "attack_chain_alert",
                    "host": host,
                    "ip": attack_ip,
                    "failed_count": count_failed,
                    "message": "SSH brute force → success → privilege escalation → persistence"
                })
                break

    return alerts