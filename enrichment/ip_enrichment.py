import requests

def get_ip_info(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()
    return {
        "ip": ip,
        "country": data.get("country"),
        "city": data.get("city"),
        "org": data.get("org")
    }
