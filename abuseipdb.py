import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_ip(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
    except requests.exceptions.RequestException:
        return {"error": "AbuseIPDB unreachable"}

    if response.status_code != 200:
        return {"error": f"AbuseIPDB returned status {response.status_code}"}

    return response.json()["data"]