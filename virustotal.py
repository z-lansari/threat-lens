import os
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"


def _query(path: str):
    url = f"{BASE_URL}/{path}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.RequestException:
        return {"error": "VirusTotal unreachable"}

    if response.status_code != 200:
        return {"error": f"VirusTotal returned status {response.status_code}"}

    data = response.json()
    return data["data"]["attributes"]["last_analysis_stats"]


def check_ip(ip: str):
    return _query(f"ip_addresses/{ip}")


def check_domain(domain: str):
    return _query(f"domains/{domain}")