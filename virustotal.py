import os
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_ip(ip: str):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.RequestException:
        return {"error": "VirusTotal unreachable"}

    if response.status_code != 200:
        return {
            "error": f"VirusTotal returned status {response.status_code}"
        }

    data = response.json()

    return data["data"]["attributes"]["last_analysis_stats"]