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

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    return data["data"]