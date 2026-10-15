import ipaddress
import re
from urllib.parse import urlparse

HASH_LENGTHS = {32, 40, 64}  # MD5, SHA1, SHA256
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_REGEX.match(value))


def is_valid_hash(value: str) -> bool:
    return len(value) in HASH_LENGTHS and re.fullmatch(r"[A-Fa-f0-9]+", value) is not None


def is_valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def validate_ioc(ioc: str, ioc_type: str) -> bool:
    if ioc_type == "ip":
        return is_valid_ip(ioc)
    if ioc_type == "domain":
        return is_valid_domain(ioc)
    if ioc_type == "hash":
        return is_valid_hash(ioc)
    if ioc_type == "url":
        return is_valid_url(ioc)
    return False