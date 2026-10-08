"""Indicator validation and classification module."""

import ipaddress
import re
from typing import Literal

IndicatorType = Literal["ipv4", "hash_md5", "hash_sha1", "hash_sha256", "unknown"]

MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def classify_indicator(indicator: str) -> IndicatorType:
    """Classifies an indicator string by type."""
    cleaned = indicator.strip()

    try:
        ip = ipaddress.ip_address(cleaned)
        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4"
    except ValueError:
        pass

    if SHA256_REGEX.match(cleaned):
        return "hash_sha256"
    if SHA1_REGEX.match(cleaned):
        return "hash_sha1"
    if MD5_REGEX.match(cleaned):
        return "hash_md5"

    return "unknown"


def is_routable_ip(ip_str: str) -> bool:
    """Checks if an IPv4 address is public/routable."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False
