"""
Geolocation helper for HEIAuthRisk.

Conservative behavior:
- validates IP input;
- uses explicit timeouts;
- returns a fixed schema;
- uses regionName for ip_region (not countryCode);
- validates coordinate ranges;
- never guesses/fixes decimal shifts;
- exposes geo_source so future extraction code can preserve provenance;
- keeps legacy `continent` only for compatibility with older extraction code.
"""

from __future__ import annotations

import ipaddress
import os
import time
from functools import lru_cache

import requests

IP_API_URL = os.environ.get("IP_GEO_API_URL", "PUT_YOUR_IP_API_URL_HERE")  # e.g. "http://ip-api.com/json/{ip}"
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("IP_GEO_TIMEOUT", "5"))
REQUEST_PAUSE_SECONDS = float(os.environ.get("IP_GEO_PAUSE", "1.4"))

_SESSION = requests.Session()


def create_empty_fallback():
    return {
        "ip_country": None,
        "ip_region": None,
        "ip_city": None,
        "continent": None,  # legacy compatibility only
        "timezone_region": None,
        "timezone": None,
        "ip_version": None,
        "latitude": None,
        "longitude": None,
        "geo_source": None,
        "geo_status": "missing",
    }


def _safe_float(value):
    if value in (None, ""):
        return None
    try:
        return float(str(value).replace(",", "."))
    except (TypeError, ValueError):
        return None


def _valid_lat(value):
    return value is not None and -90 <= value <= 90


def _valid_lon(value):
    return value is not None and -180 <= value <= 180


def _ip_version(ip: str):
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


@lru_cache(maxsize=100_000)
def getGeoFromPI(ip):
    """
    Retrieve geolocation using an ip-api-compatible JSON response.

    Note: `continent` is a legacy compatibility field derived from the
    timezone prefix and must not be interpreted as a validated continent.
    New code should prefer `timezone_region` for that value.
    """
    result = create_empty_fallback()

    if ip in (None, ""):
        result["geo_status"] = "empty_ip"
        return result

    ip = str(ip).strip()
    version = _ip_version(ip)
    if version is None:
        result["geo_status"] = "invalid_ip"
        return result

    result["ip_version"] = version

    try:
        response = _SESSION.get(
            IP_API_URL.format(ip=ip),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code != 200:
            result["geo_status"] = f"http_{response.status_code}"
            return result

        data = response.json()
        if data.get("status") == "fail":
            result["geo_status"] = "provider_fail"
            return result

        timezone = data.get("timezone")
        timezone_region = None
        if timezone and "/" in str(timezone):
            timezone_region = str(timezone).split("/", 1)[0]

        latitude = _safe_float(data.get("lat"))
        longitude = _safe_float(data.get("lon"))

        if not _valid_lat(latitude):
            latitude = None
        if not _valid_lon(longitude):
            longitude = None

        result.update({
            "ip_country": data.get("country"),
            "ip_region": data.get("regionName"),
            "ip_city": data.get("city"),
            "continent": timezone_region,
            "timezone_region": timezone_region,
            "timezone": timezone,
            "ip_version": version,
            "latitude": latitude,
            "longitude": longitude,
            "geo_source": "ip-api.com",
            "geo_status": "ok",
        })
        return result

    except requests.RequestException as exc:
        result["geo_status"] = f"request_error:{type(exc).__name__}"
        return result
    except (ValueError, TypeError):
        result["geo_status"] = "invalid_response"
        return result
    finally:
        if REQUEST_PAUSE_SECONDS > 0:
            time.sleep(REQUEST_PAUSE_SECONDS)


get_geo_from_ip = getGeoFromPI
