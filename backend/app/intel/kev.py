import time

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_SECONDS = 6 * 3600

_cache: tuple[float, frozenset[str]] | None = None


def get_known_exploited_cves(client: httpx.Client) -> frozenset[str] | None:
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < CACHE_SECONDS:
        return _cache[1]
    try:
        response = client.get(KEV_URL, timeout=30)
        response.raise_for_status()
        entries = response.json().get("vulnerabilities", [])
        cves = frozenset(entry["cveID"] for entry in entries if "cveID" in entry)
    except (httpx.HTTPError, ValueError, AttributeError):
        return _cache[1] if _cache is not None else None
    _cache = (now, cves)
    return cves