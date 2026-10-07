import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import httpx

from app.analysis.types import PackageRef
from app.intel.errors import IntelligenceUnavailable

QUERY_URL = "https://api.osv.dev/v1/query"
BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
BATCH_SIZE = 500
MAX_WORKERS = 8
ATTEMPTS = 3


def _request(client: httpx.Client, method: str, url: str, **kwargs) -> dict:
    error = "unknown error"
    for attempt in range(ATTEMPTS):
        try:
            response = client.request(method, url, **kwargs)
        except httpx.TransportError as exc:
            error = type(exc).__name__
        else:
            if response.status_code < 400:
                return response.json()
            error = f"HTTP {response.status_code}"
            if response.status_code != 429 and response.status_code < 500:
                break
        time.sleep(2**attempt)
    raise IntelligenceUnavailable(f"OSV request failed ({error})")


def _query(package: PackageRef) -> dict:
    return {
        "package": {"name": package.name, "ecosystem": package.ecosystem},
        "version": package.version,
    }


def fetch_vulnerability_ids(
    client: httpx.Client,
    packages: list[PackageRef],
) -> dict[PackageRef, list[str]]:
    found: dict[PackageRef, list[str]] = {}
    for start in range(0, len(packages), BATCH_SIZE):
        chunk = packages[start : start + BATCH_SIZE]
        queries = [_query(package) for package in chunk]
        data = _request(client, "POST", BATCH_URL, json={"queries": queries})
        results = data.get("results", [])
        if len(results) != len(chunk):
            raise IntelligenceUnavailable("OSV returned an incomplete batch response")
        for package, query, entry in zip(chunk, queries, results):
            ids = {vuln["id"] for vuln in entry.get("vulns", [])}
            token = entry.get("next_page_token")
            while token:
                page = _request(client, "POST", QUERY_URL, json={**query, "page_token": token})
                ids.update(vuln["id"] for vuln in page.get("vulns", []))
                token = page.get("next_page_token")
            found[package] = sorted(ids)
    return found


def fetch_records(client: httpx.Client, vuln_ids: list[str]) -> dict[str, dict]:
    if not vuln_ids:
        return {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        records = pool.map(
            lambda vuln_id: _request(client, "GET", VULN_URL.format(vuln_id=quote(vuln_id, safe=""))),
            vuln_ids,
        )
        return dict(zip(vuln_ids, records))