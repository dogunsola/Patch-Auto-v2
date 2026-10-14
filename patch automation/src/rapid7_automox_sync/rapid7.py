import logging
import os
from collections.abc import Iterator
from typing import Any

from .http import HttpClient

LOG = logging.getLogger(__name__)

VALID_REGIONS = {"us", "us2", "us3", "eu", "ca", "au", "ap", "aps2", "me1"}
SEVERITY_FILTER = "vulnerability.severity DOES NOT CONTAIN 'moderate' && vulnerability.categories NOT IN ['microsoft patch']"
ASSET_FILTER = (
    "asset.lastScanTime > /NOW - P7D/ && asset.groups IN ['workstations/laptops']"
)


class Rapid7Client:
    def __init__(
        self,
        api_key: str = os.getenv("RAPID7-API-KEY-SECRET-NAME", ""),
        region: str = "ca",
        page_size: int = 500,
        http: HttpClient | None = None,
    ) -> None:
        if region not in VALID_REGIONS:
            raise ValueError(f"Unsupported Rapid7 region: {region}")
        if not 1 <= page_size <= 500:
            raise ValueError("Rapid7 page size must be between 1 and 500")
        host = f"{region}.api.insight.rapid7.com"
        self.base_url = f"https://{host}/vm/v4/integration"
        self.page_size = page_size
        self.http = http or HttpClient(
            headers={
                "X-Api-Key": api_key,
                "Accept": "application/json",
                "User-Agent": "rapid7-automox-sync/0.1.0",
            },
            allowed_hosts={host},
        )

    def iter_vulnerability_catalog(self) -> Iterator[dict[str, Any]]:
        yield from self._post_pages(
            "/vulnerabilities",
            {"vulnerability": SEVERITY_FILTER},
        )

    def iter_affected_assets(self) -> Iterator[dict[str, Any]]:
        yield from self._post_pages(
            "/assets",
            {"asset": ASSET_FILTER, "vulnerability": SEVERITY_FILTER},
            extra_params={"includeSame": "true"},
        )

    def _post_pages(
        self,
        path: str,
        body: dict[str, str],
        extra_params: dict[str, str] | None = None,
    ) -> Iterator[dict[str, Any]]:
        page = 0
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {
                "page": page,
                "size": self.page_size,
                **(extra_params or {}),
            }
            if cursor:
                params["cursor"] = cursor
            payload = self.http.request_json(
                "POST",
                f"{self.base_url}{path}",
                params=params,
                json_body=body,
                timeout=300,
            )
            data = payload.get("data", [])
            LOG.debug("Rapid7 %s page %s returned %s records", path, page, len(data))
            yield from data

            metadata = payload.get("metadata", {})
            total_pages = int(metadata.get("totalPages", 0))
            if page + 1 >= total_pages:
                break
            cursor = metadata.get("cursor")
            page += 1
