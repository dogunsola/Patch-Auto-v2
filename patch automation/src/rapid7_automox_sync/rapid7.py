import base64
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote, urlparse

from .http import HttpClient


class Rapid7SolutionClient:
    """Security Console v3 client using HTTPS and Basic authentication."""

    def __init__(self, console_url: str, username: str, password: str,
                 http: HttpClient | None = None, *, page_size: int = 500,
                 asset_group: str = "workstations/laptops") -> None:
        if not 1 <= page_size <= 500:
            raise ValueError("Rapid7 page size must be between 1 and 500")
        if not asset_group.strip():
            raise ValueError("Rapid7 asset group must not be empty")
        self.page_size = page_size
        self.asset_group = asset_group
        parsed = urlparse(console_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in ("", "/")
                or parsed.params or parsed.query or parsed.fragment):
            raise ValueError("Rapid7 console URL must be an HTTPS origin, e.g. https://console:3780")
        if not username or ":" in username or not password:
            raise ValueError("Rapid7 console username and password are required; username cannot contain ':'")
        self.base_url = console_url.rstrip("/") + "/api/3"
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        self.http = http or HttpClient(
            headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
            allowed_hosts={parsed.hostname},
        )
        self._solutions: dict[str, dict[str, Any]] = {}
        self._vulnerabilities: dict[str, list[dict[str, Any]]] = {}

    def get_vulnerability_solutions(self, vulnerability_id: str) -> list[dict[str, Any]]:
        if vulnerability_id not in self._vulnerabilities:
            payload = self.http.request_json(
                "GET", f"{self.base_url}/vulnerabilities/{quote(vulnerability_id, safe='')}/solutions"
            )
            solutions = []
            for solution_id in payload["resources"]:
                if not isinstance(solution_id, str) or not solution_id:
                    raise ValueError("Rapid7 returned an invalid solution ID")
                if solution_id not in self._solutions:
                    self._solutions[solution_id] = self.http.request_json(
                        "GET", f"{self.base_url}/solutions/{quote(solution_id, safe='')}"
                    )
                solutions.append(self._solutions[solution_id])
            self._vulnerabilities[vulnerability_id] = solutions
        return self._vulnerabilities[vulnerability_id]


class Rapid7Client(Rapid7SolutionClient):
    def _pages(self, path: str, *, method: str = "GET",
               body: dict[str, Any] | None = None,
               params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        page = 0
        while True:
            kwargs: dict[str, Any] = {
                "params": {**(params or {}), "page": page, "size": self.page_size},
                "timeout": 300,
            }
            if body is not None:
                kwargs["json_body"] = body
            payload = self.http.request_json(method, f"{self.base_url}{path}", **kwargs)
            yield from payload["resources"]
            if page + 1 >= int(payload["page"]["totalPages"]):
                return
            page += 1

    def iter_vulnerability_catalog(self) -> Iterator[dict[str, Any]]:
        for vulnerability in self._pages("/vulnerabilities"):
            if str(vulnerability.get("severity", "")).lower() not in {"critical", "severe"}:
                continue
            if any(str(category).lower() == "microsoft patch"
                   for category in vulnerability.get("categories", [])):
                continue
            yield vulnerability

    def iter_affected_assets(self) -> Iterator[dict[str, Any]]:
        groups = [group for group in self._pages(
            "/asset_groups", params={"name": self.asset_group}
        ) if group["name"].casefold() == self.asset_group.casefold()]
        if len(groups) != 1:
            raise ValueError(f"Expected exactly one accessible Rapid7 asset group named {self.asset_group!r}; found {len(groups)}")
        group_id = quote(str(groups[0]["id"]), safe="")
        membership = self.http.request_json(
            "GET", f"{self.base_url}/asset_groups/{group_id}/assets"
        )
        member_ids = {str(asset_id) for asset_id in membership["resources"]}
        if not member_ids:
            return
        criteria = {"match": "all", "filters": [
            {"field": "last-scan-date", "operator": "is-within-the-last", "value": 7},
        ]}
        for asset in self._pages("/assets/search", method="POST", body=criteria):
            if str(asset["id"]) not in member_ids:
                continue
            asset_id = quote(str(asset["id"]), safe="")
            # Normalize v3 records into the exporter's internal asset/finding format.
            findings = [
                {"vulnerability_id": str(finding["id"])}
                for finding in self._pages(f"/assets/{asset_id}/vulnerabilities")
                if finding["status"] == "vulnerable"
            ]
            yield {"id": asset["id"], "host_name": asset.get("hostName", ""),
                   "ip": asset.get("ip", ""), "new": findings}
