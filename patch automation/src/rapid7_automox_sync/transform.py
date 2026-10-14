import csv
import os
import re
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import AutomoxFinding, TransformStats

SEVERITY_MAP = {"critical": "critical", "severe": "high"}
ACTIVE_FINDING_FIELDS = ("new", "same")
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
MICROSOFT_TOKENS = ("microsoft", "windows", "office", "azure", "sql server")


def build_catalog(
    vulnerabilities: Iterable[dict[str, Any]],
) -> dict[str, tuple[str, str, str, str]]:
    catalog: dict[str, tuple[str, str, str, str]] = {}
    for vulnerability in vulnerabilities:
        vulnerability_id = str(vulnerability.get("id", "")).strip()
        severity = SEVERITY_MAP.get(str(vulnerability.get("severity", "")).lower())
        if not vulnerability_id or not severity:
            continue
        software = str(vulnerability.get("name") or vulnerability.get("title") or "Unknown Service")
        software = _normalize_software_name(software)
        solution = _clean_cell(_rapid7_text(vulnerability.get("solution")))
        fix_details = _clean_cell(
            _rapid7_text(vulnerability.get("fix_details") or vulnerability.get("fix"))
        )
        catalog[vulnerability_id] = (severity, software, solution, fix_details)
    return catalog


def transform_assets(
    assets: Iterable[dict[str, Any]],
    catalog: dict[str, tuple[str, str, str, str]],
    hostname_fallback: str = "skip",
) -> tuple[list[AutomoxFinding], TransformStats]:
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    assets_seen = 0
    assets_without_host = 0
    unknown_ids = 0

    for asset in assets:
        assets_seen += 1
        host = _clean_cell(str(asset.get("host_name") or "").strip())
        if not host and hostname_fallback == "ip":
            host = _clean_cell(str(asset.get("ip") or "").strip())
        if not host:
            assets_without_host += 1
            continue

        for field in ACTIVE_FINDING_FIELDS:
            for item in asset.get(field) or []:
                vulnerability_id = str(item.get("vulnerability_id", "")).strip()
                catalog_entry = catalog.get(vulnerability_id)
                if catalog_entry is None:
                    unknown_ids += 1
                    continue
                severity, software, solution, fix_details = catalog_entry
                if _is_microsoft_software(software):
                    continue
                key = (solution, fix_details)
                group = findings.setdefault(
                    key,
                    {"solution": solution, "fix_details": fix_details, "hosts": set()},
                )
                group["hosts"].add(host)

    ordered = [
        AutomoxFinding(
            hosts=tuple(sorted(entry["hosts"])),
            solution=entry["solution"],
            fix_details=entry["fix_details"],
        )
        for entry in sorted(findings.values(), key=lambda item: (item["solution"], item["fix_details"]))
    ]
    return ordered, TransformStats(
        assets_seen=assets_seen,
        findings_written=len(ordered),
        assets_without_host=assets_without_host,
        vulnerability_ids_not_in_catalog=unknown_ids,
    )


def write_automox_csv(path: Path, findings: Iterable[AutomoxFinding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    os.chmod(temp_name, 0o600)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(("Hosts", "Solution", "Fix details"))

            for item in findings:
                writer.writerow(
                    [
                        _clean_cell(";".join(item.hosts)),
                        _clean_cell(item.solution),
                        _clean_cell(item.fix_details),
                    ]
                )
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _clean_cell(value: str) -> str:
    cleaned = value.replace("\x00", "").strip()
    if cleaned.startswith(CSV_FORMULA_PREFIXES):
        return f"'{cleaned}"
    return cleaned


def _rapid7_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "; ".join(str(item) for item in value)
    if isinstance(value, dict):
        return "; ".join(f"{key}: {item}" for key, item in value.items())
    return str(value)


def _normalize_software_name(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value).strip()
    if not cleaned:
        return "Unknown Service"


    for marker in (" - ", " – ", ":", " for ", " on ", " with ", " related to "):
        cleaned_lower = cleaned.lower()
        if marker in cleaned_lower:
            idx = cleaned_lower.index(marker)
            cleaned = cleaned[:idx].strip()

    cleaned = re.sub(r"\s*\(.*\)\s*$", "", cleaned)

    cleaned = re.sub(
        r"\s*(?:cve-\d{4}-\d{4,}|security update|patch|advisory|vulnerability).*$",
        "",
        cleaned,
        flags=re.IGNORECASE
    ).strip()

    if not cleaned:
        return "Unknown Service"
    return cleaned


def _is_microsoft_software(software: str) -> bool:
    lowered = software.lower()
    return any(token in lowered for token in MICROSOFT_TOKENS)
