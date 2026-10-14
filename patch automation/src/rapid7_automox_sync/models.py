from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class AutomoxFinding:
    hosts: tuple[str, ...]
    solution: str
    fix_details: str


@dataclass(frozen=True)
class TransformStats:
    assets_seen: int
    findings_written: int
    assets_without_host: int
    vulnerability_ids_not_in_catalog: int
