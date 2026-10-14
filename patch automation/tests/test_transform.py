import csv
import stat
import tempfile
import unittest
from pathlib import Path

from rapid7_automox_sync.models import AutomoxFinding
from rapid7_automox_sync.transform import (
    build_catalog,
    transform_assets,
    write_automox_csv,
)


class TransformTests(unittest.TestCase):
    def test_build_catalog_maps_severity_and_remediation_details(self) -> None:
        catalog = build_catalog(
            [
                {
                    "id": "vuln-1",
                    "severity": "Critical",
                    "cves": "CVE-2025-1234, cve-2025-56789",
                    "name": "Example Service",
                    "solution": "Upgrade Example Service",
                    "fix": "Install version 2.0",
                },
                {
                    "id": "vuln-2",
                    "severity": "Severe",
                    "cves": "CVE-2024-9999",
                    "name": "Example Service",
                    "solution": "Apply vendor update",
                    "fix_details": "Restart the service",
                },
                {"id": "moderate", "severity": "Moderate", "cves": "CVE-2020-0001"},
            ]
        )
        self.assertEqual(
            catalog,
            {
                "vuln-1": ("critical", "Example Service", "Upgrade Example Service", "Install version 2.0"),
                "vuln-2": ("high", "Example Service", "Apply vendor update", "Restart the service"),
            },
        )

    def test_transform_uses_active_findings_and_deduplicates(self) -> None:
        catalog = {
            "vuln-1": ("critical", "Example Service", "Upgrade", "Install 2.0"),
            "no-cve": ("high", "Example Service", "Upgrade", "Install 2.0"),
            "microsoft": ("critical", "Microsoft Windows Server", "Update Windows", "Install patch"),
        }
        assets = [
            {
                "host_name": "host.example.com",
                "new": [{"vulnerability_id": "vuln-1"}],
                "same": [
                    {"vulnerability_id": "vuln-1"},
                    {"vulnerability_id": "no-cve"},
                    {"vulnerability_id": "missing"},
                ],
                "remediated": [{"vulnerability_id": "vuln-1"}],
            },
            {"host_name": "host2.example.com", "new": [{"vulnerability_id": "vuln-1"}]},
            {"ip": "10.0.0.2", "new": [{"vulnerability_id": "vuln-1"}]},
        ]
        findings, stats = transform_assets(assets, catalog)
        self.assertEqual(
            findings,
            [
                AutomoxFinding(
                    hosts=("host.example.com", "host2.example.com"),
                    solution="Upgrade",
                    fix_details="Install 2.0",
                )
            ],
        )
        self.assertEqual(stats.assets_seen, 3)
        self.assertEqual(stats.assets_without_host, 1)
        self.assertEqual(stats.vulnerability_ids_not_in_catalog, 1)

    def test_ip_fallback_and_csv_format(self) -> None:
        findings, _ = transform_assets(
            [{"ip": "10.0.0.2", "new": [{"vulnerability_id": "vuln-1"}]}],
            {"vuln-1": ("critical", "Example Service", "Upgrade", "Install 2.0")},
            hostname_fallback="ip",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.csv"
            write_automox_csv(output, findings)
            with output.open(newline="", encoding="utf-8") as file:
                rows = list(csv.reader(file))
        self.assertEqual(
            rows,
            [
                ["Hosts", "Solution", "Fix details"],
                ["10.0.0.2", "Upgrade", "Install 2.0"],
            ],
        )

    def test_csv_formula_cells_are_escaped_and_file_is_private(self) -> None:
        findings = [
            AutomoxFinding(
                hosts=("host.example.com",),
                solution="=cmd|calc",
                fix_details="Install 2.0",
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.csv"
            write_automox_csv(output, findings)
            with output.open(newline="", encoding="utf-8") as file:
                rows = list(csv.reader(file))
            mode = stat.S_IMODE(output.stat().st_mode)
        self.assertEqual(rows[1], ["host.example.com", "'=cmd|calc", "Install 2.0"])
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
