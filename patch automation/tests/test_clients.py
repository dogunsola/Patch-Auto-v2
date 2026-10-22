import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from rapid7_automox_sync.automox import AutomoxClient, _safe_filename
from rapid7_automox_sync.http import ApiError, HttpClient
from rapid7_automox_sync.rapid7 import Rapid7Client

class ClientTests(unittest.TestCase):
    def test_console_assets_pagination_membership_and_active_findings(self) -> None:
        def page(resources, total=1):
            return {"resources": resources, "page": {"totalPages": total}}
        http = Mock()
        http.request_json.side_effect = [
            page([{"id": 1, "name": "other workstations/laptops"}], 2),
            page([{"id": 2, "name": "workstations/laptops"}], 2),
            {"resources": [10, 20]},
            page([{"id": 99}, {"id": 10, "hostName": "host-a", "ip": "10.0.0.1"}], 2),
            page([{"id": "v1", "status": "vulnerable"}], 2),
            page([{"id": "v2", "status": "invulnerable"},
                  {"id": "v3", "status": "no-results"}], 2),
            page([{"id": 20, "ip": "10.0.0.2"}], 2),
            page([{"id": "v4", "status": "vulnerable"}]),
        ]
        client = Rapid7Client("https://console.example:3780", "user", "password",
                              http=http, page_size=100)
        self.assertEqual(list(client.iter_affected_assets()), [
            {"id": 10, "host_name": "host-a", "ip": "10.0.0.1", "new": [{"vulnerability_id": "v1"}]},
            {"id": 20, "host_name": "", "ip": "10.0.0.2", "new": [{"vulnerability_id": "v4"}]},
        ])
        calls = http.request_json.call_args_list
        self.assertTrue(all(c.args[1].startswith("https://console.example:3780/api/3/") for c in calls))
        self.assertEqual(calls[1].kwargs['params']['page'], 1)
        self.assertEqual(calls[2].args[1], 'https://console.example:3780/api/3/asset_groups/2/assets')
        self.assertEqual(calls[3].args[0], 'POST')
        self.assertEqual(calls[3].kwargs['json_body'], {'match': 'all', 'filters': [
            {'field': 'last-scan-date', 'operator': 'is-within-the-last', 'value': 7}]})
        self.assertEqual(calls[5].kwargs['params']['page'], 1)
        self.assertEqual(calls[6].kwargs['params']['page'], 1)

    def test_console_catalog_filters_severity_and_category(self):
        http = Mock()
        http.request_json.side_effect = [
            {'resources': [{'id': 'a', 'severity': 'Critical'},
                           {'id': 'b', 'severity': 'Moderate'}], 'page': {'totalPages': 2}},
            {'resources': [{'id': 'c', 'severity': 'Severe', 'categories': ['Microsoft Patch']},
                           {'id': 'd', 'severity': 'Severe', 'categories': ['Apache']}],
             'page': {'totalPages': 2}},
        ]
        client = Rapid7Client('https://console:3780', 'user', 'password', http=http)
        self.assertEqual([v['id'] for v in client.iter_vulnerability_catalog()], ['a', 'd'])
        self.assertEqual(http.request_json.call_args.args, ('GET', 'https://console:3780/api/3/vulnerabilities'))

    def test_missing_group_fails_without_broadening_scope(self):
        http = Mock()
        http.request_json.return_value = {'resources': [], 'page': {'totalPages': 0}}
        client = Rapid7Client('https://console:3780', 'user', 'password', http=http)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            list(client.iter_affected_assets())
        self.assertEqual(http.request_json.call_count, 1)

    def test_empty_group_has_no_assets(self):
        http = Mock()
        http.request_json.side_effect = [
            {'resources': [{'id': 2, 'name': 'workstations/laptops'}], 'page': {'totalPages': 1}},
            {'resources': []},
        ]
        client = Rapid7Client('https://console:3780', 'user', 'password', http=http)
        self.assertEqual(list(client.iter_affected_assets()), [])
        self.assertEqual(http.request_json.call_count, 2)

    def test_automox_upload_uses_rapid7_format(self) -> None:
        http = Mock()
        http.request_json.return_value = {"id": 123, "status": "building"}
        client = AutomoxClient("key", 42, http=http)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.csv"
            path.write_text("Hosts,Solution,Fix details\nhost,Upgrade,Install 2.0\n")
            result = client.upload_rapid7_csv(path)

        self.assertEqual(result["id"], 123)
        kwargs = http.request_json.call_args.kwargs
        self.assertEqual(kwargs["params"], {"source": "rapid7"})
        self.assertIn(b'name="format"\r\n\r\nrapid7', kwargs["body"])
        self.assertIn(b"Hosts,Solution,Fix details", kwargs["body"])

    def test_multipart_filename_is_sanitized(self) -> None:
        self.assertEqual(_safe_filename('bad"\r\nname.csv'), "bad___name.csv")

    def test_http_client_rejects_unexpected_urls(self) -> None:
        http = HttpClient(allowed_hosts={"api.example.com"})
        with self.assertRaises(ApiError):
            http.request_json("GET", "http://api.example.com/test")
        with self.assertRaises(ApiError):
            http.request_json("GET", "https://evil.example.com/test")


if __name__ == "__main__":
    unittest.main()