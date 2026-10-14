import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from rapid7_automox_sync.automox import AutomoxClient, _safe_filename
from rapid7_automox_sync.http import ApiError, HttpClient
from rapid7_automox_sync.rapid7 import Rapid7Client

class ClientTests(unittest.TestCase):
    def test_rapid7_cursor_pagination_and_include_same(self) -> None:
        http = Mock()
        http.request_json.side_effect = [
            {
                "data": [{"id": "asset-1"}],
                "metadata": {"totalPages": 2, "cursor": "next-cursor"},
            },
            {
                "data": [{"id": "asset-2"}],
                "metadata": {"totalPages": 2, "cursor": "done"},
            },
        ]
        client = Rapid7Client("key", "ca", page_size=100, http=http)

        self.assertEqual(
            list(client.iter_affected_assets()),
            [{"id": "asset-1"}, {"id": "asset-2"}],
        )
        first_params = http.request_json.call_args_list[0].kwargs["params"]
        second_params = http.request_json.call_args_list[1].kwargs["params"]
        first_body = http.request_json.call_args_list[0].kwargs["json_body"]
        self.assertEqual(first_params["includeSame"], "true")
        self.assertNotIn("cursor", first_params)
        self.assertEqual(second_params["cursor"], "next-cursor")
        asset_filter = first_body["asset"]
        self.assertEqual(
            asset_filter,
            "asset.lastScanTime > /NOW - P7D/ && asset.groups IN ['workstations/laptops']",
        )
        self.assertEqual(
            first_body["vulnerability"],
            "vulnerability.severity DOES NOT CONTAIN 'moderate' && "
            "vulnerability.categories NOT IN ['microsoft patch']",
        )

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