import csv
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapid7_automox_sync.cli import main


class ConsoleExportTests(unittest.TestCase):
    def test_export_uses_only_console_credentials_and_v3_routes(self):
        origin = 'https://security-console.example:3780/api/3'
        def page(records):
            return {'resources': records, 'page': {'totalPages': 1}}
        responses = {
            ('GET', '/vulnerabilities'): page([
                {'id': 'apache-vuln', 'title': 'Apache vulnerability', 'severity': 'Critical'},
                {'id': 'moderate', 'title': 'Apache issue', 'severity': 'Moderate'},
                {'id': 'ms', 'title': 'Other', 'severity': 'Severe', 'categories': ['Microsoft Patch']},
            ]),
            ('GET', '/asset_groups'): page([{'id': 8, 'name': 'workstations/laptops'}]),
            ('GET', '/asset_groups/8/assets'): {'resources': [42]},
            ('POST', '/assets/search'): page([{'id': 42, 'hostName': 'laptop.example'}]),
            ('GET', '/assets/42/vulnerabilities'): page([
                {'id': 'apache-vuln', 'status': 'vulnerable'},
                {'id': 'moderate', 'status': 'vulnerable'},
                {'id': 'ms', 'status': 'vulnerable'},
                {'id': 'exception', 'status': 'invulnerable'},
            ]),
            ('GET', '/vulnerabilities/apache-vuln/solutions'): {'resources': ['apache-upgrade']},
            ('GET', '/solutions/apache-upgrade'): {
                'summary': {'text': 'Upgrade Apache'}, 'steps': {'text': 'Install latest release'},
            },
        }
        seen = []
        def request(client, method, url, **kwargs):
            self.assertTrue(url.startswith(origin + '/'), url)
            self.assertEqual(client.headers['Authorization'], 'Basic dXNlcjpwYXNzd29yZA==')
            self.assertNotIn('X-Api-Key', client.headers)
            key = (method, url[len(origin):])
            seen.append(key)
            return responses[key]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'export.csv'
            with patch.dict(os.environ, {
                'RAPID7_CONSOLE_URL': origin.removesuffix('/api/3'),
                'RAPID7_CONSOLE_USERNAME': 'user', 'RAPID7_CONSOLE_PASSWORD': 'password',
            }, clear=True), patch('sys.argv', ['sync', '--output', str(output)]), patch(
                'rapid7_automox_sync.http.HttpClient.request_json', new=request
            ):
                main()
            with output.open(newline='') as file:
                self.assertEqual(list(csv.reader(file)), [
                    ['Hosts', 'Solution', 'Fix details'],
                    ['laptop.example', 'Upgrade Apache', 'Install latest release'],
                ])
        self.assertEqual(set(seen), set(responses))
