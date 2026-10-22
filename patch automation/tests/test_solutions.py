import unittest
from unittest.mock import Mock

from rapid7_automox_sync.rapid7 import Rapid7SolutionClient
from rapid7_automox_sync.transform import build_catalog, transform_assets


class SolutionTests(unittest.TestCase):
    def test_solution_lookup_and_caching(self):
        http = Mock()
        record = {'summary': {'text': 'Upgrade'}, 'steps': {'text': 'Install update'}}
        http.request_json.side_effect = [
            {'resources': ['fix/id']}, record, {'resources': ['fix/id']},
        ]
        client = Rapid7SolutionClient('https://console:3780', 'user', 'password', http)
        self.assertEqual(client.get_vulnerability_solutions('vuln/id'), [record])
        self.assertEqual(client.get_vulnerability_solutions('vuln/id'), [record])
        self.assertEqual(client.get_vulnerability_solutions('other'), [record])
        self.assertEqual(http.request_json.call_count, 3)
        self.assertEqual(http.request_json.call_args_list[0].args,
                         ('GET', 'https://console:3780/api/3/vulnerabilities/vuln%2Fid/solutions'))
        self.assertEqual(http.request_json.call_args_list[1].args,
                         ('GET', 'https://console:3780/api/3/solutions/fix%2Fid'))

    def test_console_url_and_auth(self):
        for url in ['http://console', 'https://user:pass@console', 'https://console/path', 'https://console?x=1']:
            with self.assertRaises(ValueError):
                Rapid7SolutionClient(url, 'user', 'password')
        client = Rapid7SolutionClient('https://console:3780', 'user', 'password')
        self.assertEqual(client.http.headers['Authorization'], 'Basic dXNlcjpwYXNzd29yZA==')
        self.assertNotIn('X-Api-Key', client.http.headers)

    def test_transform_uses_multiple_solution_records(self):
        catalog = build_catalog([{'id': 'v', 'severity': 'Severe', 'name': 'Apache', 'solution': 'old'}])
        assets = [{'host_name': host, 'new': [{'vulnerability_id': 'v'}]} for host in ['a', 'b']]
        lookup = Mock(return_value=[
            {'summary': {'text': 'Upgrade'}, 'steps': {'text': 'Install 2'}},
            {'summary': {'text': 'Configure'}, 'steps': {'text': 'Disable feature'}},
        ])
        findings, _ = transform_assets(assets, catalog, solution_lookup=lookup)
        self.assertEqual([(f.hosts, f.solution, f.fix_details) for f in findings], [
            (('a', 'b'), 'Configure', 'Disable feature'),
            (('a', 'b'), 'Upgrade', 'Install 2'),
        ])
        self.assertEqual(transform_assets(assets, catalog, solution_lookup=lambda _: [])[0], [])
        lookup.side_effect = RuntimeError('API failure')
        with self.assertRaises(RuntimeError):
            transform_assets(assets, catalog, solution_lookup=lookup)
