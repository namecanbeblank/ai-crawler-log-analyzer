import csv
import gzip
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import analyze


class AnalyzerTests(unittest.TestCase):
    def test_combined_w3c_json_and_gzip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'combined.log').write_text(
                '192.0.2.1 - - [01/Nov/2026:08:15:00 +0000] "GET /guide?x=1 HTTP/1.1" 200 20 "-" "GPTBot/1.0"\n', encoding='utf8')
            (root / 'iis.log').write_text(
                '#Fields: date c-ip cs-uri-stem sc-status cs(User-Agent)\n'
                '2026-11-02 198.51.100.2 /article 403 Mozilla%2F5.0+ClaudeBot\n', encoding='utf8')
            with gzip.open(root / 'edge.jsonl.gz', 'wt', encoding='utf8') as f:
                f.write(json.dumps({'ClientIP': '203.0.113.5', 'ClientRequestUserAgent': 'PerplexityBot',
                                    'EdgeResponseStatus': 200, 'ClientRequestURI': '/faq',
                                    'EdgeStartTimestamp': '2026-11-03T01:00:00Z'}) + '\n')
            stats, mismatches, totals, _ = analyze.analyze(root, {})
            self.assertEqual((totals['files'], totals['parsed'], totals['bot_hits']), (3, 3, 3))
            self.assertEqual(stats['GPTBot'].paths['/guide'], 1)
            self.assertEqual(stats['ClaudeBot'].statuses['403'], 1)
            self.assertEqual(stats['PerplexityBot'].dates['2026-11-03'], 1)
            self.assertFalse(mismatches)

    def test_range_matches_mismatches_and_missing_ip_stay_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = [
                {'ClientIP': '192.0.2.5', 'ClientRequestUserAgent': 'GPTBot', 'ClientRequestURI': '/ok'},
                {'ClientIP': '198.51.100.5', 'ClientRequestUserAgent': 'GPTBot', 'ClientRequestURI': '/other'},
                {'ClientRequestUserAgent': 'GPTBot', 'ClientRequestURI': '/unknown'},
            ]
            (root / 'events.jsonl').write_text('\n'.join(map(json.dumps, entries)), encoding='utf8')
            ranges = {'gptbot': [ipaddress.ip_network('192.0.2.0/24')]}
            stats, mismatches, totals, dates = analyze.analyze(root, ranges)
            self.assertEqual(stats['GPTBot'].verdicts, {'range match': 1, 'unverified': 1})
            self.assertEqual(mismatches['GPTBot'].hits, 1)
            analyze.write_csvs(root, stats, mismatches)
            with (root / 'ips.csv').open(encoding='utf8', newline='') as source:
                rows = list(csv.DictReader(source))
            self.assertEqual({r['verdict'] for r in rows}, {'range match', 'unverified', 'outside published range'})
            analyze.write_report(root, 'Example', stats, mismatches, totals, dates, ranges, set(), None)
            report = (root / 'report.md').read_text(encoding='utf8')
            self.assertIn('Requests outside published IP ranges', report)
            self.assertNotIn('scrapers in disguise', report)

    def test_only_outside_range_still_reports_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'events.jsonl').write_text(json.dumps({'ip': '198.51.100.2', 'ua': 'GPTBot', 'path': '/'}), encoding='utf8')
            ranges = {'gptbot': [ipaddress.ip_network('192.0.2.0/24')]}
            stats, mismatches, totals, dates = analyze.analyze(root, ranges)
            analyze.write_report(root, 'Example', stats, mismatches, totals, dates, ranges, set(), None)
            self.assertIn('Requests outside published IP ranges', (root / 'report.md').read_text(encoding='utf8'))

    def test_offline_sitemap_index_does_not_fetch_remote_child(self):
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / 'sitemap.xml'
            index.write_text('<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://example.test/map.xml</loc></sitemap></sitemapindex>', encoding='utf8')
            with patch.object(analyze, '_fetch', side_effect=AssertionError('unexpected network')):
                self.assertEqual(analyze.load_sitemap_paths(index, allow_network=False), set())


if __name__ == '__main__':
    unittest.main()
