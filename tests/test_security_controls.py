import unittest
from types import SimpleNamespace

from routes_tools import _safe_archive_name
from security_controls import FixedWindowLimiter, is_same_origin_request, request_client_address


class SecurityControlTests(unittest.TestCase):
    def test_rate_limiter(self):
        limiter = FixedWindowLimiter()
        self.assertTrue(limiter.allow(('ip', 'endpoint'), 2, 60))
        self.assertTrue(limiter.allow(('ip', 'endpoint'), 2, 60))
        self.assertFalse(limiter.allow(('ip', 'endpoint'), 2, 60))
        self.assertTrue(limiter.is_blocked(('ip', 'endpoint'), 2, 60))

    def test_private_proxy_client_address(self):
        request = SimpleNamespace(
            remote_addr='172.18.0.2',
            headers={'X-Forwarded-For': '203.0.113.9, 172.18.0.2'},
        )
        self.assertEqual(request_client_address(request), '203.0.113.9')

    def test_same_origin_browser_requests(self):
        good = SimpleNamespace(headers={'Origin': 'https://tools.example'}, host_url='https://tools.example/', remote_addr='203.0.113.8')
        bad = SimpleNamespace(headers={'Origin': 'https://evil.example'}, host_url='https://tools.example/', remote_addr='203.0.113.8')
        cross_site = SimpleNamespace(headers={'Sec-Fetch-Site': 'cross-site'}, host_url='https://tools.example/', remote_addr='203.0.113.8')
        cli = SimpleNamespace(headers={}, host_url='https://tools.example/', remote_addr='203.0.113.8')
        self.assertTrue(is_same_origin_request(good))
        self.assertFalse(is_same_origin_request(bad))
        self.assertFalse(is_same_origin_request(cross_site))
        self.assertTrue(is_same_origin_request(cli))

    def test_same_origin_behind_private_reverse_proxy(self):
        request = SimpleNamespace(
            remote_addr='172.18.0.2', host_url='http://security-tools:5001/',
            headers={
                'Origin': 'https://tools.example',
                'X-Forwarded-Host': 'tools.example',
                'Sec-Fetch-Site': 'same-origin',
            },
        )
        self.assertTrue(is_same_origin_request(request))

    def test_zip_entry_name_is_flat(self):
        self.assertEqual(_safe_archive_name('../../evil.exe', 'fallback'), 'evil.exe')
        self.assertEqual(_safe_archive_name(r'C:\\temp\\payload.txt', 'fallback'), 'payload.txt')
        self.assertEqual(_safe_archive_name('', 'fallback'), 'fallback')


if __name__ == '__main__':
    unittest.main()
