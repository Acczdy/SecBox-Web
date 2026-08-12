import os
import unittest
from unittest.mock import MagicMock, patch

import docker_entrypoint


class DockerEntrypointTests(unittest.TestCase):
    def test_explicit_oob_host_has_priority(self):
        with patch.dict(os.environ, {'OOB_HOST': '203.0.113.10'}, clear=False), \
             patch('docker_entrypoint.urllib.request.urlopen') as urlopen:
            host, source = docker_entrypoint.discover_public_ip()
        self.assertEqual(host, '203.0.113.10')
        self.assertEqual(source, 'configured')
        urlopen.assert_not_called()

    def test_discovery_rejects_private_and_uses_next_public_ip(self):
        private = MagicMock()
        private.__enter__.return_value.read.return_value = b'127.0.0.1\n'
        public = MagicMock()
        public.__enter__.return_value.read.return_value = b'8.8.8.8\n'
        with patch.dict(os.environ, {
            'OOB_HOST': '', 'OOB_PUBLIC_IP_SERVICES': 'https://one,https://two'
        }, clear=False), patch(
            'docker_entrypoint.urllib.request.urlopen', side_effect=[private, public]
        ):
            host, source = docker_entrypoint.discover_public_ip()
        self.assertEqual(host, '8.8.8.8')
        self.assertEqual(source, 'https://two')

    def test_configure_applies_one_host_to_all_callback_protocols(self):
        with patch.dict(os.environ, {
            'OOB_HOST': '', 'OOB_HTTP_HOST': '', 'OOB_HTTP_CALLBACK_HOST': ''
        }, clear=False), patch(
            'docker_entrypoint.discover_public_ip', return_value=('8.8.4.4', 'test')
        ):
            docker_entrypoint.configure_oob_host()
            self.assertEqual(os.environ['OOB_HOST'], '8.8.4.4')
            self.assertEqual(os.environ['OOB_HTTP_HOST'], '8.8.4.4')
            self.assertEqual(os.environ['OOB_HTTP_CALLBACK_HOST'], '8.8.4.4')


if __name__ == '__main__':
    unittest.main()
