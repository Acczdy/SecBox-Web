import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

# OOB 端口没有产品默认值。测试必须显式使用仅供测试的高位端口，
# 避免测试套件依赖开发者机器上的 .env。
os.environ.setdefault('OOB_RMI_PORT', '45101')
os.environ.setdefault('OOB_LDAP_PORT', '45102')
os.environ.setdefault('OOB_HTTP_CALLBACK_PORT', '45103')

from routes_parser import parser_bp
from routes_tools import tools_bp
from routes_oob import oob_bp
from runtime_secrets import ensure_state, reset_oob_password


class RouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime_dir = tempfile.TemporaryDirectory()
        os.environ['APP_STATE_DIR'] = cls.runtime_dir.name
        ensure_state(password='Initial-Test-Password1!')
        project_root = str(Path(__file__).resolve().parents[1])
        app = Flask(__name__, root_path=project_root,
                    template_folder='templates', static_folder='static')
        app.config.update(TESTING=True, SECRET_KEY='test')
        app.register_blueprint(tools_bp)
        app.register_blueprint(parser_bp)
        app.register_blueprint(oob_bp)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.runtime_dir.cleanup()

    def test_all_tool_pages_render(self):
        pages = [
            '/payloader', '/cyberchef', '/assetdata-filter',
            '/file-analysis',
            '/http-analysis',
            '/reverse-shell', '/file-download', '/process-check',
            '/passwd-tools', '/jsfuck', '/passwd',
            '/windows-systeminfo', '/search-hacking',
            '/email-analyze', '/jwt-tool', '/parser'
        ]
        for path in pages:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_data_apis(self):
        for path in ('/api/payloads', '/api/passwords',
                     '/api/win-patches', '/api/tools'):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.is_json)

    def test_jwt_generate_decode_and_crack(self):
        payload = {'sub': 'tester'}
        generated = self.client.post('/api/jwt/generate', json={
            'header': {'alg': 'HS256', 'typ': 'JWT'}, 'payload': payload,
            'secret': 'secret'
        }).get_json()
        token = generated['token']
        self.assertEqual(self.client.post('/api/jwt/decode', json={'token': token}).get_json()['payload'], payload)
        cracked = self.client.post('/api/jwt/crack', json={'token': token}).get_json()
        self.assertTrue(cracked['found'])
        self.assertEqual(cracked['secret'], 'secret')

    def test_single_part_email_extracts_links(self):
        message = ('From: Alice <alice@example.com>\r\nSubject: test\r\n'
                   'Content-Type: text/plain; charset=utf-8\r\n\r\n'
                   'See https://example.com/login now.')
        data = self.client.post('/api/email/analyze', json={'content': message}).get_json()
        self.assertIn('https://example.com/login', data['links'])

    def test_invalid_json_is_handled(self):
        response = self.client.post('/jwt-generate', data='null', content_type='application/json')
        self.assertTrue(response.is_json)
        self.assertIn('success', response.get_json())

    def test_oob_requires_password_and_uses_seven_day_signed_cookie(self):
        reset_oob_password('Correct-Test-Password1!')
        with patch.dict(os.environ, {'OOB_COOKIE_SECURE': '1'}, clear=False):
            client = self.client.application.test_client()
            self.assertEqual(client.get('/oob', base_url='https://tools.example').status_code, 302)
            self.assertEqual(client.get('/oob/api/results', base_url='https://tools.example').status_code, 401)
            self.assertEqual(client.post('/oob/login', data={'password': 'wrong'}, base_url='https://tools.example').status_code, 200)
            response = client.post('/oob/login', data={'password': 'Correct-Test-Password1!'}, base_url='https://tools.example')
            cookie = response.headers.get('Set-Cookie', '')
            self.assertEqual(response.status_code, 302)
            self.assertIn('Max-Age=604800', cookie)
            self.assertIn('HttpOnly', cookie)
            self.assertIn('Secure', cookie)
            self.assertIn('SameSite=Strict', cookie)
            self.assertEqual(client.get('/oob', base_url='https://tools.example').status_code, 200)

    def test_oob_http_login_does_not_create_secure_cookie_redirect_loop(self):
        reset_oob_password('Correct-Test-Password1!')
        with patch.dict(os.environ, {'OOB_COOKIE_SECURE': '1'}, clear=False):
            client = self.client.application.test_client()
            response = client.post('/oob/login', data={
                'password': 'Correct-Test-Password1!'
            }, base_url='http://192.0.2.10')
            cookie = response.headers.get('Set-Cookie', '')
            self.assertEqual(response.status_code, 302)
            self.assertIn('HttpOnly', cookie)
            self.assertNotIn('Secure', cookie)
            self.assertEqual(client.get('/oob', base_url='http://192.0.2.10').status_code, 200)

    def test_oob_proxy_https_sets_secure_cookie(self):
        reset_oob_password('Correct-Test-Password1!')
        with patch.dict(os.environ, {'OOB_COOKIE_SECURE': '1'}, clear=False):
            response = self.client.post('/oob/login', data={
                'password': 'Correct-Test-Password1!'
            }, base_url='http://tools.internal', headers={'X-Forwarded-Proto': 'https'})
            self.assertIn('Secure', response.headers.get('Set-Cookie', ''))


if __name__ == '__main__':
    unittest.main()
