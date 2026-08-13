import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask


class AIRoutesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.runtime_dir = tempfile.TemporaryDirectory()
        os.environ['AI_API_URL'] = 'https://ai.invalid/v1/chat/completions'
        os.environ['AI_API_KEY'] = 'test-key-not-real'
        os.environ['AI_MODEL'] = 'test-model'
        os.environ['AI_DATA_DIR'] = cls.tempdir.name
        os.environ['APP_STATE_DIR'] = cls.runtime_dir.name
        from runtime_secrets import ensure_state
        ensure_state(password='Shared-Test-Password1!')
        from routes_ai import ai_bp
        project_root = str(Path(__file__).resolve().parents[1])
        app = Flask(__name__, root_path=project_root)
        app.config.update(TESTING=True, SECRET_KEY='test-secret')
        app.register_blueprint(ai_bp)
        cls.app = app

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()
        cls.runtime_dir.cleanup()

    def setUp(self):
        self.client = self.app.test_client()

    def _login(self, client=None, password='Shared-Test-Password1!'):
        response = (client or self.client).post('/api/ai/login', json={'password': password})
        self.assertEqual(response.status_code, 200)
        return response

    def _artifact(self):
        self._login()
        response = self.client.post('/api/ai/artifacts', json={
            'type': 'email', 'filename': 'sample.eml', 'parser_type': 'email',
            'data': {
                'subject': 'Password reset', 'text_body': 'Verify your account',
                'attachments': [{'filename': 'invoice.exe', 'data': 'SECRET-BINARY'}],
                'raw_content': 'RAW-SHOULD-NOT-BE-SAVED',
            },
        })
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def test_status_does_not_expose_key(self):
        response = self.client.get('/api/ai/status')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['enabled'])
        self.assertNotIn('api_key', payload)
        self.assertFalse(payload['authenticated'])

    def test_default_prompt_and_output_limit_are_concise(self):
        import routes_ai
        prompt = routes_ai._system_prompt('email', 'email')
        self.assertIn('全部高价值关键证据', prompt)
        self.assertIn('不得因数量限制遗漏关键风险', prompt)
        self.assertNotIn('最多 3 条', prompt)
        self.assertIn('详细分析', prompt)
        self.assertEqual(routes_ai._config()['max_output_tokens'], 1600)

    def test_password_required_and_wrong_password_rejected(self):
        response = self.client.post('/api/ai/artifacts', json={
            'type': 'email', 'data': {'subject': 'test'}
        })
        self.assertEqual(response.status_code, 401)
        self.assertTrue(response.get_json()['auth_required'])
        response = self.client.post('/api/ai/login', json={'password': 'wrong-password'})
        self.assertEqual(response.status_code, 401)
        self._login()
        status = self.client.get('/api/ai/status').get_json()
        self.assertTrue(status['authenticated'])

    def test_artifact_is_sanitized_and_isolated(self):
        created = self._artifact()
        import routes_ai
        with routes_ai._db() as conn:
            row = conn.execute('SELECT data_json FROM artifacts WHERE id=?',
                               (created['artifact_id'],)).fetchone()
        self.assertNotIn('SECRET-BINARY', row['data_json'])
        self.assertNotIn('RAW-SHOULD-NOT-BE-SAVED', row['data_json'])
        other = self.app.test_client()
        self._login(other)
        response = other.get('/api/ai/conversations/' + created['conversation_id'])
        self.assertEqual(response.status_code, 404)

    def test_streaming_chat_and_history(self):
        created = self._artifact()
        with patch('routes_ai._provider_stream', return_value=iter(['高风险。', '需要隔离附件。'])):
            response = self.client.post(
                '/api/ai/conversations/' + created['conversation_id'] + '/messages',
                json={'message': '请分析'}, buffered=True)
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('event: delta', body)
        self.assertIn('高风险', body)
        history = self.client.get('/api/ai/conversations/' + created['conversation_id'])
        messages = history.get_json()['messages']
        self.assertEqual([x['role'] for x in messages], ['user', 'assistant'])

    def test_delete_removes_conversation(self):
        created = self._artifact()
        response = self.client.delete('/api/ai/conversations/' + created['conversation_id'])
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/api/ai/conversations/' + created['conversation_id'])
        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
