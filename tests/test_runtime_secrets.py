import tempfile
import unittest
from pathlib import Path

from runtime_secrets import ensure_state, password_marker, reset_oob_password, verify_oob_password


class RuntimeSecretsTests(unittest.TestCase):
    def test_first_start_stores_hash_not_plaintext_and_reset_invalidates_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'secrets.json'
            state, shown = ensure_state(path, password='Initial-Password1!')
            self.assertEqual(shown, 'Initial-Password1!')
            self.assertNotIn('Initial-Password1!', path.read_text(encoding='utf-8'))
            self.assertTrue(verify_oob_password('Initial-Password1!', state))
            old_marker = password_marker(state)

            reset_oob_password('Replacement-Password2!', path)
            updated, shown_again = ensure_state(path)
            self.assertIsNone(shown_again)
            self.assertFalse(verify_oob_password('Initial-Password1!', updated))
            self.assertTrue(verify_oob_password('Replacement-Password2!', updated))
            self.assertNotEqual(old_marker, password_marker(updated))

    def test_short_password_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                ensure_state(Path(directory) / 'secrets.json', password='short')


if __name__ == '__main__':
    unittest.main()
