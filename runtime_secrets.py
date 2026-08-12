"""持久化运行时密钥管理。

公开仓库和镜像不保存密码。Docker 首次启动时创建 Flask 签名密钥与
OOB 密码的 PBKDF2 哈希；明文密码只在首次启动日志中显示一次。
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import tempfile
from pathlib import Path


PBKDF2_ITERATIONS = 600_000
DEFAULT_STATE_DIR = str(Path(__file__).resolve().parent / 'runtime')
STATE_FILE_NAME = 'secrets.json'


def state_path():
    directory = Path(os.environ.get('APP_STATE_DIR', DEFAULT_STATE_DIR)).expanduser()
    return directory / STATE_FILE_NAME


def generate_password(length=24):
    alphabet = string.ascii_letters + string.digits + '-_!@#%'
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(c in '-_!@#%' for c in value)):
            return value


def _password_record(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return {
        'algorithm': 'pbkdf2_sha256',
        'iterations': PBKDF2_ITERATIONS,
        'salt': base64.b64encode(salt).decode('ascii'),
        'digest': base64.b64encode(digest).decode('ascii'),
    }


def validate_password(password):
    if len(password) < 12:
        raise ValueError('密码至少需要 12 个字符')
    if len(password) > 128:
        raise ValueError('密码不能超过 128 个字符')


def _write_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix='.secrets-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def load_state(path=None):
    target = Path(path) if path else state_path()
    with target.open('r', encoding='utf-8') as handle:
        state = json.load(handle)
    if not state.get('flask_secret') or not state.get('oob_password'):
        raise RuntimeError('运行时密钥文件不完整，请执行密码重置命令修复')
    return state


def ensure_state(path=None, password=None):
    target = Path(path) if path else state_path()
    if target.exists():
        return load_state(target), None
    initial_password = password or generate_password()
    validate_password(initial_password)
    state = {
        'version': 1,
        'flask_secret': secrets.token_hex(32),
        'oob_password': _password_record(initial_password),
    }
    _write_state(target, state)
    return state, initial_password


def reset_oob_password(password, path=None):
    validate_password(password)
    target = Path(path) if path else state_path()
    state, _ = ensure_state(target, password=password)
    state['oob_password'] = _password_record(password)
    _write_state(target, state)


def verify_oob_password(password, state=None):
    record = (state or load_state()).get('oob_password', {})
    if record.get('algorithm') != 'pbkdf2_sha256':
        return False
    try:
        salt = base64.b64decode(record['salt'], validate=True)
        expected = base64.b64decode(record['digest'], validate=True)
        iterations = int(record['iterations'])
    except (KeyError, TypeError, ValueError):
        return False
    actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return hmac.compare_digest(actual, expected)


def password_marker(state=None):
    record = (state or load_state()).get('oob_password', {})
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode('utf-8')).hexdigest()
