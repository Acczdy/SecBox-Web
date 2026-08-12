"""反连服务（OOB Callback）路由 —— 多用户隔离

凭证模型（类似 DNSlog 平台）：
- 首次访问自动发放随机凭证 token，写入 HttpOnly Cookie；
- 回调按 URL 首段路径归属凭证，用户仅能查看自己凭证下的记录；
- 凭证过期后可重新获取（原记录一并失效清理）。
"""
import os

from flask import Blueprint, render_template, jsonify, request, make_response, redirect, url_for, current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from oob_services import platform, get_config, SESSION_TTL_HOURS
from security_controls import FixedWindowLimiter, request_client_address
from runtime_secrets import password_marker, verify_oob_password

oob_bp = Blueprint('oob', __name__, url_prefix='/oob')

COOKIE_NAME = 'oob_token'
ACCESS_COOKIE_NAME = 'oob_access'
ACCESS_MAX_AGE = 7 * 24 * 3600
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW = 15 * 60
_login_failure_limiter = FixedWindowLimiter(max_keys=10000)


def _cookie_secure():
    """仅在客户端实际使用 HTTPS 时签发 Secure Cookie。

    公网 HTTPS 常由反向代理终止 TLS，因此只读取 X-Forwarded-Proto 的
    协议提示，不启用 ProxyFix，也不会信任 X-Forwarded-For 改写限流来源。
    HTTP 若强行设置 Secure，浏览器会丢弃 Cookie 并造成登录重定向循环。
    """
    enabled = os.environ.get('OOB_COOKIE_SECURE', '0').strip().lower()
    if enabled not in ('1', 'true', 'yes', 'on'):
        return False
    forwarded_proto = request.headers.get('X-Forwarded-Proto', '').split(',', 1)[0].strip().lower()
    return request.is_secure or forwarded_proto == 'https'


def _access_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='oob-access-v1')


def _has_access():
    signed = request.cookies.get(ACCESS_COOKIE_NAME, '')
    if not signed:
        return False
    try:
        payload = _access_serializer().loads(signed, max_age=ACCESS_MAX_AGE)
        return (payload.get('scope') == 'oob' and
                payload.get('marker', '') == password_marker())
    except (BadSignature, SignatureExpired):
        return False


def _access_denied(api=False):
    if api:
        return jsonify({'error': '请先输入反连服务访问密码'}), 401
    return redirect(url_for('oob.login', next=request.path))


@oob_bp.route('/login', methods=['GET', 'POST'])
def login():
    """后端校验访问密码，签发 7 天时效的签名 Cookie。"""
    if _has_access():
        return redirect(url_for('oob.index'))
    error = ''
    if request.method == 'POST':
        client = request_client_address(request)
        limiter_key = ('oob-login-failure', client)
        if _login_failure_limiter.is_blocked(
                limiter_key, LOGIN_FAILURE_LIMIT, LOGIN_FAILURE_WINDOW):
            resp = make_response(render_template(
                'tools/oob_login.html', title='反连服务访问验证',
                hide_page_header=True,
                error='密码错误次数过多，请 15 分钟后再试',
                retry_after=LOGIN_FAILURE_WINDOW,
            ), 429)
            resp.headers['Retry-After'] = str(LOGIN_FAILURE_WINDOW)
            return resp
        supplied = request.form.get('password', '')
        if verify_oob_password(supplied):
            resp = make_response(redirect(url_for('oob.index')))
            resp.set_cookie(
                ACCESS_COOKIE_NAME, _access_serializer().dumps({
                    'scope': 'oob', 'marker': password_marker()
                }),
                max_age=ACCESS_MAX_AGE, httponly=True, samesite='Strict',
                secure=_cookie_secure(), path='/oob',
            )
            return resp
        _login_failure_limiter.allow(
            limiter_key, LOGIN_FAILURE_LIMIT, LOGIN_FAILURE_WINDOW)
        error = '密码错误，请检查后重新输入'
    return render_template(
        'tools/oob_login.html', title='反连服务访问验证',
        hide_page_header=True,
        error=error, retry_after=0,
    )


def _set_token_cookie(resp, token):
    resp.set_cookie(
        COOKIE_NAME, token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,            # 凭证不可被 JS 读取
        samesite='Strict',
        secure=_cookie_secure(),  # HTTPS 部署时通过 OOB_COOKIE_SECURE=1 开启
        path='/oob',
    )
    return resp


def _current_token():
    """从 Cookie 读取并校验当前凭证，无效返回 None"""
    token = request.cookies.get(COOKIE_NAME, '')
    if token and platform.session_info(token).get('valid'):
        return token
    return None


@oob_bp.route('')
def index():
    """反连服务页面：无有效凭证时自动发放"""
    if not _has_access():
        return _access_denied()
    token = _current_token()
    need_cookie = token is None
    if need_cookie:
        token = platform.issue_token()
    info = platform.session_info(token)
    resp = make_response(render_template(
        'tools/oob_callback.html',
        title='反连服务',
        cfg=get_config(),
        token=token,
        expires=info.get('expires', ''),
    ))
    if need_cookie:
        _set_token_cookie(resp, token)
    return resp


@oob_bp.route('/api/results')
def api_results():
    """当前凭证的回调结果（最新在前）"""
    if not _has_access():
        return _access_denied(api=True)
    token = _current_token()
    if not token:
        return jsonify({'expired': True, 'count': 0, 'items': [],
                        'msg': '凭证不存在或已过期，请重新获取'}), 200
    platform.touch(token)
    items = platform.list_records(token)
    return jsonify({'expired': False, 'count': len(items), 'items': items})


@oob_bp.route('/api/record/<int:rid>')
def api_record(rid):
    """单条记录的完整原始数据包（仅本凭证可见）"""
    if not _has_access():
        return _access_denied(api=True)
    token = _current_token()
    if not token:
        return jsonify({'expired': True, 'raw': ''}), 200
    raw = platform.get_record_raw(token, rid)
    if raw is None:
        return jsonify({'error': '记录不存在或不属于当前凭证'}), 404
    return jsonify({'id': rid, 'raw': raw})


@oob_bp.route('/api/clear', methods=['POST'])
def api_clear():
    """清空当前凭证的回调结果"""
    if not _has_access():
        return _access_denied(api=True)
    token = _current_token()
    if token:
        platform.clear_records(token)
    return jsonify({'ok': True})


@oob_bp.route('/api/new', methods=['POST'])
def api_new():
    """获取新凭证（相当于 DNSlog 平台的"重新获取域名"）"""
    if not _has_access():
        return _access_denied(api=True)
    token = platform.issue_token()
    info = platform.session_info(token)
    resp = make_response(jsonify({
        'ok': True, 'token': token, 'expires': info.get('expires', ''),
    }))
    _set_token_cookie(resp, token)
    return resp


@oob_bp.route('/api/status')
def api_status():
    """服务状态（不含任何凭证/记录信息）"""
    if not _has_access():
        return _access_denied(api=True)
    return jsonify(get_config())
