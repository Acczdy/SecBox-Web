"""
安全辅助工具平台 - 独立 SaaS 版

从 vuln_manager（蓝军工作辅助平台）中拆分出的"安全辅助工具"模块，
作为独立 Web 服务部署：无需认证、无数据库依赖、开箱即用。

包含工具：安全载荷手册、编码解码(CyberChef)、资产一键分拣、反弹Shell生成器、
文件下载命令、Windows进程识别、社工密码生成、JSFuck编码、默认密码查询、
Windows提权辅助、搜索引擎语法、Email分析、JWT工具、带外检测平台(OOB)。
"""
from flask import Flask, abort, jsonify, redirect, request, url_for
from werkzeug.routing import RequestRedirect
from werkzeug.exceptions import MethodNotAllowed, NotFound
import os

from routes_tools import tools_bp
from routes_oob import oob_bp
from routes_parser import parser_bp
from routes_ai import ai_bp
from oob_services import platform, extract_token, start_oob_services, record_http_callback
from security_controls import FixedWindowLimiter, is_same_origin_request, request_client_address
from runtime_secrets import ensure_state

app = Flask(__name__, static_folder='static', template_folder='templates')

# 首次启动生成并持久化签名密钥；仓库、镜像和环境变量均不保存密钥。
runtime_state, _ = ensure_state()
app.config['SECRET_KEY'] = runtime_state['flask_secret']

# 安全加固：限制请求体大小（JWT 字典上传自身限 5MB，此处全局兜底）
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
limiter = FixedWindowLimiter()

# 注册工具蓝图
app.register_blueprint(tools_bp)
# 注册带外检测平台蓝图（多用户凭证隔离）
app.register_blueprint(oob_bp)
# 注册扫描结果解析蓝图（纯前端解析）
app.register_blueprint(parser_bp)
# 邮件与扫描报告的可选 AI 深度分析。
app.register_blueprint(ai_bp)


@app.before_request
def public_saas_request_guard():
    """公网部署的资源与跨站请求保护。

    仅对来自内网/回环代理或显式授权的代理读取客户端转发地址，
    避免直连时伪造 X-Forwarded-For 绕过限流。
    """
    if request.path.startswith('/static/'):
        return None
    client = request_client_address(request)
    endpoint = request.endpoint or request.path
    if request.path.startswith('/api/ai/'):
        limit, window = 30, 60
    elif endpoint in ('tools.jwt_crack', 'tools.jwt_crack_file', 'tools.api_jwt_crack',
                      'tools.email_analyze_api', 'tools.api_email_analyze',
                      'tools.email_analyze_export'):
        limit, window = 20, 60
    elif '/api/' in request.path:
        limit, window = 90, 60
    else:
        limit, window = 240, 60
    if not limiter.allow((client, endpoint), limit, window):
        response = jsonify({'error': '请求过于频繁，请稍后再试'})
        response.status_code = 429
        response.headers['Retry-After'] = str(window)
        return response
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and not is_same_origin_request(request):
        return jsonify({'error': '已拒绝跨站写请求'}), 403
    return None


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; "
        "form-action 'self'; connect-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'"
    )
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if (request.path.startswith(('/oob/', '/email-analyze', '/api/ai/')) or
            request.path == '/oob'):
        response.cache_control.no_store = True
        response.cache_control.no_cache = True
        response.cache_control.must_revalidate = True
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    # 静态资源缓存（10 分钟，便于样式迭代生效；首次打开请 Ctrl+F5 强刷）
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 600
    return response


@app.route('/')
def index():
    """首页：重定向到编码解码工具"""
    return redirect(url_for('tools.cyberchef'))


@app.route('/tools')
def legacy_tools_index():
    return redirect(url_for('tools.cyberchef'), code=308)


@app.route('/tools/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def legacy_tools_redirect(path):
    """兼容旧版 /tools 地址，只转发到真实存在的根级功能路由。"""
    target = '/' + path.lstrip('/')
    adapter = app.url_map.bind_to_environ(request.environ)
    try:
        endpoint, _ = adapter.match(target, method=request.method)
    except (RequestRedirect, MethodNotAllowed, NotFound):
        abort(404)
    if endpoint in ('oob_http_callback', 'legacy_tools_redirect'):
        abort(404)

    response = redirect(target + (('?' + request.query_string.decode('latin-1'))
                                  if request.query_string else ''), code=308)
    # 旧 OOB Cookie 的 Path 是 /tools/oob；重定向时复制到新的 /oob，
    # 避免已登录用户迁移后被要求重新输入密码。
    if path == 'oob' or path.startswith('oob/'):
        secure = request.is_secure or request.headers.get('X-Forwarded-Proto', '').split(',')[0].strip() == 'https'
        for cookie_name in ('oob_access', 'oob_token'):
            value = request.cookies.get(cookie_name)
            if value:
                response.set_cookie(cookie_name, value, max_age=7 * 24 * 3600,
                                    httponly=True, secure=secure, samesite='Strict', path='/oob')
    return response


@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def oob_http_callback(path):
    """HTTP 带外回调：记录任意外部请求，按首段路径归属凭证

    平台自身路由与 /static/* 更具体、优先匹配；
    其余所有路径均视为带外回调（如 ${jndi:ldap://...} 触发的二次加载、
    SSRF、curl 外带等）。
    """
    if path.startswith(('tools/', 'static/', 'api/')):
        abort(404)
    body_raw = ''
    clen = request.content_length or 0
    if 0 < clen <= 4096:
        try:
            body_raw = request.get_data(as_text=True)[:2048]
        except Exception:
            body_raw = ''
    status, data = record_http_callback(request.method, path, request.headers,
                                        body_raw, request.remote_addr)
    return data, status


# 启动 RMI / LDAP 带外检测服务与凭证清理线程。
# 注意：凭证与回调结果存于内存，必须以单进程部署（gunicorn -w 1，可多线程）。
start_oob_services()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
