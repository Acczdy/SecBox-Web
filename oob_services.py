"""
OOB (Out-of-Band) 带外回调检测服务 —— 多用户隔离版

为 JNDI 注入（Log4Shell 等）、SSRF 等漏洞的带外探测提供三种回调协议：
- RMI Registry 服务：接收 rmi:// 回调，解析客户端请求的名称
- LDAP 服务：接收 ldap:// 回调，解析 Bind/Search 的 Base DN，
  并返回 Java Naming Reference 条目（低版本 JDK 会继续请求 javaCodeBase，
  触发 HTTP 二次回调，且归属同一凭证）
- HTTP 回调由 Flask 主服务的全捕获路由处理（见 app.py）

多用户模型（类似 DNSlog 平台）：
- 每个访问者自动分配一个随机凭证 token（相当于 DNSlog 分配的唯一子域名）；
  本平台没有公网域名，因此以回调 URL 的"首段路径"作为凭证标识。
- 回调到达时按首段路径归属凭证；用户只能查看自己凭证下的记录。
- 凭证有有效期（默认 24 小时），过期后需重新获取；记录随之清理。

注意：凭证与结果保存在内存中，必须以单进程部署（gunicorn -w 1，可多线程）。
DNSLog 需要公网 DNS 域名解析服务，本平台无域名，不包含 DNS 协议。
"""
import os
import secrets
import socket
import socketserver
import string
import struct
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

# 北京时间（东八区）。容器默认 UTC 且不含 tzdata，统一用此时区生成所有
# 展示/比较时间戳，使回调日志、凭证过期均显示北京时间，不依赖宿主/容器 TZ。
BJT = timezone(timedelta(hours=8))


# ============================================================
# 配置
# ============================================================

def _required_oob_port(name):
    """读取用户显式配置的 OOB 端口，不提供可被批量扫描的公共默认值。"""
    raw = os.environ.get(name, '').strip()
    if not raw:
        raise RuntimeError(
            '{} 未设置。Docker 用户请在项目根目录 .env 中设置三个 OOB 端口；'
            'Python 用户请在启动前设置同名环境变量。'.format(name)
        )
    try:
        port = int(raw)
    except ValueError as exc:
        raise RuntimeError('{} 必须是整数端口'.format(name)) from exc
    if not 1024 <= port <= 65535:
        raise RuntimeError('{} 必须在 1024-65535 范围内'.format(name))
    return port


RMI_PORT = _required_oob_port('OOB_RMI_PORT')
LDAP_PORT = _required_oob_port('OOB_LDAP_PORT')
HTTP_PORT = int(os.environ.get('PORT', '5001'))
# 前端展示/回调地址用的 HTTP 端口（反代对外端口）；实际监听仍为 PORT
HTTP_DISPLAY_PORT = int(os.environ.get('OOB_HTTP_DISPLAY_PORT', '10051'))
# HTTP 回调专用端口：不经过 WAF 反代，直连随机高位端口（防 WAF 拦截回调）
HTTP_CALLBACK_PORT = _required_oob_port('OOB_HTTP_CALLBACK_PORT')

if len({RMI_PORT, LDAP_PORT, HTTP_CALLBACK_PORT, HTTP_PORT}) != 4:
    raise RuntimeError('OOB_RMI_PORT、OOB_LDAP_PORT、OOB_HTTP_CALLBACK_PORT 和 PORT 不能重复')

SESSION_TTL_HOURS = int(os.environ.get('OOB_SESSION_TTL_HOURS', '24'))  # 凭证有效期(小时)
MAX_SESSIONS = int(os.environ.get('OOB_MAX_SESSIONS', '10000'))         # 凭证数量上限
MAX_RECORDS_PER_TOKEN = int(os.environ.get('OOB_MAX_RECORDS', '200'))   # 每凭证记录上限
COOKIE_SECURE = os.environ.get('OOB_COOKIE_SECURE', '0') == '1'         # HTTPS 部署时置 1
RAW_LIMIT = int(os.environ.get('OOB_RAW_LIMIT', '6000'))                # 单条记录原始报文保存上限(字符)

# 并发连接上限：RMI/LDAP 合计最多 200 并发，超出直接拒绝（防线程洪泛 DoS）
MAX_CONNS = int(os.environ.get('OOB_MAX_CONNS', '200'))
_conn_sem = threading.BoundedSemaphore(MAX_CONNS)

# 单 IP 记录限速窗口
RATE_WINDOW = 60
RATE_LIMIT = 120

TOKEN_ALPHABET = string.ascii_lowercase + string.digits
TOKEN_LEN = 8


_STATUS = {}


def get_public_host():
    """返回容器入口探测或部署方显式配置的服务器 A 公网地址。"""
    return os.environ.get('OOB_HOST', '').strip()


def get_config():
    public_host = get_public_host()
    http_host = os.environ.get('OOB_HTTP_HOST', '').strip() or public_host
    callback_host = os.environ.get('OOB_HTTP_CALLBACK_HOST', '').strip() or public_host
    return {
        'host': public_host,
        'rmi_port': RMI_PORT,
        'ldap_port': LDAP_PORT,
        'http_port': HTTP_DISPLAY_PORT,
        'http_host': http_host,
        'http_callback_port': HTTP_CALLBACK_PORT,
        'http_callback_host': callback_host,
        'public_host_ready': bool(public_host and callback_host),
        'public_host_source': os.environ.get('OOB_PUBLIC_HOST_SOURCE', ''),
        'session_ttl_hours': SESSION_TTL_HOURS,
        'rmi_running': _STATUS.get('rmi', False),
        'ldap_running': _STATUS.get('ldap', False),
    }


def extract_token(name):
    """从回调的路径 / DN / RMI 查找名中提取凭证标识（首段路径）。

    示例:
      'ab12cd34'                 -> 'ab12cd34'
      'ab12cd34/test'            -> 'ab12cd34'
      'cn=ab12cd34,dc=x'         -> 'ab12cd34'
      '/ab12cd34/Exploit.class'  -> 'ab12cd34'
    """
    if not name:
        return ''
    seg = name.strip().lstrip('/')
    seg = seg.split(',')[0]                # DN 取第一个 RDN
    if '=' in seg:
        seg = seg.split('=', 1)[1]
    seg = seg.split('/', 1)[0]
    return seg.strip().lower()


# ============================================================
# 多用户凭证与结果管理
# ============================================================


class OOBPlatform:
    """多用户凭证与回调结果管理（线程安全、内存存储、自动过期）"""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions = {}   # token -> {'created','expires','last'}
        self._records = {}    # token -> deque(record)
        self._ip_rate = {}   # ip -> deque(timestamps) 限速用
        self._seq = 0

    # ---------- 凭证 ----------

    def issue_token(self):
        """发放新凭证（容量超限时淘汰最久未活跃的凭证）"""
        with self._lock:
            self._cleanup_locked()
            while len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda t: self._sessions[t]['last'])
                self._drop_locked(oldest)
            token = self._unique_token_locked()
            now = datetime.now(BJT)
            self._sessions[token] = {
                'created': now,
                'expires': now + timedelta(hours=SESSION_TTL_HOURS),
                'last': now,
            }
            self._records[token] = deque(maxlen=MAX_RECORDS_PER_TOKEN)
            return token

    def _unique_token_locked(self):
        while True:
            token = ''.join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LEN))
            if token not in self._sessions:
                return token

    def session_info(self, token):
        """查询凭证状态: {'valid': False} 或 {'valid': True, 'expires': '...'}"""
        if not token:
            return {'valid': False}
        with self._lock:
            s = self._sessions.get(token)
            if not s:
                return {'valid': False}
            if datetime.now(BJT) > s['expires']:
                self._drop_locked(token)
                return {'valid': False}
            return {'valid': True, 'expires': s['expires'].strftime('%Y-%m-%d %H:%M:%S')}

    def touch(self, token):
        with self._lock:
            s = self._sessions.get(token)
            if s and datetime.now(BJT) <= s['expires']:
                s['last'] = datetime.now(BJT)
                return True
            return False

    # ---------- 记录 ----------

    def add_record(self, token, proto, record, ip, detail='', raw=''):
        """记录一次回调。token 无需事先注册：未知凭证隔离存放，任何人不可见

        raw: 完整原始报文（HTTP 请求行+头+体 或 RMI/LDAP hexdump），按 RAW_LIMIT 截断。
        """
        token = (token or '').strip().lower() or '_unknown'
        now_ts = time.time()
        with self._lock:
            # 单 IP 限速：60s 内最多 RATE_LIMIT 条，超出静默丢弃
            dq_ts = self._ip_rate.setdefault(ip or '-', deque(maxlen=RATE_LIMIT + 1))
            while dq_ts and now_ts - dq_ts[0] > RATE_WINDOW:
                dq_ts.popleft()
            if len(dq_ts) >= RATE_LIMIT:
                return
            dq_ts.append(now_ts)
            dq = self._records.get(token)
            if dq is None:
                if len(self._records) >= MAX_SESSIONS * 2:
                    return  # 未知桶总量保护
                dq = deque(maxlen=50)
                self._records[token] = dq
            self._seq += 1
            dq.append({
                'id': self._seq,
                'time': datetime.now(BJT).strftime('%Y-%m-%d %H:%M:%S'),
                'type': proto,
                'record': (record or '-')[:200],
                'ip': ip or '-',
                'detail': (detail or '')[:300],
                'raw': (raw or '')[:RAW_LIMIT],
            })

    def list_records(self, token):
        """列表（供 3 秒轮询）：剥离 raw 原始报文以保持响应轻量，仅给出 has_raw 标记"""
        with self._lock:
            dq = self._records.get(token)
            if not dq:
                return []
            out = []
            for r in list(dq)[::-1]:
                item = dict(r)
                item['has_raw'] = bool(item.pop('raw', ''))
                out.append(item)
            return out

    def get_record_raw(self, token, record_id):
        """按 ID 取某条记录的完整原始报文（仅本凭证可见；不存在返回 None）"""
        with self._lock:
            dq = self._records.get(token)
            if not dq:
                return None
            for r in dq:
                if r['id'] == record_id:
                    return r.get('raw', '')
            return None

    def clear_records(self, token):
        with self._lock:
            dq = self._records.get(token)
            if dq:
                dq.clear()

    # ---------- 清理 ----------

    def cleanup_expired(self):
        with self._lock:
            self._cleanup_locked()

    def _cleanup_locked(self):
        now = datetime.now(BJT)
        expired = [t for t, s in self._sessions.items() if now > s['expires']]
        for t in expired:
            self._drop_locked(t)

    def _drop_locked(self, token):
        self._sessions.pop(token, None)
        self._records.pop(token, None)


platform = OOBPlatform()


# ============================================================
# 通用工具
# ============================================================


def _recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


def _extract_tc_strings(data):
    """从 Java 序列化流中顺序提取所有 TC_STRING(0x74) 字符串"""
    out, i, n = [], 0, len(data)
    while i < n:
        if data[i] == 0x74 and i + 3 <= n:
            length = (data[i + 1] << 8) | data[i + 2]
            if 0 < length <= 512 and i + 3 + length <= n:
                raw = data[i + 3:i + 3 + length]
                try:
                    text = raw.decode('utf-8')
                    if text.isprintable():
                        out.append(text)
                        i += 3 + length
                        continue
                except UnicodeDecodeError:
                    pass
        i += 1
    return out


def _hexdump(data, limit=None):
    """生成 hexdump 风格的报文转储（用于 RMI/LDAP 原始报文展示）"""
    if limit is None:
        limit = RAW_LIMIT
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = ' '.join('%02x' % b for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        out.append('%08x  %-47s  %s' % (i, hexs, asc))
    return ('\n'.join(out))[:limit]


def _packet(req_dump, resp_dump=''):
    """拼接 请求 + 响应 完整数据包"""
    if not resp_dump:
        return req_dump
    return req_dump + '\n\n' + '─' * 16 + ' Response ' + '─' * 16 + '\n' + resp_dump


# ============================================================
# RMI Registry 检测服务
# ============================================================


class _RMIHandler(socketserver.BaseRequestHandler):
    """最小 RMI Registry 协议实现：完成握手后读取 Call，提取请求名称并按凭证记录（含完整数据包）"""

    def handle(self):
        if not _conn_sem.acquire(timeout=1):
            return  # 并发已满，拒绝
        try:
            self._handle()
        finally:
            _conn_sem.release()

    def _handle(self):
        conn = self.request
        conn.settimeout(8)
        ip = self.client_address[0]
        raw = bytearray()  # 收到的全部原始字节（用于数据包展示）

        def recv(n):
            b = _recv_exact(conn, n)
            if len(raw) < 2048:
                raw.extend(b[:2048 - len(raw)])
            return b

        sent = bytearray()  # 平台发出的应答字节

        def send(b):
            conn.send(b)
            if len(sent) < 2048:
                sent.extend(b[:2048 - len(sent)])

        try:
            # 协议头: 'JRMI' + version(2) + StreamProtocol(0x4B)
            header = recv(7)
            if header[:4] != b'JRMI':
                platform.add_record('', 'RMI', '(非RMI连接)', ip,
                                    'HEX=' + header.hex(), _hexdump(bytes(raw)))
                return
            # ProtocolAck(0x4E) + 服务端 endpoint(UTF host + INT port)
            host = get_public_host().encode('utf-8')
            send(b'\x4e' + struct.pack('>H', len(host)) + host + struct.pack('>i', RMI_PORT))
            # 客户端 endpoint: UTF host + INT port
            name_len = struct.unpack('>H', recv(2))[0]
            recv(min(name_len, 512))
            recv(4)
            # 调用循环
            while True:
                op = recv(1)
                if op == b'\x50':  # Call
                    data = b''
                    try:
                        while len(data) < 65536:
                            chunk = conn.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                            if len(raw) < 2048:
                                raw.extend(chunk[:2048 - len(raw)])
                            if len(chunk) < 4096:
                                break
                    except socket.timeout:
                        pass
                    strings = _extract_tc_strings(data)
                    name = strings[0] if strings else ''
                    detail = ' | '.join(strings) if strings else data[:64].hex()
                    platform.add_record(extract_token(name), 'RMI',
                                        name or '(未解析到名称)', ip, detail,
                                        _packet(_hexdump(bytes(raw)), _hexdump(bytes(sent))))
                    return
                elif op == b'\x51':  # Ping -> PingAck
                    send(b'\x53')
                else:
                    platform.add_record('', 'RMI', '(未知操作)', ip,
                                        'OP=' + op.hex(),
                                        _packet(_hexdump(bytes(raw)), _hexdump(bytes(sent))))
                    return
        except Exception:
            if raw:  # 收到过数据但协议不完整（如端口扫描器），也留档便于排查
                platform.add_record('', 'RMI', '(连接中断/协议不完整)', ip, '',
                                    _hexdump(bytes(raw)))


# ============================================================
# LDAP 检测服务（最小 BER 编解码）
# ============================================================


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, content):
    return bytes([tag]) + _ber_len(len(content)) + content


def _ber_int_body(v):
    if v == 0:
        return b'\x00'
    body = v.to_bytes((v.bit_length() + 7) // 8, 'big')
    if body[0] & 0x80:
        body = b'\x00' + body
    return body


def _ber_int(v):
    return _tlv(0x02, _ber_int_body(v))


def _ber_enum(v):
    return _tlv(0x0a, _ber_int_body(v))


def _ber_octet(b):
    return _tlv(0x04, b)


def _read_tlv(buf, pos):
    tag = buf[pos]
    pos += 1
    l0 = buf[pos]
    pos += 1
    if l0 & 0x80:
        n = l0 & 0x7f
        length = int.from_bytes(buf[pos:pos + n], 'big')
        pos += n
    else:
        length = l0
    return tag, buf[pos:pos + length], pos + length


def _read_tlv_sock(conn):
    """读取一条完整 BER TLV，返回 (tag, value, 完整原始字节)"""
    head = _recv_exact(conn, 2)
    tag, l0 = head[0], head[1]
    if l0 & 0x80:
        n = l0 & 0x7f
        lb = _recv_exact(conn, n)
        length = int.from_bytes(lb, 'big')
        head += lb
    else:
        length = l0
    if length > (1 << 20):
        raise ValueError('LDAP message too large')
    value = _recv_exact(conn, length)
    return tag, value, head + value


class _LDAPHandler(socketserver.BaseRequestHandler):
    """最小 LDAP 服务：响应 Bind/Search，按凭证记录 DN，返回 JNDI Reference 条目"""

    def handle(self):
        if not _conn_sem.acquire(timeout=1):
            return  # 并发已满，拒绝
        try:
            self._handle()
        finally:
            _conn_sem.release()

    def _handle(self):
        conn = self.request
        conn.settimeout(8)
        ip = self.client_address[0]
        try:
            while True:
                tag, value, raw_msg = _read_tlv_sock(conn)
                if tag != 0x30:  # LDAPMessage SEQUENCE
                    return
                raw_dump = _hexdump(raw_msg)
                _, mval, nxt = _read_tlv(value, 0)      # messageID
                msg_id = int.from_bytes(mval, 'big') if mval else 0
                otag, oval, _ = _read_tlv(value, nxt)   # protocolOp
                if otag == 0x60:  # bindRequest
                    dn = self._first_octet(oval)
                    resp = self._bind_response(msg_id)
                    if dn:  # JNDI 简单绑定通常为空 DN，空则不记录
                        platform.add_record(extract_token(dn), 'LDAP', dn, ip,
                                            'bindRequest', _packet(raw_dump, _hexdump(resp)))
                    conn.send(resp)
                elif otag == 0x63:  # searchRequest
                    dn = self._first_octet(oval)
                    resp = self._search_response(msg_id, dn)
                    platform.add_record(extract_token(dn), 'LDAP', dn or '(空DN)', ip,
                                        'searchRequest', _packet(raw_dump, _hexdump(resp)))
                    conn.send(resp)
                elif otag == 0x42:  # unbindRequest
                    return
                else:
                    platform.add_record('', 'LDAP', '(未知操作)', ip,
                                        'OP=0x%02x' % otag, raw_dump)
                    return
        except Exception:
            pass

    @staticmethod
    def _first_octet(buf):
        """取第一个 OCTET STRING 子元素（bindRequest 的 name / searchRequest 的 baseObject）"""
        pos = 0
        while pos < len(buf):
            try:
                tag, val, pos = _read_tlv(buf, pos)
            except Exception:
                break
            if tag == 0x04:
                try:
                    return val.decode('utf-8')
                except UnicodeDecodeError:
                    return val.hex()
        return ''

    @staticmethod
    def _bind_response(msg_id):
        body = _ber_enum(0) + _ber_octet(b'') + _ber_octet(b'')
        return _tlv(0x30, _ber_int(msg_id) + _tlv(0x61, body))

    @staticmethod
    def _search_response(msg_id, dn):
        """返回 searchResEntry(javaNamingReference) + searchResultDone

        javaCodeBase 指向本平台 HTTP 服务且带上凭证前缀：
        若目标 JDK 信任远程引用（JDK < 8u191 等），会再发起
        http://host:port/<token>/<Factory>.class 请求，二次回调仍归属同一凭证。
        """
        token = extract_token(dn)
        cb_host = os.environ.get('OOB_HTTP_CALLBACK_HOST', '').strip() or get_public_host()
        base = 'http://{}:{}/'.format(cb_host, HTTP_CALLBACK_PORT)
        if token and token != '_unknown':
            base += token + '/'
        attrs = b''
        for name, val in ((b'objectClass', b'javaNamingReference'),
                          (b'javaClassName', b'oob'),
                          (b'javaFactory', b'Exploit'),
                          (b'javaCodeBase', base.encode('utf-8'))):
            attrs += _tlv(0x30, _ber_octet(name) + _tlv(0x31, _ber_octet(val)))
        entry = _tlv(0x64, _ber_octet((dn or '').encode('utf-8')) + _tlv(0x30, attrs))
        done = _tlv(0x65, _ber_enum(0) + _ber_octet(b'') + _ber_octet(b''))
        return (_tlv(0x30, _ber_int(msg_id) + entry) +
                _tlv(0x30, _ber_int(msg_id) + done))


# ============================================================
# HTTP 回调记录（Web 捕获路由与独立回调服务共用）
# ============================================================

def record_http_callback(method, path, headers, body_text, ip):
    """记录一次 HTTP 带外回调，返回 (status_code, response_bytes)"""
    detail_parts = [method]
    ua = ''
    try:
        ua = headers.get('User-Agent', '') or ''
    except Exception:
        pass
    if ua:
        detail_parts.append('UA=' + ua[:120])
    body_text = body_text or ''
    if body_text.strip():
        detail_parts.append('BODY=' + ' '.join(body_text.split())[:180])

    req_lines = ['%s /%s HTTP/1.1' % (method, path)]
    try:
        for k, v in headers.items():
            req_lines.append('%s: %s' % (k, v))
    except Exception:
        pass
    req_dump = '\r\n'.join(req_lines) + '\r\n\r\n' + body_text[:2048]
    resp_dump = ('HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n'
                 'Content-Length: 0\r\nConnection: close\r\n\r\n(\u7a7a\u54cd\u5e94\u4f53)')
    raw_dump = req_dump + '\r\n\r\n' + '\u2500' * 16 + ' Response ' + '\u2500' * 16 + '\r\n' + resp_dump
    platform.add_record(extract_token(path), 'HTTP', '/' + path[:200], ip,
                        ' '.join(detail_parts)[:300], raw_dump)
    return 200, b''


# ============================================================
# 服务启动
# ============================================================


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


_started = False
_start_lock = threading.Lock()


def _cleanup_loop():
    """定期清理过期凭证及其记录"""
    while True:
        time.sleep(600)
        try:
            platform.cleanup_expired()
        except Exception:
            pass


import http.server as _http_server
from urllib.parse import urlparse as _urlparse


class _HttpCallbackHandler(_http_server.BaseHTTPRequestHandler):
    """独立 HTTP 回调端口处理器：任何路径都记录回调并返回 200 空体"""
    protocol_version = 'HTTP/1.1'

    def _handle(self):
        if not _conn_sem.acquire(timeout=1):
            return
        try:
            path = _urlparse(self.path).path.lstrip('/') or ''
            size = int(self.headers.get('Content-Length') or 0)
            body = b''
            if 0 < size <= 4096:
                try:
                    body = self.rfile.read(size)[:2048]
                except Exception:
                    body = b''
            try:
                text = body.decode('utf-8', 'replace')[:2048]
            except Exception:
                text = ''
            if path.startswith(('tools/', 'static/')):
                self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers()
                return
            record_http_callback(self.command, path, self.headers, text, self.client_address[0])
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', '0')
            self.end_headers()
        except Exception:
            pass
        finally:
            _conn_sem.release()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle

    def log_message(self, *args):
        pass


def start_http_callback_server():
    """启动独立 HTTP 回调服务（随机高位端口，绕过 WAF）"""
    try:
        srv = _http_server.ThreadingHTTPServer(('0.0.0.0', HTTP_CALLBACK_PORT), _HttpCallbackHandler)
    except Exception as e:
        print('[oob] HTTP 回调服务启动失败（端口 {}）: {}'.format(HTTP_CALLBACK_PORT, e))
        return
    print('[oob] HTTP 回调服务已监听 0.0.0.0:{}（绕过 WAF 直连）'.format(HTTP_CALLBACK_PORT))
    srv.serve_forever()


def start_oob_services():
    """启动 RMI / LDAP / HTTP 带外检测服务与凭证清理线程（幂等、守护线程）"""
    global _started
    with _start_lock:
        if _started:
            return
        _started = True

    def _serve(handler_cls, port, name):
        try:
            srv = _ThreadingTCPServer(('0.0.0.0', port), handler_cls)
        except Exception as e:
            _STATUS[name] = False
            print('[oob] {} 服务启动失败（端口 {}）: {}'.format(name.upper(), port, e))
            return
        _STATUS[name] = True
        print('[oob] {} 回调服务已监听 0.0.0.0:{}'.format(name.upper(), port))
        srv.serve_forever()

    threading.Thread(target=_serve, args=(_RMIHandler, RMI_PORT, 'rmi'), daemon=True).start()
    threading.Thread(target=_serve, args=(_LDAPHandler, LDAP_PORT, 'ldap'), daemon=True).start()
    threading.Thread(target=start_http_callback_server, daemon=True).start()
    threading.Thread(target=_cleanup_loop, daemon=True).start()
