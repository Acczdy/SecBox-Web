"""适用于单进程部署的轻量安全控制。"""
import ipaddress
import os
import threading
import time
from urllib.parse import urlsplit


class FixedWindowLimiter:
    """内存限流器；单进程 gunicorn 模式下线程安全。"""

    def __init__(self, max_keys=20000):
        self.max_keys = max_keys
        self._items = {}
        self._lock = threading.Lock()

    def allow(self, key, limit, window_seconds):
        now = time.monotonic()
        bucket = int(now // window_seconds)
        item_key = (key, window_seconds)
        with self._lock:
            old_bucket, count = self._items.get(item_key, (bucket, 0))
            if old_bucket != bucket:
                count = 0
            count += 1
            self._items[item_key] = (bucket, count)
            if len(self._items) > self.max_keys:
                cutoff = bucket - 2
                self._items = {k: v for k, v in self._items.items() if v[0] >= cutoff}
            return count <= limit

    def is_blocked(self, key, limit, window_seconds):
        """只检查当前窗口，不增加计数。用于仅统计认证失败的限流场景。"""
        now = time.monotonic()
        bucket = int(now // window_seconds)
        item_key = (key, window_seconds)
        with self._lock:
            old_bucket, count = self._items.get(item_key, (bucket, 0))
            return old_bucket == bucket and count >= limit


def _can_trust_forwarded_headers(req):
    peer = (req.remote_addr or 'unknown').strip()
    trust_forwarded = os.environ.get('TRUST_PROXY_HEADERS', '0') == '1'
    try:
        peer_ip = ipaddress.ip_address(peer)
        trust_forwarded = trust_forwarded or peer_ip.is_private or peer_ip.is_loopback
    except ValueError:
        pass
    return trust_forwarded


def request_client_address(req):
    """返回限流地址；默认仅信任来自内网或回环代理的转发头。"""
    peer = (req.remote_addr or 'unknown').strip()
    if _can_trust_forwarded_headers(req):
        candidates = [
            req.headers.get('CF-Connecting-IP', ''),
            req.headers.get('X-Forwarded-For', '').split(',', 1)[0],
            req.headers.get('X-Real-IP', ''),
        ]
        for candidate in candidates:
            try:
                return str(ipaddress.ip_address(candidate.strip()))
            except ValueError:
                continue
    return peer


def is_same_origin_request(req):
    """有 Origin 或 Sec-Fetch-Site 的浏览器写请求必须同源；CLI 客户端可不携带这些头。"""
    fetch_site = (req.headers.get('Sec-Fetch-Site') or '').lower()
    if fetch_site and fetch_site not in ('same-origin', 'none'):
        return False
    origin = (req.headers.get('Origin') or '').rstrip('/')
    if origin:
        try:
            request_host = urlsplit(req.host_url).netloc.lower()
            if _can_trust_forwarded_headers(req):
                forwarded_host = req.headers.get('X-Forwarded-Host', '').split(',', 1)[0].strip().lower()
                if forwarded_host:
                    request_host = forwarded_host
            if urlsplit(origin).netloc.lower() != request_host:
                return False
        except ValueError:
            return False
    return True
