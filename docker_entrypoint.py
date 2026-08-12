"""容器入口：启动时探测宿主出口公网 IP，再执行 gunicorn。

显式设置 OOB_HOST 时不发起探测。探测结果只用于生成回调地址，
不会改变服务监听地址，也不会影响 Web 站点经 WAF 反向代理访问。
"""
import ipaddress
import os
import sys
import urllib.request

from runtime_secrets import ensure_state, state_path


DEFAULT_IP_SERVICES = (
    'https://api.ipify.org',
    'https://checkip.amazonaws.com',
    'https://ifconfig.me/ip',
)


def _valid_public_ip(value):
    try:
        address = ipaddress.ip_address(value.strip())
        return str(address) if address.is_global else ''
    except ValueError:
        return ''


def discover_public_ip():
    configured = os.environ.get('OOB_HOST', '').strip()
    if configured:
        return configured, 'configured'

    raw_urls = os.environ.get('OOB_PUBLIC_IP_SERVICES', '')
    urls = [item.strip() for item in raw_urls.split(',') if item.strip()] or DEFAULT_IP_SERVICES
    timeout = float(os.environ.get('OOB_PUBLIC_IP_TIMEOUT', '4'))
    for url in urls:
        try:
            request = urllib.request.Request(url, headers={
                'User-Agent': 'security-tools-oob-ip-discovery/1.0',
                'Accept': 'text/plain',
            })
            with urllib.request.urlopen(request, timeout=timeout) as response:
                value = response.read(128).decode('ascii', 'ignore').strip()
            public_ip = _valid_public_ip(value)
            if public_ip:
                return public_ip, url
        except Exception as error:
            print('[startup] 公网 IP 探测失败 {}: {}'.format(url, error), flush=True)
    return '', 'unavailable'


def configure_oob_host():
    host, source = discover_public_ip()
    if not host:
        os.environ['OOB_PUBLIC_HOST_ERROR'] = '1'
        print('[startup] 未能获取服务器公网 IP；OOB 页面将禁用回调地址。请设置 OOB_HOST。', flush=True)
        return

    # 三种协议默认全部直连服务器 A；部署方仍可分别覆盖 HTTP 地址。
    os.environ['OOB_HOST'] = host
    if not os.environ.get('OOB_HTTP_HOST', '').strip():
        os.environ['OOB_HTTP_HOST'] = host
    if not os.environ.get('OOB_HTTP_CALLBACK_HOST', '').strip():
        os.environ['OOB_HTTP_CALLBACK_HOST'] = host
    os.environ['OOB_PUBLIC_HOST_SOURCE'] = source
    print('[startup] OOB 公网回调主机: {} ({})'.format(host, source), flush=True)


def main():
    _, initial_password = ensure_state()
    if initial_password:
        print('', flush=True)
        print('=' * 72, flush=True)
        print('[首次启动] OOB 反连服务访问密码: {}'.format(initial_password), flush=True)
        print('[首次启动] 请立即妥善保存；该明文密码不会再次显示。', flush=True)
        print('[首次启动] 重置命令: docker compose exec security-tools python manage.py reset-oob-password', flush=True)
        print('[首次启动] 密钥文件: {}'.format(state_path()), flush=True)
        print('=' * 72, flush=True)
        print('', flush=True)
    configure_oob_host()
    if len(sys.argv) < 2:
        raise SystemExit('docker_entrypoint.py 缺少启动命令')
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == '__main__':
    main()
