"""
网络模块 — HTTP 传输层

处理:
- 自定义 HTTP 客户端 (headers, cookies)
- 网卡绑定 (多网卡场景)
- DNS 自定义解析
- 门户检测 (generate_204)
"""

import hashlib
import logging
import socket
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

from .protocol import USER_AGENT

logger = logging.getLogger(__name__)

# 用于检测 portal 的测试 URL (优先级从高到低)
PORTAL_TEST_URLS = [
    "http://connect.rom.miui.com/generate_204",
    "http://www.gstatic.com/generate_204",       # Google captive portal
    "http://captive.apple.com/hotspot-detect.html",  # Apple
    "http://www.msftconnecttest.com/connecttest.txt",  # Microsoft
    "http://cp.cloudflare.com/generate_204",      # Cloudflare
]


class BoundHTTPAdapter(HTTPAdapter):
    """绑定指定网络接口的 HTTP 适配器"""

    def __init__(self, bind_ip: Optional[str] = None, dns_server: Optional[str] = None):
        self.bind_ip = bind_ip
        self.dns_server = dns_server
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs['source_address'] = (self.bind_ip, 0) if self.bind_ip else None
        super().init_poolmanager(*args, **kwargs)

    def send(self, request, **kwargs):
        # 自定义 DNS 解析
        if self.dns_server:
            # 使用自定义 DNS 服务器解析
            hostname = request.url.split('/')[2].split(':')[0]
            try:
                ip = _resolve_with_dns(hostname, self.dns_server)
                if ip:
                    # 替换 URL 中的主机名为 IP
                    request.url = request.url.replace(
                        f"://{hostname}", f"://{ip}", 1
                    )
                    # 更新 Host 头
                    request.headers['Host'] = hostname
            except Exception:
                pass  # 回退到系统 DNS

        return super().send(request, **kwargs)


class NetworkClient:
    """天翼校园网 HTTP 客户端

    封装认证过程中所有 HTTP 请求，处理:
    - 自定义 UA 和认证相关 headers
    - CDC-* 系列学校信息头
    - MD5 校验和
    - 网卡绑定
    - 不自动跟随重定向 (需要捕获 302)
    """

    def __init__(
        self,
        bind_interface: Optional[str] = None,
        dns_address: Optional[str] = None,
        timeout: int = 10,
    ):
        self.timeout = timeout
        self.bind_ip: Optional[str] = None
        self.dns_server: Optional[str] = None

        # 解析网卡绑定
        if bind_interface and bind_interface != "sys_default":
            self.bind_ip = _get_interface_ip(bind_interface)
            if not self.bind_ip:
                logger.warning(f"Cannot bind to interface {bind_interface}, "
                              f"using default")
            else:
                logger.info(f"Bound to interface {bind_interface} ({self.bind_ip})")

        # DNS 自定义
        if dns_address:
            self.dns_server = dns_address

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,text/xml,application/xhtml+xml,'
                      'application/x-javascript,*/*',
            'Connection': 'keep-alive',
        })

        # 添加绑定适配器
        adapter = BoundHTTPAdapter(self.bind_ip, self.dns_server)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    # ---- 请求方法 ----

    def get(self, url: str, client_id: str = "", school_info=None,
            allow_redirects: bool = False) -> requests.Response:
        """GET 请求"""
        headers = self._build_headers(client_id, school_info, None)
        return self.session.get(
            url,
            headers=headers,
            timeout=self.timeout,
            allow_redirects=allow_redirects,
        )

    def post_raw(self, url: str, data: bytes, client_id: str = "",
                 algo_id: str = "", school_info=None) -> requests.Response:
        """POST 原始数据 (二进制)"""
        headers = self._build_headers(client_id, school_info, algo_id)
        # MD5 校验和
        md5sum = hashlib.md5(data).hexdigest()
        headers['CDC-Checksum'] = md5sum
        return self.session.post(
            url,
            data=data,
            headers=headers,
            timeout=self.timeout,
        )

    def get_redirect_url(self) -> Optional[str]:
        """检测是否有 portal 重定向 (依次尝试多个已知 URL)"""
        for url in PORTAL_TEST_URLS:
            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 302:
                    return resp.headers.get('Location', '')
                elif resp.status_code == 204:
                    # 已在线, 无需重定向
                    return None
            except requests.RequestException:
                continue
        return None

    def check_online(self) -> bool:
        """检查网络是否在线 (已认证状态, 带重试与回退)"""
        # 策略 1: 用多个已知 URL 检测 portal
        for url in PORTAL_TEST_URLS:
            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 204:
                    return True
                elif resp.status_code == 200:
                    # 某些探测 URL 返回 200 (如 Apple 的 hotspot-detect.html)
                    body = resp.text.strip()
                    if body == "Success" or "Success" in body:
                        return True
            except requests.RequestException:
                continue

        # 策略 2: 回退 — 尝试 DNS 解析 (发一个 HTTP 请求到公共服务器)
        try:
            resp = self.session.get(
                "http://httpbin.org/ip",
                timeout=self.timeout,
                allow_redirects=True,
            )
            if resp.status_code == 200:
                return True
        except requests.RequestException:
            pass

        return False

    # ---- 内部方法 ----

    def _build_headers(self, client_id: str, school_info,
                       algo_id: Optional[str]) -> dict:
        """构建请求头"""
        headers = {}
        if client_id:
            headers['Client-ID'] = client_id
        if algo_id:
            headers['Algo-ID'] = algo_id
        if school_info:
            if school_info.school_id:
                headers['CDC-SchoolId'] = school_info.school_id
            if school_info.domain:
                headers['CDC-Domain'] = school_info.domain
            if school_info.area:
                headers['CDC-Area'] = school_info.area
        return headers

    def close(self):
        """关闭会话"""
        self.session.close()


# ============================================================
# 辅助函数
# ============================================================
def _get_interface_ip(interface_name: str) -> Optional[str]:
    """获取指定网卡的 IPv4 地址"""
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface_name)
        for addr in addrs.get(netifaces.AF_INET, []):
            ip = addr.get('addr')
            if ip and not ip.startswith('127.'):
                return ip
    except ImportError:
        pass

    # 回退: 使用 socket 方式
    try:
        # Windows 上尝试
        import subprocess
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True, text=True,
            timeout=5
        )
        # 简单解析 ipconfig 输出 (Windows)
        # 注: 更可靠的方式需要更复杂的解析或 psutil
    except Exception:
        pass

    return None


def _resolve_with_dns(hostname: str, dns_server: str) -> Optional[str]:
    """使用指定 DNS 服务器解析域名"""
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server.split(':')[0]]
    try:
        answers = resolver.resolve(hostname, 'A')
        return str(answers[0])
    except Exception:
        return None
