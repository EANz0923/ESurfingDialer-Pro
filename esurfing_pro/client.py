"""
核心客户端模块 — 天翼校园网认证流程

完整认证流程 (8 步):
  1. 门户检测 — GET generate_204 → 302 重定向
  2. 获取学校信息 — 从 302 响应头提取 domain/area/schoolid
  3. 解析 EConfig — 从门户 HTML 提取 ticket-url/auth-url
  4. 协商加密算法 — POST 默认 algo_id=0, 服务器返回真实算法
  5. 初始化密码器 — 根据 algo_id 选择对应加密算法
  6. 获取票据 — 构造设备 XML, 加密 POST → ticket-url
  7. 登录 — XML 包含用户名/密码/ticket, 加密 POST → auth-url
  8. 心跳维持 — 周期性发送状态 XML 到 keep-url

特性:
  - 自动重连 (断网检测 + 指数退避重试)
  - 多账号并发 (threading)
  - 结构化日志
  - 连接状态回调
"""

import logging
import random
import string
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .ciphers import Cipher, new_cipher
from .network import NetworkClient
from .protocol import (
    EConfig, LoginRequest, LoginResponse, SchoolInfo,
    StateRequest, StateResponse, TicketRequest, TicketResponse,
    build_login_request, build_state_request, build_ticket_request,
    extract_url_params, format_local_time, parse_algo_id,
    parse_econfig, parse_login_response, parse_school_info,
    parse_state_response, parse_ticket_response,
)

logger = logging.getLogger(__name__)


# ============================================================
# 连接状态
# ============================================================
class ClientState(Enum):
    IDLE = "idle"
    DETECTING = "detecting"
    AUTHING = "authing"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


# ============================================================
# 客户端配置
# ============================================================
@dataclass
class ClientConfig:
    """单个账号的客户端配置"""
    username: str = ""
    password: str = ""
    check_interval: int = 10         # 断网检测间隔 (秒)
    retry_interval: int = 10         # 失败重试间隔 (秒), <0 = 不重试
    bind_interface: str = ""         # 绑定的网卡名称
    dns_address: str = ""            # 自定义 DNS

    def validate(self) -> bool:
        return bool(self.username and self.password)


# ============================================================
# 连接统计
# ============================================================
@dataclass
class ConnectionStats:
    """连接统计信息"""
    connect_time: float = 0.0
    last_heartbeat: float = 0.0
    heartbeat_count: int = 0
    reconnect_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


# ============================================================
# 核心客户端
# ============================================================
class ESurfingClient:
    """天翼校园网认证客户端

    每个实例代表一个账号的认证会话。

    Usage:
        config = ClientConfig(username="xxx", password="xxx")
        client = ESurfingClient(config)
        client.start()  # 阻塞运行

    Callbacks:
        on_state_change(state: ClientState)
        on_log(message: str, level: str)
        on_error(error: Exception)
    """

    def __init__(self, config: ClientConfig):
        if not config.validate():
            raise ValueError("username and password are required")

        self.config = config
        self.network: Optional[NetworkClient] = None
        self.cipher: Optional[Cipher] = None
        self.state = ClientState.IDLE
        self.stats = ConnectionStats()

        # 协议状态
        self.client_id: str = ""
        self.hostname: str = ""
        self.mac_address: str = ""
        self.user_ip: str = ""
        self.ac_ip: str = ""
        self.ticket: str = ""
        self.algo_id: str = "00000000-0000-0000-0000-000000000000"

        # URL
        self.index_url: str = ""
        self.ticket_url: str = ""
        self.auth_url: str = ""
        self.keep_url: str = ""
        self.term_url: str = ""
        self.redirect_url: str = ""

        # 心跳
        self._heartbeat_interval: int = 60
        self._heartbeat_timer: Optional[threading.Timer] = None
        self._running = False
        self._stop_event = threading.Event()
        self._lock = threading.RLock()          # 可重入锁，保护 login/logout/heartbeat 互斥
        self._relogin_cooldown: float = 0.0     # 防止短时间内反复重登
        self._last_error: str = ""              # 最后一次登录失败的错误消息

        # 回调
        self.on_state_change: Optional[Callable] = None
        self.on_log: Optional[Callable] = None
        self.on_error: Optional[Callable] = None

    # ================================================================
    # 公开接口
    # ================================================================

    def start(self):
        """启动客户端 (阻塞)"""
        self._running = True
        self._stop_event.clear()
        logger.info(f"[user:{self.config.username}] Client starting")

        try:
            self._init_network()
            self._init_identity()

            while self._running and not self._stop_event.is_set():
                try:
                    # 检查是否需要认证
                    if not self._check_online():
                        self._set_state(ClientState.AUTHING)
                        self._authenticate()
                        self._set_state(ClientState.CONNECTED)
                        self._schedule_heartbeat()
                    else:
                        self._set_state(ClientState.CONNECTED)

                    # 等待下次检测
                    self._sleep(self.config.check_interval)

                except Exception as e:
                    logger.error(f"Auth error: {e}")
                    self._set_state(ClientState.ERROR)
                    if self.config.retry_interval < 0:
                        break
                    self._sleep(max(self.config.retry_interval, 5))

        finally:
            self._cleanup()

    def stop(self):
        """停止客户端 (线程安全)"""
        self._running = False
        self._stop_event.set()
        with self._lock:
            self._cancel_heartbeat()
            self._logout()

    def login(self) -> bool:
        """手动执行一次登录 (非阻塞，线程安全)"""
        with self._lock:
            # 确保 _running 标志已设置，否则 _schedule_heartbeat() 不会调度心跳
            self._running = True
            self._stop_event.clear()
            try:
                self._init_network()
                self._init_identity()
                self._set_state(ClientState.AUTHING)
                self._authenticate()
                self._set_state(ClientState.CONNECTED)
                self._schedule_heartbeat()
                self._relogin_cooldown = time.time() + 10  # 10s 冷却
                return True
            except Exception as e:
                self._last_error = str(e)
                logger.error(f"Login failed: {e}")
                self._set_state(ClientState.ERROR)
                self._relogin_cooldown = time.time() + 5   # 失败也冷却 5s
                return False

    def logout(self):
        """手动登出 (线程安全)"""
        with self._lock:
            self._cancel_heartbeat()
            self._logout()
            self._set_state(ClientState.DISCONNECTED)

    def is_online(self) -> bool:
        """检查当前是否在线"""
        if self.network:
            return self.network.check_online()
        return False

    def get_status(self) -> dict:
        """获取当前状态摘要"""
        online_sec = time.time() - self.stats.connect_time if self.stats.connect_time else 0
        return {
            'state': self.state.value,
            'username': self.config.username,
            'user_ip': self.user_ip,
            'ac_ip': self.ac_ip,
            'algo_id': self.algo_id[:8] + '...' if self.algo_id else 'N/A',
            'online_seconds': int(online_sec),
            'heartbeat_count': self.stats.heartbeat_count,
            'reconnect_count': self.stats.reconnect_count,
        }

    # ================================================================
    # 认证流程 (8 步)
    # ================================================================

    def _authenticate(self):
        """执行完整认证流程"""
        logger.info(f"[user:{self.config.username}] Starting authentication...")

        # Step 1-2: 门户检测 + 获取学校信息
        self._log("Step 1-2: Detecting portal...")
        redirect_url = self.network.get_redirect_url()
        if not redirect_url:
            raise RuntimeError("No portal redirect detected — "
                              "are you connected to campus network?")

        self.redirect_url = redirect_url
        school_info = self._get_school_info(redirect_url)
        self._log(f"School: domain={school_info.domain}, "
                   f"area={school_info.area}")

        # Step 3: 解析 EConfig
        self._log("Step 3: Fetching portal config...")
        econfig = self._get_econfig(school_info)
        self.ticket_url = econfig.ticket_url
        self.auth_url = econfig.auth_url
        self._log(f"Ticket URL: {self.ticket_url}")

        # Step 4: 协商算法
        self._log("Step 4: Negotiating encryption...")
        self.algo_id = self._negotiate_algo()
        self._log(f"AlgoID: {self.algo_id[:20]}...")

        # Step 5: 初始化密码器
        self._log("Step 5: Initializing cipher...")
        self.cipher = new_cipher(self.algo_id)
        self._log(f"Cipher: {type(self.cipher).__name__}")

        # 提取用户 IP 和 AC IP
        params = extract_url_params(self.ticket_url)
        self.user_ip = params.get('wlanuserip', '')
        self.ac_ip = params.get('wlanacip', '')
        if not self.user_ip or not self.ac_ip:
            raise RuntimeError(f"Missing user_ip or ac_ip in ticket URL: "
                              f"user_ip={self.user_ip}, ac_ip={self.ac_ip}")
        self._log(f"User IP: {self.user_ip}, AC IP: {self.ac_ip}")

        # Step 6: 获取票据
        self._log("Step 6: Getting ticket...")
        self.ticket = self._get_ticket()

        # 等待一小段时间
        time.sleep(0.4)

        # Step 7: 登录
        self._log("Step 7: Logging in...")
        login_resp = self._login()
        self.keep_url = login_resp.keep_url
        self.term_url = login_resp.term_url
        try:
            self._heartbeat_interval = int(login_resp.keep_retry)
        except (ValueError, TypeError):
            self._heartbeat_interval = 60

        self.stats.connect_time = time.time()
        self._log(f"Login SUCCESS! Heartbeat interval: "
                   f"{self._heartbeat_interval}s")

    def _get_school_info(self, redirect_url: str) -> SchoolInfo:
        """Step 2: 从重定向获取学校信息"""
        resp = self.network.get(redirect_url, self.client_id)
        if resp.status_code != 302:
            raise RuntimeError(f"Expected 302, got {resp.status_code}")

        info = parse_school_info(dict(resp.headers))
        if not info.domain or not info.school_id or not info.index_url:
            raise RuntimeError(f"Incomplete school info: {info}")

        self.index_url = info.index_url
        return info

    def _get_econfig(self, school_info: SchoolInfo) -> EConfig:
        """Step 3: 获取门户配置"""
        resp = self.network.get(
            self.index_url, self.client_id, school_info
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch index page: {resp.status_code}")

        return parse_econfig(resp.content)

    def _negotiate_algo(self) -> str:
        """Step 4: 协商加密算法"""
        resp = self.network.post_raw(
            self.ticket_url,
            self.algo_id.encode(),
            self.client_id,
            self.algo_id,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Algo negotiation failed: {resp.status_code}")

        algo_id, key = parse_algo_id(resp.content)
        logger.debug(f"Negotiated algo_id={algo_id}, key_len={len(key)}")
        return algo_id

    def _get_ticket(self) -> str:
        """Step 6: 获取认证票据"""
        req = TicketRequest(
            client_id=self.client_id,
            local_time=format_local_time(),
            host_name=self.hostname,
            ipv4=self.user_ip,
            mac=self.mac_address,
            ostag=self.hostname,
            gwip=self.ac_ip,
        )
        xml_data = build_ticket_request(req)
        encrypted = self.cipher.encrypt(xml_data)

        resp = self.network.post_raw(
            self.ticket_url, encrypted, self.client_id, self.algo_id
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Get ticket failed: {resp.status_code}")

        decrypted = self.cipher.decrypt(resp.content)
        ticket_resp = parse_ticket_response(decrypted)
        logger.debug(f"Ticket: {ticket_resp.ticket[:20]}...")
        return ticket_resp.ticket

    def _login(self) -> LoginResponse:
        """Step 7: 登录认证"""
        req = LoginRequest(
            client_id=self.client_id,
            ticket=self.ticket,
            local_time=format_local_time(),
            userid=self.config.username,
            passwd=self.config.password,
        )
        xml_data = build_login_request(req)
        encrypted = self.cipher.encrypt(xml_data)

        resp = self.network.post_raw(
            self.auth_url, encrypted, self.client_id, self.algo_id
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Login failed: {resp.status_code}")

        decrypted = self.cipher.decrypt(resp.content)
        return parse_login_response(decrypted)

    # ================================================================
    # 心跳维持
    # ================================================================

    def _send_heartbeat(self):
        """发送心跳包 (线程安全: 与 login/logout 互斥)"""
        # 快速非锁检查
        if not self._running or self._stop_event.is_set():
            return

        with self._lock:
            # 二次检查 (获取锁之后状态可能变了)
            if not self._running or self._stop_event.is_set():
                return
            if not self.cipher or not self.network or not self.keep_url:
                return
            if self.state != ClientState.CONNECTED:
                return

            try:
                state_req = StateRequest(
                    client_id=self.client_id,
                    local_time=format_local_time(),
                    host_name=self.hostname,
                    ipv4=self.user_ip,
                    ticket=self.ticket,
                    mac=self.mac_address,
                    ostag=self.hostname,
                )
                xml_data = build_state_request(state_req)
                encrypted = self.cipher.encrypt(xml_data)

                resp = self.network.post_raw(
                    self.keep_url, encrypted, self.client_id, self.algo_id
                )
                decrypted = self.cipher.decrypt(resp.content)
                state_resp = parse_state_response(decrypted)

                try:
                    self._heartbeat_interval = int(state_resp.interval)
                except (ValueError, TypeError):
                    pass

                self.stats.last_heartbeat = time.time()
                self.stats.heartbeat_count += 1
                logger.debug(f"Heartbeat OK, next in {self._heartbeat_interval}s")

            except Exception as e:
                logger.warning(f"Heartbeat failed: {e}")
                # 心跳失败可能意味着断网，触发重连检测
                self._set_state(ClientState.DISCONNECTED)

        # 安排下一次心跳 (在锁外面，避免死锁)
        self._schedule_heartbeat()

    def _schedule_heartbeat(self):
        """安排下一次心跳 (线程安全)"""
        with self._lock:
            self._cancel_heartbeat()
            if self._running and not self._stop_event.is_set():
                self._heartbeat_timer = threading.Timer(
                    self._heartbeat_interval, self._send_heartbeat
                )
                self._heartbeat_timer.daemon = True
                self._heartbeat_timer.start()

    def _cancel_heartbeat(self):
        """取消心跳定时器 (必须在锁内调用)"""
        if self._heartbeat_timer:
            self._heartbeat_timer.cancel()
            self._heartbeat_timer = None

    # ================================================================
    # 登出
    # ================================================================

    def _logout(self):
        """发送登出请求"""
        if not self.cipher or not self.term_url:
            return

        try:
            state_req = StateRequest(
                client_id=self.client_id,
                local_time=format_local_time(),
                host_name=self.hostname,
                ipv4=self.user_ip,
                ticket=self.ticket,
                mac=self.mac_address,
                ostag=self.hostname,
            )
            xml_data = build_state_request(state_req)
            encrypted = self.cipher.encrypt(xml_data)

            # 登出时使用短超时
            self.network.session.post(
                self.term_url,
                data=encrypted,
                timeout=3,
            )
            logger.info(f"[user:{self.config.username}] Logged out")
        except Exception as e:
            logger.debug(f"Logout request failed (may be fine): {e}")

    # ================================================================
    # 辅助方法
    # ================================================================

    def _init_network(self):
        """初始化网络客户端"""
        if self.network:
            self.network.close()
        self.network = NetworkClient(
            bind_interface=self.config.bind_interface or None,
            dns_address=self.config.dns_address or None,
        )

    def _init_identity(self):
        """初始化设备标识"""
        self.client_id = str(uuid.uuid4())
        self.hostname = _random_string(10)
        self.mac_address = _random_mac()

    def _check_online(self) -> bool:
        """检查网络是否在线"""
        if not self.network:
            return False
        return self.network.check_online()

    def _set_state(self, state: ClientState):
        """设置状态并触发回调"""
        old_state = self.state
        self.state = state
        if old_state != state:
            logger.info(f"[user:{self.config.username}] "
                        f"State: {old_state.value} -> {state.value}")
            if self.on_state_change:
                try:
                    self.on_state_change(state)
                except Exception:
                    pass

    def _log(self, message: str):
        """记录日志并触发回调"""
        logger.info(f"[user:{self.config.username}] {message}")
        if self.on_log:
            try:
                self.on_log(message, 'info')
            except Exception:
                pass

    def _sleep(self, seconds: int):
        """可中断的 sleep"""
        if seconds <= 0:
            return
        self._stop_event.wait(seconds)

    def _cleanup(self):
        """清理资源"""
        self._cancel_heartbeat()
        if self.network:
            self.network.close()
            self.network = None
        self._set_state(ClientState.DISCONNECTED)
        logger.info(f"[user:{self.config.username}] Client stopped")


# ============================================================
# 多账号管理器
# ============================================================
class ClientManager:
    """管理多个认证客户端实例"""

    def __init__(self):
        self.clients: list[ESurfingClient] = []
        self._threads: list[threading.Thread] = []

    def add(self, config: ClientConfig) -> ESurfingClient:
        """添加一个客户端"""
        client = ESurfingClient(config)
        self.clients.append(client)
        return client

    def start_all(self):
        """启动所有客户端 (各在独立线程)"""
        for client in self.clients:
            t = threading.Thread(
                target=client.start,
                name=f"esurfing-{client.config.username}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def stop_all(self):
        """停止所有客户端"""
        for client in self.clients:
            client.stop()
        for t in self._threads:
            t.join(timeout=5)

    def get_status_all(self) -> list[dict]:
        """获取所有客户端状态"""
        return [c.get_status() for c in self.clients]


# ============================================================
# 工具函数
# ============================================================
CHARSET = string.ascii_letters + string.digits


def _random_string(length: int) -> str:
    """生成随机字符串"""
    return ''.join(random.choice(CHARSET) for _ in range(length))


def _random_mac() -> str:
    """生成随机 MAC 地址 (本地管理单播)"""
    mac = [random.randint(0, 255) for _ in range(6)]
    # 设置本地管理位 (bit 1) 和单播位 (bit 0 = 0)
    mac[0] = (mac[0] & 0xFE) | 0x02
    return ':'.join(f'{b:02x}' for b in mac)
