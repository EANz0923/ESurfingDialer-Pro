"""
守护进程模块 — 智能重连与自动重登

支持的重登模式:
  - net: 检测到断网时自动重登
  - itv: 每隔指定时间自动重登
  - dls: 下载速率连续低于阈值时重登
  - uls: 上传速率连续低于阈值时重登
  - dlt: 累计下载流量达到阈值时重登
  - ult: 累计上传流量达到阈值时重登
"""

import logging
import threading
import time
from enum import Enum
from typing import Optional

from .client import ESurfingClient, ClientState
from .monitor import TrafficMonitor

logger = logging.getLogger(__name__)


class ReloginMode(Enum):
    """重登触发模式"""
    NET = "net"     # 断网检测
    ITV = "itv"     # 定时重登
    DLS = "dls"     # 下载速率低于阈值
    ULS = "uls"     # 上传速率低于阈值
    DLT = "dlt"     # 累计下载流量达阈值
    ULT = "ult"     # 累计上传流量达阈值


class Daemon:
    """守护进程 - 管理客户端的自动重连和重登逻辑

    Usage:
        daemon = Daemon(client)
        daemon.set_relogin(ReloginMode.NET)
        daemon.start()
    """

    def __init__(self, client: ESurfingClient):
        self.client = client
        self.monitor = TrafficMonitor()
        self._running = False
        self._stop_event = threading.Event()

        # 重登配置
        self.mode: Optional[ReloginMode] = None
        self.interval: int = 300           # 定时重登间隔 (秒)
        self.speed_threshold: float = 10.0  # 速率阈值 (KB/s)
        self.traffic_threshold: float = 500  # 流量阈值 (MB)
        self.speed_check_seconds: int = 10  # 速率检测持续秒数

    def set_relogin(self, mode: ReloginMode, **kwargs):
        """配置重登模式"""
        self.mode = mode
        if 'interval' in kwargs:
            self.interval = kwargs['interval']
        if 'speed_threshold' in kwargs:
            self.speed_threshold = kwargs['speed_threshold']
        if 'traffic_threshold' in kwargs:
            self.traffic_threshold = kwargs['traffic_threshold']
        if 'speed_check_seconds' in kwargs:
            self.speed_check_seconds = kwargs['speed_check_seconds']

    def start(self):
        """启动守护进程"""
        self._running = True
        self._stop_event.clear()
        self.monitor.start()

        # 轮询间隔使用配置值，至少 5 秒，避免频繁 HTTP 请求
        poll_interval = max(self.client.config.check_interval, 5)

        logger.info(f"Daemon started, mode={self.mode.value if self.mode else 'none'}, "
                    f"poll_interval={poll_interval}s")

        while self._running and not self._stop_event.is_set():
            try:
                if self.mode:
                    should_relogin = self._check_trigger()
                    if should_relogin:
                        self._do_relogin()

                self._stop_event.wait(poll_interval)

            except Exception as e:
                logger.error(f"Daemon error: {e}")
                self._stop_event.wait(5)

    def stop(self):
        """停止守护进程"""
        self._running = False
        self._stop_event.set()
        self.monitor.stop()

    def _check_trigger(self) -> bool:
        """检查是否触发重登条件"""
        if self.mode == ReloginMode.NET:
            return self._check_net()
        elif self.mode == ReloginMode.ITV:
            return self._check_itv()
        elif self.mode == ReloginMode.DLS:
            return self._check_speed(download=True)
        elif self.mode == ReloginMode.ULS:
            return self._check_speed(download=False)
        elif self.mode == ReloginMode.DLT:
            return self._check_traffic(download=True)
        elif self.mode == ReloginMode.ULT:
            return self._check_traffic(download=False)
        return False

    def _check_net(self) -> bool:
        """检查是否断网 (带冷却保护)"""
        # 防止刚登录/重登完成后立即再次触发
        if time.time() < self.client._relogin_cooldown:
            return False
        return not self.client.is_online()

    def _check_itv(self) -> bool:
        """检查是否到达定时重登时间"""
        now = time.time()
        if now - self._last_relogin >= self.interval:
            return True
        return False

    def _check_speed(self, download: bool) -> bool:
        """检查速率是否持续低于阈值"""
        direction = 'download' if download else 'upload'
        low_count = 0

        for _ in range(self.speed_check_seconds):
            speed = self.monitor.get_speed(direction)
            if speed < self.speed_threshold:
                low_count += 1
            time.sleep(1)

        return low_count >= self.speed_check_seconds

    def _check_traffic(self, download: bool) -> bool:
        """检查累计流量是否达到阈值"""
        direction = 'download' if download else 'upload'
        total = self.monitor.get_total_traffic(direction)
        return total >= self.traffic_threshold

    def _do_relogin(self):
        """执行重登 (线程安全) — ZUC 失败时立即重试，服务器可能换算法"""
        # 防止短时间内反复重登（非 ZUC 失败）
        now = time.time()
        if now < self._last_relogin + 10:
            # ZUC 失败可以跳过冷却：服务器每次可能分配不同算法
            if not self._last_was_zuc_fail:
                logger.debug("Relogin skipped: still in cooldown")
                return False
            self._last_was_zuc_fail = False

        logger.info(f"Trigger [{self.mode.value}]: re-logging in...")
        self.client.logout()
        time.sleep(2)
        success = self.client.login()
        if success:
            self._last_relogin = time.time()
            self._last_was_zuc_fail = False
            self.monitor.reset_counters()
        else:
            self._last_relogin = time.time()
            # ZUC 失败 (no element found) → 缩短冷却到 5s，给服务器换算法
            if 'no element found' in str(getattr(self.client, '_last_error', '')):
                logger.warning("Relogin failed (ZUC mismatch), retrying soon...")
                self._last_relogin = time.time() - 5  # 5s 后重试
                self._last_was_zuc_fail = True
            else:
                logger.warning("Relogin failed, cooling down for 30s")
                self._last_relogin = time.time() + 20  # 等价 30s 冷却
                self._last_was_zuc_fail = False
        return success

    _last_was_zuc_fail: bool = False

    _last_relogin: float = 0.0
