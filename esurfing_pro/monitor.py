"""
网络监控模块 — 速率和流量检测

提供:
  - 实时上传/下载速率 (KB/s)
  - 累计流量统计
  - 网卡级别的流量监控
"""

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """网络流量监控器

    使用 psutil 监控指定网卡的流量和速率。
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._running = False
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # 统计
        self._bytes_sent = 0
        self._bytes_recv = 0
        self._total_sent = 0
        self._total_recv = 0
        self._download_speed = 0.0  # KB/s
        self._upload_speed = 0.0   # KB/s

        # 上次采样
        self._last_sent = 0
        self._last_recv = 0
        self._last_time = 0.0

    def start(self):
        """启动监控"""
        self._running = True
        self._stop_event.clear()
        self._last_time = time.time()
        self._sample()

        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        logger.debug("Traffic monitor started")

    def stop(self):
        """停止监控"""
        self._running = False
        self._stop_event.set()

    def get_speed(self, direction: str = 'download') -> float:
        """获取当前速率 (KB/s)"""
        with self._lock:
            if direction == 'download':
                return self._download_speed
            return self._upload_speed

    def get_total_traffic(self, direction: str = 'download') -> float:
        """获取累计流量 (MB)"""
        with self._lock:
            if direction == 'download':
                return self._total_recv / (1024 * 1024)
            return self._total_sent / (1024 * 1024)

    def reset_counters(self):
        """重置累计计数"""
        with self._lock:
            self._total_sent = 0
            self._total_recv = 0
            self._bytes_sent = 0
            self._bytes_recv = 0

    def get_stats(self) -> dict:
        """获取完整统计"""
        with self._lock:
            return {
                'download_speed_kbs': round(self._download_speed, 1),
                'upload_speed_kbs': round(self._upload_speed, 1),
                'total_download_mb': round(self._total_recv / (1024 * 1024), 2),
                'total_upload_mb': round(self._total_sent / (1024 * 1024), 2),
            }

    def _run(self):
        """后台监控循环"""
        while self._running and not self._stop_event.is_set():
            try:
                self._sample()
            except Exception as e:
                logger.debug(f"Traffic sample error: {e}")
            self._stop_event.wait(1)

    def _sample(self):
        """采样网络流量"""
        try:
            import psutil

            now = time.time()
            counters = psutil.net_io_counters(pernic=True)

            total_sent = 0
            total_recv = 0

            if self.interface and self.interface in counters:
                nic = counters[self.interface]
                total_sent = nic.bytes_sent
                total_recv = nic.bytes_recv
            else:
                # 汇总所有网卡
                for nic in counters.values():
                    total_sent += nic.bytes_sent
                    total_recv += nic.bytes_recv

            elapsed = now - self._last_time if self._last_time else 1
            if elapsed > 0:
                sent_diff = total_sent - self._last_sent
                recv_diff = total_recv - self._last_recv

                with self._lock:
                    self._download_speed = (recv_diff / elapsed) / 1024
                    self._upload_speed = (sent_diff / elapsed) / 1024
                    self._total_sent += sent_diff
                    self._total_recv += recv_diff

            self._last_sent = total_sent
            self._last_recv = total_recv
            self._last_time = now

        except ImportError:
            # psutil 不可用时的回退
            with self._lock:
                self._download_speed = 0.0
                self._upload_speed = 0.0
