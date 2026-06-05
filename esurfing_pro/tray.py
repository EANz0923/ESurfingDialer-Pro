"""
System tray icon for ESurfingDialer-Pro.

Shows a colored dot in the notification area:
  green  = connected
  red    = disconnected
  yellow = authenticating

Right-click menu: status display + exit.
"""

import logging
import threading
import time
from PIL import Image, ImageDraw
import pystray

logger = logging.getLogger(__name__)

# 32x32 colored circle icons
def _make_icon(color: str) -> Image.Image:
    """Generate a 32x32 colored circle icon."""
    img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Outer ring (dark)
    draw.ellipse([1, 1, 30, 30], fill=None, outline=(60, 60, 60, 255), width=2)
    # Inner filled circle
    colors = {
        "green":  (76, 175, 80, 255),
        "red":    (244, 67, 54, 255),
        "yellow": (255, 193, 7, 255),
    }
    fill = colors.get(color, colors["red"])
    draw.ellipse([4, 4, 27, 27], fill=fill)
    return img


class TrayIcon:
    """Manages the system tray icon and daemon lifecycle."""

    def __init__(self, daemon, client):
        self.daemon = daemon
        self.client = client
        self._icons = {
            "green":  _make_icon("green"),
            "red":    _make_icon("red"),
            "yellow": _make_icon("yellow"),
        }
        self._current = "red"
        self._tray: pystray.Icon | None = None
        self._running = False

    def _build_menu(self) -> pystray.Menu:
        """Build the right-click menu with current status."""
        status = self.client.get_status()
        state = status['state']
        online_m = status['online_seconds'] // 60
        hb = status['heartbeat_count']

        if state == 'connected' or (state == 'error' and self.client.is_online()):
            status_line = f"Online: {online_m}min  |  HB: {hb}"
        elif state == 'authing':
            status_line = "Authenticating..."
        elif state == 'error':
            status_line = "Login failed, retrying..."
        else:
            status_line = f"State: {state}"

        return pystray.Menu(
            pystray.MenuItem("ESurfingDialer-Pro", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(status_line, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._on_exit),
        )

    def _update_tray(self):
        """Update tray icon color and menu based on current state."""
        if not self._tray:
            return

        state = self.client.state.value
        online = self.client.is_online()

        if state == 'connected' or online:
            new_color = "green"
        elif state == 'authing':
            new_color = "yellow"
        else:
            new_color = "red"

        if new_color != self._current:
            self._tray.icon = self._icons[new_color]
            self._current = new_color

        self._tray.menu = self._build_menu()

    def _refresh_loop(self):
        """Periodically update the tray icon (runs in a timer thread)."""
        while self._running:
            try:
                self._update_tray()
            except Exception:
                pass
            time.sleep(3)

    def _on_exit(self, icon, item):
        """Exit: stop daemon and tray."""
        self._running = False
        if self.daemon:
            self.daemon.stop()
        if self.client:
            self.client.stop()
        if self._tray:
            self._tray.stop()

    def run(self):
        """Start the tray icon (blocking — runs the pystray event loop)."""
        self._running = True

        # Start daemon in background thread
        daemon_thread = threading.Thread(
            target=self.daemon.start, daemon=True, name="esurfing-daemon"
        )
        daemon_thread.start()

        # Start refresh timer
        refresh_thread = threading.Thread(
            target=self._refresh_loop, daemon=True, name="esurfing-tray-refresh"
        )
        refresh_thread.start()

        # Start tray icon
        self._tray = pystray.Icon(
            "ESurfingDialer-Pro",
            self._icons["red"],
            "ESurfingDialer-Pro",
            menu=self._build_menu(),
        )
        self._tray.run()
