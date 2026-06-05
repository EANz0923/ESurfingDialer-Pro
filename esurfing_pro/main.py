"""
CLI entry point for ESurfingDialer-Pro

Usage:
    python -m esurfing_pro.main setup       (首次使用向导)
    python -m esurfing_pro.main daemon      (守护模式)
    python -m esurfing_pro.main status      (查看配置)
"""

import argparse
import logging
import os
import signal
import sys
import time

from .client import ESurfingClient, ClientConfig, ClientManager, ClientState
from .config import load_config, create_example_config
from .daemon import Daemon, ReloginMode

# 设置日志格式
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def setup_logging(verbose: bool = False):
    """Setup logging with UTF-8 encoding for Windows compatibility"""
    level = logging.DEBUG if verbose else logging.INFO
    import io
    # Wrap stdout/stderr so print() doesn't crash on Chinese in Windows console
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',
                                       errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8',
                                       errors='replace')
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


def cmd_login(args):
    """单次登录命令"""
    configs = load_config(args.config)
    if not configs:
        print("ERROR: No valid configs found. Run 'example' first.")
        sys.exit(1)

    manager = ClientManager()
    for c in configs:
        client = manager.add(c)
        client.on_log = lambda msg, lvl: print(f"  {msg}")

    print(f"Logging in with {len(configs)} account(s)...")
    manager.start_all()

    # 等待连接
    time.sleep(15)

    for c in manager.clients:
        status = c.get_status()
        print(f"\n--- {status['username']} ---")
        print(f"  State: {status['state']}")
        print(f"  Online: {status['online_seconds']}s")
        print(f"  Reconnects: {status['reconnect_count']}")

    # 保持运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        manager.stop_all()


def _wait_for_network_ready(timeout: int = 120) -> bool:
    """等待网络就绪（开机自启时网卡可能尚未初始化）

    检测方法：尝试连接多个 portal 探测 URL，只要能收到 HTTP 响应即为就绪。
    开机时 DHCP 可能还没拿到 IP，portal 可能还没启动——此函数会轮询等待。

    Args:
        timeout: 最长等待秒数

    Returns:
        网络是否就绪
    """
    import requests

    # 测试 URL（只需要能建立 TCP 连接+收到 HTTP 响应，不用管状态码）
    test_urls = [
        "http://connect.rom.miui.com/generate_204",
        "http://www.gstatic.com/generate_204",
        "http://captive.apple.com/hotspot-detect.html",
        "http://cp.cloudflare.com/generate_204",
    ]

    start_time = time.time()
    attempt = 0

    print("  Waiting for network to be ready...")

    while time.time() - start_time < timeout:
        attempt += 1

        for url in test_urls:
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False)
                # 只要能收到 HTTP 响应（不管 204/302/200），就说明网络通了
                elapsed = time.time() - start_time
                print(f"  Network ready after {elapsed:.1f}s "
                      f"(HTTP {resp.status_code}, attempt {attempt})")
                return True
            except requests.RequestException:
                continue

        # 指数退避，但不超过 10 秒
        wait = min(2 ** (attempt - 1), 10)
        print(f"  Network not ready, retrying in {wait}s "
              f"(attempt {attempt}, "
              f"elapsed {time.time() - start_time:.0f}s)")
        time.sleep(wait)

    print(f"  Network still not ready after {timeout}s, "
          f"will attempt login anyway")
    return False


def _check_really_online() -> bool:
    """用独立 session 检测是否真的在线（排除假在线/portal 白名单绕过）

    认证失败后，NetworkClient session 里残留的 cookie 可能导致
    generate_204 返回 204 而非 302，造成 is_online() 假阳性。
    此函数用全新的 requests session 做检测。

    检测策略:
      1. 标准 portal URL → 302 = captive portal → 不在线
      2. Canary URL + 内容验证 → 排除白名单绕过
    """
    import requests

    test_urls = [
        "http://connect.rom.miui.com/generate_204",
        "http://www.gstatic.com/generate_204",
    ]

    # Phase 1: 标准 portal 探测
    with requests.Session() as s:
        for url in test_urls:
            try:
                resp = s.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 302:
                    return False  # Portal 劫持
                # 204 不直接判定在线，继续验证
            except requests.RequestException:
                continue

    # Phase 2: Canary URL — 非 portal 探测域名，校园网不会白名单
    canary_checks = [
        ("http://httpbin.org/ip", '"origin"'),
        ("http://neverssl.com/", "NeverSSL"),
        ("http://example.com/", "Example Domain"),
    ]

    with requests.Session() as s:
        for url, expected in canary_checks:
            try:
                resp = s.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 302:
                    return False  # Portal 劫持 → 假在线
                elif resp.status_code == 200:
                    if expected in resp.text:
                        return True  # 内容匹配 → 真正在线
            except requests.RequestException:
                continue

    return False


def cmd_daemon(args):
    """守护模式"""
    configs = load_config(args.config)
    if not configs:
        print("ERROR: No valid configs found.")
        sys.exit(1)

    manager = ClientManager()
    daemons = []

    for c in configs:
        client = manager.add(c)
        d = Daemon(client)

        # 配置重登模式
        if args.mode:
            mode = ReloginMode(args.mode)
            kwargs = {}
            if args.interval:
                kwargs['interval'] = args.interval
            if args.threshold:
                kwargs['speed_threshold'] = args.threshold
                kwargs['traffic_threshold'] = args.threshold
            d.set_relogin(mode, **kwargs)

        daemons.append(d)

        # 在线状态变化回调
        client.on_state_change = lambda s, c=client: \
            print(f"[{c.config.username}] State: {s.value}")

    print(f"Starting daemon with {len(daemons)} account(s)...")

    # === 等待网络就绪（开机自启时网卡/portal 可能未初始化）===
    _wait_for_network_ready(timeout=120)

    # === Initial login with retries ===
    # 部分认证后 session 残留 cookie 会导致 is_online() 假阳性，
    # 所以用独立 requests 做真实性检测，不受 NetworkClient session 影响。
    MAX_RETRIES = 3
    RETRY_DELAYS = [2, 5, 10]  # 递增等待

    for client in manager.clients:
        print(f"  [{client.config.username}] Force initial login...")

        for attempt in range(MAX_RETRIES):
            success = client.login()
            if success:
                print(f"  [{client.config.username}] Login OK, heartbeat started")
                break

            # 用独立的 requests 检测是否真的在线（避免 session cookie 干扰）
            really_online = _check_really_online()
            if really_online:
                print(f"  [{client.config.username}] Already online (old session alive)")
                print(f"  [{client.config.username}] Daemon monitoring - will re-auth when expired")
                # 手动把状态设为 connected，让 daemon 正常工作
                client.state = ClientState.CONNECTED
                break

            if attempt < MAX_RETRIES - 1:
                delay = RETRY_DELAYS[attempt]
                print(f"  [{client.config.username}] Login failed, "
                      f"retry in {delay}s (attempt {attempt + 2}/{MAX_RETRIES})...")
                time.sleep(delay)
            else:
                print(f"  [{client.config.username}] Login FAILED after "
                      f"{MAX_RETRIES} attempts, daemon will keep retrying")

    # === Start daemon threads (or use tray if requested) ===
    use_tray = getattr(args, 'tray', False)

    if use_tray and len(daemons) == 1:
        # System tray mode: icon in notification area, no console window
        try:
            from .tray import TrayIcon
            print("Starting in system tray mode (check notification area)...")
            tray = TrayIcon(daemons[0], manager.clients[0])
            tray.run()
        except ImportError as e:
            print(f"Tray dependencies missing: {e}")
            print("Install with: pip install pystray Pillow")
            print("Falling back to console mode...")
            use_tray = False
        except Exception as e:
            print(f"Tray error: {e}, falling back to console mode...")
            use_tray = False

    if not use_tray:
        import threading
        for d in daemons:
            t = threading.Thread(target=d.start, daemon=True)
            t.start()

        # 等待信号
        def on_signal(sig, frame):
            print("\nShutting down...")
            for d in daemons:
                d.stop()
            manager.stop_all()
            sys.exit(0)

        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)

        # 保持运行
        try:
            while True:
                time.sleep(10)
                # 打印状态
                for c in manager.clients:
                    s = c.get_status()
                    online_m = s['online_seconds'] // 60
                    print(f"[{s['username']}] {s['state']} | "
                          f"online: {online_m}m | "
                          f"hb: {s['heartbeat_count']}")
        except KeyboardInterrupt:
            print("\nStopping...")
            for d in daemons:
                d.stop()
            manager.stop_all()


def cmd_status(args):
    """查看状态"""
    configs = load_config(args.config)
    if not configs:
        print("No config found.")
        return

    for c in configs:
        print(f"\nAccount: {c.username}")
        print(f"  Bind: {c.bind_interface or 'default'}")
        print(f"  Check interval: {c.check_interval}s")
        print(f"  Retry interval: {c.retry_interval}s")


def cmd_example(args):
    """Generate example config"""
    path = getattr(args, 'config', None) or "config.json"
    create_example_config(path)


def cmd_setup(args):
    """交互式首次配置向导 — 输入账号密码即可完成全部设置"""
    from .config import save_config, get_default_config_path

    print()
    print("=" * 50)
    print("  ESurfingDialer-Pro  首次配置向导")
    print("=" * 50)
    print()
    print("  此向导只需运行一次，之后无需再配置。")
    print()

    # --- 账号 ---
    while True:
        username = input("  请输入校园网账号 (学号): ").strip()
        if username:
            break
        print("  [!] 账号不能为空，请重新输入")

    # --- 密码 ---
    while True:
        password = input("  请输入校园网密码: ").strip()
        if password:
            break
        print("  [!] 密码不能为空，请重新输入")

    # --- 确认 ---
    print()
    print(f"  账号: {username}")
    print(f"  密码: {'*' * len(password)}")
    print()

    # --- 检测间隔 (可选) ---
    try:
        interval = input("  断网检测间隔秒数 (默认10s，直接回车跳过): ").strip()
        check_interval = int(interval) if interval else 10
    except ValueError:
        check_interval = 10

    # --- 保存配置 ---
    config_path = get_default_config_path()
    config = ClientConfig(
        username=username,
        password=password,
        check_interval=check_interval,
        retry_interval=10,
    )
    save_config([config], config_path)
    print(f"  [OK] 配置已保存到: {config_path}")
    print()

    # --- 开机自启 ---
    choice = input("  是否安装开机自启? (每次开机自动后台联网) [Y/n]: ").strip().lower()
    if choice != 'n':
        _install_autostart()
        print("  [OK] 开机自启已安装")
    else:
        print("  [--] 跳过开机自启 (以后可双击 install_autostart.bat 安装)")

    # --- 立即启动 ---
    print()
    choice = input("  是否立即启动守护进程? [Y/n]: ").strip().lower()
    if choice != 'n':
        print()
        print("  正在启动守护进程...")
        print("  (按 Ctrl+C 可停止)")
        print()
        # 构造一个 fake args 传给 cmd_daemon
        class FakeArgs:
            config = config_path
            mode = 'net'
            tray = True
            interval = None
            threshold = None
        cmd_daemon(FakeArgs())
    else:
        print()
        print("  配置完成! 以后双击 start.bat 即可启动。")
        print()


def _install_autostart():
    """在 Windows 启动文件夹创建自启脚本（bat + pythonw，无持久窗口）"""
    startup_dir = os.path.join(
        os.environ.get('APPDATA', ''),
        r'Microsoft\Windows\Start Menu\Programs\Startup'
    )
    os.makedirs(startup_dir, exist_ok=True)

    # pythonw.exe = 无控制台窗口的 Python
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python_dir = os.path.dirname(sys.executable)
    pythonw_exe = os.path.join(python_dir, 'pythonw.exe')

    bat_path = os.path.join(startup_dir, 'ESurfingDialer-Pro.bat')
    bat_content = (
        f'@echo off\r\n'
        f'cd /d "{project_dir}"\r\n'
        f'start "" /b "{pythonw_exe}"'
        f' -m esurfing_pro.main daemon --mode net --tray\r\n'
    )

    # 删掉旧的 vbs 版本（如果有）
    old_vbs = os.path.join(startup_dir, 'ESurfingDialer-Pro.vbs')
    if os.path.exists(old_vbs):
        os.remove(old_vbs)

    with open(bat_path, 'w', encoding='ascii') as f:
        f.write(bat_content)


def main():
    parser = argparse.ArgumentParser(
        description='ESurfingDialer-Pro v2.0 - Tianyi Campus Network Auth Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m esurfing_pro.main setup      (首次使用，输入账号密码即可)
  python -m esurfing_pro.main daemon     (守护模式，断网自动重连)
  python -m esurfing_pro.main status     (查看已保存的配置)
        """,
    )

    parser.add_argument('-c', '--config', default=None,
                       help='Config file path (default: ~/.esurfing_pro/config.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # setup
    subparsers.add_parser('setup', help='Interactive first-time setup wizard')

    # login
    login_parser = subparsers.add_parser('login', help='Login once and stay connected')
    login_parser.add_argument('-c', '--config', default=None, help='Config file path')

    # daemon
    daemon_parser = subparsers.add_parser('daemon', help='Run as daemon with auto-relogin')
    daemon_parser.add_argument('-c', '--config', default=None, help='Config file path')
    daemon_parser.add_argument('--mode', choices=['net', 'itv', 'dls', 'uls', 'dlt', 'ult'],
                              default='net', help='Relogin trigger mode (default: net)')
    daemon_parser.add_argument('--tray', action='store_true',
                              help='Run in system tray (notification area icon)')
    daemon_parser.add_argument('--interval', type=int, default=None,
                              help='Interval in seconds (for itv mode)')
    daemon_parser.add_argument('--threshold', type=float, default=None,
                              help='Speed (KB/s) or traffic (MB) threshold')

    # status
    status_parser = subparsers.add_parser('status', help='Show saved config')
    status_parser.add_argument('-c', '--config', default=None, help='Config file path')

    # example
    example_parser = subparsers.add_parser('example', help='Create example config file')
    example_parser.add_argument('-c', '--config', default=None, help='Output config file path')

    args = parser.parse_args()

    if not args.command:
        try:
            parser.print_help()
        except UnicodeEncodeError:
            print("ESurfingDialer-Pro v2.0 - Tianyi Campus Network Client")
            print("Commands: setup, daemon, status")
            print("Run with --help for details (use 'chcp 65001' on Windows)")
        return

    setup_logging(args.verbose)

    commands = {
        'setup': cmd_setup,
        'login': cmd_login,
        'daemon': cmd_daemon,
        'status': cmd_status,
        'example': cmd_example,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)


if __name__ == '__main__':
    main()
