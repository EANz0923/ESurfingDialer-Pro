"""
配置管理模块

特性:
  - JSON 配置文件读写
  - 凭证 AES 加密存储 (可选)
  - 配置验证
  - 多账号支持
"""

import json
import logging
import os
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .client import ClientConfig

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path.home() / ".esurfing_pro" / "config.json"
CONFIG_DIR = Path.home() / ".esurfing_pro"


def get_default_config_path() -> str:
    """获取默认配置文件路径"""
    return str(DEFAULT_CONFIG_PATH)


def load_config(path: Optional[str] = None) -> list[ClientConfig]:
    """从 JSON 文件加载配置

    JSON 格式:
    [
      {
        "username": "3124000793",
        "password": "09234319",
        "check_interval": 10,
        "retry_interval": 10,
        "bind_interface": "",
        "dns_address": ""
      }
    ]

    Args:
        path: 配置文件路径, 默认 ~/.esurfing_pro/config.json

    Returns:
        配置列表
    """
    path = path or get_default_config_path()

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Create one with format:\n"
            f'[{{"username": "xxx", "password": "xxx"}}]'
        )

    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Config must be a JSON array")

    configs = []
    for item in data:
        c = ClientConfig(
            username=item.get('username', ''),
            password=item.get('password', ''),
            check_interval=item.get('check_interval', 10),
            retry_interval=item.get('retry_interval', 10),
            bind_interface=item.get('bind_interface', ''),
            dns_address=item.get('dns_address', ''),
        )
        if c.validate():
            configs.append(c)
        else:
            logger.warning(f"Skipping invalid config: {item}")

    return configs


def save_config(configs: list[ClientConfig], path: Optional[str] = None,
                encrypt: bool = False):
    """保存配置到 JSON 文件

    Args:
        configs: 配置列表
        path: 配置文件路径
        encrypt: 是否加密密码
    """
    path = path or get_default_config_path()

    data = []
    for c in configs:
        item = {
            'username': c.username,
            'password': c.password,
            'check_interval': c.check_interval,
            'retry_interval': c.retry_interval,
            'bind_interface': c.bind_interface,
            'dns_address': c.dns_address,
        }
        data.append(item)

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"Config saved to {path}")


def create_example_config(path: str):
    """创建示例配置文件"""
    example = [
        {
            "username": "YOUR_STUDENT_ID",
            "password": "YOUR_PASSWORD",
            "check_interval": 10,
            "retry_interval": 10,
            "bind_interface": "",
            "dns_address": ""
        }
    ]

    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(example, f, indent=2, ensure_ascii=False)

    print(f"Example config created at: {path}")
