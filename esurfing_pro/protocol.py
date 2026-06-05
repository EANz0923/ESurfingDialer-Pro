"""
协议模块 — 天翼校园网 ZSM 协议 XML 消息构造与解析

处理:
- TicketRequest / TicketResponse
- LoginRequest / LoginResponse
- State (心跳) / StateResponse
- EConfig (portal 配置)
- AlgoID 协商
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional
from xml.etree import ElementTree as ET

USER_AGENT = "CCTP/android64_vpn/2093"


# ============================================================
# 数据模型
# ============================================================
@dataclass
class SchoolInfo:
    """学校/区域信息 (从 HTTP 302 响应头提取)"""
    domain: str = ""
    area: str = ""
    school_id: str = ""
    index_url: str = ""


@dataclass
class EConfig:
    """Portal 配置 (从 HTML 注释提取)"""
    ticket_url: str = ""
    auth_url: str = ""


@dataclass
class TicketRequest:
    """获取票据请求"""
    user_agent: str = USER_AGENT
    client_id: str = "00000000-0000-0000-0000-000000000000"
    local_time: str = ""
    host_name: str = ""
    ipv4: str = ""
    ipv6: str = ""
    mac: str = ""
    ostag: str = ""
    gwip: str = ""


@dataclass
class TicketResponse:
    """票据响应"""
    ticket: str = ""
    expire: str = ""


@dataclass
class LoginRequest:
    """登录请求"""
    user_agent: str = USER_AGENT
    client_id: str = ""
    ticket: str = ""
    local_time: str = ""
    userid: str = ""
    passwd: str = ""


@dataclass
class LoginResponse:
    """登录响应"""
    userid: str = ""
    keep_retry: str = "60"
    keep_url: str = ""
    term_url: str = ""
    against_interval: str = "0"
    domain_config: str = ""


@dataclass
class StateRequest:
    """心跳/状态请求"""
    user_agent: str = USER_AGENT
    client_id: str = ""
    local_time: str = ""
    host_name: str = ""
    ipv4: str = ""
    ticket: str = ""
    ipv6: str = ""
    mac: str = ""
    ostag: str = ""


@dataclass
class StateResponse:
    """心跳响应"""
    interval: str = "60"
    level: str = "0"


# ============================================================
# XML 构造
# ============================================================
XML_DECLARATION = b'<?xml version="1.0" encoding="UTF-8"?>'


def _to_xml(obj, root_tag: str) -> bytes:
    """将 dataclass 序列化为 XML 字节串"""
    root = ET.Element(root_tag)
    for key, value in obj.__dict__.items():
        if value is not None and value != "":
            elem = ET.SubElement(root, key.replace('_', '-'))
            elem.text = str(value)
    xml_bytes = ET.tostring(root, encoding='utf-8')
    return XML_DECLARATION + xml_bytes


def build_ticket_request(req: TicketRequest) -> bytes:
    """构造获取票据的 XML"""
    return _to_xml(req, 'request')


def build_login_request(req: LoginRequest) -> bytes:
    """构造登录的 XML"""
    return _to_xml(req, 'request')


def build_state_request(req: StateRequest) -> bytes:
    """构造心跳状态的 XML"""
    return _to_xml(req, 'request')


# ============================================================
# XML 解析
# ============================================================
def parse_ticket_response(xml_data: bytes) -> TicketResponse:
    """解析票据响应"""
    root = ET.fromstring(xml_data)
    return TicketResponse(
        ticket=_get_text(root, 'ticket'),
        expire=_get_text(root, 'expire'),
    )


def parse_login_response(xml_data: bytes) -> LoginResponse:
    """解析登录响应"""
    root = ET.fromstring(xml_data)
    resp = LoginResponse(
        userid=_get_text(root, 'userid'),
        keep_retry=_get_text(root, 'keep-retry'),
        keep_url=_get_text(root, 'keep-url'),
        term_url=_get_text(root, 'term-url'),
    )
    # 用户配置
    uc = root.find('user-config')
    if uc is not None:
        resp.against_interval = _get_text(uc, 'against-interval')
    resp.domain_config = _get_text(root, 'domain-config')
    return resp


def parse_state_response(xml_data: bytes) -> StateResponse:
    """解析心跳响应"""
    root = ET.fromstring(xml_data)
    return StateResponse(
        interval=_get_text(root, 'interval'),
        level=_get_text(root, 'level'),
    )


def _get_text(element, tag: str) -> str:
    """安全获取子元素的文本"""
    child = element.find(tag)
    return child.text if child is not None and child.text else ""


# ============================================================
# EConfig 解析
# ============================================================
E_CONFIG_START = "<!--//config.campus.js.chinatelecom.com "
E_CONFIG_END = "//config.campus.js.chinatelecom.com-->"


def parse_econfig(html: bytes) -> EConfig:
    """从 HTML 注释中提取 portal 配置"""
    text = html.decode('utf-8', errors='replace')

    # 提取注释中的 XML
    pattern = re.escape(E_CONFIG_START) + r'(.*?)' + re.escape(E_CONFIG_END)
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        raise ValueError("EConfig not found in HTML")

    xml_str = match.group(1)
    # 移除广告参数
    xml_str = xml_str.replace('&width=0', '').replace('&adtype=0', '')

    root = ET.fromstring(xml_str)
    return EConfig(
        ticket_url=_get_text(root, 'ticket-url'),
        auth_url=_get_text(root, 'auth-url'),
    )


# ============================================================
# SchoolInfo 解析
# ============================================================
def parse_school_info(headers: dict) -> SchoolInfo:
    """从 HTTP 响应头提取学校信息"""
    info = SchoolInfo()
    # 头可能是大小写混合
    header_lower = {k.lower(): v for k, v in headers.items()}
    info.domain = header_lower.get('domain', '')
    info.area = header_lower.get('area', '')
    info.school_id = header_lower.get('schoolid', '')
    info.index_url = header_lower.get('location', '')
    return info


# ============================================================
# AlgoID 解析
# ============================================================
def parse_algo_id(data: bytes) -> tuple:
    """解析服务器返回的算法 ID

    格式:
      [4字节头][key_len(1字节)][key_bytes][algo_id_len(1字节)][algo_id_bytes]

    Returns:
      (algo_id: str, key: str)
    """
    if len(data) < 4:
        raise ValueError("data too short for header")

    pos = 4
    # 读取 key
    len1 = data[3]
    if pos + len1 > len(data):
        raise ValueError("key length exceeds data")
    key = data[pos:pos + len1].decode()
    pos += len1

    # 读取 algo_id
    if pos >= len(data):
        raise ValueError("missing algo_id")
    len2 = data[pos]
    pos += 1
    if pos + len2 > len(data):
        raise ValueError("algo_id length exceeds data")
    algo_id = data[pos:pos + len2].decode()

    return algo_id, key


# ============================================================
# URL 参数提取
# ============================================================
def extract_url_params(url: str) -> dict:
    """从 URL 中提取查询参数"""
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] if v else '' for k, v in params.items()}


# ============================================================
# 时间格式化
# ============================================================
def format_local_time() -> str:
    """返回服务器期望的时间格式: YYYY-MM-DD HH:MM:SS"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
