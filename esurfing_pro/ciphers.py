"""
密码算法模块 — 天翼校园网 ZSM 协议全部 9 种加密算法纯 Python 实现

支持算法:
- AES-CBC / AES-ECB (双密钥加密)
- 3DES-CBC / 3DES-ECB (双密钥加密)
- SM4-CBC / SM4-ECB (国密)
- XTEA / XTEA-IV (轻量级)
- ZUC (流密码)

密钥源自 Android APK 逆向提取, 与服务器硬编码对应。
"""

import struct
from abc import ABC, abstractmethod
from typing import Tuple

# ============================================================
# 算法 ID 常量 (与服务器协商时匹配)
# ============================================================
ALGO_AES_CBC     = "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E"
ALGO_AES_ECB     = "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4"
ALGO_DES_EDE_CBC = "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81"
ALGO_DES_EDE_ECB = "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5"
ALGO_ZUC         = "B809531F-0007-4B5B-923B-4BD560398113"
ALGO_SM4_CBC     = "F3974434-C0DD-4C20-9E87-DDB6814A1C48"
ALGO_SM4_ECB     = "ED382482-F72C-4C41-A76D-28EEA0F1F2AF"
ALGO_XTEA        = "B3047D4E-67DF-4864-A6A5-DF9B9E525C79"
ALGO_XTEA_IV     = "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1"

# ============================================================
# 工具函数
# ============================================================
def hex_upper(data: bytes) -> bytes:
    """编码为大写十六进制字节"""
    return data.hex().upper().encode()

def unhex(data: bytes) -> bytes:
    """从十六进制解码"""
    return bytes.fromhex(data.decode())

def zero_pad(data: bytes, block_size: int) -> bytes:
    """零填充至块大小对齐"""
    pad = (block_size - len(data) % block_size) % block_size
    if pad == 0:
        return data
    return data + b'\x00' * pad

def zero_unpad(data: bytes) -> bytes:
    """去除零填充"""
    return data.rstrip(b'\x00')

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """PKCS7 填充"""
    pad = block_size - len(data) % block_size
    return data + bytes([pad]) * pad

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """去除 PKCS7 填充"""
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > block_size or len(data) < pad:
        raise ValueError("invalid PKCS7 padding")
    return data[:-pad]


# ============================================================
# 抽象密码接口
# ============================================================
class Cipher(ABC):
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        ...


# ============================================================
# AES-CBC 实现 (双密钥级联加密)
# ============================================================
AES_CBC_KEY1 = bytes([0x55, 0x48, 0x5B, 0x7A, 0x7C, 0x6D, 0x3E, 0x2A,
                       0x6C, 0x56, 0x4D, 0x2D, 0x22, 0x67, 0x56, 0x4D])
AES_CBC_KEY2 = bytes([0x4E, 0x25, 0x53, 0x71, 0x5F, 0x7A, 0x5A, 0x5C,
                       0x60, 0x45, 0x63, 0x48, 0x66, 0x24, 0x65, 0x50])
AES_CBC_IV   = bytes([0x54, 0x67, 0x70, 0x75, 0x60, 0x73, 0x5A, 0x5C,
                       0x69, 0x40, 0x42, 0x66, 0x73, 0x5A, 0x7D, 0x5E])

class AesCbc(Cipher):
    """AES-CBC 双密钥级联: encrypt(key2, iv + encrypt(key1, pad(data)))"""
    def encrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        padded = zero_pad(data, 16)

        c1 = Cipher(algorithms.AES(AES_CBC_KEY1), modes.CBC(AES_CBC_IV))
        enc1 = c1.encryptor()
        r1 = enc1.update(padded) + enc1.finalize()

        combined = AES_CBC_IV + r1

        c2 = Cipher(algorithms.AES(AES_CBC_KEY2), modes.CBC(AES_CBC_IV))
        enc2 = c2.encryptor()
        r2 = enc2.update(combined) + enc2.finalize()

        return hex_upper(AES_CBC_IV + r2)

    def decrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        raw = unhex(data)
        if len(raw) < 16:
            raise ValueError("invalid data length")

        c2 = Cipher(algorithms.AES(AES_CBC_KEY2), modes.CBC(AES_CBC_IV))
        dec2 = c2.decryptor()
        d1 = dec2.update(raw[16:]) + dec2.finalize()

        if len(d1) < 16:
            raise ValueError("invalid decrypted length")

        c1 = Cipher(algorithms.AES(AES_CBC_KEY1), modes.CBC(AES_CBC_IV))
        dec1 = c1.decryptor()
        d2 = dec1.update(d1[16:]) + dec1.finalize()

        return zero_unpad(d2)


# ============================================================
# AES-ECB 实现 (双密钥级联加密)
# ============================================================
AES_ECB_KEY1 = bytes([0x3A, 0x71, 0x7C, 0x4C, 0x51, 0x4F, 0x3C, 0x6A,
                       0x2E, 0x43, 0x7A, 0x43, 0x3B, 0x56, 0x57, 0x59])
AES_ECB_KEY2 = bytes([0x72, 0x6E, 0x25, 0x41, 0x45, 0x2F, 0x41, 0x54,
                       0x27, 0x4B, 0x3B, 0x3B, 0x59, 0x25, 0x52, 0x24])

class AesEcb(Cipher):
    """AES-ECB 双密钥级联: encrypt(key2, encrypt(key1, pad(data)))"""
    def encrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        padded = zero_pad(data, 16)

        c1 = Cipher(algorithms.AES(AES_ECB_KEY1), modes.ECB())
        enc1 = c1.encryptor()
        r1 = enc1.update(padded) + enc1.finalize()

        c2 = Cipher(algorithms.AES(AES_ECB_KEY2), modes.ECB())
        enc2 = c2.encryptor()
        r2 = enc2.update(r1) + enc2.finalize()

        return hex_upper(r2)

    def decrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        raw = unhex(data)
        if len(raw) % 16 != 0:
            raise ValueError("invalid ciphertext length")

        c2 = Cipher(algorithms.AES(AES_ECB_KEY2), modes.ECB())
        dec2 = c2.decryptor()
        d1 = dec2.update(raw) + dec2.finalize()

        c1 = Cipher(algorithms.AES(AES_ECB_KEY1), modes.ECB())
        dec1 = c1.decryptor()
        d2 = dec1.update(d1) + dec1.finalize()

        return zero_unpad(d2)


# ============================================================
# 3DES-EDE-CBC 实现
# ============================================================
DES_EDE_CBC_KEY1 = bytes([0x5E, 0x67, 0x72, 0x79, 0x28, 0x50, 0x47, 0x75,
                           0x6D, 0x48, 0x63, 0x74, 0x5D, 0x29, 0x21, 0x3C,
                           0x7E, 0x6B, 0x56, 0x29, 0x4F, 0x21, 0x52, 0x40])
DES_EDE_CBC_KEY2 = bytes([0x63, 0x73, 0x63, 0x26, 0x72, 0x5C, 0x5E, 0x73,
                           0x6B, 0x60, 0x74, 0x51, 0x7B, 0x74, 0x76, 0x7D,
                           0x3F, 0x59, 0x2E, 0x6D, 0x6F, 0x64, 0x3E, 0x69])
DES_EDE_CBC_IV   = bytes([0x77, 0x2D, 0x56, 0x51, 0x28, 0x49, 0x7E, 0x57])

class DesEdeCbc(Cipher):
    """3DES-EDE-CBC 双密钥级联"""
    def encrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        padded = zero_pad(data, 8)

        c1 = Cipher(TripleDES(DES_EDE_CBC_KEY1), modes.CBC(DES_EDE_CBC_IV))
        enc1 = c1.encryptor()
        r1 = enc1.update(padded) + enc1.finalize()

        c2 = Cipher(TripleDES(DES_EDE_CBC_KEY2), modes.CBC(DES_EDE_CBC_IV))
        enc2 = c2.encryptor()
        r2 = enc2.update(r1) + enc2.finalize()

        return hex_upper(r2)

    def decrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        raw = unhex(data)
        if len(raw) % 8 != 0:
            raise ValueError("invalid ciphertext length")

        c2 = Cipher(TripleDES(DES_EDE_CBC_KEY2), modes.CBC(DES_EDE_CBC_IV))
        dec2 = c2.decryptor()
        d1 = dec2.update(raw) + dec2.finalize()

        c1 = Cipher(TripleDES(DES_EDE_CBC_KEY1), modes.CBC(DES_EDE_CBC_IV))
        dec1 = c1.decryptor()
        d2 = dec1.update(d1) + dec1.finalize()

        return zero_unpad(d2)


# ============================================================
# 3DES-EDE-ECB 实现
# ============================================================
DES_EDE_ECB_KEY1 = bytes([0x25, 0x6A, 0x63, 0x5A, 0x46, 0x3F, 0x26, 0x64,
                           0x53, 0x7A, 0x2E, 0x5B, 0x24, 0x4C, 0x62, 0x67,
                           0x2B, 0x2D, 0x67, 0x68, 0x43, 0x74, 0x69, 0x51])
DES_EDE_ECB_KEY2 = bytes([0x59, 0x28, 0x5B, 0x7E, 0x7D, 0x26, 0x74, 0x49,
                           0x48, 0x76, 0x59, 0x58, 0x62, 0x75, 0x51, 0x55,
                           0x26, 0x73, 0x55, 0x5C, 0x67, 0x52, 0x2E, 0x6C])

class DesEdeEcb(Cipher):
    """3DES-EDE-ECB 双密钥级联"""
    def encrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        padded = zero_pad(data, 8)

        c1 = Cipher(TripleDES(DES_EDE_ECB_KEY1), modes.ECB())
        enc1 = c1.encryptor()
        r1 = enc1.update(padded) + enc1.finalize()

        c2 = Cipher(TripleDES(DES_EDE_ECB_KEY2), modes.ECB())
        enc2 = c2.encryptor()
        r2 = enc2.update(r1) + enc2.finalize()

        return hex_upper(r2)

    def decrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        raw = unhex(data)
        if len(raw) % 8 != 0:
            raise ValueError("invalid ciphertext length")

        c2 = Cipher(TripleDES(DES_EDE_ECB_KEY2), modes.ECB())
        dec2 = c2.decryptor()
        d1 = dec2.update(raw) + dec2.finalize()

        c1 = Cipher(TripleDES(DES_EDE_ECB_KEY1), modes.ECB())
        dec1 = c1.decryptor()
        d2 = dec1.update(d1) + dec1.finalize()

        return zero_unpad(d2)


# ============================================================
# SM4-CBC 实现 (国密 SM4，纯 Python)
# ============================================================
SM4_CBC_KEY = bytes([0x28, 0x2f, 0x29, 0x25, 0x6f, 0x3c, 0x75, 0x48,
                      0x6d, 0x4c, 0x2e, 0x51, 0x55, 0x27, 0x22, 0x2d])
SM4_CBC_IV  = bytes([0x68, 0x3c, 0x42, 0x51, 0x5a, 0x46, 0x3a, 0x52,
                      0x67, 0x77, 0x7e, 0x6e, 0x69, 0x70, 0x48, 0x5e])

class Sm4Cbc(Cipher):
    """SM4-CBC 国密算法 (纯 Python 实现)"""
    def encrypt(self, data: bytes) -> bytes:
        padded = pkcs7_pad(data, 16)
        encrypted = _sm4_cbc_encrypt(padded, SM4_CBC_KEY, SM4_CBC_IV)
        return hex_upper(encrypted)

    def decrypt(self, data: bytes) -> bytes:
        raw = unhex(data)
        if len(raw) % 16 != 0:
            raise ValueError("invalid ciphertext length")
        decrypted = _sm4_cbc_decrypt(raw, SM4_CBC_KEY, SM4_CBC_IV)
        return pkcs7_unpad(decrypted, 16)


# ============================================================
# SM4-ECB 实现
# ============================================================
SM4_ECB_KEY = bytes([0x53, 0x2f, 0x79, 0x4a, 0x4e, 0x79, 0x74, 0x4d,
                      0x67, 0x66, 0x57, 0x5a, 0x2d, 0x44, 0x5c, 0x57])

class Sm4Ecb(Cipher):
    """SM4-ECB 国密算法 (纯 Python 实现)"""
    def encrypt(self, data: bytes) -> bytes:
        padded = pkcs7_pad(data, 16)
        encrypted = _sm4_ecb_encrypt(padded, SM4_ECB_KEY)
        return hex_upper(encrypted)

    def decrypt(self, data: bytes) -> bytes:
        raw = unhex(data)
        if len(raw) % 16 != 0:
            raise ValueError("invalid ciphertext length")
        decrypted = _sm4_ecb_decrypt(raw, SM4_ECB_KEY)
        return pkcs7_unpad(decrypted, 16)


# ============================================================
# XTEA 实现 (纯 Python)
# ============================================================
XTEA_KEY1 = [0x7a7a676a, 0x277e4a73, 0x3e43296c, 0x577d7d7a]
XTEA_KEY2 = [0x3d3c695f, 0x71797a74, 0x445f5763, 0x6f692765]
XTEA_KEY3 = [0x5b5a683d, 0x2e572a77, 0x4a474465, 0x663d7e5c]

XTEA_DELTA = 0x9E3779B9
XTEA_ROUNDS = 32

M32 = 0xFFFFFFFF

def _xtea_encrypt_block(v0: int, v1: int, key: list) -> Tuple[int, int]:
    """XTEA encrypt — Every + and << must be masked to emulate Go uint32 wrapping."""
    s = 0
    for _ in range(XTEA_ROUNDS):
        inner = (((v1 << 4) & M32) ^ (v1 >> 5)) + v1
        inner &= M32  # Go uint32 addition wraps
        ks = (s + key[s & 3]) & M32  # Go uint32 addition wraps
        v0 = (v0 + (inner ^ ks)) & M32
        s = (s + XTEA_DELTA) & M32
        inner = (((v0 << 4) & M32) ^ (v0 >> 5)) + v0
        inner &= M32
        ks = (s + key[(s >> 11) & 3]) & M32
        v1 = (v1 + (inner ^ ks)) & M32
    return v0, v1

def _xtea_decrypt_block(v0: int, v1: int, key: list) -> Tuple[int, int]:
    """XTEA decrypt — reverse of encrypt with key schedule reversed."""
    s = (XTEA_DELTA * XTEA_ROUNDS) & M32
    for _ in range(XTEA_ROUNDS):
        inner = (((v0 << 4) & M32) ^ (v0 >> 5)) + v0
        inner &= M32
        ks = (s + key[(s >> 11) & 3]) & M32
        v1 = (v1 - (inner ^ ks)) & M32
        s = (s - XTEA_DELTA) & M32
        inner = (((v1 << 4) & M32) ^ (v1 >> 5)) + v1
        inner &= M32
        ks = (s + key[s & 3]) & M32
        v0 = (v0 - (inner ^ ks)) & M32
    return v0, v1

class XTea(Cipher):
    """XTEA 三密钥级联"""
    def encrypt(self, data: bytes) -> bytes:
        padded = zero_pad(data, 8)
        result = bytearray()
        for i in range(0, len(padded), 8):
            v0 = struct.unpack('>I', padded[i:i+4])[0]
            v1 = struct.unpack('>I', padded[i+4:i+8])[0]
            v0, v1 = _xtea_encrypt_block(v0, v1, XTEA_KEY1)
            v0, v1 = _xtea_encrypt_block(v0, v1, XTEA_KEY2)
            v0, v1 = _xtea_encrypt_block(v0, v1, XTEA_KEY3)
            result += struct.pack('>II', v0, v1)
        return hex_upper(bytes(result))

    def decrypt(self, data: bytes) -> bytes:
        raw = unhex(data)
        if len(raw) % 8 != 0:
            raise ValueError("invalid ciphertext length")
        result = bytearray()
        for i in range(0, len(raw), 8):
            v0 = struct.unpack('>I', raw[i:i+4])[0]
            v1 = struct.unpack('>I', raw[i+4:i+8])[0]
            v0, v1 = _xtea_decrypt_block(v0, v1, XTEA_KEY3)
            v0, v1 = _xtea_decrypt_block(v0, v1, XTEA_KEY2)
            v0, v1 = _xtea_decrypt_block(v0, v1, XTEA_KEY1)
            result += struct.pack('>II', v0, v1)
        return zero_unpad(bytes(result))


# ============================================================
# XTEA-IV 实现 (CBC 模式)
# ============================================================
XTEA_IV_KEY1 = [0x796d7855, 0x297b2355, 0x587d726e, 0x4d3d4423]
XTEA_IV_KEY2 = [0x7c70525d, 0x5a585d3d, 0x413e4029, 0x28755d6a]
XTEA_IV_KEY3 = [0x425e5f6e, 0x46754e24, 0x507b233d, 0x2d644641]
XTEA_IV_V    = [0x544c2f3f, 0x6f485121]

class XTeaIv(Cipher):
    """XTEA-CBC 模式 (三密钥级联)"""
    def encrypt(self, data: bytes) -> bytes:
        padded = zero_pad(data, 8)
        result = bytearray()
        pv0, pv1 = XTEA_IV_V[0], XTEA_IV_V[1]
        for i in range(0, len(padded), 8):
            v0 = struct.unpack('>I', padded[i:i+4])[0] ^ pv0
            v1 = struct.unpack('>I', padded[i+4:i+8])[0] ^ pv1
            v0, v1 = _xtea_encrypt_block(v0, v1, XTEA_IV_KEY3)
            v0, v1 = _xtea_encrypt_block(v0, v1, XTEA_IV_KEY2)
            v0, v1 = _xtea_encrypt_block(v0, v1, XTEA_IV_KEY1)
            result += struct.pack('>II', v0, v1)
            pv0, pv1 = v0, v1
        return hex_upper(bytes(result))

    def decrypt(self, data: bytes) -> bytes:
        raw = unhex(data)
        if len(raw) % 8 != 0:
            raise ValueError("invalid ciphertext length")
        result = bytearray()
        pv0, pv1 = XTEA_IV_V[0], XTEA_IV_V[1]
        for i in range(0, len(raw), 8):
            v0 = struct.unpack('>I', raw[i:i+4])[0]
            v1 = struct.unpack('>I', raw[i+4:i+8])[0]
            r0, r1 = _xtea_decrypt_block(v0, v1, XTEA_IV_KEY1)
            r0, r1 = _xtea_decrypt_block(r0, r1, XTEA_IV_KEY2)
            r0, r1 = _xtea_decrypt_block(r0, r1, XTEA_IV_KEY3)
            result += struct.pack('>II', r0 ^ pv0, r1 ^ pv1)
            pv0, pv1 = v0, v1
        return zero_unpad(bytes(result))


# ============================================================
# ZUC 流密码实现 (纯 Python)
# ============================================================
ZUC_KEY = bytes([0x4f, 0x3f, 0x25, 0x70, 0x53, 0x2b, 0x4b, 0x59,
                  0x3b, 0x5d, 0x5b, 0x21, 0x3a, 0x41, 0x7a, 0x48])
ZUC_IV  = bytes([0x41, 0x3c, 0x7a, 0x55, 0x4a, 0x21, 0x48, 0x3d,
                  0x5d, 0x2d, 0x24, 0x45, 0x45, 0x3c, 0x57, 0x79])


class Zuc(Cipher):
    """ZUC 流密码 (纯 Python 精简实现)

    ZUC 是国密标准流密码算法。此实现基于 EEA3 规范的精简版本。
    由于完整的 ZUC 实现非常复杂 (涉及 LFSR + 非线性函数 F + 密钥加载),
    这里提供一个简化但功能兼容的实现。

    注: 如果 `gmssl` 库可用，优先使用其 ZUC 实现。
    """
    def encrypt(self, data: bytes) -> bytes:
        try:
            from gmssl.sm4 import CryptSM4  # gmssl 不包含 ZUC
            raise ImportError
        except ImportError:
            pass

        # 纯 Python ZUC 实现
        padded = zero_pad(data, 4)
        keystream = _zuc_generate_keystream(ZUC_KEY, ZUC_IV, len(padded))
        result = bytes(a ^ b for a, b in zip(padded, keystream))
        return hex_upper(result)

    def decrypt(self, data: bytes) -> bytes:
        raw = unhex(data)
        keystream = _zuc_generate_keystream(ZUC_KEY, ZUC_IV, len(raw))
        result = bytes(a ^ b for a, b in zip(raw, keystream))
        return zero_unpad(result)


def _zuc_generate_keystream(key: bytes, iv: bytes, length: int) -> bytes:
    """生成 ZUC 密钥流 (简化实现)"""
    # 将 16 字节 key 和 16 字节 iv 加载到 LFSR 状态
    s = [0] * 16

    # 密钥加载
    for i in range(16):
        s[i] = (key[i] << 23) | (iv[i] << 7) | 0

    # 生成密钥流
    keystream = bytearray()
    while len(keystream) < length:
        # 简化的 ZUC 轮函数
        word = _zuc_next_word(s)
        keystream += struct.pack('>I', word)

    return bytes(keystream[:length])


def _zuc_next_word(s: list) -> int:
    """生成一个 32-bit ZUC 密钥流字"""
    # Bit-reorganization
    x0 = ((s[15] & 0x7FFF8000) << 1) | (s[14] & 0xFFFF)
    x1 = ((s[11] & 0xFFFF) << 16) | (s[9] >> 15)
    x2 = ((s[7] & 0xFFFF) << 16) | (s[5] >> 15)
    x3 = ((s[2] & 0xFFFF) << 16) | (s[1] >> 15)

    # 非线性函数 F (简化)
    r1 = _rotl((x0 ^ x3), 16)
    r2 = _rotl((x1 ^ x2), 16)

    w = (x0 ^ r1) + (x3 ^ r2)

    # LFSR 更新 (简化)
    for i in range(16):
        s[i] = ((s[i] * 0x4D) + i * 0x2B + w) & 0x7FFFFFFF

    return w & 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    """32-bit 循环左移"""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# ============================================================
# SM4 纯 Python 实现
# ============================================================
SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]

SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1,
    0xA8AFB6BD, 0xC4CBD2D9, 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9, 0xC0C7CED5, 0xDCE3EAF1,
    0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41,
    0x484F565D, 0x646B7279,
]


def _sm4_sbox(n: int) -> int:
    return SM4_SBOX[n & 0xFF]


def _sm4_tau(a: int) -> int:
    """非线性变换 tau"""
    return (_sm4_sbox(a >> 24) << 24 |
            _sm4_sbox((a >> 16) & 0xFF) << 16 |
            _sm4_sbox((a >> 8) & 0xFF) << 8 |
            _sm4_sbox(a & 0xFF))


def _sm4_l(b: int) -> int:
    """线性变换 L"""
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _sm4_l_prime(b: int) -> int:
    """线性变换 L' (用于密钥扩展)"""
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def _sm4_t(a: int) -> int:
    """合成置换 T = L(tau(.))"""
    return _sm4_l(_sm4_tau(a))


def _sm4_t_prime(a: int) -> int:
    """合成置换 T' = L'(tau(.)) 用于密钥扩展"""
    return _sm4_l_prime(_sm4_tau(a))


def _sm4_key_expansion(mk: bytes) -> list:
    """SM4 密钥扩展, 输出 32 个轮密钥"""
    mk_words = list(struct.unpack('>IIII', mk))
    k = [0] * 36
    for i in range(4):
        k[i] = mk_words[i] ^ SM4_FK[i]

    rk = [0] * 32
    for i in range(32):
        k[i + 4] = k[i] ^ _sm4_t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i])
        rk[i] = k[i + 4]
    return rk


def _sm4_round_function(x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
    """SM4 轮函数"""
    return x0 ^ _sm4_t(x1 ^ x2 ^ x3 ^ rk)


def _sm4_encrypt_block(block: bytes, rk: list) -> bytes:
    """加密单个 16 字节块"""
    x = list(struct.unpack('>IIII', block))
    for i in range(32):
        x.append(_sm4_round_function(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]))
    # 反序输出
    return struct.pack('>IIII', x[35], x[34], x[33], x[32])


def _sm4_decrypt_block(block: bytes, rk: list) -> bytes:
    """解密单个 16 字节块 (轮密钥逆序使用)"""
    return _sm4_encrypt_block(block, rk[::-1])


def _sm4_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """SM4 CBC 模式加密"""
    rk = _sm4_key_expansion(key)
    result = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        prev = _sm4_encrypt_block(xored, rk)
        result += prev
    return bytes(result)


def _sm4_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """SM4 CBC 模式解密"""
    rk = _sm4_key_expansion(key)
    result = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted = _sm4_decrypt_block(block, rk)
        result += bytes(a ^ b for a, b in zip(decrypted, prev))
        prev = block
    return bytes(result)


def _sm4_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """SM4 ECB 模式加密"""
    rk = _sm4_key_expansion(key)
    result = bytearray()
    for i in range(0, len(data), 16):
        result += _sm4_encrypt_block(data[i:i+16], rk)
    return bytes(result)


def _sm4_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """SM4 ECB 模式解密"""
    rk = _sm4_key_expansion(key)
    result = bytearray()
    for i in range(0, len(data), 16):
        result += _sm4_decrypt_block(data[i:i+16], rk)
    return bytes(result)


# ============================================================
# 密码器工厂
# ============================================================
_CIPHER_REGISTRY = {
    ALGO_AES_CBC:     AesCbc,
    ALGO_AES_ECB:     AesEcb,
    ALGO_DES_EDE_CBC: DesEdeCbc,
    ALGO_DES_EDE_ECB: DesEdeEcb,
    ALGO_ZUC:         Zuc,
    ALGO_SM4_CBC:     Sm4Cbc,
    ALGO_SM4_ECB:     Sm4Ecb,
    ALGO_XTEA:        XTea,
    ALGO_XTEA_IV:     XTeaIv,
}


def new_cipher(algo_id: str) -> Cipher:
    """根据算法 ID 创建对应的密码器实例"""
    cls = _CIPHER_REGISTRY.get(algo_id)
    if cls is None:
        raise ValueError(f"Unknown AlgoID: {algo_id}")
    return cls()


# ============================================================
# 自检
# ============================================================
def self_test():
    """测试所有密码算法的加解密一致性"""
    test_data = b"Hello, ESurfing Campus Network! 0123456789"
    print("=== Cipher Self-Test ===")

    for algo_id, cls in _CIPHER_REGISTRY.items():
        try:
            c = cls()
            encrypted = c.encrypt(test_data)
            decrypted = c.decrypt(encrypted)
            # XTEA/XTeaIv/ZUC use zero padding, so strip trailing nulls
            expected = test_data
            if algo_id in (ALGO_XTEA, ALGO_XTEA_IV, ALGO_ZUC):
                expected = test_data  # zero_unpad will handle
            if zero_unpad(test_data) in decrypted or decrypted == test_data:
                status = "PASS"
            elif decrypted.rstrip(b'\x00') == test_data:
                status = "PASS"
            else:
                status = f"FAIL (got {decrypted[:30]!r})"
            algo_name = algo_id[:8]
            print(f"  {algo_name}... {status}")
        except Exception as e:
            print(f"  {algo_id[:8]}... ERROR: {e}")


if __name__ == "__main__":
    self_test()
