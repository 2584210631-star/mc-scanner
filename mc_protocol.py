"""
Minecraft Java Edition 协议工具
基于 MCPyBot (Fireroth/MCPyBot) 的经过实测的协议实现
支持 Minecraft 1.21.x（协议版本 774，1.21.11）
零第三方依赖
"""

import io
import json
import socket
import struct
import uuid
import zlib
import time


# ============================================================
# 协议常量 (Protocol 774 = Minecraft 1.21.11)
# ============================================================

PROTOCOL_VERSION = 774

# 连接状态
STATE_HANDSHAKE = 0
STATE_STATUS = 1
STATE_LOGIN = 2
STATE_CONFIGURATION = 3
STATE_PLAY = 4

# --- Login Clientbound ---
LOGIN_CB_DISCONNECT = 0x00
LOGIN_CB_ENCRYPTION_REQUEST = 0x01
LOGIN_CB_LOGIN_SUCCESS = 0x02
LOGIN_CB_SET_COMPRESSION = 0x03
LOGIN_CB_LOGIN_PLUGIN_REQUEST = 0x04

# --- Login Serverbound ---
LOGIN_SB_LOGIN_START = 0x00
LOGIN_SB_LOGIN_ACKNOWLEDGED = 0x03

# --- Configuration Clientbound ---
CONFIG_CB_COOKIE_REQUEST = 0x00
CONFIG_CB_PLUGIN_MESSAGE = 0x01
CONFIG_CB_DISCONNECT = 0x02
CONFIG_CB_FINISH_CONFIGURATION = 0x03
CONFIG_CB_KEEP_ALIVE = 0x04
CONFIG_CB_PING = 0x05
CONFIG_CB_RESET_CHAT = 0x06
CONFIG_CB_REGISTRY_DATA = 0x07
CONFIG_CB_REMOVE_RESOURCE_PACK = 0x08
CONFIG_CB_ADD_RESOURCE_PACK = 0x09
CONFIG_CB_STORE_COOKIE = 0x0A
CONFIG_CB_TRANSFER = 0x0B
CONFIG_CB_FEATURE_FLAGS = 0x0C
CONFIG_CB_UPDATE_TAGS = 0x0D
CONFIG_CB_KNOWN_PACKS = 0x0E
CONFIG_CB_CUSTOM_REPORT_DETAILS = 0x0F
CONFIG_CB_SERVER_LINKS = 0x10

# --- Configuration Serverbound ---
CONFIG_SB_CLIENT_INFORMATION = 0x00
CONFIG_SB_COOKIE_RESPONSE = 0x01
CONFIG_SB_PLUGIN_MESSAGE = 0x02
CONFIG_SB_FINISH_CONFIGURATION = 0x03
CONFIG_SB_KEEP_ALIVE = 0x04
CONFIG_SB_PONG = 0x05
CONFIG_SB_RESOURCE_PACK_RESPONSE = 0x06
CONFIG_SB_KNOWN_PACKS = 0x07

# --- Play Clientbound ---
PLAY_CB_KEEP_ALIVE = 0x2B
PLAY_CB_LOGIN_PLAY = 0x30
PLAY_CB_PING = 0x3E
PLAY_CB_DISCONNECT = 0x20
PLAY_CB_SYSTEM_CHAT_MESSAGE = 0x77
PLAY_CB_PLAYER_CHAT = 0x3F

# --- Play Serverbound ---
PLAY_SB_CONFIRM_TELEPORT = 0x00
PLAY_SB_KEEP_ALIVE = 0x1B
PLAY_SB_CHAT_COMMAND = 0x06
PLAY_SB_CHAT_MESSAGE = 0x08
PLAY_SB_PONG = 0x2C
PLAY_SB_CLIENT_INFORMATION = 0x0D
PLAY_SB_PLUGIN_MESSAGE = 0x15
PLAY_SB_SET_PLAYER_ON_GROUND = 0x20


# ============================================================
# VarInt / VarLong 编解码
# ============================================================

def write_varint(value: int) -> bytes:
    result = bytearray()
    value &= 0xFFFFFFFF
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            break
    return bytes(result)


def read_varint(data: bytes, offset: int = 0) -> tuple:
    """从 bytes 解码 VarInt，返回 (value, new_offset)"""
    result = 0
    num_read = 0
    while True:
        if offset + num_read >= len(data):
            raise ValueError("VarInt 数据不完整")
        byte = data[offset + num_read]
        result |= (byte & 0x7F) << (7 * num_read)
        num_read += 1
        if not (byte & 0x80):
            break
        if num_read > 5:
            raise ValueError("VarInt 过长")
    if result >= (1 << 31):
        result -= (1 << 32)
    return result, offset + num_read


def read_varint_from_stream(stream) -> int:
    """从类文件流读取 VarInt"""
    result = 0
    num_read = 0
    while True:
        b = stream.read(1)
        if len(b) == 0:
            raise ConnectionError("连接已关闭")
        byte = b[0]
        result |= (byte & 0x7F) << (7 * num_read)
        num_read += 1
        if not (byte & 0x80):
            break
        if num_read > 5:
            raise ValueError("VarInt 过长")
    if result >= (1 << 31):
        result -= (1 << 32)
    return result


# ============================================================
# 字符串 / UUID
# ============================================================

def write_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return write_varint(len(encoded)) + encoded


def read_string(data: bytes, offset: int = 0) -> tuple:
    length, offset = read_varint(data, offset)
    if offset + length > len(data):
        raise ValueError("字符串数据不完整")
    s = data[offset:offset + length].decode("utf-8", errors="replace")
    return s, offset + length


def read_string_from_stream(stream) -> str:
    length = read_varint_from_stream(stream)
    data = stream.read(length)
    if len(data) != length:
        raise ConnectionError("字符串被截断")
    return data.decode("utf-8", errors="replace")


def write_uuid(u: uuid.UUID) -> bytes:
    return u.int.to_bytes(16, "big")


def read_uuid_from_stream(stream) -> uuid.UUID:
    data = stream.read(16)
    if len(data) != 16:
        raise ConnectionError("UUID 被截断")
    return uuid.UUID(int=int.from_bytes(data, "big"))


def offline_uuid(username: str) -> uuid.UUID:
    """离线模式玩家 UUID 的标准生成方式"""
    return uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{username}")


# ============================================================
# Minecraft 连接类（处理压缩、状态、收发包）
# 基于 MCPyBot 的 SocketStream，经过实测验证
# ============================================================

class MCConnection:
    def __init__(self, host: str, port: int = 25565, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.compression_threshold = -1
        self.state = STATE_HANDSHAKE

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def send_packet(self, packet_id: int, payload: bytes = b""):
        if self.sock is None:
            raise ConnectionError("未连接")
        id_bytes = write_varint(packet_id)
        uncompressed = id_bytes + payload

        if self.compression_threshold >= 0:
            if len(uncompressed) >= self.compression_threshold:
                data_length = write_varint(len(uncompressed))
                compressed = zlib.compress(uncompressed)
                packet_data = data_length + compressed
            else:
                packet_data = write_varint(0) + uncompressed
        else:
            packet_data = uncompressed

        frame = write_varint(len(packet_data)) + packet_data
        self.sock.sendall(frame)

    def recv_packet(self, timeout: float | None = None) -> tuple:
        """接收一个数据包，返回 (packet_id, payload_bytes)
        读包数据中途失败（半包）时关闭连接，避免后续流错位；
        仅等待数据时的正常超时不关闭连接（调用方用于轮询）
        """
        if self.sock is None:
            raise ConnectionError("未连接")

        if timeout is not None:
            self.sock.settimeout(timeout)

        try:
            packet_length = self._recv_varint()
            try:
                raw = self._recv_exact(packet_length)
            except Exception:
                # 已读到包长度但数据没读完（半包），关闭连接避免流错位
                self.close()
                raise
        finally:
            if timeout is not None and self.sock is not None:
                try:
                    self.sock.settimeout(self.timeout)
                except Exception:
                    pass

        if self.compression_threshold >= 0:
            buf = io.BytesIO(raw)
            data_length = read_varint_from_stream(buf)
            remaining = buf.read()
            if data_length == 0:
                decompressed = remaining
            else:
                decompressed = zlib.decompress(remaining)
        else:
            decompressed = raw

        buf = io.BytesIO(decompressed)
        packet_id = read_varint_from_stream(buf)
        payload = buf.read()
        return packet_id, payload

    def _recv_varint(self) -> int:
        result = 0
        num_read = 0
        while True:
            b = self.sock.recv(1)
            if not b:
                raise ConnectionError("连接已关闭")
            byte = b[0]
            result |= (byte & 0x7F) << (7 * num_read)
            num_read += 1
            if not (byte & 0x80):
                break
            if num_read > 5:
                raise ValueError("VarInt 过长")
        if result >= (1 << 31):
            result -= (1 << 32)
        return result

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("连接已关闭")
            buf.extend(chunk)
        return bytes(buf)


# ============================================================
# Server List Ping (SLP) - 获取服务器信息
# ============================================================

def server_list_ping(
    host: str,
    port: int = 25565,
    timeout: float = 5.0,
    protocol_version: int = PROTOCOL_VERSION,
    retries: int = 2,
) -> dict | None:
    """
    发送 Server List Ping，获取服务器信息
    返回包含 version、players、description 等字段的字典
    失败时自动重试 retries 次
    """
    last_error = None
    for attempt in range(retries + 1):
        try:
            conn = MCConnection(host, port, timeout)
            conn.connect()
            conn.state = STATE_STATUS

            # 握手，next_state = 1 (status)
            handshake_data = (
                write_varint(protocol_version)
                + write_string(host)
                + struct.pack(">H", port)
                + write_varint(1)
            )
            conn.send_packet(0x00, handshake_data)

            # Status Request
            conn.send_packet(0x00)

            # Status Response
            packet_id, data = conn.recv_packet(timeout=timeout)
            if packet_id == 0x00:
                buf = io.BytesIO(data)
                response_json = read_string_from_stream(buf)
                try:
                    result = json.loads(response_json)
                except json.JSONDecodeError:
                    # 截断容错：某些服务器(如Hypixel部分节点)声明的JSON长度比实际短
                    extra = buf.read()
                    if extra:
                        try:
                            result = json.loads(response_json + extra.decode('utf-8', errors='replace'))
                        except json.JSONDecodeError:
                            conn.close()
                            return None
                    else:
                        conn.close()
                        return None
                conn.close()
                return result

            conn.close()
            return None

        except Exception as e:
            last_error = e
            if attempt < retries:
                time.sleep(0.3 * (attempt + 1))
                continue
            return None


# ============================================================
# 多版本支持（1.12 - 最新）
# ============================================================

# 协议版本 -> 游戏版本 映射
PROTOCOL_TO_VERSION = {
    340: "1.12.2",
    393: "1.13",
    401: "1.13.2",
    477: "1.14.4",
    498: "1.14.4+",
    573: "1.15.2",
    578: "1.16.1",
    735: "1.16.2",
    751: "1.16.3",
    753: "1.16.3+",
    754: "1.16.4/1.16.5",
    755: "1.17",
    756: "1.17.1",
    757: "1.18/1.18.1",
    758: "1.18.2",
    759: "1.19",
    760: "1.19.1/1.19.2",
    761: "1.19.3",
    762: "1.19.4",
    763: "1.20/1.20.1",
    764: "1.20.2",
    765: "1.20.3/1.20.4",
    766: "1.20.5/1.20.6",
    767: "1.21/1.21.1",
    768: "1.21.2/1.21.3",
    769: "1.21.4",
    770: "1.21.5",
    771: "1.21.6",
    772: "1.21.7",
    773: "1.21.8/1.21.9",
    774: "1.21.10/1.21.11",
    775: "1.21.12+",
}

# 支持的协议版本范围
MIN_SUPPORTED_PROTOCOL = 340  # 1.12.2
MAX_SUPPORTED_PROTOCOL = 9999

# 分版本的配置表
# chat_format:
#   "simple"         - 1.18及以下，聊天包只有一个 String
#   "old_signed_759" - 1.19，带时间戳/盐/签名，末尾 hasSignedPreview
#   "old_signed_760" - 1.19.1/1.19.2，带 messageType + hasTarget
#   "old_signed_761" - 1.19.3-1.20.4，带 offset + acknowledged(BitSet 3字节)
#   "new"            - 1.20.5+，带 offset/acknowledged/checksum
# has_configuration: 是否有 configuration 状态（1.20.2+）
# login_start_uuid: Login Start 包是否带 UUID 字段（1.20.2+）
# uuid_is_string: Login Success 中 UUID 是否为字符串（1.15.2及以下）
PLAY_PACKET_TABLES = [
    {
        "min_proto": 340,
        "max_proto": 578,
        "label": "1.12.x-1.15.2",
        "sb_chat": 0x02,
        "chat_format": "simple",
        "has_configuration": False,
        "login_start_uuid": False,
        "uuid_is_string": True,
    },
    {
        "min_proto": 579,
        "max_proto": 758,
        "label": "1.16-1.18.2",
        "sb_chat": 0x03,
        "chat_format": "simple",
        "has_configuration": False,
        "login_start_uuid": False,
        "uuid_is_string": False,
    },
    {
        "min_proto": 759,
        "max_proto": 759,
        "label": "1.19",
        "sb_chat": 0x04,
        "chat_format": "old_signed_759",
        "has_configuration": False,
        "login_start_uuid": False,
        "uuid_is_string": False,
    },
    {
        "min_proto": 760,
        "max_proto": 760,
        "label": "1.19.1/1.19.2",
        "sb_chat": 0x05,
        "chat_format": "old_signed_760",
        "has_configuration": False,
        "login_start_uuid": False,
        "uuid_is_string": False,
    },
    {
        "min_proto": 761,
        "max_proto": 763,
        "label": "1.19.3-1.20.1",
        "sb_chat": 0x05,
        "chat_format": "old_signed_761",
        "has_configuration": False,
        "login_start_uuid": False,
        "uuid_is_string": False,
    },
    {
        "min_proto": 764,
        "max_proto": 764,
        "label": "1.20.2",
        "cb_disconnect": 0x1B,
        "cb_keep_alive": 0x24,
        "cb_ping": 0x33,
        "cb_teleport": 0x3E,
        "cb_login": 0x29,
        "sb_keep_alive": 0x14,
        "sb_chat": 0x05,
        "sb_chat_command": 0x04,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x23,
        "chat_format": "old_signed_761",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x01, "cb_finish": 0x02, "cb_keep_alive": 0x03,
            "cb_ping": 0x04, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x07,
            "sb_client_info": 0x00, "sb_plugin": 0x01, "sb_finish": 0x02,
            "sb_keep_alive": 0x03, "sb_pong": 0x04, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x05,
        },
    },
    {
        "min_proto": 765,
        "max_proto": 765,
        "label": "1.20.3-1.20.4",
        "cb_disconnect": 0x1B,
        "cb_keep_alive": 0x24,
        "cb_ping": 0x33,
        "cb_teleport": 0x3E,
        "cb_login": 0x29,
        "sb_keep_alive": 0x15,
        "sb_chat": 0x05,
        "sb_chat_command": 0x04,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x24,
        "chat_format": "old_signed_761",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x01, "cb_finish": 0x02, "cb_keep_alive": 0x03,
            "cb_ping": 0x04, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x07,
            "sb_client_info": 0x00, "sb_plugin": 0x01, "sb_finish": 0x02,
            "sb_keep_alive": 0x03, "sb_pong": 0x04, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x05,
        },
    },
    {
        "min_proto": 766,
        "max_proto": 766,
        "label": "1.20.5-1.20.6",
        "cb_disconnect": 0x1D,
        "cb_keep_alive": 0x26,
        "cb_ping": 0x35,
        "cb_teleport": 0x40,
        "cb_login": 0x2b,
        "sb_keep_alive": 0x18,
        "sb_chat": 0x06,
        "sb_chat_command": 0x04,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x27,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 767,
        "max_proto": 767,
        "label": "1.21/1.21.1",
        "cb_disconnect": 0x1D,
        "cb_keep_alive": 0x26,
        "cb_ping": 0x35,
        "cb_teleport": 0x40,
        "cb_login": 0x2b,
        "sb_keep_alive": 0x18,
        "sb_chat": 0x06,
        "sb_chat_command": 0x04,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x27,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 768,
        "max_proto": 768,
        "label": "1.21.2-1.21.3",
        "cb_disconnect": 0x1E,
        "cb_keep_alive": 0x27,
        "cb_ping": 0x37,
        "cb_teleport": 0x44,
        "cb_login": 0x2c,
        "sb_keep_alive": 0x1a,
        "sb_chat": 0x07,
        "sb_chat_command": 0x05,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x29,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 769,
        "max_proto": 769,
        "label": "1.21.4",
        "cb_disconnect": 0x1E,
        "cb_keep_alive": 0x27,
        "cb_ping": 0x37,
        "cb_teleport": 0x44,
        "cb_login": 0x2c,
        "sb_keep_alive": 0x1a,
        "sb_chat": 0x07,
        "sb_chat_command": 0x05,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x2b,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 770,
        "max_proto": 770,
        "label": "1.21.5",
        "cb_disconnect": 0x1E,
        "cb_keep_alive": 0x26,
        "cb_ping": 0x36,
        "cb_teleport": 0x44,
        "cb_login": 0x2b,
        "sb_keep_alive": 0x1a,
        "sb_chat": 0x07,
        "sb_chat_command": 0x05,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x2b,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 771,
        "max_proto": 772,
        "label": "1.21.6-1.21.8",
        "cb_disconnect": 0x1E,
        "cb_keep_alive": 0x26,
        "cb_ping": 0x36,
        "cb_teleport": 0x44,
        "cb_login": 0x2b,
        "sb_keep_alive": 0x1b,
        "sb_chat": 0x08,
        "sb_chat_command": 0x06,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x2c,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 773,
        "max_proto": 773,
        "label": "1.21.9",
        "cb_disconnect": 0x20,
        "cb_keep_alive": 0x2b,
        "cb_ping": 0x3b,
        "cb_teleport": 0x46,
        "cb_login": 0x30,
        "sb_keep_alive": 0x1b,
        "sb_chat": 0x08,
        "sb_chat_command": 0x06,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x2c,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 774,
        "max_proto": 775,
        "label": "1.21.10-1.21.12",
        "cb_disconnect": 0x20,
        "cb_keep_alive": 0x2b,
        "cb_ping": 0x3b,
        "cb_teleport": 0x46,
        "cb_login": 0x30,
        "sb_keep_alive": 0x1b,
        "sb_chat": 0x08,
        "sb_chat_command": 0x06,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x2c,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
    {
        "min_proto": 776,
        "max_proto": 9999,
        "label": "1.21.13+",
        "cb_disconnect": 0x20,
        "cb_keep_alive": 0x2b,
        "cb_ping": 0x3b,
        "cb_teleport": 0x46,
        "cb_login": 0x30,
        "sb_keep_alive": 0x1b,
        "sb_chat": 0x08,
        "sb_chat_command": 0x06,
        "sb_confirm_teleport": 0x00,
        "sb_pong": 0x2c,
        "chat_format": "new",
        "has_configuration": True,
        "login_start_uuid": True,
        "uuid_is_string": False,
        "config": {
            "cb_disconnect": 0x02, "cb_finish": 0x03, "cb_keep_alive": 0x04,
            "cb_ping": 0x05, "cb_known_packs": 0x0E, "cb_add_resource_pack": 0x09,
            "sb_client_info": 0x00, "sb_plugin": 0x02, "sb_finish": 0x03,
            "sb_keep_alive": 0x04, "sb_pong": 0x05, "sb_known_packs": 0x07,
            "sb_resource_pack": 0x06,
        },
    },
]


def get_play_packets(protocol_version: int) -> dict | None:
    """根据协议版本获取配置表，不支持的版本返回 None"""
    if protocol_version < MIN_SUPPORTED_PROTOCOL:
        return None
    for table in PLAY_PACKET_TABLES:
        if table["min_proto"] <= protocol_version <= table["max_proto"]:
            return table
    return None


def get_version_name(protocol_version: int) -> str:
    """协议版本号转游戏版本名（找最接近的）"""
    if protocol_version in PROTOCOL_TO_VERSION:
        return PROTOCOL_TO_VERSION[protocol_version]
    # 找最接近的
    closest = min(PROTOCOL_TO_VERSION.keys(), key=lambda x: abs(x - protocol_version))
    return f"{PROTOCOL_TO_VERSION[closest]}~(协议{protocol_version})"
