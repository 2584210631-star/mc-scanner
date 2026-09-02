"""
Minecraft 机器人模块
基于 MCPyBot (Fireroth/MCPyBot) 的经过实测的协议实现
支持 Minecraft 1.20.2 ~ 1.21.11+（协议 764-775），仅离线模式服务器

自动版本适配：从 SLP 获取服务器协议版本，自动切换包 ID 和聊天格式
完整流程：握手 → Login → Configuration → Play → 发消息 → 退出
"""

import io
import socket
import struct
import time
import uuid
import threading
from dataclasses import dataclass

from mc_protocol import (
    MCConnection,
    PROTOCOL_VERSION,
    STATE_LOGIN,
    STATE_CONFIGURATION,
    STATE_PLAY,
    # Login
    LOGIN_CB_DISCONNECT,
    LOGIN_CB_ENCRYPTION_REQUEST,
    LOGIN_CB_LOGIN_SUCCESS,
    LOGIN_CB_SET_COMPRESSION,
    LOGIN_CB_LOGIN_PLUGIN_REQUEST,
    LOGIN_SB_LOGIN_START,
    LOGIN_SB_LOGIN_ACKNOWLEDGED,
    # Configuration
    CONFIG_CB_FINISH_CONFIGURATION,
    CONFIG_CB_KNOWN_PACKS,
    CONFIG_CB_KEEP_ALIVE,
    CONFIG_CB_PING,
    CONFIG_CB_DISCONNECT,
    CONFIG_CB_ADD_RESOURCE_PACK,
    CONFIG_SB_CLIENT_INFORMATION,
    CONFIG_SB_PLUGIN_MESSAGE,
    CONFIG_SB_FINISH_CONFIGURATION,
    CONFIG_SB_KNOWN_PACKS,
    CONFIG_SB_KEEP_ALIVE,
    CONFIG_SB_PONG,
    CONFIG_SB_RESOURCE_PACK_RESPONSE,
    # 多版本
    get_play_packets,
    get_version_name,
    # 工具函数
    write_varint,
    write_string,
    write_uuid,
    read_varint_from_stream,
    read_string_from_stream,
    read_uuid_from_stream,
    offline_uuid,
    server_list_ping,
)


# 默认警告消息
DEFAULT_WARNING_MESSAGES = [
    "您好，我是安全扫描机器人，不会破坏您的服务器",
    "检测到您的服务器处于离线模式(offline-mode)，攻击者可伪造OP用户名登录",
    "建议：1.在 server.properties 中设置 online-mode=true",
    "2.如必须离线模式，请安装 AuthMe 等登录插件并开启白名单",
    "3.定期检查 ops.json，删除不认识的管理员",
    "参考: https://matdoes.dev/matscan",
]


@dataclass
class BotResult:
    """机器人执行结果"""
    ip: str
    port: int
    success: bool = False
    is_offline: bool = False
    is_whitelist: bool = False
    auth_mode: str = "unknown"  # offline / online / whitelist / rejected / unknown
    server_info: dict | None = None
    protocol_version: int = 0
    version_name: str = ""
    motd: str = ""
    players_online: int = 0
    players_max: int = 0
    error: str = ""
    messages_sent: int = 0
    authme_used: bool = False


def _build_client_information(protocol_version: int = 767) -> bytes:
    """构建 Client Information 包（configuration 阶段）
    1.21.2+ (协议768+) 增加 particleStatus 字段
    """
    buf = bytearray()
    buf += write_string("en_us")              # locale
    buf += struct.pack("b", 8)                 # view distance
    buf += write_varint(0)                     # chat mode (0 = enabled)
    buf += struct.pack("?", True)              # chat colors
    buf += struct.pack("B", 0x7F)              # displayed skin parts (全部)
    buf += write_varint(1)                     # main hand (1 = right)
    buf += struct.pack("?", False)             # enable text filtering
    buf += struct.pack("?", True)              # allow server listings
    if protocol_version >= 769:
        buf += write_varint(0)                 # particleStatus (0 = all, 1.21.4+)
    return bytes(buf)


def _send_chat_message_new(conn: MCConnection, message: str, chat_id: int, protocol_version: int = 774):
    """
    发送聊天消息（1.20.5+ 新格式，协议 766+）
    checksum 字段 1.21.5(770) 才加入，766-769 不需要
    """
    timestamp = int(time.time() * 1000)
    salt = 0
    payload = (
        write_string(message[:256])
        + struct.pack(">q", timestamp)
        + struct.pack(">q", salt)
        + write_varint(0)           # message count: 0
        + b'\x00\x00\x00'           # acknowledged: 20-bit fixed bitset (3 bytes)
    )
    if protocol_version >= 770:
        payload += b'\x00'           # checksum: 0 (1.21.5+)
    conn.send_packet(chat_id, payload)


def _send_chat_message_759(conn: MCConnection, message: str, chat_id: int, protocol_version: int = 759):
    """
    发送聊天消息（1.19，协议 759）
    格式: String + Long(timestamp) + Long(salt) + Boolean(hasSignature) + Boolean(hasSignedPreview)
    """
    timestamp = int(time.time() * 1000)
    salt = 0
    payload = (
        write_string(message[:256])
        + struct.pack(">q", timestamp)
        + struct.pack(">q", salt)
        + b'\x00'                   # hasSignature: False
        + b'\x00'                   # hasSignedPreview: False
    )
    conn.send_packet(chat_id, payload)


def _send_chat_message_760(conn: MCConnection, message: str, chat_id: int, protocol_version: int = 760):
    """
    发送聊天消息（1.19.1/1.19.2，协议 760）
    格式: String + Long(timestamp) + Long(salt) + Boolean(hasSignature)
          + VarInt(messageType) + Boolean(hasTarget)
    """
    timestamp = int(time.time() * 1000)
    salt = 0
    payload = (
        write_string(message[:256])
        + struct.pack(">q", timestamp)
        + struct.pack(">q", salt)
        + b'\x00'                   # hasSignature: False
        + write_varint(0)           # messageType: 0 (CHAT)
        + b'\x00'                   # hasTarget: False
    )
    conn.send_packet(chat_id, payload)


def _send_chat_message_761(conn: MCConnection, message: str, chat_id: int, protocol_version: int = 761):
    """
    发送聊天消息（1.19.3-1.20.4，协议 761-765）
    格式: String + Long(timestamp) + Long(salt) + Boolean(hasSignature)
          + VarInt(offset) + BitSet(acknowledged, 3字节固定长度)
    """
    timestamp = int(time.time() * 1000)
    salt = 0
    payload = (
        write_string(message[:256])
        + struct.pack(">q", timestamp)
        + struct.pack(">q", salt)
        + b'\x00'                   # hasSignature: False
        + write_varint(0)           # offset: 0
        + b'\x00\x00\x00'           # acknowledged: 3字节空 BitSet
    )
    conn.send_packet(chat_id, payload)


def _send_chat_message_simple(conn: MCConnection, message: str, chat_id: int, protocol_version: int = 340):
    """
    发送聊天消息（1.18及以下纯String格式，协议 < 759）
    """
    conn.send_packet(chat_id, write_string(message[:256]))


def _send_chat_command(conn: MCConnection, command: str, command_id: int):
    """
    发送聊天命令（1.19.3+，协议 761+）
    命令不带斜杠，格式为纯 String
    """
    if command.startswith('/'):
        command = command[1:]
    conn.send_packet(command_id, write_string(command[:256]))


def _handle_play_packets(conn: MCConnection, packets: dict, stop_event: threading.Event):
    """
    后台线程：处理 Play 阶段的 incoming 包
    必须处理 Keep Alive 和 Teleport，否则会被服务器踢
    packets: 分版本的包 ID 表
    """
    while not stop_event.is_set():
        try:
            packet_id, data = conn.recv_packet(timeout=1.0)
        except socket.timeout:
            continue
        except Exception:
            break

        if packet_id == packets["cb_keep_alive"]:
            # Keep Alive 必须回复
            if len(data) >= 8:
                try:
                    conn.send_packet(packets["sb_keep_alive"], data[:8])
                except Exception:
                    break

        elif packet_id == packets["cb_teleport"]:
            # 同步位置，需要回复 Confirm Teleport
            try:
                buf = io.BytesIO(data)
                teleport_id = read_varint_from_stream(buf)
                conn.send_packet(packets["sb_confirm_teleport"],
                                 write_varint(teleport_id))
            except Exception:
                pass

        elif packet_id == packets["cb_ping"]:
            # Ping 需要回复 Pong
            if len(data) >= 4:
                try:
                    conn.send_packet(packets["sb_pong"], data[:4])
                except Exception:
                    break

        elif packet_id == packets["cb_disconnect"]:
            # 被踢
            break

        # 其他包忽略（Login Play, Chunk Data, Chat 等）


def join_and_warn(
    host: str,
    port: int = 25565,
    username: str = "SecurityBot",
    messages: list[str] | None = None,
    timeout: float = 20.0,
    message_delay: float = 0.6,
    protocol_version: int | None = None,
    authme_password: str | None = None,
) -> BotResult:
    """
    完整流程：连接 → 登录 → 配置 → 发警告 → 退出

    Args:
        host: 服务器 IP
        port: 端口
        username: 机器人用户名
        messages: 警告消息列表，None 用默认
        timeout: 连接超时
        message_delay: 消息间隔秒数
        protocol_version: 强制指定协议版本，None 则自动从 SLP 检测
        authme_password: AuthMe 自动注册/登录密码，None 不启用

    Returns:
        BotResult
    """
    if messages is None:
        messages = DEFAULT_WARNING_MESSAGES

    result = BotResult(ip=host, port=port)

    # 获取服务器信息（SLP）
    result.server_info = server_list_ping(host, port, timeout=5.0)

    # 提取服务器信息
    if result.server_info:
        v = result.server_info.get('version', {})
        p = result.server_info.get('players', {})
        result.version_name = v.get('name', '')
        result.players_online = p.get('online', 0)
        result.players_max = p.get('max', 0)
        desc = result.server_info.get('description', '')
        if isinstance(desc, dict):
            result.motd = desc.get('text', str(desc))[:200]
        else:
            result.motd = str(desc)[:200]

    # 确定协议版本
    if protocol_version is None:
        if result.server_info and 'version' in result.server_info:
            protocol_version = result.server_info['version'].get('protocol', PROTOCOL_VERSION)
        else:
            # SLP 失败，使用默认协议但标注警告
            protocol_version = PROTOCOL_VERSION
            result.error = "SLP探测失败，使用默认协议(可能不兼容)"

    result.protocol_version = protocol_version

    # 检查版本支持
    packets = get_play_packets(protocol_version)
    if packets is None:
        result.error = f"协议版本 {protocol_version} ({get_version_name(protocol_version)}) 不支持，需要 1.20.2+"
        return result

    version_name = get_version_name(protocol_version)
    conn = MCConnection(host, port, timeout)
    stop_event = threading.Event()
    play_thread = None

    try:
        # ===== 连接 =====
        conn.connect()

        # ===== 握手 (state=2 login)，用服务器的协议版本 =====
        handshake_data = (
            write_varint(protocol_version)
            + write_string(host)
            + struct.pack(">H", port)
            + write_varint(2)  # next state: Login
        )
        conn.send_packet(0x00, handshake_data)
        conn.state = STATE_LOGIN

        # ===== Login Start =====
        player_uuid = offline_uuid(username)
        if packets.get("login_start_uuid", False):
            # 1.20.2+: Login Start 带 UUID
            login_data = write_string(username) + write_uuid(player_uuid)
        else:
            # 1.20.1及以下: Login Start 只有用户名
            login_data = write_string(username)
        conn.send_packet(LOGIN_SB_LOGIN_START, login_data)

        # ===== Login 阶段：等待 Login Success =====
        login_ok = False
        while conn.state == STATE_LOGIN:
            packet_id, data = conn.recv_packet(timeout=timeout)
            buf = io.BytesIO(data)

            if packet_id == LOGIN_CB_ENCRYPTION_REQUEST:
                # 在线模式服务器
                result.auth_mode = "online"
                result.error = "online-mode (服务器要求正版验证)"
                conn.close()
                return result

            elif packet_id == LOGIN_CB_DISCONNECT:
                reason = read_string_from_stream(buf)
                reason_lower = reason.lower()
                # 白名单检测：断开消息含 whitelist/白名单关键词
                if "whitelist" in reason_lower or "白名单" in reason or "not white-listed" in reason_lower:
                    result.is_whitelist = True
                    result.auth_mode = "whitelist"
                    result.error = f"whitelist: {reason[:120]}"
                else:
                    result.auth_mode = "rejected"
                    result.error = f"登录被踢: {reason[:150]}"
                conn.close()
                return result

            elif packet_id == LOGIN_CB_SET_COMPRESSION:
                threshold = read_varint_from_stream(buf)
                conn.compression_threshold = threshold

            elif packet_id == LOGIN_CB_LOGIN_SUCCESS:
                # 登录成功
                if packets.get("uuid_is_string", False):
                    # 1.15.2及以下：UUID 是 36 字符字符串
                    uuid_str = read_string_from_stream(buf)
                    uuid_val = uuid.UUID(uuid_str) if uuid_str else uuid.uuid4()
                else:
                    # 1.16+：UUID 是 16 字节二进制
                    uuid_val = read_uuid_from_stream(buf)
                name = read_string_from_stream(buf)
                if packets.get("has_configuration", False):
                    # 1.20.2+: 发 ACK，进入 configuration 状态
                    conn.send_packet(LOGIN_SB_LOGIN_ACKNOWLEDGED)
                    conn.state = STATE_CONFIGURATION
                else:
                    # 1.20.1及以下: 直接进入 play 状态
                    conn.state = STATE_PLAY
                login_ok = True
                result.auth_mode = "offline"

            elif packet_id == LOGIN_CB_LOGIN_PLUGIN_REQUEST:
                # 插件请求，回复 declined
                msg_id = read_varint_from_stream(buf)
                response = write_varint(msg_id) + b'\x00'
                conn.send_packet(0x02, response)

        if not login_ok:
            result.error = "登录流程异常"
            conn.close()
            return result

        # ===== Configuration 阶段（仅 1.20.2+）=====
        config_ok = True
        if packets.get("has_configuration", False):
            cfg = packets.get("config", {})
            cb_finish = cfg.get("cb_finish", CONFIG_CB_FINISH_CONFIGURATION)
            cb_known_packs = cfg.get("cb_known_packs", CONFIG_CB_KNOWN_PACKS)
            cb_keep_alive = cfg.get("cb_keep_alive", CONFIG_CB_KEEP_ALIVE)
            cb_ping = cfg.get("cb_ping", CONFIG_CB_PING)
            cb_add_rp = cfg.get("cb_add_resource_pack", CONFIG_CB_ADD_RESOURCE_PACK)
            cb_disconnect = cfg.get("cb_disconnect", CONFIG_CB_DISCONNECT)
            sb_client_info = cfg.get("sb_client_info", CONFIG_SB_CLIENT_INFORMATION)
            sb_plugin = cfg.get("sb_plugin", CONFIG_SB_PLUGIN_MESSAGE)
            sb_finish = cfg.get("sb_finish", CONFIG_SB_FINISH_CONFIGURATION)
            sb_known_packs = cfg.get("sb_known_packs", CONFIG_SB_KNOWN_PACKS)
            sb_keep_alive = cfg.get("sb_keep_alive", CONFIG_SB_KEEP_ALIVE)
            sb_pong = cfg.get("sb_pong", CONFIG_SB_PONG)
            sb_rp = cfg.get("sb_resource_pack", CONFIG_SB_RESOURCE_PACK_RESPONSE)

            # 发送 Client Information
            conn.send_packet(sb_client_info, _build_client_information(protocol_version))

            # 发送 brand
            brand_payload = write_string("minecraft:brand") + write_string("MCScanner")
            conn.send_packet(sb_plugin, brand_payload)

            config_ok = False
            config_start = time.time()
            config_fallback = 3.0  # 超时兜底：3s没收到finish就主动发(借鉴v2)
            while conn.state == STATE_CONFIGURATION:
                # 超时兜底：某些服务器(Paper/Spigot某些版本)可能不主动发finish
                if time.time() - config_start > config_fallback and not config_ok:
                    try:
                        conn.send_packet(sb_finish)
                        conn.state = STATE_PLAY
                        config_ok = True
                        break
                    except Exception:
                        break
                packet_id, data = conn.recv_packet(timeout=min(timeout, 1.0))
                buf = io.BytesIO(data)

                if packet_id == cb_finish:
                    conn.send_packet(sb_finish)
                    conn.state = STATE_PLAY
                    config_ok = True

                elif packet_id == cb_known_packs:
                    # 回显服务器发的 packs（关键！不能发空列表）
                    pack_count = read_varint_from_stream(buf)
                    response = write_varint(pack_count)
                    for _ in range(pack_count):
                        ns = read_string_from_stream(buf)
                        pid = read_string_from_stream(buf)
                        ver = read_string_from_stream(buf)
                        response += write_string(ns) + write_string(pid) + write_string(ver)
                    conn.send_packet(sb_known_packs, response)

                elif packet_id == cb_keep_alive:
                    if len(data) >= 8:
                        conn.send_packet(sb_keep_alive, data[:8])

                elif packet_id == cb_ping:
                    if len(data) >= 4:
                        conn.send_packet(sb_pong, data[:4])

                elif packet_id == cb_add_rp:
                    # 资源包，回复 accepted (3)
                    # 764 只有 result，UUID 是 765+ 才引入的
                    if protocol_version >= 765:
                        rp_uuid = read_uuid_from_stream(buf)
                        response = write_uuid(rp_uuid) + write_varint(3)
                    else:
                        response = write_varint(3)
                    conn.send_packet(sb_rp, response)

                elif packet_id == cb_disconnect:
                    try:
                        reason = read_string_from_stream(buf)
                    except Exception:
                        reason = data.hex()
                    result.error = f"配置阶段被踢: {reason[:150]}"
                    conn.close()
                    return result

                # 其他包忽略（Registry Data, Update Tags, Feature Flags 等）

            if not config_ok:
                result.error = "配置阶段异常"
                conn.close()
                return result

        # 确认是离线模式（走到这里说明没有 Encryption Request）
        result.is_offline = True

        # ===== Play 阶段 =====
        # 1.20.2+ 启动后台线程处理 Keep Alive / Teleport
        # 老版本连接时间短，不需要处理
        play_thread = None
        if "cb_keep_alive" in packets:
            stop_event.clear()
            play_thread = threading.Thread(
                target=_handle_play_packets,
                args=(conn, packets, stop_event),
                daemon=True,
            )
            play_thread.start()

        # 等一下让服务器完成初始化（发 Login Play, Chunk 等）
        time.sleep(1.5)

        # 选择聊天格式
        fmt = packets["chat_format"]
        if fmt == "new":
            send_chat = _send_chat_message_new
        elif fmt == "old_signed_759":
            send_chat = _send_chat_message_759
        elif fmt == "old_signed_760":
            send_chat = _send_chat_message_760
        elif fmt == "old_signed_761":
            send_chat = _send_chat_message_761
        else:  # simple
            send_chat = _send_chat_message_simple

        # AuthMe 自动注册/登录（默认启用，密码自动生成随机字符串）
        # authme_password 为 None/空字符串时自动生成；设为 False 可禁用
        if authme_password is not False:
            if not authme_password:
                import random, string
                authme_password = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            try:
                # 764/765 的 chat_command 是签名格式，只发String会流错位
                # 这些版本改用普通聊天消息发送指令；766+ 才用纯String的chat_command
                use_cmd = "sb_chat_command" in packets and protocol_version >= 766
                cmd_id = packets.get("sb_chat_command", packets["sb_chat"])
                # 先尝试登录（可能已注册）
                if use_cmd:
                    _send_chat_command(conn, f"/login {authme_password}", cmd_id)
                else:
                    send_chat(conn, f"/login {authme_password}", packets["sb_chat"], protocol_version)
                time.sleep(0.5)
                # 再尝试注册（新账号）
                if use_cmd:
                    _send_chat_command(conn, f"/register {authme_password} {authme_password}", cmd_id)
                else:
                    send_chat(conn, f"/register {authme_password} {authme_password}", packets["sb_chat"], protocol_version)
                time.sleep(1.0)
                # 再登录一次确保生效
                if use_cmd:
                    _send_chat_command(conn, f"/login {authme_password}", cmd_id)
                else:
                    send_chat(conn, f"/login {authme_password}", packets["sb_chat"], protocol_version)
                time.sleep(0.5)
                result.authme_used = True
            except Exception:
                pass

        # 发送警告消息
        sent = 0
        for msg in messages:
            try:
                send_chat(conn, msg, packets["sb_chat"], protocol_version)
                sent += 1
                time.sleep(message_delay)
            except Exception as e:
                result.error = f"发送消息失败: {str(e)[:100]}"
                break

        result.messages_sent = sent

        # 等一下让消息送达
        time.sleep(1.0)

        if sent > 0:
            result.success = True

    except socket.timeout:
        result.error = result.error or "连接超时"
    except ConnectionRefusedError:
        result.error = "连接被拒绝"
    except Exception as e:
        result.error = f"错误: {str(e)[:150]}"
    finally:
        stop_event.set()
        if play_thread:
            play_thread.join(timeout=2.0)
        conn.close()

    return result


def scan_and_warn(
    targets: list[tuple[str, int]],
    username: str = "SecurityBot",
    messages: list[str] | None = None,
    max_workers: int = 10,
    timeout: float = 20.0,
) -> list[BotResult]:
    """
    批量对服务器进行离线模式检测和警告
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []
    total = len(targets)

    print(f"[*] 开始对 {total} 个服务器进行检测和警告（并发 {max_workers}）")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(join_and_warn, ip, port, username, messages, timeout): (ip, port)
            for ip, port in targets
        }

        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)

            icon = "✓" if result.success else "✗"
            tag = "[离线]" if result.is_offline else "[其他]"
            ver = get_version_name(result.protocol_version) if result.protocol_version else "?"
            err = f" | {result.error}" if result.error else ""
            print(f"  [{i}/{total}] {icon} {result.ip}:{result.port} "
                  f"{tag} {ver} 发{result.messages_sent}条{err}")

    success = sum(1 for r in results if r.success)
    offline = sum(1 for r in results if r.is_offline)
    print(f"[*] 完成: 共{total}个, 离线模式{offline}个, 成功警告{success}个")

    return results
