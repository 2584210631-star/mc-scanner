#!/usr/bin/env python3
"""
Minecraft 服务器命令执行工具
使用命令包 (chat_command) 发送指令，而不是普通聊天消息
用法: python3 mc_send_command.py <IP> <端口> <用户名> <命令>
示例: python3 mc_send_command.py 103.85.86.51 43453 Fejiehe "op IRmks"
"""

import sys
import time
import uuid
import threading

from mc_protocol import (
    MCConnection,
    server_list_ping,
    get_play_packets,
    write_string,
    write_uuid,
    write_varint,
)
from bot import _send_chat_command, _handle_play_packets


def send_command(ip: str, port: int, username: str, command: str, timeout: int = 15) -> bool:
    """登录服务器并用命令包执行指令"""
    # SLP 探测获取协议版本
    info = server_list_ping(ip, port, timeout=5)
    if not info:
        print(f"[错误] 无法连接 {ip}:{port}")
        return False

    proto = info["version"]["protocol"]
    players_online = info["players"]["online"]
    print(f"[信息] 服务器: {info['version']['name']} (协议{proto}), 在线: {players_online}")

    packets = get_play_packets(proto)
    player_uuid = uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{username}")

    # 连接
    conn = MCConnection(ip, port, timeout=timeout)
    conn.connect()
    print(f"[信息] 已连接 {ip}:{port}")

    # 握手 (state=2 login)
    handshake = write_varint(proto) + write_string(ip) + port.to_bytes(2, "big") + write_varint(2)
    conn.send_packet(0x00, handshake)

    # Login Start (带 UUID, 1.19+)
    login_data = write_string(username) + write_uuid(player_uuid)
    conn.send_packet(0x00, login_data)

    # 等待 Login Success (可能先收到 Set Compression)
    login_ok = False
    for _ in range(50):
        pid, data = conn.recv_packet()
        if pid == 0x03:  # Set Compression
            conn.compression_threshold = int.from_bytes(data[:1], "big") if data else 0
        elif pid == 0x02:  # Login Success
            login_ok = True
            break
        elif pid == 0x00:  # Disconnect
            print(f"[错误] 登录被踢: {data[:100]}")
            return False

    if not login_ok:
        print("[错误] 登录失败")
        return False

    print(f"[信息] 登录成功: {username}")
    conn.send_packet(0x03, b"")  # Login Acknowledged

    # 配置阶段
    cfg = packets.get("config", {})
    cfg_done = False
    while not cfg_done:
        pid, data = conn.recv_packet()
        if pid == cfg.get("cb_finish", 0x03):
            conn.send_packet(cfg.get("sb_finish", 0x03), b"")
            cfg_done = True
        elif pid == cfg.get("cb_keep_alive", 0x04):
            conn.send_packet(cfg.get("sb_keep_alive", 0x04), data)
        elif pid == cfg.get("cb_known_packs", 0x0E):
            conn.send_packet(cfg.get("sb_known_packs", 0x07), write_varint(0))
        elif pid == 0x00:
            print(f"[错误] 配置阶段被踢: {data[:100]}")
            return False

    print("[信息] 配置阶段完成，进入 Play")

    # 启动后台线程处理保活/传送等包
    stop_event = threading.Event()
    handler = threading.Thread(
        target=_handle_play_packets,
        args=(conn, packets, stop_event),
        daemon=True,
    )
    handler.start()

    time.sleep(2)  # 等 Play 阶段初始化

    # 用命令包发送指令 (去掉开头的 /)
    cmd = command.lstrip("/")
    cmd_id = packets.get("sb_chat_command", packets["sb_chat"])
    _send_chat_command(conn, cmd, cmd_id)
    print(f"[成功] 已发送命令: /{cmd}")

    time.sleep(2)
    stop_event.set()
    conn.close()
    print("[信息] 完成")
    return True


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    username = sys.argv[3]
    command = sys.argv[4]

    send_command(ip, port, username, command)


if __name__ == "__main__":
    main()
