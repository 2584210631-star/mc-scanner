#!/usr/bin/env python3
"""
Mock Minecraft 离线模式服务器
用于测试机器人的登录/配置/聊天流程
协议版本 774 (1.21.11)
"""

import io
import socket
import struct
import threading
import time
import uuid
import zlib
import sys

sys.path.insert(0, '.')
from mc_protocol import (
    write_varint, write_string, write_uuid,
    read_varint_from_stream, read_string_from_stream, read_uuid_from_stream,
    PROTOCOL_VERSION,
)


class SocketStream:
    """给 socket 加一个 read() 方法，兼容流读取"""
    def __init__(self, sock):
        self.sock = sock
    def read(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf


class MockServer:
    def __init__(self, host='127.0.0.1', port=25565):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.received_messages = []

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        self.sock.settimeout(30)
        self.running = True
        print(f"[MOCK] 服务器启动在 {self.host}:{self.port}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

    def accept_and_handle(self, max_connections=3):
        """接受多个连接并处理（第一个通常是 SLP，第二个是登录）"""
        for i in range(max_connections):
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                print(f"[MOCK] 等待连接超时 ({i}/{max_connections})")
                break

            print(f"[MOCK] 客户端连接 #{i+1}: {addr}")
            client.settimeout(10)

            try:
                self._handle_client(client)
            except Exception as e:
                print(f"[MOCK] 处理错误: {e}")
            finally:
                client.close()

        print(f"[MOCK] 服务器结束，共收到 {len(self.received_messages)} 条消息")
        for i, msg in enumerate(self.received_messages, 1):
            print(f"  消息{i}: {msg}")

    def _send_packet(self, client, packet_id, payload=b'', compression=-1):
        id_bytes = write_varint(packet_id)
        uncompressed = id_bytes + payload
        if compression >= 0:
            if len(uncompressed) >= compression:
                data_length = write_varint(len(uncompressed))
                compressed = zlib.compress(uncompressed)
                packet_data = data_length + compressed
            else:
                packet_data = write_varint(0) + uncompressed
        else:
            packet_data = uncompressed
        frame = write_varint(len(packet_data)) + packet_data
        client.sendall(frame)

    def _recv_packet(self, stream, compression=-1):
        # 读取长度
        length = read_varint_from_stream(stream)
        raw = stream.read(length)

        if compression >= 0:
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

    def _handle_client(self, client):
        stream = SocketStream(client)
        compression = -1
        state = 'handshake'

        # 读取握手包
        packet_id, data = self._recv_packet(stream)
        buf = io.BytesIO(data)
        proto = read_varint_from_stream(buf)
        host = read_string_from_stream(buf)
        port = struct.unpack(">H", buf.read(2))[0]
        next_state = read_varint_from_stream(buf)
        print(f"[MOCK] 握手: proto={proto}, next_state={next_state}")

        if next_state == 1:
            # Status 请求
            status_json = '{"version":{"name":"Mock 1.21.11","protocol":774},"players":{"online":0,"max":20},"description":{"text":"Mock Server"}}'
            self._send_packet(client, 0x00, write_string(status_json))
            print("[MOCK] 已发送 Status Response")
            return

        # next_state == 2: Login
        state = 'login'

        # Login Start
        packet_id, data = self._recv_packet(stream)
        buf = io.BytesIO(data)
        username = read_string_from_stream(buf)
        player_uuid = read_uuid_from_stream(buf)
        print(f"[MOCK] Login Start: username={username}, uuid={player_uuid}")

        # 模拟离线模式：不发 Encryption Request
        # 先发 Set Compression（测试压缩处理）
        compression = 256
        self._send_packet(client, 0x03, write_varint(compression))
        print("[MOCK] 已发送 Set Compression (threshold=256)")

        # Login Success
        success_uuid = uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{username}")
        success_payload = write_uuid(success_uuid) + write_string(username)
        self._send_packet(client, 0x02, success_payload, compression)
        print(f"[MOCK] 已发送 Login Success: {username}")

        # 等待 Login Acknowledged
        packet_id, data = self._recv_packet(stream, compression)
        print(f"[MOCK] 收到 Login Acknowledged (packet_id=0x{packet_id:02x})")
        state = 'configuration'

        # Configuration 阶段
        # 等待 Client Information
        packet_id, data = self._recv_packet(stream, compression)
        print(f"[MOCK] 收到 Client Information (packet_id=0x{packet_id:02x})")

        # 等待 Plugin Message (brand)
        packet_id, data = self._recv_packet(stream, compression)
        print(f"[MOCK] 收到 Plugin Message (packet_id=0x{packet_id:02x})")

        # 发送 Known Packs（测试客户端是否回显）
        known_packs = write_varint(1) + write_string("minecraft") + write_string("core") + write_string("1.21.11")
        self._send_packet(client, 0x0E, known_packs, compression)
        print("[MOCK] 已发送 Known Packs (1个)")

        # 等待客户端回显 Known Packs
        packet_id, data = self._recv_packet(stream, compression)
        buf = io.BytesIO(data)
        pack_count = read_varint_from_stream(buf)
        print(f"[MOCK] 收到 Known Packs 回复: {pack_count}个 (packet_id=0x{packet_id:02x})")

        # 发送 Finish Configuration
        self._send_packet(client, 0x03, b'', compression)
        print("[MOCK] 已发送 Finish Configuration")

        # 等待 Acknowledge Finish Configuration
        packet_id, data = self._recv_packet(stream, compression)
        print(f"[MOCK] 收到 Finish ACK (packet_id=0x{packet_id:02x})")
        state = 'play'

        # 发送 Login Play (让客户端知道进入游戏了)
        login_play = b''
        login_play += struct.pack(">i", 1)  # entity id
        login_play += b'\x00'  # is hardcore = false
        login_play += write_varint(1)  # dimensions count
        login_play += write_string("minecraft:overworld")
        login_play += write_string("minecraft:overworld")  # dimension type
        login_play += write_string("minecraft:overworld")  # dimension name
        login_play += struct.pack(">q", 0)  # hashed seed
        login_play += write_varint(20)  # max players
        login_play += write_varint(8)  # view distance
        login_play += write_varint(8)  # simulation distance
        login_play += b'\x00'  # reduced debug info
        login_play += b'\x01'  # enable respawn screen
        login_play += b'\x00'  # do limited crafting
        login_play += b'\x00'  # is debug
        login_play += b'\x00'  # is flat
        login_play += b'\x00'  # has death location
        login_play += struct.pack(">i", 0)  # portal cooldown
        self._send_packet(client, 0x30, login_play, compression)
        print("[MOCK] 已发送 Login Play")

        # 发送 Keep Alive
        ka_id = struct.pack(">q", 12345)
        self._send_packet(client, 0x2B, ka_id, compression)
        print("[MOCK] 已发送 Keep Alive")

        # 等待客户端发消息（超时 10 秒）
        client.settimeout(10)
        messages_received = 0
        start = time.time()
        while time.time() - start < 10:
            try:
                packet_id, data = self._recv_packet(stream, compression)
                if packet_id == 0x08:  # Chat Message
                    buf = io.BytesIO(data)
                    msg = read_string_from_stream(buf)
                    self.received_messages.append(msg)
                    messages_received += 1
                    print(f"[MOCK] 收到聊天消息: {msg}")
                elif packet_id == 0x1B:  # Keep Alive response
                    print("[MOCK] 收到 Keep Alive 回复")
                elif packet_id == 0x00:  # Confirm Teleport
                    print("[MOCK] 收到 Confirm Teleport")
                else:
                    print(f"[MOCK] 收到其他包: 0x{packet_id:02x}")
            except socket.timeout:
                break
            except Exception as e:
                print(f"[MOCK] 接收错误: {e}")
                break

        print(f"[MOCK] Play 阶段结束，收到 {messages_received} 条聊天消息")


if __name__ == '__main__':
    server = MockServer('127.0.0.1', 25565)
    server.start()
    server.accept_and_handle()
    server.stop()
