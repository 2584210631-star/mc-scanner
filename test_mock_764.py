#!/usr/bin/env python3
"""测试 1.20.2 (协议 764) 旧格式的 Mock 服务器"""
import io, socket, struct, time, uuid, zlib, sys, threading
sys.path.insert(0, '.')
from mc_protocol import write_varint, write_string, write_uuid, read_varint_from_stream, read_string_from_stream, read_uuid_from_stream

class S:
    def __init__(self, s): self.s = s
    def read(self, n):
        b = b''
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c: raise ConnectionError()
            b += c
        return b

def send_pkt(client, pid, payload=b'', comp=-1):
    unc = write_varint(pid) + payload
    if comp >= 0:
        if len(unc) >= comp:
            pd = write_varint(len(unc)) + zlib.compress(unc)
        else:
            pd = write_varint(0) + unc
    else:
        pd = unc
    client.sendall(write_varint(len(pd)) + pd)

def recv_pkt(stream, comp=-1):
    length = read_varint_from_stream(stream)
    raw = stream.read(length)
    if comp >= 0:
        buf = io.BytesIO(raw)
        dl = read_varint_from_stream(buf)
        dec = zlib.decompress(buf.read()) if dl else buf.read()
    else:
        dec = raw
    buf = io.BytesIO(dec)
    return read_varint_from_stream(buf), buf.read()

# 764 包 ID
CB_KEEP_ALIVE = 0x24
CB_TELEPORT = 0x3E
CB_DISCONNECT = 0x1B
CB_PING = 0x33
CB_LOGIN = 0x29
SB_KEEP_ALIVE = 0x14
SB_CHAT = 0x05
SB_CONFIRM_TELEPORT = 0x00
SB_PONG = 0x23

def run():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 25566))
    srv.listen(1)
    srv.settimeout(20)
    print("[MOCK764] 启动在 25566 (协议764)")

    for _ in range(3):
        try: client, _ = srv.accept()
        except: break
        st = S(client)
        comp = -1
        try:
            pid, data = recv_pkt(st)
            buf = io.BytesIO(data)
            proto = read_varint_from_stream(buf)
            read_string_from_stream(buf)
            buf.read(2)
            ns = read_varint_from_stream(buf)
            print(f"[MOCK764] 握手 proto={proto} next_state={ns}")

            if ns == 1:
                info = '{"version":{"name":"1.20.2","protocol":764},"players":{"online":0,"max":20},"description":{"text":"Mock 1.20.2"}}'
                send_pkt(client, 0x00, write_string(info))
                client.close()
                continue

            # Login
            pid, data = recv_pkt(st)
            buf = io.BytesIO(data)
            uname = read_string_from_stream(buf)
            print(f"[MOCK764] Login Start: {uname}")

            comp = 256
            send_pkt(client, 0x03, write_varint(comp), -1)  # Set Compression 本身不压缩
            suid = uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{uname}")
            send_pkt(client, 0x02, write_uuid(suid) + write_string(uname), comp)
            pid, _ = recv_pkt(st, comp)
            print(f"[MOCK764] Login ACK (0x{pid:02x})")

            # Configuration
            send_pkt(client, 0x00, b'\x02en_us\x08\x00\x01\x7f\x01\x00\x01\x00', comp)  # client info won't be read by us, skip
            pid, _ = recv_pkt(st, comp)  # client info
            pid, _ = recv_pkt(st, comp)  # brand
            # Known packs
            send_pkt(client, 0x0E, write_varint(1) + write_string("minecraft") + write_string("core") + write_string("1.20.2"), comp)
            pid, data = recv_pkt(st, comp)
            buf = io.BytesIO(data)
            cnt = read_varint_from_stream(buf)
            print(f"[MOCK764] Known Packs回显: {cnt}个 (0x{pid:02x})")
            # Finish (真实764配置阶段finish=0x02)
            send_pkt(client, 0x02, b'', comp)
            pid, _ = recv_pkt(st, comp)
            print(f"[MOCK764] Finish ACK (0x{pid:02x})")

            # Play
            login_play = struct.pack(">i", 1) + b'\x00' + write_varint(1) + write_string("minecraft:overworld") * 3 + struct.pack(">q", 0) + write_varint(20) + write_varint(8) * 2 + b'\x00\x01\x00\x00\x00\x00' + struct.pack(">i", 0)
            send_pkt(client, CB_LOGIN, login_play, comp)
            send_pkt(client, CB_KEEP_ALIVE, struct.pack(">q", 999), comp)
            print("[MOCK764] 已发送 Login Play + Keep Alive(0x24)")

            client.settimeout(8)
            msgs = []
            start = time.time()
            while time.time() - start < 8:
                try:
                    pid, data = recv_pkt(st, comp)
                    if pid == SB_CHAT:
                        buf = io.BytesIO(data)
                        msg = read_string_from_stream(buf)
                        ts = struct.unpack(">q", buf.read(8))[0]
                        salt = struct.unpack(">q", buf.read(8))[0]
                        has_sig = buf.read(1)[0]
                        # 1.19.3+ (协议761+) 正确格式: offset(VarInt) + acknowledged(BitSet 3字节)
                        offset = read_varint_from_stream(buf)
                        acknowledged = buf.read(3)
                        msgs.append(msg)
                        print(f"[MOCK764] 收到聊天(0x05): '{msg}' offset={offset} ack={acknowledged.hex()}")
                    elif pid == SB_KEEP_ALIVE:
                        print("[MOCK764] 收到 Keep Alive 回复(0x14)")
                    elif pid == SB_CONFIRM_TELEPORT:
                        print("[MOCK764] 收到 Confirm Teleport(0x00)")
                    elif pid == SB_PONG:
                        print("[MOCK764] 收到 Pong(0x23)")
                    else:
                        print(f"[MOCK764] 其他包: 0x{pid:02x}")
                except: break
            print(f"[MOCK764] 完成，收到 {len(msgs)} 条消息: {msgs}")
        except Exception as e:
            print(f"[MOCK764] 错误: {e}")
        finally:
            client.close()
    srv.close()

if __name__ == '__main__':
    run()
