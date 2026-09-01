#!/usr/bin/env python3
"""测试 1.12.2 (协议340) 纯String格式的 Mock 服务器"""
import io, socket, struct, time, uuid, zlib, sys
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
        pd = (write_varint(len(unc)) + zlib.compress(unc)) if len(unc) >= comp else (write_varint(0) + unc)
    else:
        pd = unc
    client.sendall(write_varint(len(pd)) + pd)

def recv_pkt(stream, comp=-1):
    length = read_varint_from_stream(stream)
    raw = stream.read(length)
    if comp >= 0:
        buf = io.BytesIO(raw); dl = read_varint_from_stream(buf)
        dec = zlib.decompress(buf.read()) if dl else buf.read()
    else:
        dec = raw
    buf = io.BytesIO(dec)
    return read_varint_from_stream(buf), buf.read()

def run():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 25567)); srv.listen(1); srv.settimeout(20)
    print("[MOCK340] 启动在 25567 (协议340=1.12.2)")

    for _ in range(3):
        try: client, _ = srv.accept()
        except: break
        st = S(client); comp = -1
        try:
            pid, data = recv_pkt(st)
            buf = io.BytesIO(data)
            proto = read_varint_from_stream(buf); read_string_from_stream(buf); buf.read(2)
            ns = read_varint_from_stream(buf)
            print(f"[MOCK340] 握手 proto={proto} next_state={ns}")
            if ns == 1:
                info = '{"version":{"name":"1.12.2","protocol":340},"players":{"online":0,"max":20},"description":{"text":"Mock 1.12.2"}}'
                send_pkt(client, 0x00, write_string(info)); client.close(); continue

            # Login Start (1.12只有username)
            pid, data = recv_pkt(st)
            buf = io.BytesIO(data)
            uname = read_string_from_stream(buf)
            print(f"[MOCK340] Login Start: {uname} (无UUID字段)")

            # Set Compression
            comp = 256
            send_pkt(client, 0x03, write_varint(comp), -1)
            # Login Success (直接进play，无configuration)
            # 1.12.2 (协议340) 的 UUID 是字符串格式，不是16字节二进制
            suid = uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{uname}")
            send_pkt(client, 0x02, write_string(str(suid)) + write_string(uname), comp)
            print("[MOCK340] 已发送 Login Success (字符串UUID) -> 直接Play")

            # 发个 Keep Alive (1.12是0x1F, VarInt)
            send_pkt(client, 0x1F, write_varint(42), comp)
            print("[MOCK340] 已发送 Keep Alive(0x1F)")

            client.settimeout(8)
            msgs = []
            start = time.time()
            while time.time() - start < 8:
                try:
                    pid, data = recv_pkt(st, comp)
                    if pid == 0x02:  # Chat Message (1.12 serverbound)
                        buf = io.BytesIO(data)
                        msg = read_string_from_stream(buf)
                        msgs.append(msg)
                        print(f"[MOCK340] 收到聊天(0x02纯String): '{msg}'")
                    elif pid == 0x0C:  # Keep Alive回复
                        print("[MOCK340] 收到 Keep Alive 回复(0x0C)")
                    else:
                        print(f"[MOCK340] 其他包: 0x{pid:02x}")
                except: break
            print(f"[MOCK340] 完成，收到 {len(msgs)} 条: {msgs}")
        except Exception as e:
            print(f"[MOCK340] 错误: {e}")
        finally:
            client.close()
    srv.close()

if __name__ == '__main__':
    run()
