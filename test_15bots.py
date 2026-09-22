"""并发机器人压力测试（pytest 版）。

原脚本直接对公网真实服务器（103.85.86.51:41543）发起 15 个真实登录，
已改为本地 Mock 服务器，避免对未授权目标发起真实连接。
"""
import sys
import threading

sys.path.insert(0, '.')
from bot import join_and_warn
from mc_protocol import server_list_ping
from test_mock_server import MockServer

BOT_COUNT = 3
MESSAGE = "concurrency test message"


def test_concurrent_bots():
    """多个机器人并发对 mock 774 登录发消息，断言有成功且消息送达"""
    srv = MockServer('127.0.0.1', 0)
    srv.start()
    port = srv.port

    # 每台服务器连接（SLP + 登录）由一个独立线程处理，模拟真实并发
    handlers = []
    for _ in range(BOT_COUNT * 2 + 2):
        th = threading.Thread(
            target=lambda: srv.accept_and_handle(max_connections=1), daemon=True
        )
        handlers.append(th)
        th.start()

    try:
        info = server_list_ping('127.0.0.1', port, timeout=5, protocol_version=774)
        assert info, "SLP 探测 mock 失败"

        results = []
        lock = threading.Lock()

        def bot_worker(i):
            try:
                r = join_and_warn(
                    '127.0.0.1', port,
                    username=f"Bot{i:02d}", messages=[MESSAGE], timeout=15,
                    protocol_version=774,
                )
                with lock:
                    results.append(r.success)
            except Exception:
                with lock:
                    results.append(False)

        threads = [
            threading.Thread(target=bot_worker, args=(i,))
            for i in range(BOT_COUNT)
        ]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=40)

        assert results, "没有任何并发结果产生"
        assert sum(results) >= 1, f"并发 bot 全部失败: {results}"
        assert any(MESSAGE in m for m in srv.received_messages), \
            f"mock 未收到任何消息: {srv.received_messages}"
    finally:
        srv.stop()
