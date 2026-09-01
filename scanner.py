"""
端口扫描模块（加强版）
支持 CIDR 网段、端口范围、多线程并发、结果去重、进度回调、可停止
"""
import socket
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class ScanResult:
    """扫描结果"""
    ip: str
    port: int
    is_open: bool
    latency_ms: float = 0.0
    error: str = ""


def parse_port_spec(spec: str) -> list[int]:
    """
    解析端口规格，支持：
    - 单个端口: "25565"
    - 逗号分隔: "25565,25566,25570"
    - 范围: "25565-25575"
    - 混合: "25565,25570-25580"
    """
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                for p in range(start, min(end, 65535) + 1):
                    ports.add(p)
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(ports)


MAX_TARGETS = 2_000_000  # 防止大网段 OOM


def parse_targets(targets: list[str], default_ports: list[int] | None = None) -> list[tuple[str, int]]:
    """
    解析目标列表，支持以下格式：
    - 单个 IP: "192.168.1.1"
    - IP:端口: "192.168.1.1:25566"
    - CIDR 网段: "192.168.1.0/24"
    - CIDR:端口: "192.168.1.0/24:25566"
    - 主机名: "example.com"
    - 主机名:端口: "example.com:25566"
    如果目标不带端口，使用 default_ports 展开
    返回 (ip, port) 列表（超过 MAX_TARGETS 会截断并警告）
    """
    if default_ports is None:
        default_ports = [25565]

    results = []
    for target in targets:
        target = target.strip()
        if not target or target.startswith('#'):
            continue

        # 检查是否包含端口（最后一段是数字）
        addr_part = target
        port = None
        if target.count(':') == 1:
            parts = target.rsplit(':', 1)
            if parts[1].isdigit():
                addr_part = parts[0]
                port = int(parts[1])

        # 尝试解析为 CIDR 或 IP
        try:
            network = ipaddress.ip_network(addr_part, strict=False)
            num_hosts = network.num_addresses - 2 if network.num_addresses > 2 else 1
            est = num_hosts * (1 if port else len(default_ports))
            if len(results) + est > MAX_TARGETS:
                print(f"[!] 目标 {target} 约 {est} 个，超过上限 {MAX_TARGETS}，已跳过（请缩小网段）")
                continue
            # 直接迭代，不物化整个列表，避免大网段中间占用
            hosts = network.hosts() if network.num_addresses > 2 else [network.network_address]
            for ip in hosts:
                if port is not None:
                    results.append((str(ip), port))
                else:
                    for p in default_ports:
                        results.append((str(ip), p))
        except ValueError:
            # 不是 CIDR/IP，当作主机名
            try:
                resolved = socket.gethostbyname(addr_part)
                if port is not None:
                    results.append((resolved, port))
                else:
                    for p in default_ports:
                        results.append((resolved, p))
            except socket.gaierror:
                print(f"[!] 无法解析: {addr_part}")
    return results


def check_port(ip: str, port: int, timeout: float = 3.0) -> ScanResult:
    """检查单个端口是否开放（TCP 全连接扫描）"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        latency = (time.time() - start) * 1000
        sock.close()
        if result == 0:
            return ScanResult(ip=ip, port=port, is_open=True, latency_ms=latency)
        return ScanResult(ip=ip, port=port, is_open=False, latency_ms=latency,
                          error=f"connect_ex={result}")
    except socket.timeout:
        return ScanResult(ip=ip, port=port, is_open=False, error="timeout")
    except Exception as e:
        return ScanResult(ip=ip, port=port, is_open=False, error=str(e)[:100])


def scan_ports(
    targets: list[tuple[str, int]],
    max_workers: int = 200,
    timeout: float = 3.0,
    show_progress: bool = True,
    progress_callback: Optional[Callable[[int, int, int], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> list[ScanResult]:
    """
    多线程扫描端口
    Args:
        targets: (ip, port) 列表
        max_workers: 并发线程数
        timeout: 连接超时
        show_progress: 是否打印进度
        progress_callback: 回调函数(done, total, open_count)
        stop_event: 停止事件，设置后提前结束
    Returns:
        所有结果（包括关闭的）
    """
    results = []
    total = len(targets)
    done = 0
    open_count = 0
    lock = threading.Lock()

    if show_progress:
        print(f"[*] 开始扫描 {total} 个目标，并发数 {max_workers}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for ip, port in targets:
            if stop_event and stop_event.is_set():
                break
            futures[executor.submit(check_port, ip, port, timeout)] = (ip, port)

        for future in as_completed(futures):
            if stop_event and stop_event.is_set():
                # 取消剩余任务
                for f in futures:
                    f.cancel()
                break
            try:
                result = future.result()
            except Exception:
                continue
            results.append(result)
            with lock:
                done += 1
                if result.is_open:
                    open_count += 1
                if progress_callback:
                    progress_callback(done, total, open_count)
                if show_progress and (done % 500 == 0 or done == total):
                    print(f"[*] 进度: {done}/{total} ({done*100//total}%) 开放: {open_count}")

    if show_progress:
        print(f"[*] 扫描完成，共 {total} 个目标，开放 {open_count} 个")

    return results


def get_open_ports(results: list[ScanResult]) -> list[tuple[str, int]]:
    """从扫描结果中提取开放的 (ip, port)"""
    return [(r.ip, r.port) for r in results if r.is_open]


def deduplicate_targets(targets: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """去重目标列表"""
    seen = set()
    unique = []
    for ip, port in targets:
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique
