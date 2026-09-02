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


def parse_targets(targets: list[str], default_ports: list[int] | None = None):
    """
    解析目标列表（惰性生成器，不物化，避免大网段OOM）
    支持格式：单个IP、IP:端口、CIDR网段、CIDR:端口、主机名、主机名:端口
    如果目标不带端口，使用 default_ports 展开
    超过 MAX_TARGETS 的目标会跳过并警告
    """
    if default_ports is None:
        default_ports = [25565]

    count = 0
    for target in targets:
        target = target.strip()
        if not target or target.startswith('#'):
            continue

        addr_part = target
        port = None
        if target.count(':') == 1:
            parts = target.rsplit(':', 1)
            if parts[1].isdigit():
                addr_part = parts[0]
                port = int(parts[1])

        try:
            network = ipaddress.ip_network(addr_part, strict=False)
            num_hosts = network.num_addresses - 2 if network.num_addresses > 2 else 1
            est = num_hosts * (1 if port else len(default_ports))
            if count + est > MAX_TARGETS:
                print(f"[!] 目标 {target} 约 {est} 个，超过上限 {MAX_TARGETS}，已跳过（请缩小网段或用连续扫描模式）")
                continue
            hosts = network.hosts() if network.num_addresses > 2 else [network.network_address]
            for ip in hosts:
                if port is not None:
                    count += 1
                    yield (str(ip), port)
                else:
                    for p in default_ports:
                        count += 1
                        yield (str(ip), p)
        except ValueError:
            try:
                resolved = socket.gethostbyname(addr_part)
                if port is not None:
                    count += 1
                    yield (resolved, port)
                else:
                    for p in default_ports:
                        count += 1
                        yield (resolved, p)
            except socket.gaierror:
                print(f"[!] 无法解析: {addr_part}")


def count_targets(targets: list[str], default_ports: list[int] | None = None) -> int:
    """快速估算目标总数（不物化，只计数）"""
    if default_ports is None:
        default_ports = [25565]
    count = 0
    for target in targets:
        target = target.strip()
        if not target or target.startswith('#'):
            continue
        addr_part = target
        port = None
        if target.count(':') == 1:
            parts = target.rsplit(':', 1)
            if parts[1].isdigit():
                addr_part = parts[0]
                port = int(parts[1])
        try:
            network = ipaddress.ip_network(addr_part, strict=False)
            num_hosts = network.num_addresses - 2 if network.num_addresses > 2 else 1
            count += num_hosts * (1 if port else len(default_ports))
        except ValueError:
            try:
                socket.gethostbyname(addr_part)
                count += 1 if port else len(default_ports)
            except socket.gaierror:
                pass
    return min(count, MAX_TARGETS)


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
    targets,
    max_workers: int = 200,
    timeout: float = 3.0,
    show_progress: bool = True,
    progress_callback: Optional[Callable[[int, int, int], None]] = None,
    stop_event: Optional[threading.Event] = None,
    rate: int = 0,
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
        rate: 每秒最大连接数，0=不限速
    Returns:
        所有结果（包括关闭的）
    """
    results = []
    # 生成器转列表（ThreadPoolExecutor需要知道所有任务）
    # 大网段建议用连续扫描模式拆/24逐个扫
    targets = list(targets)
    total = len(targets)
    done = 0
    open_count = 0
    lock = threading.Lock()

    if show_progress:
        print(f"[*] 开始扫描 {total} 个目标，并发数 {max_workers}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        last_submit = time.time()
        submitted = 0
        for ip, port in targets:
            if stop_event and stop_event.is_set():
                break
            # 限速：控制每秒提交数
            if rate > 0:
                submitted += 1
                if submitted % rate == 0:
                    elapsed = time.time() - last_submit
                    if elapsed < 1.0:
                        time.sleep(1.0 - elapsed)
                    last_submit = time.time()
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


def load_exclude_list(filepath: str) -> list:
    """加载排除列表文件，每行一个 CIDR。文件不存在返回空列表。"""
    networks = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    continue
    except FileNotFoundError:
        pass
    return networks


def filter_excluded(targets: list, exclude_networks: list) -> list:
    """过滤掉在排除列表中的目标。IP 无法解析时保留（不排除）。"""
    if not exclude_networks:
        return targets
    filtered = []
    for ip, port in targets:
        try:
            addr = ipaddress.ip_address(ip)
            if any(addr in net for net in exclude_networks):
                continue
        except ValueError:
            pass  # 域名等非IP，不排除
        filtered.append((ip, port))
    return filtered


def has_masscan() -> bool:
    """检测系统是否安装了 masscan"""
    import shutil
    return shutil.which('masscan') is not None


def masscan_scan(
    targets: list[str],
    ports: list[int],
    rate: int = 1000,
    timeout: int = 10,
) -> list[tuple[str, int]]:
    """
    使用 masscan 高速扫描端口（需要 root 权限）
    返回开放的 (ip, port) 列表
    """
    import subprocess
    import tempfile
    import os

    if not has_masscan():
        raise RuntimeError("masscan 未安装")

    # 把目标转成 masscan 格式（去掉端口）
    target_list = []
    for t in targets:
        t = t.strip()
        if ':' in t:
            t = t.rsplit(':', 1)[0]
        target_list.append(t)

    port_str = ','.join(str(p) for p in ports)
    target_str = ' '.join(target_list)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_file = f.name

    try:
        cmd = [
            'masscan', target_str,
            '-p', port_str,
            '--rate', str(rate),
            '--wait', str(timeout),
            '-oJ', output_file,
        ]
        print(f"[*] 使用 masscan 扫描: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        if result.returncode != 0 and result.stderr:
            print(f"[!] masscan 警告: {result.stderr[:200]}")

        # 解析 masscan 输出
        open_ports = []
        try:
            with open(output_file, 'r') as f:
                content = f.read().strip()
                if content:
                    # masscan 输出可能是 JSON 数组，也可能最后有个逗号
                    if content.endswith(','):
                        content = content[:-1]
                    if not content.startswith('['):
                        content = '[' + content + ']'
                    data = json.loads(content)
                    for entry in data:
                        ip = entry.get('ip')
                        for port_info in entry.get('ports', []):
                            if port_info.get('status') == 'open':
                                open_ports.append((ip, port_info['port']))
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"[!] 解析 masscan 输出失败: {e}")

        return open_ports
    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def scan_ports_auto(
    targets: list[str],
    ports: list[int],
    max_workers: int = 200,
    timeout: float = 2.5,
    use_masscan: bool = True,
    masscan_rate: int = 1000,
    progress_callback=None,
    stop_event=None,
) -> list[tuple[str, int]]:
    """
    自动选择扫描方式：有 masscan 且允许则用 masscan，否则用 Python socket
    返回开放的 (ip, port) 列表
    """
    if use_masscan and has_masscan():
        try:
            return masscan_scan(targets, ports, rate=masscan_rate, timeout=int(timeout))
        except Exception as e:
            print(f"[!] masscan 失败({e})，回退 Python 扫描")

    # 回退 Python 扫描
    target_list = list(parse_targets(targets, ports))
    results = scan_ports(target_list, max_workers=max_workers, timeout=timeout,
                         show_progress=True, progress_callback=progress_callback,
                         stop_event=stop_event)
    return get_open_ports(results)
