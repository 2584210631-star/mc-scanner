#!/usr/bin/env python3
"""
Minecraft 服务器扫描与安全提醒机器人
功能：扫描端口 → SLP探测 → 检测离线模式 → 登录发送警告 → 退出

用法：
  python main.py scan 1.2.3.0/24                    # 扫描+SLP探测
  python main.py warn 1.2.3.0/24                    # 扫描+离线检测+发警告
  python main.py warn -f targets.txt                 # 从文件读目标
  python main.py warn -c config.json 1.2.3.0/24     # 使用配置文件
  python main.py portscan 1.2.3.0/24                # 只扫端口
"""
import argparse
import json
import csv
import sys
import os
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner import parse_targets, scan_ports, get_open_ports, deduplicate_targets, parse_port_spec, count_targets, masscan_scan, has_masscan, scan_ports_auto
from bot import join_and_warn, DEFAULT_WARNING_MESSAGES
from mc_protocol import server_list_ping, get_version_name


# ============================================================
# 配置文件
# ============================================================
DEFAULT_CONFIG = {
    "username": "SecurityBot",
    "messages": None,  # None 表示用默认
    "ports": [25565],
    "scan_threads": 200,
    "scan_timeout": 2.5,
    "bot_threads": 10,
    "bot_timeout": 12,
    "message_delay": 0.8,
    "retry_count": 1,
    "output_format": "json",
    "output_file": None,
}


def load_config(path: str) -> dict:
    """加载配置文件，与默认配置合并"""
    cfg = DEFAULT_CONFIG.copy()
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            user_cfg = json.load(f)
        cfg.update(user_cfg)
        print(f"[*] 已加载配置文件: {path}")
    # 处理端口规格（支持字符串 "25565-25575,25580"）
    if isinstance(cfg.get('ports'), str):
        cfg['ports'] = parse_port_spec(cfg['ports'])
    elif not isinstance(cfg.get('ports'), list):
        cfg['ports'] = [25565]
    return cfg


# ============================================================
# 进度条
# ============================================================
class ProgressBar:
    def __init__(self, total: int, desc: str = "扫描中"):
        self.total = total
        self.done = 0
        self.desc = desc
        self.lock = threading.Lock()
        self.start_time = time.time()

    def update(self, n: int = 1):
        with self.lock:
            self.done += n
            pct = self.done / self.total * 100 if self.total else 100
            elapsed = time.time() - self.start_time
            bar_len = 30
            filled = int(bar_len * self.done / self.total) if self.total else bar_len
            bar = '█' * filled + '░' * (bar_len - filled)
            sys.stdout.write(f'\r  {self.desc} |{bar}| {self.done}/{self.total} ({pct:.0f}%) {elapsed:.1f}s')
            sys.stdout.flush()
            if self.done >= self.total:
                print()

    def finish(self):
        with self.lock:
            if self.done < self.total:
                self.done = self.total
        print()


# ============================================================
# 结果导出
# ============================================================
def save_results(results, output_file: str, fmt: str = "json"):
    """保存结果到文件，支持 json 和 csv"""
    if not output_file:
        return

    # 统一转换为字典列表
    rows = []
    for r in results:
        if hasattr(r, '__dataclass_fields__'):
            rows.append({
                'ip': r.ip, 'port': r.port,
                'success': r.success, 'is_offline': r.is_offline,
                'messages_sent': r.messages_sent, 'error': r.error,
                'protocol_version': getattr(r, 'protocol_version', ''),
                'version_name': get_version_name(getattr(r, 'protocol_version', 0)) if getattr(r, 'protocol_version', 0) else '',
                'server_info': str(r.server_info)[:200] if r.server_info else '',
            })
        elif isinstance(r, dict):
            rows.append(r)
        else:
            rows.append({'data': str(r)})

    if fmt == 'csv' or output_file.endswith('.csv'):
        if rows:
            keys = list(rows[0].keys())
            with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                w.writerows(rows)
        print(f"[*] 结果已保存到 {output_file} (CSV)")
    else:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        print(f"[*] 结果已保存到 {output_file} (JSON)")


# ============================================================
# 统计汇总
# ============================================================
def print_summary(results, label: str = "扫描"):
    """打印结果统计"""
    def _get(r, key, default=False):
        if isinstance(r, dict):
            return r.get(key, default)
        return getattr(r, key, default)

    total = len(results)
    success = sum(1 for r in results if _get(r, 'success'))
    offline = sum(1 for r in results if _get(r, 'is_offline'))
    msg_sent = sum(_get(r, 'messages_sent', 0) for r in results)

    print(f"\n{'='*50}")
    print(f"  {label}完成")
    print(f"  总目标: {total}")
    print(f"  离线模式服务器: {offline}")
    print(f"  成功发送警告: {success}")
    print(f"  发送消息总数: {msg_sent}")
    print(f"{'='*50}")


# ============================================================
# 子命令
# ============================================================
def cmd_portscan(args, cfg):
    targets = _load_targets(args, cfg, cfg['ports'])
    if not targets:
        print("[!] 没有有效的目标"); return

    print(f"[*] 目标数: {len(targets)} | 端口: {cfg['ports']} | 线程: {cfg['scan_threads']}")
    results = scan_ports(targets, max_workers=cfg['scan_threads'], timeout=cfg['scan_timeout'], show_progress=False)
    open_ports = get_open_ports(results)

    print(f"\n[*] 开放端口 ({len(open_ports)} 个):")
    for ip, port in open_ports:
        print(f"  {ip}:{port}")

    if args.output or cfg['output_file']:
        save_results([{'ip': r.ip, 'port': r.port, 'open': r.is_open,
                       'latency_ms': round(r.latency_ms, 1)} for r in results],
                     args.output or cfg['output_file'], cfg['output_format'])


def cmd_scan(args, cfg):
    """扫描端口 + SLP 探测"""
    targets = _load_targets(args, cfg, cfg['ports'])
    if not targets:
        print("[!] 没有有效的目标"); return

    print(f"[*] 目标数: {len(targets)} | 端口: {cfg['ports']} | 线程: {cfg['scan_threads']}")

    # 阶段1: 端口扫描
    port_results = scan_ports(targets, max_workers=cfg['scan_threads'], timeout=cfg['scan_timeout'], show_progress=False)
    open_ports = get_open_ports(port_results)
    print(f"[*] 端口扫描完成，开放 {len(open_ports)} 个")

    if not open_ports:
        print("[!] 没有发现开放端口"); return

    # 阶段2: SLP 探测（带进度条）
    print(f"[*] SLP 探测 {len(open_ports)} 个目标...")
    mc_servers = []
    pb = ProgressBar(len(open_ports), "SLP探测")

    def probe(ip_port):
        ip, port = ip_port
        try:
            info = server_list_ping(ip, port, timeout=cfg['scan_timeout'])
            return (ip, port, info)
        except:
            return (ip, port, None)
        finally:
            pb.update()

    with ThreadPoolExecutor(max_workers=min(30, len(open_ports))) as ex:
        for ip, port, info in ex.map(probe, open_ports):
            if info:
                mc_servers.append({'ip': ip, 'port': port, 'info': info})

    # 输出结果
    print(f"\n[*] 发现 {len(mc_servers)} 个 Minecraft 服务器:")
    for s in sorted(mc_servers, key=lambda x: x['info'].get('version', {}).get('protocol', 0)):
        info = s['info']
        v = info.get('version', {})
        p = info.get('players', {})
        proto = v.get('protocol', '?')
        print(f"  {s['ip']}:{s['port']} | {get_version_name(proto)}(协议{proto}) | {p.get('online','?')}/{p.get('max','?')}人")

    if args.output or cfg['output_file']:
        save_results(mc_servers, args.output or cfg['output_file'], cfg['output_format'])

    return mc_servers


def cmd_warn(args, cfg):
    """完整流程：扫描 → 离线检测 → 发警告"""
    targets = _load_targets(args, cfg, cfg['ports'])
    if not targets:
        print("[!] 没有有效的目标"); return

    # 消息
    messages = cfg['messages'] or DEFAULT_WARNING_MESSAGES
    if args.message_file:
        with open(args.message_file, 'r', encoding='utf-8') as f:
            messages = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    if args.message:
        messages = args.message

    username = args.username or cfg['username']

    print(f"[*] 目标数: {len(targets)} | 端口: {cfg['ports']}")
    print(f"[*] 机器人: {username} | 消息: {len(messages)}条 | 机器人并发: {cfg['bot_threads']}")

    # 阶段1: 端口扫描
    if args.skip_portscan:
        open_ports = targets
    else:
        port_results = scan_ports(targets, max_workers=cfg['scan_threads'], timeout=cfg['scan_timeout'], show_progress=False)
        open_ports = get_open_ports(port_results)
    print(f"[*] 开放端口: {len(open_ports)} 个")

    if not open_ports:
        print("[!] 没有开放端口，跳过"); return

    # 阶段2: 批量连接检测+发警告（带进度条）
    print(f"[*] 开始离线模式检测和警告...")
    results = []
    pb = ProgressBar(len(open_ports), "警告发送")

    def warn_one(ip_port):
        ip, port = ip_port
        last_err = None
        for attempt in range(cfg['retry_count'] + 1):
            try:
                r = join_and_warn(ip, port, username=username, messages=messages,
                                  timeout=cfg['bot_timeout'], message_delay=cfg['message_delay'])
                return r
            except Exception as e:
                last_err = str(e)
                time.sleep(0.5)
        from bot import BotResult
        return BotResult(ip=ip, port=port, success=False, error=f"重试{cfg['retry_count']}次后仍失败: {last_err}")

    with ThreadPoolExecutor(max_workers=cfg['bot_threads']) as ex:
        futures = {ex.submit(warn_one, t): t for t in open_ports}
        for f in as_completed(futures):
            results.append(f.result())
            pb.update()

    # 输出成功的
    success_list = [r for r in results if r.success and r.messages_sent > 0]
    offline_list = [r for r in results if r.is_offline]

    if success_list:
        print(f"\n[✓] 成功发送警告的服务器 ({len(success_list)} 个):")
        for r in success_list:
            print(f"  {r.ip}:{r.port} | {get_version_name(r.protocol_version)} (协议{r.protocol_version}) | 发送{r.messages_sent}条")
    if offline_list and not success_list:
        print(f"\n[*] 检测到离线模式但发送失败 ({len(offline_list)} 个):")
        for r in offline_list:
            print(f"  {r.ip}:{r.port} | {get_version_name(r.protocol_version)} | {r.error}")

    print_summary(results, "警告任务")

    if args.output or cfg['output_file']:
        save_results(results, args.output or cfg['output_file'], cfg['output_format'])

    return results


def _load_targets(args, cfg, default_ports=None):
    """从命令行参数和文件加载目标，default_ports 用于未显式指定端口的目标"""
    if default_ports is None:
        default_ports = [25565]
    targets = parse_targets(args.targets, default_ports=default_ports) if args.targets else []
    target_file = args.file or (cfg.get('target_file') if isinstance(cfg, dict) else None)
    if target_file and os.path.exists(target_file):
        with open(target_file, 'r') as f:
            file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        targets.extend(parse_targets(file_targets, default_ports=default_ports))
    return deduplicate_targets(targets)


# ============================================================
# 主入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='Minecraft 服务器扫描与安全提醒机器人',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('-c', '--config', default='config.json', help='配置文件路径 (默认: config.json)')
    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # portscan
    p1 = subparsers.add_parser('portscan', help='只扫描端口')
    p1.add_argument('targets', nargs='*', help='目标 IP/网段/主机名')
    p1.add_argument('-f', '--file', help='从文件读取目标')
    p1.add_argument('-o', '--output', help='结果输出文件')

    # scan
    p2 = subparsers.add_parser('scan', help='扫描端口并SLP探测')
    p2.add_argument('targets', nargs='*', help='目标 IP/网段/主机名')
    p2.add_argument('-f', '--file', help='从文件读取目标')
    p2.add_argument('-o', '--output', help='结果输出文件')

    # warn
    p3 = subparsers.add_parser('warn', help='扫描并对离线服发送警告')
    p3.add_argument('targets', nargs='*', help='目标 IP/网段/主机名')
    p3.add_argument('-f', '--file', help='从文件读取目标')
    p3.add_argument('-u', '--username', help='机器人用户名 (覆盖配置)')
    p3.add_argument('-m', '--message', action='append', help='自定义警告消息 (可多次)')
    p3.add_argument('--message-file', help='从文件读取警告消息')
    p3.add_argument('--skip-portscan', action='store_true', help='跳过端口扫描直接连接')
    p3.add_argument('-o', '--output', help='结果输出文件')

    # masscan
    p4 = subparsers.add_parser('masscan', help='使用 masscan 高速扫描')
    p4.add_argument('targets', nargs='*', help='目标 IP/网段')
    p4.add_argument('-p', '--ports', default='25565-25575', help='端口范围 (默认: 25565-25575)')
    p4.add_argument('--rate', type=int, default=1000, help='扫描速率 (默认: 1000)')
    p4.add_argument('-o', '--output', help='结果输出文件')

    # import
    p5 = subparsers.add_parser('import', help='导入 masscan 扫描结果')
    p5.add_argument('file', help='masscan JSON 输出文件')
    p5.add_argument('-o', '--output', help='结果输出文件')

    # query
    p6 = subparsers.add_parser('query', help='查询 SQLite 数据库')
    p6.add_argument('--auth', help='按认证模式过滤 (offline/online/whitelist)')
    p6.add_argument('--modded', type=int, choices=[0, 1], help='按模组过滤 (0=纯净,1=模组)')
    p6.add_argument('--search', help='搜索关键词 (IP/版本/MOTD)')
    p6.add_argument('--limit', type=int, default=50, help='返回数量 (默认: 50)')
    p6.add_argument('--stats', action='store_true', help='只显示统计信息')

    # bot
    p7 = subparsers.add_parser('bot', help='单独对一台服务器发消息')
    p7.add_argument('target', help='目标 IP:端口')
    p7.add_argument('-u', '--username', default='SecurityBot', help='机器人用户名 (默认: SecurityBot)')
    p7.add_argument('-m', '--message', action='append', help='消息内容 (可多次)')
    p7.add_argument('--authme', help='AuthMe 密码 (留空自动生成)')
    p7.add_argument('--protocol', type=int, default=0, help='强制协议版本 (0=自动)')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    cfg = load_config(args.config)
    start_time = time.time()

    print(f"[*] Minecraft Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    try:
        if args.command == 'portscan':
            cmd_portscan(args, cfg)
        elif args.command == 'scan':
            cmd_scan(args, cfg)
        elif args.command == 'warn':
            cmd_warn(args, cfg)
        elif args.command == 'masscan':
            cmd_masscan(args, cfg)
        elif args.command == 'import':
            cmd_import(args, cfg)
        elif args.command == 'query':
            cmd_query(args, cfg)
        elif args.command == 'bot':
            cmd_bot(args, cfg)
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(130)

    print(f"\n[*] 总耗时: {time.time() - start_time:.1f} 秒")




def cmd_masscan(args, cfg):
    """使用 masscan 高速扫描"""
    if not has_masscan():
        print("[!] masscan 未安装，回退 Python 扫描")
        targets = list(parse_targets(args.targets, parse_port_spec(args.ports)))
        results = scan_ports(targets, max_workers=cfg['scan_threads'], timeout=cfg['scan_timeout'])
        open_ports = get_open_ports(results)
    else:
        open_ports = masscan_scan(args.targets, parse_port_spec(args.ports), rate=args.rate)

    print(f"\n[*] 找到 {len(open_ports)} 个开放端口")
    for ip, port in open_ports:
        print(f"  {ip}:{port}")

    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump([{"ip": ip, "port": port} for ip, port in open_ports], f, indent=2)
        print(f"[*] 结果已保存到 {args.output}")


def cmd_import(args, cfg):
    """导入 masscan 扫描结果"""
    import json
    with open(args.file, 'r') as f:
        data = json.load(f)

    open_ports = []
    for entry in data:
        ip = entry.get('ip')
        for port_info in entry.get('ports', []):
            if port_info.get('status') == 'open':
                open_ports.append((ip, port_info['port']))

    print(f"[*] 导入 {len(open_ports)} 个开放端口")

    # SLP 探测
    print("[*] SLP 探测...")
    servers = []
    from mc_protocol import server_list_ping
    for i, (ip, port) in enumerate(open_ports):
        info = server_list_ping(ip, port, timeout=3)
        if info:
            ver = info.get('version', {})
            players = info.get('players', {})
            servers.append({
                'ip': ip, 'port': port,
                'version': ver.get('name', ''),
                'protocol': ver.get('protocol', 0),
                'players_online': players.get('online', 0),
                'players_max': players.get('max', 0),
                'motd': str(info.get('description', ''))[:100],
            })
            print(f"  [{i+1}/{len(open_ports)}] {ip}:{port} | {ver.get('name','')} | {players.get('online',0)}/{players.get('max',0)}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(servers, f, indent=2, ensure_ascii=False)
        print(f"[*] 结果已保存到 {args.output}")


def cmd_query(args, cfg):
    """查询 SQLite 数据库"""
    import db as db_store
    db_path = db_store.default_db_path()

    if args.stats:
        stats = db_store.stats(db_path)
        print(f"[*] 数据库统计:")
        print(f"  总服务器数: {stats['total']}")
        print(f"  有人在线: {stats['online_servers']}")
        print(f"  按认证模式:")
        for auth, count in stats['by_auth'].items():
            print(f"    {auth}: {count}")
        return

    rows = db_store.query(db_path, auth=args.auth, modded=args.modded,
                           search=args.search, limit=args.limit)
    total = db_store.count(db_path, auth=args.auth, modded=args.modded, search=args.search)

    print(f"[*] 查询结果: {len(rows)}/{total} 条")
    print(f"{'IP:端口':<22} {'认证':<10} {'版本':<20} {'人数':<10} MOTD")
    print("-" * 100)
    for r in rows:
        motd = (r.get('motd') or '')[:40]
        print(f"{r['ip']}:{r['port']:<16} {r.get('auth','?'):<10} {(r.get('version') or '')[:18]:<20} {r.get('players_online',0)}/{r.get('players_max',0):<7} {motd}")


def cmd_bot(args, cfg):
    """单独对一台服务器发消息"""
    from bot import join_and_warn
    if ':' in args.target:
        ip, port = args.target.rsplit(':', 1)
        port = int(port)
    else:
        ip, port = args.target, 25565

    messages = args.message or cfg.get('messages', ['安全提醒'])
    authme = args.authme if args.authme else None

    print(f"[*] 连接 {ip}:{port} 用户名={args.username}")
    result = join_and_warn(ip, port, username=args.username, messages=messages,
                            authme_password=authme, timeout=15)

    print(f"\n[*] 结果:")
    print(f"  成功: {result.success}")
    print(f"  离线模式: {result.is_offline}")
    print(f"  认证模式: {result.auth_mode}")
    print(f"  发送消息数: {result.messages_sent}")
    print(f"  版本: {result.version_name}")
    if result.error:
        print(f"  错误: {result.error}")


if __name__ == '__main__':
    main()
