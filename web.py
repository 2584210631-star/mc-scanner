#!/usr/bin/env python3
"""
Minecraft 扫描器 Web 控制面板 v3
启动: python web.py [端口]
默认: http://localhost:8080
零依赖，仅用 Python 标准库
"""
import json
import threading
import time
import os
import sys
import csv
import io
import html
import ipaddress
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner import (
    parse_targets, scan_ports, get_open_ports, deduplicate_targets, parse_port_spec,
    load_exclude_list, filter_excluded,
)
from bot import join_and_warn, DEFAULT_WARNING_MESSAGES
from mc_protocol import server_list_ping, get_version_name
import db as db_store

# ============================================================
# 全局状态
# ============================================================
MAX_HISTORY = 20
DB_PATH = db_store.default_db_path()
db_store.init_db(DB_PATH)
task_state = {
    "running": False,
    "phase": "idle",
    "progress": 0,
    "total": 0,
    "open_count": 0,
    "offline_count": 0,
    "success_count": 0,
    "messages_total": 0,
    "message": "",
    "results": [],
    "logs": [],
    "start_time": None,
    "elapsed": 0,
    "task_id": 0,
}
history = []
state_lock = threading.Lock()
stop_event = threading.Event()


def log(msg: str):
    with state_lock:
        ts = time.strftime("%H:%M:%S")
        task_state["logs"].append(f"[{ts}] {msg}")
        if len(task_state["logs"]) > 500:
            task_state["logs"] = task_state["logs"][-500:]


def update_state(**kwargs):
    with state_lock:
        task_state.update(kwargs)


def get_state():
    with state_lock:
        s = dict(task_state)
        s["logs"] = list(s["logs"])
        s["results"] = list(s["results"])
        if s["start_time"] and s["running"]:
            s["elapsed"] = round(time.time() - s["start_time"], 1)
        return s


# ============================================================
# 核心扫描逻辑
# ============================================================
def split_into_24(target: str) -> list:
    """把大 CIDR 或单个 IP 拆成 /24 网段列表，用于连续扫描"""
    target = target.strip()
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.prefixlen >= 24:
            return [str(network)]
        # 拆成 /24，限制最多 65536 个（/16），防止 /8 太大
        subnets = list(network.subnets(new_prefix=24))
        if len(subnets) > 65536:
            subnets = subnets[:65536]
        return [str(s) for s in subnets]
    except Exception:
        # 单个 IP 或域名，从所在 /24 开始
        try:
            ip_str = target.split(':')[0].split('/')[0]
            ip = ipaddress.ip_address(ip_str)
            return [str(ipaddress.ip_network(f'{ip}/24', strict=False))]
        except Exception:
            return [target]


def run_scan(cfg):
    """执行扫描任务（支持连续扫描模式 + 并发警告）"""
    global stop_event
    stop_event = threading.Event()

    target = cfg.get('target', '').strip()
    ports_str = cfg.get('ports', '25565-25700,19132-19133')
    try:
        port_list = parse_port_spec(ports_str)
    except Exception:
        port_list = [25565]
    continuous_mode = cfg.get('continuous_mode', False)
    use_exclude = cfg.get('use_exclude', True)
    exclude_nets = load_exclude_list(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exclude.conf')) if use_exclude else []
    scan_threads = int(cfg.get('scan_threads', 200))
    scan_timeout = float(cfg.get('scan_timeout', 2.5))
    bot_threads = int(cfg.get('bot_threads', 10))
    bot_timeout = float(cfg.get('bot_timeout', 12))
    username = cfg.get('bot_name', 'SecurityBot') or 'SecurityBot'
    do_warn = cfg.get('do_warn', False)
    message_count = int(cfg.get('message_count', 2))
    message_delay = float(cfg.get('message_delay', 0.8))
    authme_password = cfg.get('authme_password', '') or None
    force_protocol = cfg.get('force_protocol', '')
    force_protocol = int(force_protocol) if force_protocol and force_protocol.isdigit() else None

    messages_raw = cfg.get('messages', DEFAULT_WARNING_MESSAGES)
    if isinstance(messages_raw, str):
        messages = [m.strip() for m in messages_raw.split('\n') if m.strip()]
    else:
        messages = [m for m in messages_raw if m and str(m).strip()]
    messages = messages[:max(1, message_count)]

    if not target:
        update_state(phase="error", message="目标不能为空")
        return

    # 连续模式：把大 CIDR 拆成 /24 列表逐个扫描
    if continuous_mode:
        subnet_list = split_into_24(target)
        log(f"连续扫描模式: {target} 拆分为 {len(subnet_list)} 个 /24 网段")
    else:
        subnet_list = [target]

    update_state(
        running=True, phase="连续扫描" if continuous_mode else "解析目标",
        progress=0, total=0, open_count=0, offline_count=0,
        success_count=0, messages_total=0, results=[], logs=[],
        start_time=time.time(), task_id=task_state["task_id"] + 1,
    )
    log(f"目标: {target} | 端口: {ports_str} ({len(port_list)}个) | 扫描线程: {scan_threads}")
    if continuous_mode:
        log(f"连续扫描: 共 {len(subnet_list)} 个网段，扫完自动切换下一个")
    if do_warn:
        log(f"Bot: {username} | 每台发 {len(messages)} 条消息 | Bot线程: {bot_threads}")

    # 累计统计
    total_results = []
    total_targets = 0
    total_open = 0
    subnet_idx = 0

    for subnet_target in subnet_list:
        if stop_event.is_set():
            break
        subnet_idx += 1
        log(f"--- 网段 {subnet_idx}/{len(subnet_list)}: {subnet_target} ---")
        update_state(phase=f"扫描 {subnet_target} ({subnet_idx}/{len(subnet_list)})")

        # 阶段1: 解析目标
        try:
            targets = list(parse_targets([subnet_target], port_list))
            targets = deduplicate_targets(targets)
            # 排除列表过滤
            if use_exclude:
                before = len(targets)
                targets = filter_excluded(targets, exclude_nets)
                if before != len(targets):
                    log(f"排除列表过滤: {before} -> {len(targets)} (跳过{before-len(targets)}个)")
            subnet_total = len(targets)
        except Exception as e:
            log(f"网段 {subnet_target} 解析失败: {e}")
            continue

        total_targets += subnet_total
        update_state(total=total_targets)
        log(f"网段 {subnet_target}: {subnet_total} 个目标")

        # 阶段2: 端口扫描
        def scan_progress(done, total_t, open_cnt=0):
            if stop_event.is_set():
                return
            update_state(progress=total_targets - subnet_total + done)

        try:
            open_ports = scan_ports(
                targets, timeout=scan_timeout, max_workers=scan_threads,
                progress_callback=scan_progress, stop_event=stop_event,
            )
        except Exception as e:
            log(f"扫描异常: {e}")
            open_ports = []

        total_open += len(open_ports)
        update_state(open_count=total_open)
        log(f"网段 {subnet_target}: 发现 {len(open_ports)} 个开放端口")

        if stop_event.is_set() or not open_ports:
            continue

        # 阶段3: SLP 探测 + 离线检测 + 警告（并发）
        subnet_results = []
        done_count = 0

        def process_target(ip, port):
            nonlocal done_count
            if stop_event.is_set():
                return None
            entry = {"ip": ip, "port": port}
            try:
                info = server_list_ping(ip, port, timeout=4.0)
                if info:
                    v = info.get('version', {})
                    p = info.get('players', {})
                    desc = info.get('description', '')
                    if isinstance(desc, dict):
                        motd = desc.get('text', str(desc))[:200]
                    else:
                        motd = str(desc)[:200]
                    entry.update({
                        "version_name": v.get('name', '?'),
                        "protocol_version": v.get('protocol', 0),
                        "players_online": p.get('online', 0),
                        "players_max": p.get('max', 0),
                        "motd": motd, "slp_ok": True,
                    })
                else:
                    entry.update({"version_name": "?", "protocol_version": 0,
                                  "players_online": 0, "players_max": 0, "motd": "", "slp_ok": False})
            except Exception as e:
                entry.update({"version_name": "?", "protocol_version": 0,
                              "players_online": 0, "players_max": 0, "motd": "", "slp_ok": False, "error": str(e)[:100]})

            if do_warn and entry.get("slp_ok"):
                try:
                    proto = force_protocol or entry.get("protocol_version") or None
                    r = join_and_warn(
                        ip, port, username=username, messages=messages,
                        timeout=bot_timeout, protocol_version=proto,
                        authme_password=authme_password, message_delay=message_delay,
                    )
                    entry.update({
                        "is_offline": r.is_offline, "success": r.success,
                        "messages_sent": r.messages_sent, "authme_used": r.authme_used,
                        "error": r.error or "",
                    })
                    if r.success and r.messages_sent > 0:
                        log(f"✓ {ip}:{port} 发送{r.messages_sent}条 ({entry.get('version_name','?')})")
                except Exception as e:
                    entry.update({"is_offline": False, "success": False,
                                  "messages_sent": 0, "error": str(e)[:100]})
            else:
                if entry.get("slp_ok") and not do_warn:
                    try:
                        proto = force_protocol or entry.get("protocol_version") or None
                        r = join_and_warn(ip, port, username=username, messages=[],
                                          timeout=bot_timeout, protocol_version=proto)
                        entry["is_offline"] = r.is_offline
                    except Exception:
                        entry["is_offline"] = False
                else:
                    entry["is_offline"] = False
                entry.setdefault("success", False)
                entry.setdefault("messages_sent", 0)

            done_count += 1
            if done_count % 5 == 0 or done_count == len(open_ports):
                offline_count = sum(1 for r in total_results + subnet_results if r.get("is_offline"))
                success_count = sum(1 for r in total_results + subnet_results if r.get("success") and r.get("messages_sent", 0) > 0)
                msg_total = sum(r.get("messages_sent", 0) for r in total_results + subnet_results)
                update_state(
                    progress=total_targets - len(open_ports) + done_count,
                    results=list(total_results + subnet_results),
                    offline_count=offline_count, success_count=success_count,
                    messages_total=msg_total,
                )
            return entry

        update_state(phase=f"警告 {subnet_target} ({subnet_idx}/{len(subnet_list)})" if do_warn else f"探测 {subnet_target}")
        with ThreadPoolExecutor(max_workers=bot_threads) as executor:
            futures = {executor.submit(process_target, sr.ip, sr.port): (sr.ip, sr.port) for sr in open_ports}
            for future in as_completed(futures):
                if stop_event.is_set():
                    break
                try:
                    result = future.result()
                    if result:
                        subnet_results.append(result)
                except Exception as e:
                    ip, port = futures[future]
                    subnet_results.append({"ip": ip, "port": port, "success": False,
                                           "messages_sent": 0, "error": str(e)[:100], "is_offline": False})

        total_results.extend(subnet_results)
        log(f"网段 {subnet_target} 完成: {len(subnet_results)} 个结果")

    # 最终状态
    offline_count = sum(1 for r in total_results if r.get("is_offline"))
    success_count = sum(1 for r in total_results if r.get("success") and r.get("messages_sent", 0) > 0)
    msg_total = sum(r.get("messages_sent", 0) for r in total_results)

    update_state(
        running=False, phase="完成" if not stop_event.is_set() else "已停止",
        results=total_results, offline_count=offline_count,
        success_count=success_count, messages_total=msg_total,
        progress=total_targets, total=total_targets, open_count=total_open,
    )
    log(f"全部完成: 扫描{total_targets} 开放{total_open} 离线{offline_count} 成功{success_count} 消息{msg_total}")

    # 写入 SQLite 数据库（失败不影响主流程）
    try:
        db_records = []
        for r in total_results:
            if not r.get("slp_ok"):
                continue
            db_records.append({
                "ip": r["ip"], "port": r["port"],
                "version": r.get("version_name", ""),
                "proto": r.get("protocol_version", 0),
                "motd": r.get("motd", ""),
                "is_modded": 1 if "fabric" in r.get("version_name", "").lower() or "paper" in r.get("version_name", "").lower() or "purpur" in r.get("version_name", "").lower() else 0,
                "players_online": r.get("players_online", 0),
                "players_max": r.get("players_max", 0),
                "auth": r.get("auth_mode", "offline" if r.get("is_offline") else "unknown"),
                "ping_ms": None,
                "json": json.dumps(r, ensure_ascii=False),
            })
        if db_records:
            db_store.upsert_many(DB_PATH, db_records)
            log(f"数据库: 写入 {len(db_records)} 条记录")
    except Exception as e:
        log(f"数据库写入失败: {e}")

    _save_history(cfg, total_targets, total_open, offline_count, success_count, msg_total)


def _save_history(cfg, total, open_count, offline_count, success_count, msg_total):
    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": cfg.get('target', ''),
        "total": total, "open": open_count, "offline": offline_count,
        "success": success_count, "messages": msg_total,
    }
    history.insert(0, entry)
    if len(history) > MAX_HISTORY:
        history.pop()


def stop_task():
    stop_event.set()
    update_state(phase="停止中")
    log("收到停止信号...")


# ============================================================
# HTML 页面
# ============================================================
HTML_PAGE = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MC Scanner v3 - 控制面板</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0f1117;--bg2:#181b24;--bg3:#1e2230;--border:#2a2f3e;
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --accent:#3b82f6;--accent2:#2563eb;--green:#22c55e;--red:#ef4444;
  --yellow:#eab308;--purple:#a855f7;--cyan:#06b6d4;
}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:20px;font-weight:700;background:linear-gradient(90deg,var(--accent),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .sub{font-size:12px;color:var(--text3);margin-top:2px}
.container{max-width:1400px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:340px 1fr;gap:20px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:16px}
.card h3{font-size:14px;font-weight:600;color:var(--text2);margin-bottom:14px;text-transform:uppercase;letter-spacing:0.5px;display:flex;align-items:center;gap:8px}
.card h3::before{content:'';width:3px;height:14px;background:var(--accent);border-radius:2px}
.form-group{margin-bottom:12px}
.form-group label{display:block;font-size:12px;color:var(--text2);margin-bottom:5px;font-weight:500}
.form-group input,.form-group select,.form-group textarea{
  width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:8px 12px;color:var(--text);font-size:13px;outline:none;transition:border-color 0.2s
}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--accent)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
textarea{resize:vertical;min-height:70px;font-family:inherit}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.2s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(59,130,246,0.4)}
.btn-danger{background:var(--red);color:#fff}
.btn-danger:hover{background:#dc2626}
.btn-success{background:var(--green);color:#fff}
.btn-success:hover{background:#16a34a}
.btn-sm{padding:6px 12px;font-size:12px}
.btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
@media(max-width:600px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px;text-align:center}
.stat .num{font-size:24px;font-weight:700}
.stat .label{font-size:11px;color:var(--text3);margin-top:4px;text-transform:uppercase}
.progress-wrap{background:var(--bg3);border-radius:8px;height:8px;overflow:hidden;margin:10px 0}
.progress-bar{height:100%;background:linear-gradient(90deg,var(--accent),var(--purple));border-radius:8px;transition:width 0.3s;width:0%}
.phase-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.phase-idle{background:#334155;color:#94a3b8}
.phase-running{background:rgba(59,130,246,0.2);color:#60a5fa}
.phase-done{background:rgba(34,197,94,0.2);color:#4ade80}
.phase-error{background:rgba(239,68,68,0.2);color:#f87171}
.log-box{background:#0a0c10;border:1px solid var(--border);border-radius:8px;padding:12px;height:200px;overflow-y:auto;font-family:'Consolas','Monaco',monospace;font-size:11px;line-height:1.6}
.log-box div{color:var(--text2)}
.log-box .ok{color:var(--green)}
.log-box .err{color:var(--red)}
.log-box .warn{color:var(--yellow)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:10px 8px;color:var(--text3);font-weight:600;border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;position:sticky;top:0;background:var(--bg2)}
td{padding:8px;border-bottom:1px solid rgba(42,47,62,0.5)}
tr:hover{background:rgba(59,130,246,0.05)}
.table-wrap{max-height:400px;overflow-y:auto;border-radius:8px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600}
.badge-ok{background:rgba(34,197,94,0.15);color:#4ade80}
.badge-offline{background:rgba(234,179,8,0.15);color:#facc15}
.badge-online{background:rgba(6,182,212,0.15);color:#22d3ee}
.badge-fail{background:rgba(239,68,68,0.15);color:#f87171}
.filter-bar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.filter-bar input{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px;outline:none}
.tabs{display:flex;gap:4px;margin-bottom:14px;border-bottom:1px solid var(--border)}
.tab{padding:8px 16px;font-size:13px;color:var(--text3);cursor:pointer;border-bottom:2px solid transparent;transition:all 0.2s}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab:hover{color:var(--text)}
.history-item{padding:10px;border-bottom:1px solid rgba(42,47,62,0.5);font-size:12px;display:flex;justify-content:space-between;align-items:center}
.history-item:hover{background:rgba(59,130,246,0.05)}
.quick-test{background:linear-gradient(135deg,rgba(168,85,247,0.1),rgba(59,130,246,0.1));border:1px solid rgba(168,85,247,0.3)}
.switch{position:relative;display:inline-block;width:40px;height:22px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:var(--bg3);border-radius:22px;transition:0.3s;border:1px solid var(--border)}
.slider:before{content:'';position:absolute;height:16px;width:16px;left:2px;bottom:2px;background:var(--text3);border-radius:50%;transition:0.3s}
input:checked+.slider{background:var(--accent)}
input:checked+.slider:before{transform:translateX(18px);background:#fff}
.checkbox-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.checkbox-row label{font-size:13px;color:var(--text2);cursor:pointer}
.elapsed{font-size:12px;color:var(--text3);font-family:monospace}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>⚔ MC Scanner v3</h1>
    <div class="sub">Minecraft 服务器扫描 + 离线模式安全警告</div>
  </div>
  <div style="display:flex;align-items:center;gap:16px">
    <span class="phase-badge phase-idle" id="phaseBadge">空闲</span>
    <span class="elapsed" id="elapsed">0.0s</span>
  </div>
</div>

<div class="container">
  <div class="stats">
    <div class="stat"><div class="num" style="color:var(--accent)" id="statTotal">0</div><div class="label">扫描目标</div></div>
    <div class="stat"><div class="num" style="color:var(--cyan)" id="statOpen">0</div><div class="label">开放端口</div></div>
    <div class="stat"><div class="num" style="color:var(--yellow)" id="statOffline">0</div><div class="label">离线服务器</div></div>
    <div class="stat"><div class="num" style="color:var(--green)" id="statSuccess">0</div><div class="label">警告成功 / <span id="statMsgs">0</span>条</div></div>
  </div>

  <div class="grid">
    <!-- 左侧配置 -->
    <div>
      <div class="card">
        <h3>扫描配置</h3>
        <div class="form-group">
          <label>目标 (IP / CIDR / 域名)</label>
          <input id="target" placeholder="例如: 192.168.1.0/24 或 play.example.com" value="">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>端口范围 (支持1-65535, 逗号分隔多段)</label>
            <input id="ports" value="25565-25700,19132-19133">
          </div>
          <div class="form-group">
            <label>扫描线程</label>
            <input id="scanThreads" type="number" value="200" min="1" max="1000">
          </div>
        </div>
        <div class="checkbox-row">
          <label class="switch"><input type="checkbox" id="continuousMode"><span class="slider"></span></label>
          <label for="continuousMode">连续扫描 (大网段自动拆/24逐个扫, 扫完自动切换)</label>
        </div>
        <div class="checkbox-row">
          <label class="switch"><input type="checkbox" id="useExclude" checked><span class="slider"></span></label>
          <label for="useExclude">启用排除列表 (过滤私有地址/保留段, exclude.conf)</label>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>扫描超时(s)</label>
            <input id="scanTimeout" type="number" value="2.5" step="0.5" min="0.5">
          </div>
          <div class="form-group">
            <label>Bot线程</label>
            <input id="botThreads" type="number" value="10" min="1" max="50">
          </div>
        </div>
      </div>

      <div class="card">
        <h3>机器人配置</h3>
        <div class="checkbox-row">
          <label class="switch"><input type="checkbox" id="doWarn" checked><span class="slider"></span></label>
          <label for="doWarn">发送警告消息</label>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Bot名称</label>
            <input id="botName" value="SecurityBot">
          </div>
          <div class="form-group">
            <label>每台发消息条数</label>
            <input id="messageCount" type="number" value="2" min="1" max="10">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>消息间隔(s)</label>
            <input id="messageDelay" type="number" value="0.8" step="0.1" min="0.1">
          </div>
          <div class="form-group">
            <label>Bot超时(s)</label>
            <input id="botTimeout" type="number" value="12" min="5" max="60">
          </div>
        </div>
        <div class="form-group">
          <label>警告消息 (每行一条，按上面条数取前N条)</label>
          <textarea id="messages">您好，我是安全扫描机器人，检测到您的服务器处于离线模式
离线模式下任何人可伪造任意用户名登录，存在安全风险
建议开启 online-mode=true 或安装登录插件保护服务器</textarea>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>AuthMe密码 (留空自动生成)</label>
            <input id="authmePassword" type="text" placeholder="默认自动生成随机密码，无需填写">
          </div>
          <div class="form-group">
            <label>强制协议版本 (可选)</label>
            <input id="forceProtocol" placeholder="如: 767">
          </div>
        </div>
      </div>

      <div class="card quick-test">
        <h3 style="color:var(--purple)">⚡ 单台快速测试</h3>
        <div class="form-group">
          <label>直接对一台服务器发警告</label>
          <input id="quickTarget" placeholder="IP:端口 例如 127.0.0.1:25565">
        </div>
        <button class="btn btn-success btn-sm" onclick="quickTest()" id="quickBtn">快速发送</button>
      </div>

      <div class="btn-group" style="margin-bottom:16px">
        <button class="btn btn-primary" onclick="startScan()" id="startBtn">▶ 开始扫描</button>
        <button class="btn btn-danger" onclick="stopScan()" id="stopBtn" disabled>■ 停止</button>
      </div>
    </div>

    <!-- 右侧结果 -->
    <div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <h3 style="margin-bottom:0">任务进度</h3>
          <span id="progressText" style="font-size:12px;color:var(--text3)">0 / 0</span>
        </div>
        <div class="progress-wrap"><div class="progress-bar" id="progressBar"></div></div>
      </div>

      <div class="card">
        <div class="tabs">
          <div class="tab active" onclick="switchTab('results')">扫描结果</div>
          <div class="tab" onclick="switchTab('logs')">实时日志</div>
          <div class="tab" onclick="switchTab('history')">历史记录</div>
          <div class="tab" onclick="switchTab('database')">数据库</div>
        </div>

        <div id="tabResults">
          <div class="filter-bar">
            <input id="searchInput" placeholder="搜索 IP / 版本 / MOTD..." oninput="renderResults()" style="flex:1;min-width:150px">
            <select id="filterSelect" onchange="renderResults()" style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px">
              <option value="all">全部</option>
              <option value="offline">仅离线</option>
              <option value="success">仅成功</option>
              <option value="failed">仅失败</option>
              <option value="hasPlayers">有人在线</option>
            </select>
            <button class="btn btn-sm" style="background:var(--bg3);color:var(--text2)" onclick="exportJSON()">导出JSON</button>
            <button class="btn btn-sm" style="background:var(--bg3);color:var(--text2)" onclick="exportCSV()">导出CSV</button>
            <button class="btn btn-sm" id="batchWarnBtn" style="background:#f59e0b;color:#fff;border:none" onclick="batchWarn()">⚡ 对当前列表发警告</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th>IP:端口</th><th>版本</th><th>人数</th><th>状态</th><th>消息</th><th>MOTD</th><th>操作</th>
              </tr></thead>
              <tbody id="resultsBody"></tbody>
            </table>
          </div>
        </div>

        <div id="tabLogs" style="display:none">
          <div class="log-box" id="logBox"></div>
        </div>

        <div id="tabHistory" style="display:none">
          <div id="historyList"></div>
        </div>
        <div id="tabDatabase" style="display:none">
          <div class="cards" id="dbCards" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
            <div class="card" style="flex:1;min-width:100px;padding:10px"><div class="num" id="dbTotal" style="font-size:20px;font-weight:700">0</div><div class="label" style="font-size:11px;color:#94a3b8">服务器总数</div></div>
            <div class="card" style="flex:1;min-width:100px;padding:10px"><div class="num" id="dbOffline" style="font-size:20px;font-weight:700;color:#22c55e">0</div><div class="label" style="font-size:11px;color:#94a3b8">离线/破解</div></div>
            <div class="card" style="flex:1;min-width:100px;padding:10px"><div class="num" id="dbOnline" style="font-size:20px;font-weight:700;color:#3b82f6">0</div><div class="label" style="font-size:11px;color:#94a3b8">正版验证</div></div>
            <div class="card" style="flex:1;min-width:100px;padding:10px"><div class="num" id="dbWhitelist" style="font-size:20px;font-weight:700;color:#eab308">0</div><div class="label" style="font-size:11px;color:#94a3b8">白名单</div></div>
            <div class="card" style="flex:1;min-width:100px;padding:10px"><div class="num" id="dbHasPlayers" style="font-size:20px;font-weight:700;color:#06b6d4">0</div><div class="label" style="font-size:11px;color:#94a3b8">有人在线</div></div>
          </div>
          <div class="filters" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center">
            <select id="dbAuth" style="background:#1e2230;border:1px solid #2a2f3e;border-radius:6px;padding:6px 10px;color:#e2e8f0;font-size:12px">
              <option value="">全部认证</option>
              <option value="offline">离线/破解</option>
              <option value="online">正版</option>
              <option value="whitelist">白名单</option>
              <option value="rejected">拒绝</option>
              <option value="unknown">未知</option>
            </select>
            <select id="dbMod" style="background:#1e2230;border:1px solid #2a2f3e;border-radius:6px;padding:6px 10px;color:#e2e8f0;font-size:12px">
              <option value="">全部</option>
              <option value="1">模组服</option>
              <option value="0">纯净服</option>
            </select>
            <input id="dbSearch" placeholder="搜索 IP/版本/MOTD" style="flex:1;min-width:150px;background:#1e2230;border:1px solid #2a2f3e;border-radius:6px;padding:6px 10px;color:#e2e8f0;font-size:12px">
            <button onclick="loadDB(1)" style="background:#3b82f6;color:#fff;border:none;border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer">查询</button>
            <button onclick="loadDBStats()" style="background:#1e2230;color:#94a3b8;border:1px solid #2a2f3e;border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer">刷新统计</button>
          </div>
          <div style="overflow-x:auto"><table>
            <thead><tr><th>IP:端口</th><th>认证</th><th>版本</th><th>人数</th><th>类型</th><th>MOTD</th><th>更新时间</th></tr></thead>
            <tbody id="dbRows"></tbody>
          </table></div>
          <div class="pg" style="display:flex;gap:8px;margin-top:12px;align-items:center;font-size:12px">
            <button onclick="prevDB()" style="background:#1e2230;color:#94a3b8;border:1px solid #2a2f3e;border-radius:6px;padding:6px 12px;cursor:pointer">上一页</button>
            <span id="dbPage" style="color:#94a3b8">1</span>
            <button onclick="nextDB()" style="background:#1e2230;color:#94a3b8;border:1px solid #2a2f3e;border-radius:6px;padding:6px 12px;cursor:pointer">下一页</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let currentResults = [];
let currentFilter = 'all';
let pollTimer = null;

function esc(s){if(s==null)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

function getCfg(){
  return {
    target: document.getElementById('target').value,
    ports: document.getElementById('ports').value,
    continuous_mode: document.getElementById('continuousMode').checked,
    use_exclude: document.getElementById('useExclude').checked,
    scan_threads: document.getElementById('scanThreads').value,
    scan_timeout: document.getElementById('scanTimeout').value,
    bot_threads: document.getElementById('botThreads').value,
    bot_timeout: document.getElementById('botTimeout').value,
    bot_name: document.getElementById('botName').value,
    do_warn: document.getElementById('doWarn').checked,
    message_count: document.getElementById('messageCount').value,
    message_delay: document.getElementById('messageDelay').value,
    authme_password: document.getElementById('authmePassword').value,
    force_protocol: document.getElementById('forceProtocol').value,
    messages: document.getElementById('messages').value,
  };
}

function startScan(){
  const cfg = getCfg();
  if(!cfg.target.trim()){alert('请输入扫描目标');return;}
  fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)})
    .then(r=>r.json()).then(d=>{
      if(d.error){alert(d.error);return;}
      document.getElementById('startBtn').disabled=true;
      document.getElementById('stopBtn').disabled=false;
      if(!pollTimer)pollTimer=setInterval(pollState,1000);
    });
}

function stopScan(){
  fetch('/api/stop',{method:'POST'}).then(()=>{
    document.getElementById('stopBtn').disabled=true;
  });
}

function quickTest(){
  const t = document.getElementById('quickTarget').value.trim();
  if(!t){alert('请输入 IP:端口');return;}
  const btn = document.getElementById('quickBtn');
  btn.disabled = true; btn.textContent = '发送中...';
  const cfg = getCfg();
  cfg.target = t; cfg.ports = '';
  fetch('/api/quick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)})
    .then(r=>r.json()).then(d=>{
      btn.disabled=false; btn.textContent='快速发送';
      if(d.error){alert('失败: '+d.error);return;}
      alert('完成: 离线='+d.is_offline+' 成功='+d.success+' 消息='+d.messages_sent+(d.error?'\\n错误:'+d.error:''));
    }).catch(()=>{btn.disabled=false;btn.textContent='快速发送';});
}

function pollState(){
  fetch('/api/status').then(r=>r.json()).then(s=>{
    currentResults = s.results || [];
    document.getElementById('statTotal').textContent = s.total||0;
    document.getElementById('statOpen').textContent = s.open_count||0;
    document.getElementById('statOffline').textContent = s.offline_count||0;
    document.getElementById('statSuccess').textContent = s.success_count||0;
    document.getElementById('statMsgs').textContent = s.messages_total||0;
    document.getElementById('elapsed').textContent = (s.elapsed||0)+'s';
    const pct = s.total>0 ? Math.round((s.progress||0)/s.total*100) : 0;
    document.getElementById('progressBar').style.width = pct+'%';
    document.getElementById('progressText').textContent = (s.progress||0)+' / '+(s.total||0);
    const pb = document.getElementById('phaseBadge');
    pb.textContent = s.phase||'idle';
    pb.className = 'phase-badge '+(s.running?'phase-running':(s.phase==='完成'?'phase-done':s.phase==='错误'?'phase-error':'phase-idle'));
    if(!s.running){
      document.getElementById('startBtn').disabled=false;
      document.getElementById('stopBtn').disabled=true;
    }
    renderResults();
    renderLogs(s.logs||[]);
    if(s.history)renderHistory(s.history);
  });
}

function warnSingle(ip, port, btn){
  if(!confirm('对 '+ip+':'+port+' 发送警告?'))return;
  if(btn){btn.disabled=true; btn.textContent='发送中...'; btn.style.background='#94a3b8';}
  const cfg = getCfg();
  cfg.target = ip+':'+port;
  fetch('/api/quick', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(cfg)})
  .then(r=>r.json()).then(res=>{
    if(res.success){
      alert('警告成功! 发送了 '+res.messages_sent+' 条消息');
      currentResults.forEach(r=>{
        if(r.ip===ip && r.port===port){
          r.success = true; r.messages_sent = res.messages_sent; r.is_offline = true;
          r.auth_mode = res.auth_mode || 'offline';
        }
      });
    } else {
      alert('警告失败: '+(res.error||'未知错误'));
    }
    renderResults();
  }).catch(e=>{alert('请求失败: '+e); renderResults();});
}

function batchWarn(){
  // 获取当前筛选后的列表
  const search = document.getElementById('searchInput').value.toLowerCase();
  const filter = document.getElementById('filterSelect').value;
  let list = currentResults.filter(r=>{
    if(filter==='offline'&&!r.is_offline)return false;
    if(filter==='success'&&!(r.success&&r.messages_sent>0))return false;
    if(filter==='failed'&&r.success&&r.messages_sent>0)return false;
    if(filter==='hasPlayers'&&!(r.players_online>0))return false;
    if(search){
      const hay = (r.ip+':'+r.port+' '+(r.version_name||'')+' '+(r.motd||'')).toLowerCase();
      if(!hay.includes(search))return false;
    }
    return true;
  });
  // 只对还没发过警告的、SLP成功的服务器发
  const targets = list.filter(r=>r.slp_ok && !(r.success&&r.messages_sent>0));
  if(targets.length===0){alert('当前列表没有可警告的服务器（需要先扫描，且排除已发送的）');return;}
  if(!confirm('将对 '+targets.length+' 台服务器发送警告，确定?'))return;
  const btn = document.getElementById('batchWarnBtn');
  btn.disabled = true; btn.textContent = '发送中 0/'+targets.length;
  let done = 0, ok = 0;
  const cfg = getCfg();
  // 串行发送，避免并发过高被封
  function sendNext(){
    if(done>=targets.length){
      btn.disabled = false; btn.textContent = '⚡ 对当前列表发警告';
      alert('批量警告完成! 成功 '+ok+'/'+targets.length);
      renderResults();
      return;
    }
    const r = targets[done];
    cfg.target = r.ip+':'+r.port;
    fetch('/api/quick', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(cfg)})
    .then(res=>res.json()).then(res=>{
      done++;
      if(res.success){
        ok++;
        currentResults.forEach(x=>{
          if(x.ip===r.ip && x.port===r.port){
            x.success=true; x.messages_sent=res.messages_sent; x.is_offline=true;
          }
        });
      }
      btn.textContent = '发送中 '+done+'/'+targets.length+' (成功'+ok+')';
      setTimeout(sendNext, 500);
    }).catch(()=>{done++; btn.textContent='发送中 '+done+'/'+targets.length; setTimeout(sendNext,500);});
  }
  sendNext();
}

function renderResults(){
  const search = document.getElementById('searchInput').value.toLowerCase();
  const filter = document.getElementById('filterSelect').value;
  let list = currentResults.filter(r=>{
    if(filter==='offline'&&!r.is_offline)return false;
    if(filter==='success'&&!(r.success&&r.messages_sent>0))return false;
    if(filter==='failed'&&r.success&&r.messages_sent>0)return false;
    if(filter==='hasPlayers'&&!(r.players_online>0))return false;
    if(search){
      const hay = (r.ip+':'+r.port+' '+(r.version_name||'')+' '+(r.motd||'')).toLowerCase();
      if(!hay.includes(search))return false;
    }
    return true;
  });
  const tbody = document.getElementById('resultsBody');
  if(list.length===0){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:30px">暂无数据</td></tr>';return;}
  tbody.innerHTML = list.slice(0,200).map(r=>{
    let badge='';
    if(r.success&&r.messages_sent>0)badge='<span class="badge badge-ok">已发送</span>';
    else if(r.is_offline)badge='<span class="badge badge-offline">离线</span>';
    else if(r.slp_ok)badge='<span class="badge badge-online">在线</span>';
    else badge='<span class="badge badge-fail">失败</span>';
    return '<tr>'+
      '<td style="font-family:monospace;font-size:11px">'+esc(r.ip)+':'+r.port+'</td>'+
      '<td>'+esc(r.version_name||'?')+'</td>'+
      '<td>'+(r.players_online||0)+'/'+(r.players_max||0)+'</td>'+
      '<td>'+badge+'</td>'+
      '<td>'+(r.messages_sent||0)+'</td>'+
      '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(r.motd||'')+'">'+esc((r.motd||'').substring(0,40))+'</td>'+
      '<td><button class="btn btn-sm btn-warn" onclick="warnSingle(\''+esc(r.ip)+'\','+r.port+',this)" style="padding:3px 8px;font-size:11px;background:#f59e0b;color:#fff;border:none;border-radius:4px;cursor:pointer">警告</button></td>'+
    '</tr>';
  }).join('');
}

function renderLogs(logs){
  const box = document.getElementById('logBox');
  box.innerHTML = logs.slice(-100).map(l=>{
    let cls='';
    if(l.includes('✓')||l.includes('完成'))cls='ok';
    else if(l.includes('错误')||l.includes('失败')||l.includes('异常'))cls='err';
    else if(l.includes('警告')||l.includes('停止'))cls='warn';
    return '<div class="'+cls+'">'+esc(l)+'</div>';
  }).join('');
  box.scrollTop = box.scrollHeight;
}

function renderHistory(h){
  const list = document.getElementById('historyList');
  if(!h||h.length===0){list.innerHTML='<div style="text-align:center;color:var(--text3);padding:20px">暂无历史</div>';return;}
  list.innerHTML = h.map(item=>
    '<div class="history-item"><span>'+esc(item.time)+' '+esc(item.target)+'</span><span style="color:var(--text3)">扫描'+item.total+' 开放'+item.open+' 离线'+item.offline+' 成功'+item.success+' 消息'+item.messages+'</span></div>'
  ).join('');
}

function switchTab(tab){
  document.querySelectorAll('.tab').forEach((t,i)=>{
    t.classList.toggle('active',['results','logs','history','database'][i]===tab);
  });
  document.getElementById('tabResults').style.display = tab==='results'?'block':'none';
  document.getElementById('tabLogs').style.display = tab==='logs'?'block':'none';
  document.getElementById('tabHistory').style.display = tab==='history'?'block':'none';
  document.getElementById('tabDatabase').style.display = tab==='database'?'block':'none';
  if(tab==='database'){loadDBStats();loadDB(1);}
}

function exportJSON(){
  const blob = new Blob([JSON.stringify(currentResults,null,2)],{type:'application/json'});
  const a = document.createElement('a');a.href=URL.createObjectURL(blob);a.download='mc-scanner-results.json';a.click();
}
function exportCSV(){
  if(currentResults.length===0){alert('无数据');return;}
  const keys=['ip','port','version_name','protocol_version','players_online','players_max','is_offline','success','messages_sent','motd','error'];
  let csv = keys.join(',')+'\n';
  currentResults.forEach(r=>{
    csv += keys.map(k=>{
      let v = r[k]!=null?r[k]:'';
      v = String(v).replace(/"/g,'""');
      return '"'+v+'"';
    }).join(',')+'\n';
  });
  const blob = new Blob(['\ufeff'+csv],{type:'text/csv'});
  const a = document.createElement('a');a.href=URL.createObjectURL(blob);a.download='mc-scanner-results.csv';a.click();
}

// 加载保存的配置
window.addEventListener('load',()=>{
  const saved = localStorage.getItem('mcScannerCfg');
  if(saved){
    try{
      const c = JSON.parse(saved);
      if(c.target)document.getElementById('target').value=c.target;
      if(c.ports)document.getElementById('ports').value=c.ports;
      if(c.bot_name)document.getElementById('botName').value=c.bot_name;
      if(c.messages)document.getElementById('messages').value=c.messages;
      if(c.scan_threads)document.getElementById('scanThreads').value=c.scan_threads;
      if(c.bot_threads)document.getElementById('botThreads').value=c.bot_threads;
      if(c.message_count)document.getElementById('messageCount').value=c.message_count;
      if(c.message_delay)document.getElementById('messageDelay').value=c.message_delay;
      if(c.continuous_mode!==undefined)document.getElementById('continuousMode').checked=c.continuous_mode;
      if(c.use_exclude!==undefined)document.getElementById('useExclude').checked=c.use_exclude;
    }catch(e){}
  }
  pollState();
  if(!pollTimer)pollTimer=setInterval(pollState,2000);
});

// 自动保存配置
setInterval(()=>{localStorage.setItem('mcScannerCfg',JSON.stringify(getCfg()));},5000);

// ===== 数据库功能 =====
let dbPage=1, dbLimit=50, dbTotal=0;
function dbTag(a){const map={offline:['offline','离线'],online:['online','正版'],whitelist:['whitelist','白名单'],rejected:['rejected','拒绝'],unknown:['unknown','未知']};
 const t=map[a]||[a,a];return '<span class="badge badge-'+t[0]+'">'+t[1]+'</span>';}
function loadDBStats(){
  fetch('/api/db/stats').then(r=>r.json()).then(s=>{
    const auth=s.by_auth||{};
    document.getElementById('dbTotal').textContent=s.total||0;
    document.getElementById('dbOffline').textContent=auth.offline||0;
    document.getElementById('dbOnline').textContent=auth.online||0;
    document.getElementById('dbWhitelist').textContent=auth.whitelist||0;
    document.getElementById('dbHasPlayers').textContent=s.online_servers||0;
  });
}
function loadDB(p){
  dbPage=p;
  const q=new URLSearchParams({
    auth:document.getElementById('dbAuth').value,
    modded:document.getElementById('dbMod').value,
    search:document.getElementById('dbSearch').value,
    limit:dbLimit,offset:(dbPage-1)*dbLimit
  });
  fetch('/api/db/servers?'+q).then(r=>r.json()).then(d=>{
    dbTotal=d.total||0;
    document.getElementById('dbPage').textContent=dbPage+' / '+Math.max(1,Math.ceil(dbTotal/dbLimit));
    document.getElementById('dbRows').innerHTML=d.items.map(s=>'<tr><td style="font-family:monospace;font-size:11px">'+esc(s.ip)+':'+s.port+'</td><td>'+dbTag(s.auth)+'</td><td>'+esc(s.version)+'</td><td>'+s.players_online+'/'+s.players_max+'</td><td>'+(s.is_modded?'模组':'纯净')+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(s.motd||'')+'">'+esc((s.motd||'').substring(0,40))+'</td><td style="font-size:11px;color:#64748b">'+esc((s.last_updated||'').slice(5,16))+'</td></tr>').join('')||'<tr><td colspan="7" style="text-align:center;color:#64748b;padding:30px">数据库为空，先扫描一批服务器</td></tr>';
  });
}
function prevDB(){if(dbPage>1)loadDB(dbPage-1)}
function nextDB(){if(dbPage<Math.ceil(dbTotal/dbLimit))loadDB(dbPage+1)}
document.getElementById('dbSearch').addEventListener('keydown',e=>{if(e.key==='Enter')loadDB(1);});
</script>
</body>
</html>
"""


# ============================================================
# HTTP 处理器
# ============================================================
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # 静默

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/' or parsed.path == '/index.html':
            body = HTML_PAGE.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == '/api/status':
            s = get_state()
            s["history"] = history
            self._send_json(s)
        elif parsed.path == '/api/export':
            self._send_json({"results": get_state()["results"]})
        elif parsed.path == '/api/db/servers':
            params = parse_qs(parsed.query)
            auth = params.get("auth", [None])[0]
            modded = params.get("modded", [None])[0]
            modded = None if modded in (None, "") else (modded == "1")
            search = params.get("search", [None])[0]
            limit = min(int(params.get("limit", [50])[0]), 500)
            offset = int(params.get("offset", [0])[0])
            rows = db_store.query(DB_PATH, auth=auth, modded=modded, search=search,
                                   limit=limit, offset=offset)
            total = db_store.count(DB_PATH, auth=auth, modded=modded, search=search)
            self._send_json({"total": total, "items": rows})
        elif parsed.path == '/api/db/stats':
            self._send_json(db_store.stats(DB_PATH))
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b'{}'
        try:
            cfg = json.loads(body.decode('utf-8'))
        except Exception:
            cfg = {}

        if parsed.path == '/api/start':
            if task_state["running"]:
                self._send_json({"error": "任务正在运行中"})
                return
            t = threading.Thread(target=run_scan, args=(cfg,), daemon=True)
            t.start()
            self._send_json({"ok": True})

        elif parsed.path == '/api/stop':
            stop_task()
            self._send_json({"ok": True})

        elif parsed.path == '/api/quick':
            # 单台快速测试
            target = cfg.get('target', '').strip()
            if ':' in target:
                ip, port = target.rsplit(':', 1)
                port = int(port)
            else:
                ip, port = target, 25565
            username = cfg.get('bot_name', 'SecurityBot') or 'SecurityBot'
            messages_raw = cfg.get('messages', DEFAULT_WARNING_MESSAGES)
            if isinstance(messages_raw, str):
                messages = [m.strip() for m in messages_raw.split('\n') if m.strip()]
            else:
                messages = [m for m in messages_raw if m and str(m).strip()]
            message_count = int(cfg.get('message_count', 2))
            messages = messages[:max(1, message_count)]
            authme = cfg.get('authme_password', '') or None
            force_proto = cfg.get('force_protocol', '')
            force_proto = int(force_proto) if force_proto and force_proto.isdigit() else None
            try:
                r = join_and_warn(ip, port, username=username, messages=messages,
                                  timeout=float(cfg.get('bot_timeout', 12)),
                                  protocol_version=force_proto, authme_password=authme,
                                  message_delay=float(cfg.get('message_delay', 0.8)))
                self._send_json({
                    "is_offline": r.is_offline, "success": r.success,
                    "messages_sent": r.messages_sent, "error": r.error or "",
                })
            except Exception as e:
                self._send_json({"error": str(e)[:200]})

        else:
            self._send_json({"error": "Not found"}, 404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(('127.0.0.1', port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"=" * 50)
    print(f"  MC Scanner v3 Web 面板已启动")
    print(f"  访问地址: {url}")
    print(f"  按 Ctrl+C 停止")
    print(f"=" * 50)
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        server.shutdown()


if __name__ == '__main__':
    main()
