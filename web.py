#!/usr/bin/env python3
"""
Minecraft 扫描器 Web 控制面板（加强版）
启动: python web.py [端口]
默认: http://localhost:8080
零依赖，仅用 Python 标准库

功能:
- 实时日志输出
- 结果导出 JSON/CSV
- 配置自动保存（localStorage）
- 结果筛选/搜索
- 历史记录
- 端口范围支持
- 可停止任务
- 统计面板
"""
import json
import threading
import time
import os
import sys
import csv
import io
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from scanner import (
    parse_targets, scan_ports, get_open_ports, deduplicate_targets, parse_port_spec,
)
from bot import join_and_warn, DEFAULT_WARNING_MESSAGES
from mc_protocol import server_list_ping, get_version_name

# ============================================================
# 全局状态
# ============================================================
MAX_HISTORY = 20
task_state = {
    "running": False,
    "phase": "idle",
    "progress": 0,
    "total": 0,
    "open_count": 0,
    "message": "",
    "results": [],
    "logs": [],
    "start_time": None,
    "elapsed": 0,
    "task_id": 0,
}
history = []  # 历史任务记录
state_lock = threading.Lock()
stop_event = threading.Event()


def log(msg: str):
    """添加日志"""
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


def add_result(result):
    with state_lock:
        task_state["results"].append(result)


def save_to_history():
    """保存当前任务到历史记录"""
    with state_lock:
        if not task_state["results"]:
            return
        record = {
            "task_id": task_state["task_id"],
            "phase": task_state["phase"],
            "message": task_state["message"],
            "total": len(task_state["results"]),
            "offline": sum(1 for r in task_state["results"] if r.get("is_offline")),
            "success": sum(1 for r in task_state["results"] if r.get("success") and r.get("messages_sent", 0) > 0),
            "messages": sum(r.get("messages_sent", 0) for r in task_state["results"]),
            "elapsed": task_state["elapsed"],
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": list(task_state["results"]),
        }
        history.insert(0, record)
        if len(history) > MAX_HISTORY:
            history.pop()


# ============================================================
# 扫描任务
# ============================================================
def run_scan(cfg):
    """执行扫描任务"""
    global stop_event
    stop_event.clear()
    task_id = int(time.time())

    try:
        # 解析端口
        if isinstance(cfg.get('ports'), str):
            ports = parse_port_spec(cfg['ports'])
        elif isinstance(cfg.get('ports'), list):
            ports = cfg['ports']
        else:
            ports = [25565]

        # 解析目标
        target_list = [t.strip() for t in cfg.get('targets', '').split('\n')
                       if t.strip() and not t.strip().startswith('#')]
        targets = parse_targets(target_list, default_ports=ports)
        targets = deduplicate_targets(targets)

        if not targets:
            update_state(phase="done", message="没有有效的目标", running=False, task_id=task_id)
            log("错误: 没有有效的目标")
            return

        update_state(
            running=True, phase="portscan",
            progress=0, total=len(targets), open_count=0,
            message=f"端口扫描中... {len(targets)} 个目标",
            results=[], logs=[], start_time=time.time(), task_id=task_id,
        )
        log(f"任务启动: {len(targets)} 个目标, 端口 {ports}, 模式 {'警告' if cfg.get('do_warn') else '扫描'}")

        # 阶段1: 端口扫描
        def scan_progress(done, total, open_cnt):
            elapsed = time.time() - task_state["start_time"] if task_state["start_time"] else 1
            pps = round(done / elapsed, 1) if elapsed > 0 else 0
            update_state(progress=done, open_count=open_cnt, pps=pps,
                         message=f"端口扫描中... {done}/{total} (开放 {open_cnt}, {pps} p/s)")

        results = scan_ports(
            targets,
            max_workers=int(cfg.get('scan_threads', 200)),
            timeout=float(cfg.get('scan_timeout', 2.5)),
            show_progress=False,
            progress_callback=scan_progress,
            stop_event=stop_event,
        )
        open_ports = get_open_ports(results)
        log(f"端口扫描完成: 开放 {len(open_ports)}/{len(targets)}")

        if stop_event.is_set():
            update_state(phase="done", message="用户停止", running=False)
            log("任务被用户停止")
            return

        if not open_ports:
            update_state(phase="done", message="没有发现开放端口", running=False)
            log("没有发现开放端口")
            return

        # 阶段2
        do_warn = cfg.get('do_warn', False)
        username = cfg.get('username', 'SecurityBot')
        messages = cfg.get('messages', DEFAULT_WARNING_MESSAGES)
        bot_timeout = int(cfg.get('bot_timeout', 12))
        message_delay = float(cfg.get('message_delay', 0.8))
        authme_password = cfg.get('authme_password') or None

        update_state(
            phase="warn" if do_warn else "slp",
            progress=0, total=len(open_ports),
            message=f"{'警告发送' if do_warn else 'SLP探测'}中... 0/{len(open_ports)}",
        )

        all_results = []
        for i, (ip, port) in enumerate(open_ports):
            if stop_event.is_set():
                log("任务被用户停止")
                break

            if do_warn:
                try:
                    r = join_and_warn(
                        ip, port, username=username, messages=messages,
                        timeout=bot_timeout, message_delay=message_delay,
                        authme_password=authme_password,
                    )
                    entry = {
                        "ip": r.ip, "port": r.port,
                        "success": r.success, "is_offline": r.is_offline,
                        "protocol_version": r.protocol_version,
                        "version_name": r.version_name or get_version_name(r.protocol_version),
                        "motd": r.motd,
                        "players_online": r.players_online,
                        "players_max": r.players_max,
                        "messages_sent": r.messages_sent,
                        "authme_used": r.authme_used,
                        "error": r.error,
                        "type": "warn",
                    }
                except Exception as e:
                    entry = {
                        "ip": ip, "port": port, "success": False,
                        "is_offline": False, "error": str(e)[:200], "type": "warn",
                    }
            else:
                # SLP 探测
                entry = {"ip": ip, "port": port, "type": "slp",
                         "success": False, "is_offline": False, "messages_sent": 0}
                try:
                    info = server_list_ping(ip, port, timeout=float(cfg.get('scan_timeout', 3)))
                    if info:
                        v = info.get('version', {})
                        p = info.get('players', {})
                        proto = v.get('protocol', 0)
                        desc = info.get('description', '')
                        entry.update({
                            "success": True,
                            "protocol_version": proto,
                            "version_name": get_version_name(proto) if isinstance(proto, int) else str(proto),
                            "players_online": p.get('online', 0),
                            "players_max": p.get('max', 0),
                            "motd": (desc.get('text', str(desc)) if isinstance(desc, dict) else str(desc))[:200],
                        })
                except Exception as e:
                    entry["error"] = str(e)[:100]

            all_results.append(entry)
            update_state(progress=i + 1, results=list(all_results),
                         message=f"{'警告' if do_warn else 'SLP'}中... {i+1}/{len(open_ports)}")

            if entry.get("success") and entry.get("messages_sent", 0) > 0:
                log(f"✓ {ip}:{port} 发送{entry['messages_sent']}条 ({entry.get('version_name','?')})")
            elif entry.get("is_offline"):
                log(f"○ {ip}:{port} 离线模式 ({entry.get('version_name','?')})")

        with state_lock:
            task_state["results"] = all_results

        success_count = sum(1 for r in all_results if r.get("success") and r.get("messages_sent", 0) > 0)
        offline_count = sum(1 for r in all_results if r.get("is_offline"))
        msg_total = sum(r.get("messages_sent", 0) for r in all_results)

        update_state(
            phase="done", running=False,
            message=f"完成！离线服 {offline_count} 个，成功发送 {success_count} 个，共 {msg_total} 条消息",
        )
        log(f"任务完成: 离线{offline_count}个, 成功{success_count}个, 消息{msg_total}条")
        save_to_history()

    except Exception as e:
        update_state(phase="done", message=f"错误: {e}", running=False)
        log(f"致命错误: {e}")


# ============================================================
# HTML 控制面板
# ============================================================
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MC Scanner 控制面板 v2</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0c10;color:#e0e0e0;min-height:100vh}
.container{max-width:1400px;margin:0 auto;padding:16px}
h1{font-size:22px;margin-bottom:16px;color:#4ade80;display:flex;align-items:center;gap:10px}
h1 .ver{font-size:12px;background:#1e293b;padding:3px 8px;border-radius:4px;color:#94a3b8}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.panel{background:#12151c;border-radius:12px;padding:16px;border:1px solid #1e293b}
.panel h2{font-size:13px;margin-bottom:12px;color:#64748b;text-transform:uppercase;letter-spacing:1px;font-weight:600}
.field{margin-bottom:10px}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:4px}
input,textarea,select{width:100%;background:#0a0c10;border:1px solid #1e293b;border-radius:6px;padding:8px 10px;color:#e0e0e0;font-size:13px;font-family:inherit}
input:focus,textarea:focus{outline:none;border-color:#4ade80}
textarea{resize:vertical;min-height:70px;font-family:monospace;font-size:12px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row .field{flex:1;min-width:100px}
.btn{padding:10px 18px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:6px}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-primary{background:#4ade80;color:#0a0c10}
.btn-primary:hover:not(:disabled){background:#22c55e}
.btn-secondary{background:#1e293b;color:#e0e0e0}
.btn-secondary:hover{background:#334155}
.btn-danger{background:#ef4444;color:#fff}
.btn-sm{padding:6px 12px;font-size:12px}
.progress-wrap{margin:12px 0}
.progress-bar{background:#0a0c10;border-radius:6px;height:22px;overflow:hidden;position:relative}
.progress-fill{background:linear-gradient(90deg,#4ade80,#22c55e);height:100%;transition:width .3s;display:flex;align-items:center;justify-content:center;font-size:11px;color:#0a0c10;font-weight:700;min-width:30px}
.status-line{font-size:13px;color:#94a3b8;margin:8px 0;display:flex;gap:12px;flex-wrap:wrap}
.status-line .tag{background:#1e293b;padding:2px 8px;border-radius:4px;font-size:11px}
.status-line .tag.active{background:#166534;color:#4ade80}
.stats{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0}
.stat{text-align:center;flex:1;min-width:80px;background:#0a0c10;border-radius:8px;padding:10px}
.stat .num{font-size:22px;font-weight:700;color:#4ade80}
.stat .label{font-size:11px;color:#64748b;margin-top:2px}
.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.tab{padding:6px 14px;background:#1e293b;border-radius:6px;cursor:pointer;font-size:12px;color:#94a3b8;border:1px solid transparent}
.tab.active{background:#4ade80;color:#0a0c10;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #1e293b}
th{color:#64748b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:#12151c}
tr:hover{background:#1a1e28}
.badge{padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;white-space:nowrap}
.badge-ok{background:#166534;color:#4ade80}
.badge-off{background:#1e3a5f;color:#60a5fa}
.badge-on{background:#7f1d1d;color:#f87171}
.badge-err{background:#7f1d1d;color:#f87171}
.badge-info{background:#334155;color:#94a3b8}
.log-box{background:#0a0c10;border-radius:8px;padding:10px;font-family:monospace;font-size:11px;max-height:180px;overflow-y:auto;line-height:1.6}
.log-box .ok{color:#4ade80}
.log-box .err{color:#f87171}
.log-box .info{color:#94a3b8}
.filter-bar{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:150px}
.result-wrap{max-height:400px;overflow-y:auto}
.motd-cell{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.history-item{padding:8px 10px;border-bottom:1px solid #1e293b;cursor:pointer;display:flex;justify-content:space-between;align-items:center;font-size:12px}
.history-item:hover{background:#1a1e28}
.empty{text-align:center;padding:30px;color:#475569;font-size:13px}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
</style>
</head>
<body>
<div class="container">
  <h1>⛏ MC Scanner <span class="ver">v2.0 加强版</span></h1>

  <div class="grid">
    <!-- 左列：配置 -->
    <div>
      <div class="panel">
        <h2>机器人配置</h2>
        <div class="row">
          <div class="field">
            <label>Bot 名称</label>
            <input type="text" id="username" value="SecurityBot">
          </div>
          <div class="field">
            <label>端口（支持范围 25565-25575）</label>
            <input type="text" id="ports" value="25565,25566-25570">
          </div>
        </div>
        <div class="field">
          <label>警告消息（每行一条）</label>
          <textarea id="messages">您好，我是安全扫描机器人，不会破坏您的服务器
检测到您的服务器处于离线模式(offline-mode)，攻击者可伪造任意用户名登录
建议在 server.properties 中设置 online-mode=true
如必须离线模式，请安装 AuthMe 并开启白名单</textarea>
        </div>
      </div>

      <div class="panel">
        <h2>扫描目标与参数</h2>
        <div class="field">
          <label>目标（每行一个，支持 IP / CIDR / 主机名，# 注释）</label>
          <textarea id="targets" placeholder="192.168.1.0/24&#10;10.0.0.1&#10;# 这是注释&#10;mc.example.com"></textarea>
        </div>
        <div class="row">
          <div class="field"><label>扫描线程</label><input type="number" id="scan_threads" value="200" min="1"></div>
          <div class="field"><label>扫描超时(s)</label><input type="number" id="scan_timeout" value="2.5" step="0.5"></div>
          <div class="field"><label>机器人超时(s)</label><input type="number" id="bot_timeout" value="12" min="5"></div>
          <div class="field"><label>消息间隔(s)</label><input type="number" id="message_delay" value="0.8" step="0.1"></div>
          <div class="field"><label>AuthMe密码(可选)</label><input type="text" id="authme_password" placeholder="留空不启用"></div>
        </div>
      </div>

      <div class="panel">
        <div class="actions">
          <button class="btn btn-primary" id="btn_scan" onclick="startTask(false)">🔍 仅扫描</button>
          <button class="btn btn-primary" id="btn_warn" onclick="startTask(true)">⚠️ 扫描+警告</button>
          <button class="btn btn-danger" id="btn_stop" onclick="stopTask()" style="display:none">⏹ 停止</button>
          <button class="btn btn-secondary btn-sm" onclick="saveConfig()">💾 保存配置</button>
          <button class="btn btn-secondary btn-sm" onclick="loadConfig()">📂 加载配置</button>
        </div>
        <div class="status-line" id="status_text">
          <span class="tag">就绪</span>
        </div>
        <div class="progress-wrap">
          <div class="progress-bar"><div class="progress-fill" id="progress_fill" style="width:0%">0%</div></div>
        </div>
      </div>
    </div>

    <!-- 右列：日志+历史 -->
    <div>
      <div class="panel">
        <h2>实时日志</h2>
        <div class="log-box" id="log_box"><div class="info">等待任务启动...</div></div>
      </div>

      <div class="panel">
        <h2>历史记录</h2>
        <div id="history_list"><div class="empty">暂无历史记录</div></div>
      </div>
    </div>
  </div>

  <!-- 统计+结果 -->
  <div class="panel" id="result_panel" style="display:none">
    <h2>扫描结果</h2>
    <div class="stats" id="stats_bar"></div>
    <div class="filter-bar">
      <input type="text" id="filter_input" placeholder="搜索 IP / MOTD / 版本..." oninput="renderResults()">
      <button class="tab active" data-filter="all" onclick="setFilter('all',this)">全部</button>
      <button class="tab" data-filter="offline" onclick="setFilter('offline',this)">离线模式</button>
      <button class="tab" data-filter="success" onclick="setFilter('success',this)">已发送</button>
      <button class="tab" data-filter="failed" onclick="setFilter('failed',this)">失败</button>
      <button class="btn btn-secondary btn-sm" onclick="exportJSON()">导出JSON</button>
      <button class="btn btn-secondary btn-sm" onclick="exportCSV()">导出CSV</button>
    </div>
    <div class="result-wrap">
      <table>
        <thead><tr><th>IP:端口</th><th>版本</th><th>协议</th><th>玩家</th><th>状态</th><th>消息</th><th>MOTD/错误</th></tr></thead>
        <tbody id="results_body"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
let pollTimer = null;
let currentResults = [];
let currentFilter = 'all';

// 配置保存/加载
function saveConfig(){
  const cfg = getConfig();
  localStorage.setItem('mcscanner_cfg', JSON.stringify(cfg));
  alert('配置已保存到浏览器');
}
function loadConfig(){
  const s = localStorage.getItem('mcscanner_cfg');
  if(!s){alert('没有保存的配置');return;}
  const c = JSON.parse(s);
  document.getElementById('username').value = c.username||'';
  document.getElementById('ports').value = c.ports||'';
  document.getElementById('messages').value = (c.messages||[]).join('\n');
  document.getElementById('targets').value = c.targets||'';
  document.getElementById('scan_threads').value = c.scan_threads||200;
  document.getElementById('scan_timeout').value = c.scan_timeout||2.5;
  document.getElementById('bot_timeout').value = c.bot_timeout||12;
  document.getElementById('message_delay').value = c.message_delay||0.8;
  document.getElementById('authme_password').value = c.authme_password||'';
}
// 自动加载
(function(){const s=localStorage.getItem('mcscanner_cfg');if(s){try{const c=JSON.parse(s);document.getElementById('targets').value=c.targets||'';}catch(e){}}})();

function getConfig(){
  return {
    targets: document.getElementById('targets').value,
    username: document.getElementById('username').value,
    messages: document.getElementById('messages').value.split('\n').filter(m=>m.trim()),
    ports: document.getElementById('ports').value,
    scan_threads: parseInt(document.getElementById('scan_threads').value)||200,
    scan_timeout: parseFloat(document.getElementById('scan_timeout').value)||2.5,
    bot_timeout: parseInt(document.getElementById('bot_timeout').value)||12,
    message_delay: parseFloat(document.getElementById('message_delay').value)||0.8,
    authme_password: document.getElementById('authme_password').value.trim()||null,
  };
}

async function startTask(doWarn){
  const cfg = getConfig();
  if(!cfg.targets.trim()){alert('请输入扫描目标');return;}
  if(doWarn && !cfg.messages.length){alert('请输入至少一条警告消息');return;}

  document.getElementById('btn_scan').disabled=true;
  document.getElementById('btn_warn').disabled=true;
  document.getElementById('btn_stop').style.display='inline-flex';
  document.getElementById('result_panel').style.display='none';
  document.getElementById('log_box').innerHTML='';

  const res = await fetch('/api/start',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({...cfg,do_warn:doWarn}),
  });
  const data = await res.json();
  if(data.error){alert(data.error);resetBtns();return;}
  pollTimer = setInterval(pollStatus,400);
}

async function stopTask(){
  await fetch('/api/stop',{method:'POST'});
  if(pollTimer){clearInterval(pollTimer);pollTimer=null;}
  resetBtns();
}

function resetBtns(){
  document.getElementById('btn_scan').disabled=false;
  document.getElementById('btn_warn').disabled=false;
  document.getElementById('btn_stop').style.display='none';
}

async function pollStatus(){
  const res = await fetch('/api/status');
  const s = await res.json();

  const pct = s.total>0?Math.round(s.progress/s.total*100):0;
  document.getElementById('progress_fill').style.width=pct+'%';
  document.getElementById('progress_fill').textContent=pct+'%';

  const ppsTag = s.pps?`<span class="tag">${s.pps} p/s</span>`:'';
  document.getElementById('status_text').innerHTML =
    `<span class="tag ${s.running?'active':''}">${s.phase}</span>` +
    `<span>${s.message}</span>` +
    `<span class="tag">${s.progress}/${s.total}</span>` +
    ppsTag +
    `<span class="tag">${s.elapsed}s</span>`;

  // 日志
  const logBox = document.getElementById('log_box');
  logBox.innerHTML = s.logs.slice(-100).map(l=>{
    if(l.includes('✓'))return `<div class="ok">${l}</div>`;
    if(l.includes('错误')||l.includes('失败'))return `<div class="err">${l}</div>`;
    return `<div class="info">${l}</div>`;
  }).join('');
  logBox.scrollTop = logBox.scrollHeight;

  // 实时更新结果（运行中也显示）
  if(s.results && s.results.length>0){
    currentResults = s.results;
    renderResults();
    renderStats(s);
    document.getElementById('result_panel').style.display='block';
  }

  if(s.phase==='done'||!s.running){
    if(pollTimer){clearInterval(pollTimer);pollTimer=null;}
    resetBtns();
    currentResults = s.results;
    renderResults();
    renderStats(s);
    document.getElementById('result_panel').style.display='block';
    loadHistory();
  }
}

function renderStats(s){
  const offline = s.results.filter(r=>r.is_offline).length;
  const success = s.results.filter(r=>r.success&&r.messages_sent>0).length;
  const msgs = s.results.reduce((a,r)=>a+(r.messages_sent||0),0);

  // 版本分布统计
  const verCount = {};
  s.results.forEach(r=>{
    const v = r.version_name || '未知';
    verCount[v] = (verCount[v]||0)+1;
  });
  const verEntries = Object.entries(verCount).sort((a,b)=>b[1]-a[1]).slice(0,6);
  const maxVer = verEntries.length?verEntries[0][1]:1;
  const verChart = verEntries.map(([v,c])=>{
    const pct = Math.round(c/maxVer*100);
    return `<div style="display:flex;align-items:center;gap:8px;margin:4px 0">
      <span style="width:120px;font-size:11px;color:#94a3b8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${v}">${v}</span>
      <div style="flex:1;background:#0a0c10;border-radius:4px;height:16px;overflow:hidden">
        <div style="width:${pct}%;height:100%;background:linear-gradient(90deg,#4ade80,#22c55e);border-radius:4px"></div>
      </div>
      <span style="width:30px;text-align:right;font-size:11px;color:#4ade80">${c}</span>
    </div>`;
  }).join('');

  document.getElementById('stats_bar').innerHTML = `
    <div class="stat"><div class="num">${s.results.length}</div><div class="label">总目标</div></div>
    <div class="stat"><div class="num" style="color:#60a5fa">${offline}</div><div class="label">离线模式</div></div>
    <div class="stat"><div class="num">${success}</div><div class="label">成功发送</div></div>
    <div class="stat"><div class="num" style="color:#fbbf24">${msgs}</div><div class="label">消息总数</div></div>
    <div class="stat"><div class="num" style="color:#94a3b8">${s.elapsed}s</div><div class="label">耗时</div></div>
    <div style="flex:2;min-width:250px;background:#0a0c10;border-radius:8px;padding:10px">
      <div style="font-size:11px;color:#64748b;margin-bottom:6px;text-transform:uppercase">版本分布</div>
      ${verChart || '<div style="color:#475569;font-size:12px">暂无数据</div>'}
    </div>
  `;
}

function setFilter(f,el){
  currentFilter=f;
  document.querySelectorAll('.tab[data-filter]').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  renderResults();
}

function esc(s){
  if(s===undefined||s===null)return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function renderResults(){
  const q = document.getElementById('filter_input').value.toLowerCase();
  let list = currentResults.filter(r=>{
    if(currentFilter==='offline'&&!r.is_offline)return false;
    if(currentFilter==='success'&&!(r.success&&r.messages_sent>0))return false;
    if(currentFilter==='failed'&&r.success&&r.messages_sent>0)return false;
    if(q){
      const text = `${r.ip}:${r.port} ${r.version_name||''} ${r.motd||''} ${r.error||''}`.toLowerCase();
      if(!text.includes(q))return false;
    }
    return true;
  });
  const tbody = document.getElementById('results_body');
  if(!list.length){tbody.innerHTML='<tr><td colspan="7" class="empty">没有匹配的结果</td></tr>';return;}
  tbody.innerHTML = list.map(r=>{
    let badge;
    if(r.type==='slp'&&r.success)badge='<span class="badge badge-info">MC服务器</span>';
    else if(r.success&&r.messages_sent>0)badge='<span class="badge badge-ok">已发送</span>';
    else if(r.is_offline)badge='<span class="badge badge-off">离线模式</span>';
    else if(r.error&&/online/i.test(r.error))badge='<span class="badge badge-on">在线模式</span>';
    else badge='<span class="badge badge-err">失败</span>';
    const players = r.players_online!==undefined?`${r.players_online}/${r.players_max||'?'}`:'-';
    const detail = r.error||r.motd||'-';
    return `<tr>
      <td><b>${esc(r.ip)}:${r.port}</b></td>
      <td>${esc(r.version_name)||'-'}</td>
      <td>${r.protocol_version||'-'}</td>
      <td>${players}</td>
      <td>${badge}</td>
      <td>${r.messages_sent||0}</td>
      <td class="motd-cell" title="${esc(detail)}">${esc(detail)}</td>
    </tr>`;
  }).join('');
}

function exportJSON(){
  const ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  const blob = new Blob([JSON.stringify(currentResults,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download=`mcscanner_${ts}.json`;a.click();
}
function exportCSV(){
  if(!currentResults.length)return;
  const ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  const keys=['ip','port','version_name','protocol_version','players_online','players_max','is_offline','success','messages_sent','authme_used','motd','error'];
  const csv=[keys.join(',')].concat(currentResults.map(r=>keys.map(k=>{
    let v=r[k]!==undefined?r[k]:'';
    v=String(v).replace(/"/g,'""');
    return /[,"\n]/.test(v)?`"${v}"`:v;
  }).join(','))).join('\n');
  const blob=new Blob(['\ufeff'+csv],{type:'text/csv'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download=`mcscanner_${ts}.csv`;a.click();
}

async function loadHistory(){
  const res = await fetch('/api/history');
  const data = await res.json();
  const el = document.getElementById('history_list');
  if(!data.length){el.innerHTML='<div class="empty">暂无历史记录</div>';return;}
  el.innerHTML = data.map(h=>`
    <div class="history-item" onclick="loadHistoryResult(${h.task_id})">
      <span>${h.time} | ${h.message}</span>
      <span style="color:#64748b">离线${h.offline} 成功${h.success} 消息${h.messages}</span>
    </div>
  `).join('');
}

async function loadHistoryResult(id){
  const res = await fetch('/api/history/'+id);
  const data = await res.json();
  if(data.results){
    currentResults = data.results;
    renderResults();
    document.getElementById('result_panel').style.display='block';
    document.getElementById('stats_bar').innerHTML = `
      <div class="stat"><div class="num">${data.total}</div><div class="label">总目标</div></div>
      <div class="stat"><div class="num" style="color:#60a5fa">${data.offline}</div><div class="label">离线模式</div></div>
      <div class="stat"><div class="num">${data.success}</div><div class="label">成功发送</div></div>
      <div class="stat"><div class="num" style="color:#fbbf24">${data.messages}</div><div class="label">消息总数</div></div>
    `;
  }
}

loadHistory();
</script>
</body>
</html>"""


# ============================================================
# HTTP 处理
# ============================================================
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/':
            body = HTML_PAGE.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == '/api/status':
            self._send_json(get_state())
        elif path == '/api/history':
            self._send_json([{k: v for k, v in h.items() if k != 'results'} for h in history])
        elif path.startswith('/api/history/'):
            try:
                tid = int(path.split('/')[-1])
                rec = next((h for h in history if h['task_id'] == tid), None)
                if rec:
                    self._send_json(rec)
                else:
                    self._send_json({"error": "not found"}, 404)
            except ValueError:
                self._send_json({"error": "invalid id"}, 400)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b'{}'
        try:
            data = json.loads(body)
        except:
            data = {}

        if path == '/api/start':
            if task_state["running"]:
                self._send_json({"error": "已有任务在运行"})
                return
            t = threading.Thread(target=run_scan, args=(data,), daemon=True)
            t.start()
            self._send_json({"status": "started"})
        elif path == '/api/stop':
            stop_event.set()
            update_state(running=False, phase="done", message="用户停止")
            log("收到停止信号")
            self._send_json({"status": "stopped"})
        else:
            self._send_json({"error": "Not found"}, 404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(('127.0.0.1', port), Handler)
    print(f"[*] MC Scanner Web 控制面板 v2.0")
    print(f"[*] 浏览器打开: http://localhost:{port}")
    print(f"[*] 按 Ctrl+C 停止")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 已停止")
        server.shutdown()


if __name__ == '__main__':
    main()
