<div align="center">

# 🛡️ MC Scanner v3

### Minecraft 服务器扫描与安全提醒机器人

**零依赖 · 全版本支持 · Web 控制面板 · 自动离线检测 · SQLite存储 · 协议回退**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/Minecraft-1.12.2~Latest-orange.svg)](#支持版本)

</div>

---

## 📖 简介

扫描互联网上的 Minecraft 服务器，检测离线模式（offline-mode），自动登录并发送安全警告消息。支持全版本协议、Web 控制面板、SQLite 持久化存储、masscan 高速扫描。

协议实现基于 [MCPyBot](https://github.com/Fireroth/MCPyBot)，经过真实服务器实测验证。

## ✨ 功能特性

### 核心功能
- 🔍 **多线程端口扫描** — 支持 CIDR 网段、端口范围、主机名，惰性生成器不OOM
- 📡 **SLP 协议探测** — 获取版本、玩家数、MOTD、协议版本，JSON截断容错
- 🎯 **五态认证检测** — 离线/正版/白名单/拒绝/未知，白名单关键词自动识别
- 💬 **自动安全警告** — 登录后发送自定义警告消息，支持多条
- 🔐 **AuthMe 自动注册** — 自动执行 `/register` + `/login`，密码留空自动生成
- 🔄 **协议多级回退** — 未知协议号自动尝试常见协议号，兼容性更强

### 全版本兼容
- 📦 支持 **Minecraft 1.12.2 ~ 最新版本**（协议 340+）
- 🔄 自动版本适配：SLP 获取协议版本 → 对应包ID/登录流程/聊天格式
- 📝 协议表自动生成：运行 `gen_packets.py` 从官方 minecraft-data 生成，杜绝手抄错误
- ✅ 已实测通过：1.12.2、1.20.2、1.20.4、1.21.1、1.21.11 等

### Web 控制面板
- 🌐 浏览器可视化操作，无需记命令
- 📊 实时进度条 + 实时日志输出
- 🔎 结果筛选（全部/离线/已发送/失败/有人在线）+ 关键词搜索
- 📈 版本分布柱状图
- 💾 一键导出 JSON / CSV
- 🕐 历史记录（最近 20 次任务）
- ⚙️ 配置自动保存到浏览器
- 🎯 **单独警告** — 扫描结果里每台服务器点一下就发警告，不用重扫
- ⚡ **批量警告** — 筛选后一键对全部离线服发警告
- 🗄️ **数据库标签页** — SQLite 持久化存储，支持按认证/模组/搜索过滤+分页

### 高速扫描
- 🚀 **masscan 集成** — 自动检测，有 masscan 就用（快10倍），没有回退 Python
- 📥 **import 命令** — masscan 扫完的结果可以离线导入再 SLP 探测
- ⏱️ **--rate 限速** — 控制每秒连接数，避免被运营商封
- 🚫 **排除列表** — `exclude.conf` 自动过滤私有地址/云厂商段

### 数据存储
- 🗄️ **SQLite 持久化** — 扫描结果自动写入 `mcscanner.db`，UPSERT 去重更新
- 🔍 **query 命令** — 命令行查询数据库，按认证/模组/关键词过滤
- 📊 统计信息：总数/各认证模式分布/有人在线数

### 其他
- 📝 配置文件驱动（`config.json`），命令行参数可覆盖（--workers/--timeout/--rate等）
- 🔄 失败自动重试
- ⏹️ 随时停止任务
- 📦 零第三方依赖，仅用 Python 标准库（masscan 为可选外部工具）
- 🤖 **命令执行工具** — `mc_send_command.py` 可给服务器发指令（如 /op）

---

## 🚀 快速开始

### 环境要求
- Python 3.8+（推荐 3.10+）
- Windows / Linux / Mac 均可

### 一键启动（推荐）

**Windows:**
```bash
双击 run.bat
```

**Linux/Mac:**
```bash
chmod +x run.sh
./run.sh
```

然后浏览器打开 `http://127.0.0.1:8080`

---

## 💻 命令行用法

### 7 个子命令

```bash
# 1. 只扫描端口
python main.py portscan 1.2.3.0/24

# 2. 扫描 + SLP 探测
python main.py scan 1.2.3.0/24
python main.py scan 1.2.3.0/24 --workers 300 --timeout 2.0 --rate 500

# 3. 扫描 + 离线检测 + 发警告
python main.py warn 1.2.3.0/24
python main.py warn 1.2.3.0/24 -u MyBot -m "警告消息" --no-auth
python main.py warn 1.2.3.0/24 --rate 200 --workers 200 --bot-workers 10

# 4. 使用 masscan 高速扫描
python main.py masscan 1.2.3.0/24 -p 25565-25575 --rate 10000

# 5. 导入 masscan 结果 + SLP 探测
python main.py import masscan_result.json -o servers.json

# 6. 查询 SQLite 数据库
python main.py query --stats
python main.py query --auth offline --search 1.2.3 --limit 50
python main.py query --modded 1

# 7. 单独对一台服务器发消息
python main.py bot 1.2.3.4:25565 -u MyBot -m "你好" --authme password
```

### 常用参数

| 参数 | 说明 |
|---|---|
| `--workers N` | 扫描线程数（覆盖配置） |
| `--timeout N` | 扫描超时秒数（覆盖配置） |
| `--rate N` | 每秒最大连接数（0=不限速） |
| `--no-auth` | 只 SLP 探测，不登录发消息 |
| `--bot-workers N` | 机器人线程数 |
| `-u, --username` | 机器人用户名 |
| `-m, --message` | 警告消息（可多次） |
| `-f, --file` | 从文件读取目标 |
| `-o, --output` | 结果输出文件 |

---

## ⚙️ 配置文件（config.json）

```json
{
  "username": "SecurityBot",
  "messages": [
    "您好，我是安全扫描机器人",
    "检测到您的服务器处于离线模式",
    "建议设置 online-mode=true 保护玩家账号"
  ],
  "ports": [25565, 25566, 25570],
  "scan_threads": 200,
  "scan_timeout": 2.5,
  "bot_threads": 10,
  "bot_timeout": 12,
  "message_delay": 0.8,
  "retry_count": 1
}
```

---

## 📁 项目结构

```
mc-scanner/
├── main.py              # 命令行入口（7个子命令）
├── web.py               # Web 控制面板
├── bot.py               # 机器人核心（登录+发消息+AuthMe）
├── mc_protocol.py       # 协议层（SLP/编解码/版本表/协议回退）
├── scanner.py           # 端口扫描（多线程+masscan+限速+生成器）
├── db.py                # SQLite 存储层
├── gen_packets.py       # 协议表自动生成器
├── mc_send_command.py   # 命令执行工具（/op等）
├── config.json          # 配置文件
├── exclude.conf         # 排除列表
├── run.bat              # Windows 一键启动
├── run.sh               # Linux/Mac 一键启动
├── test_mock_*.py       # Mock 测试服务器（340/764/774）
└── README.md            # 本文档
```

---

## 🔧 高级功能

### 协议表自动生成

从官方 minecraft-data 自动生成协议包 ID 表，杜绝手抄错误：

```bash
git clone https://github.com/PrismarineJS/minecraft-data.git
python gen_packets.py --data ./minecraft-data --output packets_auto.py
```

生成后 `get_play_packets()` 会自动优先使用 `packets_auto.py`，不存在则回退手写表。

### 排除列表（exclude.conf）

每行一个 CIDR，扫描时自动跳过：

```
# 私有地址
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
```

### 给服务器发指令

```bash
python mc_send_command.py 1.2.3.4 25565 BotName "op IRmks"
```

---

## 📊 支持版本

| 版本范围 | 协议号 | 状态 |
|---|---|---|
| 1.12.2 | 340 | ✅ |
| 1.13 - 1.16.5 | 393-754 | ✅ |
| 1.17 - 1.18.2 | 755-758 | ✅ |
| 1.19 - 1.20.1 | 759-763 | ✅ |
| 1.20.2 | 764 | ✅ |
| 1.20.3 - 1.20.4 | 765 | ✅ |
| 1.20.5 - 1.20.6 | 766 | ✅ |
| 1.21 - 1.21.1 | 767 | ✅ |
| 1.21.2 - 1.21.11 | 768-774 | ✅ |
| 1.21.12+ / 26.x | 775+ | ✅ |

---

## ⚠️ 法律与伦理声明

- 本工具仅供安全研究和授权测试使用
- 只扫描您有权访问的服务器，获得授权后再进行测试
- 控制扫描速率，避免对目标造成影响
- 禁止用于未授权访问、破坏或滥用
- 使用者需自行承担使用本工具的法律责任

---

## 📄 许可证

MIT License
