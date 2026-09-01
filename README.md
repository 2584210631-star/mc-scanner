<div align="center">

# 🛡️ MC Scanner

### Minecraft 服务器扫描与安全提醒机器人

**零依赖 · 全版本支持 · Web 控制面板 · 自动离线检测**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/Minecraft-1.12.2~Latest-orange.svg)](#支持版本)

</div>

---

## 📖 简介

类似 matscan 的 Python 实现：扫描互联网上的 Minecraft 服务器，检测离线模式（offline-mode），自动登录并发送安全警告消息。

协议实现基于 [MCPyBot](https://github.com/Fireroth/MCPyBot)，经过真实服务器实测验证。

## ✨ 功能特性

### 核心功能
- 🔍 **多线程端口扫描** — 支持 CIDR 网段、端口范围（`25565-25575`）、主机名
- 📡 **SLP 协议探测** — 获取版本、玩家数、MOTD、协议版本
- 🎯 **离线模式检测** — 通过登录流程自动判断是否开启在线验证
- 💬 **自动安全警告** — 登录后发送自定义警告消息，支持多条
- 🔐 **AuthMe 自动注册** — 自动执行 `/register` + `/login`，突破登录插件

### 全版本兼容
- 📦 支持 **Minecraft 1.12.2 ~ 最新版本**（协议 340+）
- 🔄 自动版本适配：SLP 获取协议版本 → 对应包ID/登录流程/聊天格式
- ✅ 已实测通过：1.12.2、1.20.2、1.20.4、1.21.1、1.21.11 等

### Web 控制面板
- 🌐 浏览器可视化操作，无需记命令
- 📊 实时进度条 + 实时日志输出
- 🔎 结果筛选（全部/离线/已发送/失败）+ 关键词搜索
- 📈 版本分布柱状图 + 扫描速率显示
- 💾 一键导出 JSON / CSV
- 🕐 历史记录（最近 20 次任务）
- ⚙️ 配置自动保存到浏览器

### 其他
- 📝 配置文件驱动（`config.json`），命令行参数可覆盖
- 🔄 失败自动重试
- ⏹️ 随时停止任务
- 📦 零第三方依赖，仅用 Python 标准库

## 🚀 快速开始

### Web 面板（推荐）

```bash
python web.py
# 浏览器打开 http://localhost:8080
```

### 命令行

```bash
# 扫描网段并发送警告
python main.py warn 1.2.3.0/24

# Windows
run.bat warn 1.2.3.0/24

# Linux/Mac
./run.sh warn 1.2.3.0/24

# 只扫描不发消息
python main.py scan 1.2.3.0/24

# 自定义消息
python main.py warn 1.2.3.4 -m "⚠️ 离线模式警告" -m "请开启 online-mode=true"

# 从文件读取目标
python main.py warn -f targets.txt
```

## 📋 支持版本

| 版本范围 | 协议号 | 登录流程 | 聊天格式 |
|---------|--------|---------|---------|
| 1.12.2 - 1.15.2 | 340-578 | 无 Configuration | 纯 String |
| 1.16 - 1.18.2 | 735-758 | 无 Configuration | 纯 String |
| 1.19 | 759 | 无 Configuration | 带签名 (759) |
| 1.19.1 - 1.19.2 | 760 | 无 Configuration | 带签名 (760) |
| 1.19.3 - 1.20.1 | 761-763 | 无 Configuration | 带签名 (761) |
| 1.20.2 - 1.20.4 | 764-765 | Configuration 阶段 | 带签名 |
| 1.20.5 - 1.20.6 | 766 | Configuration 阶段 | 新格式 |
| 1.21 / 1.21.1 | 767 | Configuration 阶段 | 新格式 |
| 1.21.2 - 1.21.9 | 768-773 | Configuration 阶段 | 新格式 |
| 1.21.10 - 1.21.12 | 774-775 | Configuration 阶段 | 新格式 |
| 1.21.13+ | 776+ | Configuration 阶段 | 新格式 |

## ⚙️ 配置文件

编辑 `config.json`：

```json
{
  "username": "SecurityBot",
  "messages": [
    "⚠️ 此服务器处于离线模式，任何人可冒用任意用户名登录",
    "💡 建议在 server.properties 中将 online-mode 设为 true"
  ],
  "ports": [25565, 25566, 25567, 25568, 25569, 25570, 25575, 25580],
  "scan_threads": 200,
  "scan_timeout": 2.5,
  "bot_threads": 10,
  "bot_timeout": 12,
  "message_delay": 0.8,
  "retry_count": 1,
  "authme_password": "",
  "output_format": "json"
}
```

## 📁 项目结构

```
mc-scanner/
├── main.py            # 命令行入口
├── web.py             # Web 控制面板
├── mc_protocol.py     # 协议层（VarInt/压缩/SLP/全版本包ID映射）
├── scanner.py         # 端口扫描（多线程/CIDR/去重）
├── bot.py             # 机器人核心（登录/离线检测/发消息/版本适配）
├── config.json        # 配置文件
├── targets.txt        # 目标列表示例
├── messages.txt       # 警告消息示例
├── run.bat            # Windows 启动脚本
├── run.sh             # Linux/Mac 启动脚本
├── test_mock_*.py     # 各版本 Mock 测试服务器
├── LICENSE            # MIT 协议
└── README.md          # 本文件
```

## 🔧 工作原理

```
端口扫描 → SLP探测 → 版本识别 → 握手登录 → 离线检测 → 发送警告 → 退出
     ↓           ↓          ↓          ↓          ↓          ↓
  TCP全连接   版本/MOTD   协议映射   配置协商   无Encryption  聊天消息
```

1. **端口扫描** — 多线程 TCP 全连接扫描目标端口
2. **SLP 探测** — 握手 + Status Request，确认 MC 服务器并获取版本
3. **版本适配** — 根据协议版本选择对应包ID、登录流程、聊天格式
4. **离线检测** — 登录时若未收到 Encryption Request 即为离线模式
5. **发送警告** — 完成完整登录流程（含 Configuration 阶段），进入游戏后发消息
6. **自动退出** — 消息发送完毕后断开连接

## ⚠️ 免责声明

本工具仅用于**安全研究和教育目的**：

- 请勿用于骚扰、破坏或未经授权访问他人服务器
- 扫描大范围网段可能触发网络运营商告警，请控制速率
- 机器人并发数不宜过高，避免对目标服务器造成压力
- 离线模式服务器的管理员可通过日志看到连接来源 IP
- 部分服务器装有反机器人插件，可能踢掉或封禁扫描连接

## 📄 License

[MIT](LICENSE)
