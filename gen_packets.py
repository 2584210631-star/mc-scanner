# -*- coding: utf-8 -*-
"""
协议包 ID 自动生成器。
从 PrismarineJS/minecraft-data 的 protocol.json 自动生成各版本的包 ID 表，
杜绝手抄错误。借鉴 mc-scanner-v2 的 gen_packets.py。

使用方法:
  1. 下载 minecraft-data: git clone https://github.com/PrismarineJS/minecraft-data.git
  2. 运行: python3 gen_packets.py --data ./minecraft-data --output packets_auto.py
  3. 在 mc_protocol.py 里 from packets_auto import PACKET_TABLES_AUTO

注意: 生成的表是参考数据，实际使用前请与官方协议文档核对。
"""
import os
import sys
import json
import argparse
from pathlib import Path


def load_protocol(data_dir, version):
    """加载指定版本的 protocol.json"""
    # 版本目录可能是版本名或协议号
    candidates = [
        data_dir / "data" / "pc" / version / "protocol.json",
        data_dir / "data" / "pc" / f"{version}" / "protocol.json",
    ]
    for p in candidates:
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)
    return None


def extract_packet_ids(protocol_data):
    """从 protocol.json 提取各阶段的包 ID 映射"""
    result = {
        "handshaking": {"toClient": {}, "toServer": {}},
        "status": {"toClient": {}, "toServer": {}},
        "login": {"toClient": {}, "toServer": {}},
        "play": {"toClient": {}, "toServer": {}},
    }

    def walk(node, state, direction):
        """递归遍历协议树，提取包 ID"""
        if not isinstance(node, dict):
            return
        # 检查是否是包定义节点
        if "packetID" in node and "name" in node:
            pkt_id = node["packetID"]
            name = node["name"]
            if isinstance(pkt_id, str) and pkt_id.startswith("0x"):
                pkt_id = int(pkt_id, 16)
            result[state][direction][name] = pkt_id
        # 递归子节点
        for key, val in node.items():
            if key in ("types", "packetID", "name"):
                continue
            if isinstance(val, dict):
                walk(val, state, direction)

    # 遍历各阶段
    for state in ["handshaking", "status", "login", "play"]:
        for direction in ["toClient", "toServer"]:
            node = protocol_data.get(state, {}).get(direction, {})
            if node:
                walk(node, state, direction)

    return result


# 常用版本列表（游戏版本名 -> minecraft-data 目录名）
COMMON_VERSIONS = [
    "1.12.2", "1.13", "1.13.1", "1.13.2",
    "1.14", "1.14.1", "1.14.2", "1.14.3", "1.14.4",
    "1.15", "1.15.1", "1.15.2",
    "1.16", "1.16.1", "1.16.2", "1.16.3", "1.16.4", "1.16.5",
    "1.17", "1.17.1",
    "1.18", "1.18.1", "1.18.2",
    "1.19", "1.19.1", "1.19.2", "1.19.3", "1.19.4",
    "1.20", "1.20.1", "1.20.2", "1.20.3", "1.20.4", "1.20.5", "1.20.6",
    "1.21", "1.21.1", "1.21.2", "1.21.3", "1.21.4", "1.21.5",
    "1.21.6", "1.21.7", "1.21.8", "1.21.9", "1.21.10", "1.21.11",
]


def generate(data_dir, output_path, versions=None):
    """生成协议表 Python 文件"""
    if versions is None:
        versions = COMMON_VERSIONS

    all_tables = {}
    found = 0
    for ver in versions:
        proto = load_protocol(data_dir, ver)
        if proto is None:
            print(f"  [跳过] {ver}: 未找到 protocol.json")
            continue
        ids = extract_packet_ids(proto)
        all_tables[ver] = ids
        found += 1
        play_sb = ids["play"]["toServer"]
        play_cb = ids["play"]["toClient"]
        chat = play_sb.get("chat", "?")
        keep_alive_cb = play_cb.get("keep_alive", "?")
        keep_alive_sb = play_sb.get("keep_alive", "?")
        print(f"  [OK] {ver}: chat=0x{chat:02x}, cb_keepalive=0x{keep_alive_cb:02x}, sb_keepalive=0x{keep_alive_sb:02x}")

    # 生成 Python 文件
    lines = [
        "# -*- coding: utf-8 -*-",
        '"""',
        "自动生成的协议包 ID 表。",
        f"数据源: PrismarineJS/minecraft-data",
        f"生成时间: {__import__('datetime').datetime.now().isoformat()}",
        f"版本数: {found}",
        "",
        "使用方法:",
        "  from packets_auto import PACKET_TABLES_AUTO",
        "  table = PACKET_TABLES_AUTO.get('1.21.1')",
        "  chat_id = table['play']['toServer']['chat']",
        '"""',
        "",
        "PACKET_TABLES_AUTO = {",
    ]

    for ver, ids in all_tables.items():
        lines.append(f'    "{ver}": {{')
        for state in ["handshaking", "status", "login", "play"]:
            lines.append(f'        "{state}": {{')
            for direction in ["toClient", "toServer"]:
                lines.append(f'            "{direction}": {{')
                for name, pkt_id in sorted(ids[state][direction].items(), key=lambda x: x[1]):
                    lines.append(f'                "{name}": 0x{pkt_id:02x},')
                lines.append(f'            }},')
            lines.append(f'        }},')
        lines.append(f'    }},')

    lines.append("}")
    lines.append("")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    print(f"\n生成完成: {output_path}")
    print(f"共 {found} 个版本")
    return found


def main():
    parser = argparse.ArgumentParser(description="Minecraft 协议包 ID 自动生成器")
    parser.add_argument("--data", default="./minecraft-data", help="minecraft-data 目录路径")
    parser.add_argument("--output", default="packets_auto.py", help="输出文件路径")
    parser.add_argument("--versions", nargs="*", help="指定版本列表（默认全部常用版本）")
    args = parser.parse_args()

    data_dir = Path(args.data)
    if not data_dir.exists():
        print(f"错误: minecraft-data 目录不存在: {data_dir}")
        print("请先下载: git clone https://github.com/PrismarineJS/minecraft-data.git")
        sys.exit(1)

    print(f"数据源: {data_dir}")
    print(f"输出: {args.output}")
    print("正在生成协议表...\n")

    versions = args.versions if args.versions else None
    found = generate(data_dir, args.output, versions)

    if found == 0:
        print("\n警告: 未找到任何版本的 protocol.json")
        sys.exit(1)


if __name__ == "__main__":
    main()
