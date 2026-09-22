#!/bin/bash
echo "========================================"
echo "  Minecraft 服务器扫描与安全提醒机器人"
echo "========================================"
echo ""
if [ $# -eq 0 ]; then
    echo "用法:"
    echo "  ./run.sh scan 目标      扫描+SLP探测"
    echo "  ./run.sh warn 目标      扫描+发警告"
    echo "  ./run.sh portscan 目标  只扫端口"
    echo ""
    echo "示例:"
    echo "  ./run.sh warn 1.2.3.0/24"
    echo "  ./run.sh warn -f targets.txt"
    echo "  ./run.sh scan 1.2.3.4"
    exit 1
fi
python3 main.py "$@"
