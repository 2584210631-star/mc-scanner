import sys, time, threading
sys.path.insert(0, '.')
from bot import join_and_warn
from mc_protocol import server_list_ping

TARGET_IP = "103.85.86.51"
TARGET_PORT = 41543
BOT_COUNT = 15

# 英文警告消息
WARNING_MESSAGES = [
    "WARNING: This server is running in offline/insecure mode!",
    "Your account can be impersonated by anyone.",
    "Please set online-mode=true in server.properties to protect players.",
    "This is a security reminder from MC Scanner.",
]

results = []
lock = threading.Lock()

def bot_worker(bot_id):
    username = f"SecBot{bot_id:02d}"
    try:
        result = join_and_warn(
            TARGET_IP, TARGET_PORT,
            username=username,
            messages=WARNING_MESSAGES,
            timeout=15
        )
        with lock:
            results.append({
                'id': bot_id,
                'username': username,
                'success': result.success,
                'offline': result.is_offline,
                'auth_mode': result.auth_mode,
                'sent': result.messages_sent,
                'version': result.version_name,
                'error': result.error,
            })
            status = "✓" if result.success else "✗"
            print(f"  [{status}] {username}: sent={result.messages_sent}, mode={result.auth_mode}" + 
                  (f", error={result.error[:50]}" if result.error else ""))
    except Exception as e:
        with lock:
            results.append({
                'id': bot_id, 'username': username,
                'success': False, 'error': str(e)[:100]
            })
            print(f"  [✗] {username}: exception={str(e)[:80]}")

# 先探测服务器
print(f"[*] 探测 {TARGET_IP}:{TARGET_PORT}...")
info = server_list_ping(TARGET_IP, TARGET_PORT, timeout=5)
if info:
    v = info.get('version', {})
    p = info.get('players', {})
    print(f"[*] 版本: {v.get('name','?')} (协议{v.get('protocol','?')})")
    print(f"[*] 在线: {p.get('online',0)}/{p.get('max',0)}")
else:
    print("[!] SLP 探测失败，继续尝试登录...")

print(f"\n[*] 启动 {BOT_COUNT} 个机器人并发登录...")
print("=" * 60)

start = time.time()
threads = []
for i in range(1, BOT_COUNT + 1):
    t = threading.Thread(target=bot_worker, args=(i,))
    threads.append(t)
    t.start()
    time.sleep(0.3)  # 错开启动，避免同时连

for t in threads:
    t.join(timeout=30)

elapsed = time.time() - start
print("=" * 60)
print(f"\n[*] 完成! 耗时: {elapsed:.1f}秒")

success = sum(1 for r in results if r['success'])
failed = BOT_COUNT - success
total_sent = sum(r.get('sent', 0) for r in results)

print(f"\n[*] 统计:")
print(f"  成功: {success}/{BOT_COUNT}")
print(f"  失败: {failed}/{BOT_COUNT}")
print(f"  总发送消息数: {total_sent}")

if success > 0:
    print(f"\n[*] 成功的机器人:")
    for r in results:
        if r['success']:
            print(f"  ✓ {r['username']}: 发送{r['sent']}条, 版本={r.get('version','?')}")

if failed > 0:
    print(f"\n[!] 失败的机器人:")
    for r in results:
        if not r['success']:
            print(f"  ✗ {r['username']}: {r.get('error','未知错误')[:80]}")
