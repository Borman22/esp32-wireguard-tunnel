# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Borman22
import socket, threading, hashlib, os, time, subprocess, sys

TARGET_PORT, PROXY_PORT = 19000, 18080
BIG = os.urandom(5 * 1024 * 1024)

def target_server(stop):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", TARGET_PORT)); srv.listen(8); srv.settimeout(0.2)
    def handle(c):
        mode = c.recv(1)
        if mode == b"U":      # upload: читаем до EOF, отвечаем sha256
            h = hashlib.sha256()
            while True:
                d = c.recv(65536)
                if not d: break
                h.update(d)
            c.sendall(h.digest()); c.close()
        elif mode == b"D":    # download: шлём BIG, закрываем
            c.sendall(BIG); c.close()
        elif mode == b"H":    # hold: держит соединение открытым
            time.sleep(2); c.close()
        elif mode == b"I":    # idle: молчит долго, как keep-alive-соединение браузера
            time.sleep(6); c.close()
    while not stop.is_set():
        try: c, _ = srv.accept()
        except socket.timeout: continue
        threading.Thread(target=handle, args=(c,), daemon=True).start()

def connect():
    s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=20); return s

stop = threading.Event()
threading.Thread(target=target_server, args=(stop,), daemon=True).start()
time.sleep(0.3)

# 1. upload 5 МБ с half-close: проверка целостности и обратного давления
s = connect(); s.sendall(b"U")
s.sendall(BIG); s.shutdown(socket.SHUT_WR)
dig = b""
while len(dig) < 32:
    d = s.recv(32 - len(dig))
    if not d: break
    dig += d
assert dig == hashlib.sha256(BIG).digest(), "upload digest mismatch"
print("OK upload 5MB + half-close")

# 2. download 5 МБ медленным читателем
s = connect(); s.sendall(b"D")
got = bytearray(); t0 = time.time()
while True:
    d = s.recv(4096)
    if not d: break
    got += d
    if len(got) % (512*1024) < 4096: time.sleep(0.01)
assert bytes(got) == BIG, "download mismatch (%d bytes)" % len(got)
print("OK download 5MB slow reader, %.1fs" % (time.time() - t0))

# 3. четыре удержанных соединения (все слоты) + пятое ждёт в очереди и обслуживается, когда слот освободится
hold = []
for i in range(4):
    h = connect(); h.sendall(b"H"); hold.append(h)
time.sleep(0.5)
t0 = time.time()
x = connect(); x.sendall(b"U"); x.sendall(b"queued"); x.shutdown(socket.SHUT_WR)
assert x.recv(32) == hashlib.sha256(b"queued").digest(), "queued connection not served"
waited = time.time() - t0
assert waited > 0.8, "5th connection was served without waiting (%.1fs)" % waited
print("OK 5th connection queued %.1fs and then served" % waited)
for h in hold: h.close()
time.sleep(2.6)   # цель держит соединение 2 с, потом закрывается

# 4. после освобождения слотов новые соединения снова принимаются
s = connect(); s.sendall(b"U"); s.sendall(b"abc"); s.shutdown(socket.SHUT_WR)
assert s.recv(32) == hashlib.sha256(b"abc").digest()
print("OK slots recycled")

# 4b. все слоты заняты молчащими соединениями: ожидающее вытесняет самое давнее (после PROXY_EVICT_IDLE_S)
idle = []
for i in range(4):
    h = connect(); h.sendall(b"I"); idle.append(h)
time.sleep(0.5)
t0 = time.time()
s = connect(); s.sendall(b"U"); s.sendall(b"xyz"); s.shutdown(socket.SHUT_WR)
assert s.recv(32) == hashlib.sha256(b"xyz").digest(), "new connection not served after eviction"
waited = time.time() - t0
assert 2 < waited < 5.5, "eviction timing unexpected: %.1fs" % waited
print("OK idle connection evicted for waiting one after %.1fs" % waited)
for h in idle: h.close()
time.sleep(6.5)   # цель держит соединение 6 с, потом слоты освобождаются

# 5. параллельные загрузки (3 штуки)
res = []
def up(i):
    c = connect(); c.sendall(b"U"); c.sendall(BIG[: 1024*1024 * (i+1)]); c.shutdown(socket.SHUT_WR)
    res.append((i, c.recv(32) == hashlib.sha256(BIG[: 1024*1024 * (i+1)]).digest()))
ts = [threading.Thread(target=up, args=(i,)) for i in range(3)]
[t.start() for t in ts]; [t.join() for t in ts]
assert len(res) == 3 and all(ok for _, ok in res), res
print("OK 3 parallel uploads")
stop.set()
