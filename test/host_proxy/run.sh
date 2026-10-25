#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Borman22
# Хост-тест TCP-прокси: main/proxy.c собирается с заглушками ESP-IDF (shim/) под Linux
# и проверяется реальными TCP-соединениями. Запускать из любой папки.
set -euo pipefail
cd "$(dirname "$0")"
BIN=$(mktemp -u /tmp/proxy_test.XXXXXX)

gcc -std=gnu11 -Wall -Wextra -Wno-unused-parameter -g -fsanitize=address,undefined \
    -DPROXY_EVICT_IDLE_S=3 -DPROXY_HALF_CLOSE=1 -Ishim -I../../main -o "$BIN" driver.c ../../main/proxy.c -lpthread

# Основной прогон: туннельный адрес 127.0.0.1, цель — тестовый сервер на 127.0.0.1:19000
"$BIN" 127.0.0.1 2>"$BIN.log" &
PID=$!
trap 'kill $PID 2>/dev/null || true; rm -f "$BIN" "$BIN.log" "$BIN.log2"' EXIT
sleep 0.5
python3 test_proxy.py

# Чужой адрес: прокси считает туннельным 127.0.0.2, подключение с 127.0.0.1 должно быть отброшено
kill $PID; wait $PID 2>/dev/null || true
"$BIN" 127.0.0.2 2>"$BIN.log2" &
PID=$!
sleep 0.5
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 18080), timeout=5)
try:
    assert s.recv(10) == b""
except ConnectionResetError:
    pass
print("OK connection to non-tunnel address rejected")
PY

if grep -qE "runtime error|AddressSanitizer|LeakSanitizer" "$BIN.log" "$BIN.log2"; then
    echo "FAIL: sanitizer reported errors"; exit 1
fi
echo "ALL OK"
