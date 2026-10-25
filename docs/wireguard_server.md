# Настройка VPN-сервера WireGuard (VPS)

Сервер нужен с белым IP-адресом. Подойдёт любой VPS (инструкция ориентирована на Ubuntu 22.04/24.04).
Все участники (плата, ваш компьютер, при желании сам роутер) подключаются к серверу как клиенты и видят друг друга в туннельной сети.

Схема адресов в примерах:

| Участник | Адрес в туннеле |
|---|---|
| Сервер (VPS) | `10.8.0.1` |
| Плата ESP32 | `10.8.0.2` |
| Ваш ноутбук/телефон | `10.8.0.3` |

## 1. Установка и ключи на сервере

```bash
sudo apt update && sudo apt install -y wireguard
cd /etc/wireguard && sudo -i   # дальше команды от root
umask 077
wg genkey | tee server.key | wg pubkey > server.pub
wg genkey | tee esp.key    | wg pubkey > esp.pub       # ключи платы
wg genkey | tee laptop.key | wg pubkey > laptop.pub    # ключи вашего компьютера
```

Что куда вводится:

| Файл | Куда |
|---|---|
| `esp.key` (приватный) | страница настроек платы → «Приватный ключ этого устройства» |
| `server.pub` | страница настроек платы → «Публичный ключ сервера» |
| `esp.pub`, `laptop.pub` | конфиг сервера (ниже) |
| `laptop.key`, `server.pub` | конфиг клиента на ноутбуке (ниже) |

Приватные ключи (`*.key`) не отправляйте по почте и не публикуйте.

## 2. Конфиг сервера

`/etc/wireguard/wg0.conf` (подставьте содержимое файлов ключей):

```ini
[Interface]
Address    = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <содержимое server.key>

# Плата ESP32
[Peer]
PublicKey  = <содержимое esp.pub>
AllowedIPs = 10.8.0.2/32

# Ваш ноутбук
[Peer]
PublicKey  = <содержимое laptop.pub>
AllowedIPs = 10.8.0.3/32
```

У платы нет строки `Endpoint`: она за NAT провайдера, сама подключается к серверу и держит соединение открытым через keepalive.

## 3. Пересылка между участниками и файрвол

Ноутбук и плата общаются друг с другом через сервер, поэтому сервер должен пересылать пакеты между клиентами:

```bash
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf
sysctl --system

iptables -I INPUT   -p udp --dport 51820 -j ACCEPT
iptables -I FORWARD -i wg0 -o wg0        -j ACCEPT
apt install -y iptables-persistent && netfilter-persistent save

systemctl enable --now wg-quick@wg0
wg show          # проверка: интерфейс поднят, пиры перечислены
```

**Облачные провайдеры:** кроме iptables нужно открыть UDP 51820 во входящих правилах облачного файрвола (например, в Oracle Cloud: Networking → Virtual Cloud Networks → ваша сеть → Security Lists → Add Ingress Rule, источник `0.0.0.0/0`).

## 4. Клиент на ноутбуке

Linux, файл `/etc/wireguard/wg-client.conf`:

```ini
[Interface]
PrivateKey = <содержимое laptop.key>
Address    = 10.8.0.3/32

[Peer]
PublicKey           = <содержимое server.pub>
Endpoint            = <белый IP сервера>:51820
AllowedIPs          = 10.8.0.0/24
PersistentKeepalive = 25
```

```bash
sudo wg-quick up wg-client
```

`AllowedIPs = 10.8.0.0/24` направляет в туннель только туннельную сеть, остальной интернет идёт напрямую. На Windows, macOS, Android и iOS то же самое задаётся в приложении WireGuard (импорт конфига или QR-код: `qrencode -t ansiutf8 < wg-client.conf`).

## 5. Проверка

С ноутбука после `wg-quick up`:

```bash
ping 10.8.0.2                  # плата отвечает
xdg-open http://10.8.0.2/      # страница платы (вкладка «Статус»)
xdg-open http://10.8.0.2:8080  # веб-интерфейс роутера, если задан проброс 8080 -> 192.168.1.1:80
```

На сервере `wg show` покажет у пира платы свежий `latest handshake` и объём трафика.

## Если рукопожатия нет

| Симптом | Причина |
|---|---|
| На сервере в `wg show` нет `latest handshake` у платы | Не открыт UDP 51820 (iptables или облачный файрвол); неверный адрес сервера в настройках платы |
| Рукопожатие есть, но `ping 10.8.0.2` не идёт | На сервере не включён `ip_forward` или нет правила `FORWARD -i wg0 -o wg0`; в `AllowedIPs` клиента нет `10.8.0.0/24` |
| Плата пишет `wait_time` | Нет времени: плата не достучалась до NTP. Откройте любую страницу платы из браузера: она отправит время автоматически |
| Ключи «не принимаются» | Ключ скопирован с лишним пробелом или переносом; нужны ровно 44 символа base64 с `=` на конце |
