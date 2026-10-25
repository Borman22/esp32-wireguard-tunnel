/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#include "proxy.h"
#include "esp_log.h"
#include "esp_timer.h"
#ifdef CONFIG_HEAP_POISONING_COMPREHENSIVE
#include "esp_heap_caps.h"
#endif
#ifdef CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
#include <stdlib.h>
#include "esp_wifi.h"
#endif
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

static const char *TAG = "proxy";

/* ── Структуры ───────────────────────────────────────────────────────────── */

/* Буфер одного направления: данные прочитаны с одной стороны, но ещё не ушли на другую */
typedef struct {
    uint8_t buf[PROXY_BUF_SIZE];
    size_t  len;     /* сколько байт лежит в буфере */
    size_t  off;     /* сколько из них уже отправлено */
    uint32_t total;  /* сколько байт прочитано за всё время соединения (для лога) */
} pipe_t;

/*
 * Одно проксируемое соединение: клиент (из туннеля) ↔ цель (в локальной сети).
 * Данные идут через два буфера; пока буфер не опустел, из источника новые
 * данные не читаются — так обратное давление (медленный получатель) передаётся
 * отправителю через TCP-окно без роста памяти.
 */
typedef struct {
    int      client_fd;        /* -1 = слот свободен */
    int      target_fd;
    bool     connecting;       /* connect() к цели ещё не завершён */
    bool     client_eof;       /* клиент закрыл свою сторону (получен FIN) */
    bool     target_eof;
    bool     client_shut;      /* мы уже сделали shutdown(SHUT_WR) в сторону клиента */
    bool     target_shut;
    bool     first_reply_logged; /* уже залогировали первый ответ цели */
    int64_t  started_us;
    int64_t  last_activity_us;
    pipe_t   to_target;        /* клиент → цель */
    pipe_t   to_client;        /* цель → клиент */
} conn_t;

static conn_t             s_conns[PROXY_MAX_CONNS];
static int                s_listen_fd[PROXY_MAX_RULES];
static struct sockaddr_in s_target[PROXY_MAX_RULES];
static uint32_t           s_tunnel_addr;     /* туннельный IP платы, сетевой порядок байт */

static proxy_stats_t s_stats;

/* Причина последней ошибки ввода-вывода: для лога при закрытии соединения */
static int         s_io_errno;
static const char *s_io_op = "";

/* ── Вспомогательные функции ─────────────────────────────────────────────── */

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_fd(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static void close_conn(conn_t *c)
{
    /* Сколько байт прошло в каждую сторону: нулевой ответ цели при ненулевом запросе
     * клиента значит, что цель молчит (например, не понимает ClientHello) */
    ESP_LOGI(TAG, "Closed after %d s: client->target %u B, target->client %u B",
             (int)((esp_timer_get_time() - c->started_us) / 1000000LL),
             (unsigned)c->to_target.total, (unsigned)c->to_client.total);
    close_fd(&c->client_fd);
    close_fd(&c->target_fd);
    s_stats.active_conns--;
}

/* Слушающий сокет на всех интерфейсах; -1 при ошибке */
static int open_listener(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (fd < 0) return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, PROXY_LISTEN_BACKLOG) != 0) {
        close(fd);
        return -1;
    }
    set_nonblocking(fd);
    return fd;
}

/* ── Приём нового соединения ─────────────────────────────────────────────── */

static void accept_client(int rule)
{
    int fd = accept(s_listen_fd[rule], NULL, NULL);
    if (fd < 0) return;

    /* Принимаем только то, что пришло через туннель: адрес назначения должен
     * совпасть с туннельным IP платы. */
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &len) != 0 ||
        local.sin_addr.s_addr != s_tunnel_addr) {
        ESP_LOGW(TAG, "Rejected connection not from tunnel (port %u)", ntohs(local.sin_port));
        close(fd);
        s_stats.rejected_conns++;
        return;
    }

    conn_t *c = NULL;
    for (int i = 0; i < PROXY_MAX_CONNS; i++)
        if (s_conns[i].client_fd < 0) { c = &s_conns[i]; break; }
    if (!c) {
        /* Браузеры держат открытыми keep-alive-соединения, и они занимали бы слоты до
         * PROXY_IDLE_TIMEOUT_S, а новым запросам места не хватало бы (страница роутера
         * не грузилась). Поэтому вытесняем самое давно простаивающее соединение, если
         * оно молчит не меньше PROXY_EVICT_IDLE_S: клиент просто откроет новое. */
        int64_t now = esp_timer_get_time();
        conn_t *oldest = NULL;
        for (int i = 0; i < PROXY_MAX_CONNS; i++)
            if (!oldest || s_conns[i].last_activity_us < oldest->last_activity_us)
                oldest = &s_conns[i];
        if (oldest && now - oldest->last_activity_us > (int64_t)PROXY_EVICT_IDLE_S * 1000000LL) {
            ESP_LOGI(TAG, "No free slot: evicting connection idle %d s",
                     (int)((now - oldest->last_activity_us) / 1000000LL));
            close_conn(oldest);
            c = oldest;
        } else {
            ESP_LOGW(TAG, "No free connection slot");
            close(fd);
            s_stats.rejected_conns++;
            return;
        }
    }

    int tfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (tfd < 0) {
        close(fd);
        s_stats.rejected_conns++;
        return;
    }
    set_nonblocking(fd);
    set_nonblocking(tfd);

    int yes = 1;
    setsockopt(fd,  IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    setsockopt(tfd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    int rc = connect(tfd, (struct sockaddr *)&s_target[rule], sizeof(s_target[rule]));
    if (rc != 0 && errno != EINPROGRESS) {
        ESP_LOGW(TAG, "connect() to target failed: errno %d", errno);
        close(fd);
        close(tfd);
        s_stats.failed_target++;
        return;
    }

    memset(c, 0, sizeof(*c));
    c->client_fd        = fd;
    c->target_fd        = tfd;
    c->connecting       = true;
    c->started_us       = esp_timer_get_time();
    c->last_activity_us = c->started_us;
    s_stats.active_conns++;
    s_stats.total_conns++;
    ESP_LOGI(TAG, "New connection on port %u -> target", ntohs(local.sin_port));
}

/* ── Обработка одного соединения ─────────────────────────────────────────── */

/*
 * Прочитать из fd в пустой буфер. false — фатальная ошибка сокета.
 * recv() == 0 означает, что собеседник закрыл свою сторону: запоминаем это в
 * *eof, а закрытие передаём дальше только после того, как буфер будет отправлен.
 */
static bool pipe_read(int fd, pipe_t *p, bool *eof)
{
    int n = recv(fd, p->buf, sizeof(p->buf), 0);
    if (n > 0) {
        p->len = (size_t)n;
        p->off = 0;
        p->total += (uint32_t)n;
        return true;
    }
    if (n == 0) {
        *eof = true;
        return true;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
    s_io_errno = errno;
    s_io_op = "recv";
    return false;
}

/* Отправить накопленное из буфера. false — фатальная ошибка сокета. */
static bool pipe_write(int fd, pipe_t *p)
{
    int n = send(fd, p->buf + p->off, p->len - p->off, 0);
    if (n > 0) {
        p->off += (size_t)n;
        if (p->off == p->len) p->len = p->off = 0;
        return true;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
    s_io_errno = errno;
    s_io_op = "send";
    return false;
}

static bool pipe_pending(const pipe_t *p)
{
    return p->len > p->off;
}

/* Подготовить дескрипторы соединения к select(): кого читать, в кого писать */
static void conn_fill_sets(const conn_t *c, fd_set *rs, fd_set *ws, int *maxfd)
{
    if (c->connecting) {
        FD_SET(c->target_fd, ws);     /* connect() завершится как «готов к записи» */
    } else {
        if (!c->client_eof && !pipe_pending(&c->to_target)) FD_SET(c->client_fd, rs);
        if (!c->target_eof && !pipe_pending(&c->to_client)) FD_SET(c->target_fd, rs);
        if (pipe_pending(&c->to_target)) FD_SET(c->target_fd, ws);
        if (pipe_pending(&c->to_client)) FD_SET(c->client_fd, ws);
    }
    if (c->client_fd > *maxfd) *maxfd = c->client_fd;
    if (c->target_fd > *maxfd) *maxfd = c->target_fd;
}

/* Обслужить готовые дескрипторы соединения; закрывает его при ошибке или завершении */
static void conn_service(conn_t *c, fd_set *rs, fd_set *ws)
{
    int64_t now = esp_timer_get_time();

    if (c->connecting) {
        if (FD_ISSET(c->target_fd, ws)) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(c->target_fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err != 0) {
                ESP_LOGW(TAG, "Target connect failed: %d", err);
                s_stats.failed_target++;
                close_conn(c);
                return;
            }
            c->connecting = false;
            c->last_activity_us = now;
        } else if (now - c->started_us > (int64_t)PROXY_CONNECT_TIMEOUT_S * 1000000LL) {
            ESP_LOGW(TAG, "Target connect timeout");
            s_stats.failed_target++;
            close_conn(c);
        }
        return;
    }

    bool ok = true;
    if (ok && FD_ISSET(c->client_fd, rs)) ok = pipe_read(c->client_fd, &c->to_target, &c->client_eof);
    if (ok && FD_ISSET(c->target_fd, rs)) ok = pipe_read(c->target_fd, &c->to_client, &c->target_eof);
    /* Диагностика: первые байты первого ответа цели. Для TLS: 16 = handshake (ServerHello),
     * 15 = alert (за ним уровень и код: 28 handshake_failure, 2f illegal_parameter, 32 decode_error, 46 protocol_version) */
    if (ok && c->to_client.total > 0 && c->to_client.total == c->to_client.len && c->to_client.off == 0 &&
        !c->first_reply_logged) {
        c->first_reply_logged = true;
        const uint8_t *b = c->to_client.buf;
        size_t n = c->to_client.len < 8 ? c->to_client.len : 8;
        char hex[8 * 3 + 1] = "";
        for (size_t i = 0; i < n; i++) snprintf(hex + i * 3, 4, "%02x ", b[i]);
        ESP_LOGD(TAG, "Target first reply %u B: %s", (unsigned)c->to_client.len, hex);
    }
    /* Писать сразу, а не ждать следующего select(): иначе на каждый кусок данных приходится два
     * вызова select() (он на ESP-IDF дорогой). Неотправленный остаток доедет по ws в следующем проходе. */
    if (ok && pipe_pending(&c->to_target)) ok = pipe_write(c->target_fd, &c->to_target);
    if (ok && pipe_pending(&c->to_client)) ok = pipe_write(c->client_fd, &c->to_client);
    if (!ok) {
        ESP_LOGW(TAG, "I/O error: %s errno=%d (%s), client_eof=%d target_eof=%d, in %uB out %uB - closing",
                 s_io_op, s_io_errno, strerror(s_io_errno), c->client_eof, c->target_eof,
                 (unsigned)c->to_target.total, (unsigned)c->to_client.total);
        close_conn(c);
        return;
    }

    if (FD_ISSET(c->client_fd, rs) || FD_ISSET(c->target_fd, rs) ||
        FD_ISSET(c->client_fd, ws) || FD_ISSET(c->target_fd, ws))
        c->last_activity_us = now;

#if PROXY_HALF_CLOSE
    /* Передать закрытие стороны дальше (half-close), когда её данные уже отправлены */
    if (c->client_eof && !pipe_pending(&c->to_target) && !c->target_shut) {
        shutdown(c->target_fd, SHUT_WR);
        c->target_shut = true;
    }
    if (c->target_eof && !pipe_pending(&c->to_client) && !c->client_shut) {
        shutdown(c->client_fd, SHUT_WR);
        c->client_shut = true;
    }
#else
    /* Без half-close: сторона закрылась и её данные доставлены - закрываем оба сокета сразу.
     * shutdown(SHUT_WR) с последующим close() на lwIP из ESP-IDF 6.0 приводил к порче кучи
     * (воспроизводилось обрывом соединений, см. CLAUDE.md); TLS/HTTP/SSH закрывают целиком. */
    if ((c->client_eof && !pipe_pending(&c->to_target)) ||
        (c->target_eof && !pipe_pending(&c->to_client))) {
        close_conn(c);
        return;
    }
#endif

    if (c->client_eof && c->target_eof &&
        !pipe_pending(&c->to_target) && !pipe_pending(&c->to_client)) {
        close_conn(c);
        return;
    }

    /* Если одна сторона уже закрылась, а вторая молчит, слот не держим долго:
     * их всего PROXY_MAX_CONNS, и зависшая цель иначе блокировала бы весь проброс */
    int idle_limit_s = (c->client_eof || c->target_eof) ? PROXY_HALF_CLOSE_TIMEOUT_S
                                                        : PROXY_IDLE_TIMEOUT_S;
    if (now - c->last_activity_us > (int64_t)idle_limit_s * 1000000LL) {
        ESP_LOGI(TAG, "Closing idle connection");
        close_conn(c);
    }
}

/* ── Задача ──────────────────────────────────────────────────────────────── */

/* Есть ли куда принять новое соединение: свободный слот либо молчащее не меньше
 * PROXY_EVICT_IDLE_S (accept_client() его вытеснит) */
static bool slot_available_or_evictable(int64_t now)
{
    for (int i = 0; i < PROXY_MAX_CONNS; i++) {
        if (s_conns[i].client_fd < 0) return true;
        if (now - s_conns[i].last_activity_us > (int64_t)PROXY_EVICT_IDLE_S * 1000000LL) return true;
    }
    return false;
}

static void proxy_task(void *arg)
{
    for (;;) {
        fd_set rs, ws;
        FD_ZERO(&rs);
        FD_ZERO(&ws);
        int maxfd = -1;

        /* Новые соединения принимаем только если есть свободный слот или можно вытеснить
         * давно молчащее. Иначе клиент ждёт в очереди lwIP (PROXY_LISTEN_BACKLOG), а не
         * получает отказ: роутеры вроде TP-Link закрывают соединение после каждого ответа,
         * браузер открывает по шесть новых сразу, и отказ ломал бы загрузку страницы. */
        bool can_accept = slot_available_or_evictable(esp_timer_get_time());
        for (int i = 0; i < PROXY_MAX_RULES && can_accept; i++) {
            if (s_listen_fd[i] < 0) continue;
            FD_SET(s_listen_fd[i], &rs);
            if (s_listen_fd[i] > maxfd) maxfd = s_listen_fd[i];
        }
        for (int i = 0; i < PROXY_MAX_CONNS; i++)
            if (s_conns[i].client_fd >= 0) conn_fill_sets(&s_conns[i], &rs, &ws, &maxfd);

        /* Таймаут 1 с: по нему отрабатывают таймауты соединений, даже если трафика нет */
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ready = select(maxfd + 1, &rs, &ws, NULL, &tv);
        if (ready < 0) {
            ESP_LOGW(TAG, "select() failed: errno %d", errno);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        for (int i = 0; i < PROXY_MAX_RULES; i++)
            if (s_listen_fd[i] >= 0 && FD_ISSET(s_listen_fd[i], &rs)) accept_client(i);

        for (int i = 0; i < PROXY_MAX_CONNS; i++)
            if (s_conns[i].client_fd >= 0) conn_service(&s_conns[i], &rs, &ws);

#ifdef CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
        /* ОТЛАДКА скорости: раз в 5 с при активном трафике печатаем загрузку процессора по задачам
         * за прошедший интервал (IDLE = простой). Включается CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS. */
        {
            static int64_t   last_stat_us;
            static uint32_t  prev_total;
            static uint32_t  prev_run[24];
            static TaskHandle_t prev_h[24];
            int64_t tn = esp_timer_get_time();
            if (s_stats.active_conns > 0 && tn - last_stat_us > 5000000) {
                last_stat_us = tn;
                UBaseType_t n = uxTaskGetNumberOfTasks();
                TaskStatus_t *st = malloc(n * sizeof(TaskStatus_t));
                if (st) {
                    uint32_t total;
                    n = uxTaskGetSystemState(st, n, &total);
                    uint32_t dt = total - prev_total;
                    char line[200]; size_t off = 0;
                    line[0] = 0;
                    for (UBaseType_t i = 0; i < n && off < sizeof(line) - 32; i++) {
                        uint32_t before = 0;
                        for (int k = 0; k < 24; k++) if (prev_h[k] == st[i].xHandle) { before = prev_run[k]; break; }
                        uint32_t d = st[i].ulRunTimeCounter - before;
                        if (dt && d * 100ULL / dt >= 3)
                            off += snprintf(line + off, sizeof(line) - off, "%s %u%% ", st[i].pcTaskName,
                                            (unsigned)(d * 100ULL / dt));
                    }
                    for (UBaseType_t i = 0; i < n && i < 24; i++) { prev_h[i] = st[i].xHandle; prev_run[i] = st[i].ulRunTimeCounter; }
                    prev_total = total;
                    ESP_LOGI(TAG, "CPU (all cores, 200%% = both busy): %s", line);
                    free(st);
                    wifi_ap_record_t ap;
                    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
                        wifi_phy_mode_t pm = WIFI_PHY_MODE_11B;
                        esp_wifi_sta_get_negotiated_phymode(&pm);
                        /* phymode: 0=LR 1=11B 2=11G 3=11A 4=HT20 5=HT40 6=HE20 7=VHT20 */
                        ESP_LOGI(TAG, "WiFi: rssi=%d dBm ch=%u phymode=%d b=%d g=%d n=%d",
                                 ap.rssi, ap.primary, (int)pm, ap.phy_11b, ap.phy_11g, ap.phy_11n);
                    }
                }
            }
        }
#endif
#ifdef CONFIG_HEAP_POISONING_COMPREHENSIVE
        /* ОТЛАДКА порчи кучи: проверять целостность полсекунды, чтобы поймать момент порчи, а не
         * следствие. После первого обнаружения проверку отключаем (иначе спам в логе). */
        static int64_t last_check_us;
        static bool    corruption_reported;
        int64_t t = esp_timer_get_time();
        if (!corruption_reported && t - last_check_us > 500000) {
            last_check_us = t;
            if (!heap_caps_check_integrity_all(true)) {
                corruption_reported = true;
                ESP_LOGE(TAG, "HEAP CORRUPTED (periodic check): active_conns=%u total=%u",
                         (unsigned)s_stats.active_conns, (unsigned)s_stats.total_conns);
            }
        }
#endif
    }
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void proxy_start(const proxy_rule_t *rules, const char *tunnel_ip)
{
    struct in_addr addr;
    if (!tunnel_ip || inet_pton(AF_INET, tunnel_ip, &addr) != 1) {
        ESP_LOGW(TAG, "No tunnel address - proxy not started");
        return;
    }
    s_tunnel_addr = addr.s_addr;

    for (int i = 0; i < PROXY_MAX_CONNS; i++) s_conns[i].client_fd = s_conns[i].target_fd = -1;

    int opened = 0;
    for (int i = 0; i < PROXY_MAX_RULES; i++) {
        s_listen_fd[i] = -1;
        if (rules[i].listen_port == 0) continue;

        struct in_addr tip;
        if (inet_pton(AF_INET, rules[i].target_ip, &tip) != 1 || rules[i].target_port == 0) {
            ESP_LOGW(TAG, "Rule %d: bad target '%s:%u' - skipped", i,
                     rules[i].target_ip, rules[i].target_port);
            continue;
        }
        s_target[i] = (struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_port   = htons(rules[i].target_port),
            .sin_addr   = tip,
        };

        s_listen_fd[i] = open_listener(rules[i].listen_port);
        if (s_listen_fd[i] < 0) {
            ESP_LOGE(TAG, "Rule %d: cannot listen on port %u (errno %d)", i, rules[i].listen_port, errno);
            continue;
        }
        ESP_LOGI(TAG, "Rule %d: tunnel:%u -> %s:%u", i, rules[i].listen_port,
                 rules[i].target_ip, rules[i].target_port);
        opened++;
    }

    if (opened == 0) {
        ESP_LOGI(TAG, "No proxy rules configured");
        return;
    }
    xTaskCreate(proxy_task, "proxy", 4096, NULL, 5, NULL);
}

void proxy_get_stats(proxy_stats_t *out)
{
    *out = s_stats;
}
