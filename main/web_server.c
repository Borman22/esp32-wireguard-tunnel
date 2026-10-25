/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#include "web_server.h"
#include "b64.h"
#include "config.h"
#include "log_buffer.h"
#include "proxy.h"
#include "wg_tunnel.h"
#include "wifi_manager.h"
#include "cJSON.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static const char *TAG = "web_server";

/*
 * Бюджет сокетов lwIP: httpd занимает свои открытые + 3 служебных, прокси —
 * слушающие и по два на соединение. Сумма не должна превышать CONFIG_LWIP_MAX_SOCKETS,
 * иначе accept() или socket() в прокси начнут отказывать в самый неподходящий момент.
 */
_Static_assert(HTTP_MAX_OPEN_SOCKETS + 3 + PROXY_MAX_RULES + 2 * PROXY_MAX_CONNS
                   <= CONFIG_LWIP_MAX_SOCKETS,
               "Не хватает сокетов lwIP: уменьшите PROXY_MAX_* / HTTP_MAX_OPEN_SOCKETS");

#define MAX_BODY_LEN  3072   /* предел тела POST /api/settings */

extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[]   asm("_binary_index_html_end");

/* ── HTTP Basic Auth ─────────────────────────────────────────────────────── */

/*
 * Проверяет заголовок Authorization: Basic ...
 * Если пароль не задан (auth_pass пустой) — пропускает всех без проверки.
 * При отказе сам отправляет 401 и возвращает false.
 */
static bool check_auth(httpd_req_t *req)
{
    const app_config_t *cfg = settings_get();
    if (cfg->auth_pass[0] == '\0') return true;

    char hdr[200];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK)
        goto deny;
    if (strncmp(hdr, "Basic ", 6) != 0) goto deny;

    char decoded[128];
    if (b64_decode(hdr + 6, decoded, sizeof(decoded)) < 0)
        goto deny;

    char *colon = strchr(decoded, ':');
    if (!colon) goto deny;
    *colon = '\0';
    const char *got_user = decoded;
    const char *got_pass = colon + 1;

    /* Пустой логин и логин "admin" равнозначны: можно запомнить только пароль */
    const char *want_user = cfg->auth_user[0] ? cfg->auth_user : "admin";
    if (strcmp(got_user, want_user) == 0 && strcmp(got_pass, cfg->auth_pass) == 0)
        return true;

deny:
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"WG Tunnel\"");
    httpd_resp_send(req, "Unauthorized", -1);
    return false;
}

/* ── Вспомогательные функции ─────────────────────────────────────────────── */

/* Отправить cJSON-объект как ответ и освободить его */
static esp_err_t send_json(httpd_req_t *req, cJSON *root)
{
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_send(req, buf, -1);
    free(buf);
    return ESP_OK;
}

/*
 * Прочитать тело запроса целиком и разобрать как JSON.
 * httpd_req_recv() может вернуть тело по частям, поэтому читаем в цикле.
 * При ошибке сам отправляет 400 и возвращает NULL.
 */
static cJSON *read_json_body(httpd_req_t *req)
{
    if (req->content_len == 0 || req->content_len > MAX_BODY_LEN) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad body size");
        return NULL;
    }
    char *body = malloc(req->content_len + 1);
    if (!body) {
        httpd_resp_send_500(req);
        return NULL;
    }
    size_t got = 0;
    while (got < req->content_len) {
        int n = httpd_req_recv(req, body + got, req->content_len - got);
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (n <= 0) {
            free(body);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Receive error");
            return NULL;
        }
        got += n;
    }
    body[got] = '\0';

    cJSON *root = cJSON_Parse(body);
    free(body);
    if (!root) httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return root;
}

/* Копирует строку из JSON-поля, если оно есть и является строкой. true — поле присутствовало. */
static bool json_get_str(const cJSON *obj, const char *key, char *dst, size_t dst_size)
{
    const cJSON *item = cJSON_GetObjectItem(obj, key);
    if (!cJSON_IsString(item)) return false;
    strlcpy(dst, item->valuestring, dst_size);
    return true;
}

/* Число из JSON-поля. true — поле есть и является числом. */
static bool json_get_num(const cJSON *obj, const char *key, int *out)
{
    const cJSON *item = cJSON_GetObjectItem(obj, key);
    if (!cJSON_IsNumber(item)) return false;
    *out = item->valueint;
    return true;
}

static bool valid_ipv4(const char *s)
{
    struct in_addr a;
    return inet_pton(AF_INET, s, &a) == 1;
}

static bool valid_port(int p)
{
    return p >= 1 && p <= 65535;
}

/* Адрес сервера: IPv4 или DNS-имя из букв, цифр, точек и дефисов */
static bool valid_endpoint(const char *s)
{
    size_t len = strlen(s);
    if (len == 0 || len >= CONFIG_WG_ENDPOINT_MAX_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

static bool wg_equal(const wg_config_t *a, const wg_config_t *b)
{
    return strcmp(a->private_key,     b->private_key)     == 0 &&
           strcmp(a->peer_public_key, b->peer_public_key) == 0 &&
           strcmp(a->preshared_key,   b->preshared_key)   == 0 &&
           strcmp(a->endpoint,        b->endpoint)        == 0 &&
           strcmp(a->address,         b->address)         == 0 &&
           strcmp(a->netmask,         b->netmask)         == 0 &&
           a->port == b->port && a->keepalive == b->keepalive;
}

static bool rules_equal(const proxy_rule_t *a, const proxy_rule_t *b)
{
    for (int i = 0; i < PROXY_MAX_RULES; i++) {
        if (a[i].listen_port != b[i].listen_port ||
            a[i].target_port != b[i].target_port ||
            strcmp(a[i].target_ip, b[i].target_ip) != 0)
            return false;
    }
    return true;
}

/* ── GET / ───────────────────────────────────────────────────────────────── */

static esp_err_t root_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;
    size_t len = index_html_end - index_html_start;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, index_html_start, (ssize_t)len);
    return ESP_OK;
}

/* Единственный маршрут без авторизации: браузер запрашивает favicon сам, без
 * учётных данных; пустой ответ 204 избавляет от 404 в логах */
static esp_err_t favicon_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* ── GET /api/status ─────────────────────────────────────────────────────── */

static esp_err_t status_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;

    wifi_status_t wifi;
    wifi_manager_get_status(&wifi);
    wg_status_t wg;
    wg_tunnel_get_status(&wg);
    proxy_stats_t px;
    proxy_get_stats(&px);
    const wg_config_t *active = wg_tunnel_active_config();
    const esp_app_desc_t *app = esp_app_get_description();

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "version",  app->version);
    cJSON_AddNumberToObject(root, "uptime_s", (double)(esp_timer_get_time() / 1000000LL));
    cJSON_AddNumberToObject(root, "heap_free", (double)esp_get_free_heap_size());
    cJSON_AddNumberToObject(root, "epoch",    (double)time(NULL));
    cJSON_AddBoolToObject  (root, "clock_ok", wg.clock_ok);

    cJSON *w = cJSON_AddObjectToObject(root, "wifi");
    cJSON_AddBoolToObject  (w, "connected", wifi.connected);
    cJSON_AddBoolToObject  (w, "ap_mode",   wifi.ap_mode);
    cJSON_AddStringToObject(w, "ssid",      wifi.ssid);
    cJSON_AddStringToObject(w, "ip",        wifi.ip);
    cJSON_AddNumberToObject(w, "rssi",      wifi.rssi);

    cJSON *t = cJSON_AddObjectToObject(root, "wg");
    cJSON_AddBoolToObject  (t, "configured",      settings_wg_is_configured(active));
    cJSON_AddStringToObject(t, "state",           wg_state_name(wg.state));
    cJSON_AddBoolToObject  (t, "trial",           wg.trial);
    cJSON_AddNumberToObject(t, "handshake_age_s", wg.handshake_age_s);
    cJSON_AddStringToObject(t, "address",         active->address);
    cJSON_AddStringToObject(t, "endpoint",        active->endpoint);
    cJSON_AddNumberToObject(t, "port",            active->port);

    cJSON *p = cJSON_AddObjectToObject(root, "proxy");
    cJSON_AddNumberToObject(p, "active",        px.active_conns);
    cJSON_AddNumberToObject(p, "total",         px.total_conns);
    cJSON_AddNumberToObject(p, "rejected",      px.rejected_conns);
    cJSON_AddNumberToObject(p, "failed_target", px.failed_target);

    return send_json(req, root);
}

/* ── GET /api/settings ───────────────────────────────────────────────────── */

/*
 * Настройки туннеля, которые видит пользователь: кандидат, если он есть (это то,
 * что пользователь ввёл последним), иначе основные. true — это кандидат.
 */
static bool effective_wg(wg_config_t *out)
{
    if (settings_load_pending_wg(out)) return true;
    *out = settings_get()->wg;
    return false;
}

static esp_err_t settings_get_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;
    const app_config_t *cfg = settings_get();

    wg_config_t wg;
    bool pending = effective_wg(&wg);

    /* Секреты (пароли и ключи) в браузер не отправляем — только признак «задано» */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "wifi_ssid",    cfg->wifi_ssid);
    cJSON_AddBoolToObject  (root, "auth_enabled", cfg->auth_pass[0] != '\0');
    cJSON_AddStringToObject(root, "auth_user",    cfg->auth_user);

    cJSON *w = cJSON_AddObjectToObject(root, "wg");
    cJSON_AddBoolToObject  (w, "private_key_set",  wg.private_key[0] != '\0');
    cJSON_AddStringToObject(w, "peer_public_key",  wg.peer_public_key);
    cJSON_AddBoolToObject  (w, "preshared_key_set", wg.preshared_key[0] != '\0');
    cJSON_AddStringToObject(w, "endpoint",         wg.endpoint);
    cJSON_AddNumberToObject(w, "port",             wg.port);
    cJSON_AddStringToObject(w, "address",          wg.address);
    cJSON_AddStringToObject(w, "netmask",          wg.netmask);
    cJSON_AddNumberToObject(w, "keepalive",        wg.keepalive);
    cJSON_AddBoolToObject  (root, "wg_pending", pending);

    cJSON *rules = cJSON_AddArrayToObject(root, "rules");
    for (int i = 0; i < PROXY_MAX_RULES; i++) {
        if (cfg->rules[i].listen_port == 0) continue;
        cJSON *r = cJSON_CreateObject();
        cJSON_AddNumberToObject(r, "listen_port", cfg->rules[i].listen_port);
        cJSON_AddStringToObject(r, "target_ip",   cfg->rules[i].target_ip);
        cJSON_AddNumberToObject(r, "target_port", cfg->rules[i].target_port);
        cJSON_AddItemToArray(rules, r);
    }
    cJSON_AddNumberToObject(root, "max_rules", PROXY_MAX_RULES);

    return send_json(req, root);
}

/* ── POST /api/settings ──────────────────────────────────────────────────── */

/*
 * Применить блок "wg" из запроса к копии настроек туннеля. false — значение
 * не прошло проверку, в *err — причина для пользователя.
 * Пустое или отсутствующее поле означает «не менять»: секреты в браузер не
 * возвращаются, поэтому форма не может прислать их обратно, а при первом
 * включении (WiFi уже вводят, а VPN ещё нет) пустые поля не должны давать ошибку.
 */
static bool apply_wg_json(const cJSON *j, wg_config_t *wg, const char **err)
{
    char tmp[CONFIG_WG_ENDPOINT_MAX_LEN];
    int  num;

    if (json_get_str(j, "private_key", tmp, sizeof(tmp)) && tmp[0]) {
        if (!b64_is_wg_key(tmp)) { *err = "Приватный ключ: ожидается 44 символа base64"; return false; }
        strlcpy(wg->private_key, tmp, sizeof(wg->private_key));
    }
    if (json_get_str(j, "peer_public_key", tmp, sizeof(tmp)) && tmp[0]) {
        if (!b64_is_wg_key(tmp)) { *err = "Публичный ключ сервера: ожидается 44 символа base64"; return false; }
        strlcpy(wg->peer_public_key, tmp, sizeof(wg->peer_public_key));
    }
    if (cJSON_IsTrue(cJSON_GetObjectItem(j, "preshared_clear"))) {
        wg->preshared_key[0] = '\0';
    } else if (json_get_str(j, "preshared_key", tmp, sizeof(tmp)) && tmp[0]) {
        if (!b64_is_wg_key(tmp)) { *err = "Preshared key: ожидается 44 символа base64"; return false; }
        strlcpy(wg->preshared_key, tmp, sizeof(wg->preshared_key));
    }
    if (json_get_str(j, "endpoint", tmp, sizeof(tmp)) && tmp[0]) {
        if (!valid_endpoint(tmp)) { *err = "Адрес сервера: IP или имя из букв, цифр, точек и дефисов"; return false; }
        strlcpy(wg->endpoint, tmp, sizeof(wg->endpoint));
    }
    if (json_get_num(j, "port", &num) && num != 0) {
        if (!valid_port(num)) { *err = "Порт сервера: 1-65535"; return false; }
        wg->port = (uint16_t)num;
    }
    if (json_get_str(j, "address", tmp, sizeof(tmp)) && tmp[0]) {
        if (!valid_ipv4(tmp)) { *err = "Адрес в туннеле: ожидается IPv4"; return false; }
        strlcpy(wg->address, tmp, sizeof(wg->address));
    }
    if (json_get_str(j, "netmask", tmp, sizeof(tmp)) && tmp[0]) {
        if (!valid_ipv4(tmp)) { *err = "Маска туннеля: ожидается IPv4-маска"; return false; }
        strlcpy(wg->netmask, tmp, sizeof(wg->netmask));
    }
    if (json_get_num(j, "keepalive", &num)) {
        if (num < 0 || num > 65535) { *err = "Keepalive: 0-65535 секунд"; return false; }
        wg->keepalive = (uint16_t)num;
    }
    return true;
}

/*
 * Заменить правила прокси содержимым массива из запроса. Порт 80 занят
 * веб-интерфейсом, повторяющиеся порты бессмысленны.
 */
static bool apply_rules_json(const cJSON *arr, proxy_rule_t *rules, const char **err)
{
    if (cJSON_GetArraySize(arr) > PROXY_MAX_RULES) {
        *err = "Слишком много правил проброса";
        return false;
    }
    memset(rules, 0, PROXY_MAX_RULES * sizeof(proxy_rule_t));

    int n = 0;
    const cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        int lp = 0, tp = 0;
        char ip[32] = "";   /* с запасом: длинная строка не должна молча обрезаться до валидного адреса */
        json_get_num(item, "listen_port", &lp);
        json_get_num(item, "target_port", &tp);
        json_get_str(item, "target_ip", ip, sizeof(ip));

        if (lp == 0 && tp == 0 && ip[0] == '\0') continue;   /* пустая строка формы */
        if (!valid_port(lp) || lp == 80) { *err = "Порт прокси: 1-65535, кроме 80 (занят этой страницей)"; return false; }
        if (!valid_port(tp))             { *err = "Порт цели: 1-65535"; return false; }
        if (!valid_ipv4(ip) || strlen(ip) >= CONFIG_IPV4_STR_LEN) { *err = "Адрес цели: ожидается IPv4"; return false; }
        for (int i = 0; i < n; i++)
            if (rules[i].listen_port == lp) { *err = "Порты прокси не должны повторяться"; return false; }

        rules[n].listen_port = (uint16_t)lp;
        rules[n].target_port = (uint16_t)tp;
        strlcpy(rules[n].target_ip, ip, sizeof(rules[n].target_ip));
        n++;
    }
    return true;
}

/*
 * Частичное обновление: берём текущие настройки и меняем только те поля, что
 * пришли в JSON. Правила по блокам:
 *   - WiFi: новая сеть не применяется сразу, а уходит в кандидата (см. config.h);
 *     пустой SSID/пароль игнорируется, "wifi_clear":true очищает сеть;
 *   - WireGuard: если туннель уже был настроен, новая конфигурация идёт кандидатом
 *     и откатится сама, если рукопожатие не состоится. Первая настройка
 *     сохраняется сразу как основная — откатываться не к чему;
 *   - Прокси: правила заменяются целиком;
 *   - Auth: false стирает логин и пароль, true с пустым паролем пароль не меняет.
 * Валидация только здесь, на границе системы: дальше код доверяет settings_get().
 */
static esp_err_t settings_post_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;
    cJSON *root = read_json_body(req);
    if (!root) return ESP_FAIL;

    app_config_t cfg = *settings_get();
    bool wifi_changed = false, wg_changed = false, wg_pending = false, rules_changed = false;
    const char *err = NULL;
    cJSON *item;

    /* ── WiFi ── */
    cJSON *wifi_clear = cJSON_GetObjectItem(root, "wifi_clear");
    if (cJSON_IsTrue(wifi_clear)) {
        if (cfg.wifi_ssid[0] != '\0') wifi_changed = true;
        cfg.wifi_ssid[0] = '\0';
        cfg.wifi_pass[0] = '\0';
    } else if ((item = cJSON_GetObjectItem(root, "wifi_ssid")) && cJSON_IsString(item)
               && item->valuestring[0] != '\0') {
        if (strlen(item->valuestring) >= CONFIG_WIFI_SSID_MAX_LEN) { err = "SSID слишком длинный"; goto fail; }
        if (strcmp(cfg.wifi_ssid, item->valuestring) != 0) wifi_changed = true;
        strlcpy(cfg.wifi_ssid, item->valuestring, sizeof(cfg.wifi_ssid));
    }
    if ((item = cJSON_GetObjectItem(root, "wifi_pass")) && cJSON_IsString(item)
        && item->valuestring[0] != '\0') {
        if (strlen(item->valuestring) >= CONFIG_WIFI_PASS_MAX_LEN) { err = "Пароль WiFi слишком длинный"; goto fail; }
        wifi_changed = true;
        strlcpy(cfg.wifi_pass, item->valuestring, sizeof(cfg.wifi_pass));
    }

    /* ── WireGuard ── */
    wg_config_t wg_orig, wg_new;
    effective_wg(&wg_orig);
    wg_new = wg_orig;
    if ((item = cJSON_GetObjectItem(root, "wg")) && cJSON_IsObject(item)) {
        if (!apply_wg_json(item, &wg_new, &err)) goto fail;
        wg_changed = !wg_equal(&wg_orig, &wg_new);
        if (wg_changed && !settings_wg_is_configured(&wg_new)) {
            err = "WireGuard: заполните ключи, адрес сервера и адрес в туннеле";
            goto fail;
        }
    }

    /* ── Прокси ── */
    if ((item = cJSON_GetObjectItem(root, "rules")) && cJSON_IsArray(item)) {
        proxy_rule_t new_rules[PROXY_MAX_RULES];
        if (!apply_rules_json(item, new_rules, &err)) goto fail;
        rules_changed = !rules_equal(cfg.rules, new_rules);
        memcpy(cfg.rules, new_rules, sizeof(cfg.rules));
    }

    /* ── Auth ── */
    cJSON *auth_en = cJSON_GetObjectItem(root, "auth_enabled");
    if (cJSON_IsBool(auth_en)) {
        if (cJSON_IsFalse(auth_en)) {
            cfg.auth_user[0] = '\0';
            cfg.auth_pass[0] = '\0';
        } else {
            if ((item = cJSON_GetObjectItem(root, "auth_user")) && cJSON_IsString(item)) {
                if (strlen(item->valuestring) >= CONFIG_AUTH_USER_MAX_LEN) { err = "Логин слишком длинный"; goto fail; }
                strlcpy(cfg.auth_user, item->valuestring, sizeof(cfg.auth_user));
            }
            if ((item = cJSON_GetObjectItem(root, "auth_pass")) && cJSON_IsString(item)
                && item->valuestring[0] != '\0') {
                if (strlen(item->valuestring) >= CONFIG_AUTH_PASS_MAX_LEN) { err = "Пароль слишком длинный"; goto fail; }
                strlcpy(cfg.auth_pass, item->valuestring, sizeof(cfg.auth_pass));
            }
        }
    }
    cJSON_Delete(root);

    /* ── Сохранение ── */
    if (wg_changed) {
        if (!settings_wg_is_configured(&cfg.wg)) {
            /* Первая настройка: откатываться не к чему, сразу основная */
            cfg.wg = wg_new;
            settings_clear_pending_wg();
        } else if (wg_equal(&wg_new, &cfg.wg)) {
            /* Вернули прежние значения: кандидат больше не нужен */
            settings_clear_pending_wg();
        } else {
            settings_save_pending_wg(&wg_new);
            wg_pending = true;
        }
    }

    if (wifi_changed && cfg.wifi_ssid[0] != '\0') {
        /* Основные WiFi-credentials возвращаем прежние: меняется только кандидат,
         * остальные настройки сохраняются сразу. */
        const app_config_t *cur = settings_get();
        app_config_t save_cfg = cfg;
        strlcpy(save_cfg.wifi_ssid, cur->wifi_ssid, sizeof(save_cfg.wifi_ssid));
        strlcpy(save_cfg.wifi_pass, cur->wifi_pass, sizeof(save_cfg.wifi_pass));
        settings_save(&save_cfg);
        settings_save_pending_wifi(cfg.wifi_ssid, cfg.wifi_pass);
    } else {
        settings_save(&cfg);
    }

    /* Туннель и прокси читают настройки при старте, остальное действует сразу */
    bool restart_required = wifi_changed || wg_changed || rules_changed;
    char resp[96];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"restart_required\":%s,\"wg_pending\":%s}",
             restart_required ? "true" : "false", wg_pending ? "true" : "false");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, -1);
    return ESP_OK;

fail:
    cJSON_Delete(root);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, err);
    return ESP_OK;
}

/* ── GET /api/wifi/scan ──────────────────────────────────────────────────── */

/*
 * Скан выполняется однократно при старте — до поднятия AP, пока нет клиентов.
 * Здесь возвращаем закэшированные результаты.
 */
static esp_err_t wifi_scan_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;
    wifi_ap_t aps[WIFI_SCAN_MAX];
    int n = wifi_get_scanned_aps(aps, WIFI_SCAN_MAX);

    /* cJSON корректно экранирует кавычки и спецсимволы в SSID */
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "ssid",    aps[i].ssid);
        cJSON_AddNumberToObject(obj, "rssi",    aps[i].rssi);
        cJSON_AddBoolToObject  (obj, "secured", aps[i].secured);
        cJSON_AddItemToArray(arr, obj);
    }
    return send_json(req, arr);
}

/* ── GET /api/logs ───────────────────────────────────────────────────────── */

/*
 * Отдаёт строки лога с номера from. Если нужные строки уже затёрты кольцом,
 * начинаем с самой старой из имеющихся. uptime_ms браузер использует, чтобы
 * вычислить реальное время старта и превратить миллисекунды из лога в даты.
 */
static esp_err_t logs_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;
    char qbuf[64] = {0};
    uint32_t from = 0;
    if (httpd_req_get_url_query_str(req, qbuf, sizeof(qbuf)) == ESP_OK) {
        char val[16];
        if (httpd_query_key_value(qbuf, "from", val, sizeof(val)) == ESP_OK)
            from = (uint32_t)strtoul(val, NULL, 10);
    }

    uint32_t seq_end   = log_buffer_next_seq();
    uint32_t seq_start = (seq_end > LOG_BUF_COUNT) ? seq_end - LOG_BUF_COUNT : 0;
    if (from > seq_start) seq_start = from;

    cJSON *root = cJSON_CreateObject();
    cJSON *arr  = cJSON_AddArrayToObject(root, "logs");

    for (uint32_t s = seq_start; s < seq_end; s++) {
        char text[LOG_BUF_LEN];
        if (!log_buffer_get(s, text)) continue;   /* слот перезаписан, пока мы итерировали */
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddNumberToObject(entry, "seq", s);
        cJSON_AddStringToObject(entry, "msg", text);
        cJSON_AddItemToArray(arr, entry);
    }

    cJSON_AddNumberToObject(root, "next", seq_end);
    cJSON_AddNumberToObject(root, "uptime_ms", (double)(esp_timer_get_time() / 1000LL));
    return send_json(req, root);
}

/* ── POST /api/time ──────────────────────────────────────────────────────── */

/*
 * Браузер сообщает текущее unix-время. Принимается только если часы ещё не
 * установлены (иначе SNTP точнее). Нужно, когда у платы нет доступа к NTP, а
 * WireGuard без времени не поднимется.
 */
static esp_err_t time_post_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;
    cJSON *root = read_json_body(req);
    if (!root) return ESP_FAIL;

    cJSON *ep = cJSON_GetObjectItem(root, "epoch");
    if (!cJSON_IsNumber(ep) || ep->valuedouble < WG_MIN_VALID_EPOCH) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid epoch");
        return ESP_OK;
    }
    if (!wg_clock_is_valid()) {
        struct timeval tv = { .tv_sec = (time_t)ep->valuedouble, .tv_usec = 0 };
        settimeofday(&tv, NULL);
        ESP_LOGI(TAG, "Clock set from browser");
    }
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"ok\":true}", -1);
    return ESP_OK;
}

/* ── POST /api/restart ───────────────────────────────────────────────────── */

/* Отправляет ответ и через 500 мс перезагружает устройство */
static void restart_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
}

static esp_err_t restart_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"ok\":true}", -1);
    xTaskCreate(restart_task, "restart", 2048, NULL, 5, NULL);
    return ESP_OK;
}

/* ── POST /api/ota ───────────────────────────────────────────────────────── */

/*
 * Принимает бинарный образ прошивки (application/octet-stream), записывает в
 * неактивный OTA-слот, переключает загрузочный раздел и перезагружает
 * устройство. При ошибке текущий раздел не затрагивается.
 *
 * Первый байт образа ESP32 всегда 0xE9 — проверяем для быстрого отклонения
 * случайных файлов. esp_ota_end() дополнительно верифицирует SHA256.
 */
static esp_err_t ota_post_handler(httpd_req_t *req)
{
    if (!check_auth(req)) return ESP_OK;

    if (req->content_len == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");
        return ESP_FAIL;
    }

    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No OTA partition");
        return ESP_FAIL;
    }

    esp_ota_handle_t handle;
    esp_err_t err = esp_ota_begin(part, req->content_len, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "OTA: writing %d bytes to '%s'", req->content_len, part->label);

    char buf[1024];
    int remaining = req->content_len;
    int written   = 0;

    while (remaining > 0) {
        int chunk = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
        int n = httpd_req_recv(req, buf, chunk);
        /* Таймаут приёма — не ошибка: большой образ идёт по WiFi неравномерно, ждём дальше */
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (n <= 0) {
            ESP_LOGE(TAG, "OTA recv error at %d/%d", written, req->content_len);
            esp_ota_abort(handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Receive error");
            return ESP_FAIL;
        }

        if (written == 0 && (uint8_t)buf[0] != 0xE9) {
            esp_ota_abort(handle);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Not a valid ESP32 firmware");
            return ESP_FAIL;
        }

        err = esp_ota_write(handle, buf, n);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write: %s", esp_err_to_name(err));
            esp_ota_abort(handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Write failed");
            return ESP_FAIL;
        }
        written   += n;
        remaining -= n;
    }

    /* Верифицирует SHA256 образа */
    err = esp_ota_end(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Verify failed");
        return ESP_FAIL;
    }

    /* Только после успешной проверки переключаем загрузку на новый слот;
       до этого момента устройство продолжает грузиться со старой прошивки */
    err = esp_ota_set_boot_partition(part);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Set boot partition failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "OTA done: %d bytes, rebooting", written);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"ok\":true}", -1);

    /* Дать ответу уйти в сеть, иначе страница увидит обрыв вместо «ok» */
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

/* ── Запуск сервера ───────────────────────────────────────────────────────── */

void web_server_start(void)
{
    httpd_config_t config    = HTTPD_DEFAULT_CONFIG();
    config.stack_size        = 8192;
    config.max_open_sockets  = HTTP_MAX_OPEN_SOCKETS;
    config.lru_purge_enable  = true;   /* автозакрытие старых соединений при нехватке слотов */
    config.max_uri_handlers  = 12;     /* маршрутов 10, два запаса */
    config.recv_wait_timeout = 30;     /* OTA upload: до 1.9 МБ по WiFi, стандартные 5 с мало */

    httpd_handle_t server;
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    const httpd_uri_t routes[] = {
        { .uri = "/",             .method = HTTP_GET,  .handler = root_handler          },
        { .uri = "/favicon.ico",  .method = HTTP_GET,  .handler = favicon_handler       },
        { .uri = "/api/status",   .method = HTTP_GET,  .handler = status_handler        },
        { .uri = "/api/settings", .method = HTTP_GET,  .handler = settings_get_handler  },
        { .uri = "/api/settings", .method = HTTP_POST, .handler = settings_post_handler },
        { .uri = "/api/wifi/scan", .method = HTTP_GET, .handler = wifi_scan_handler     },
        { .uri = "/api/logs",     .method = HTTP_GET,  .handler = logs_handler          },
        { .uri = "/api/time",     .method = HTTP_POST, .handler = time_post_handler     },
        { .uri = "/api/restart",  .method = HTTP_POST, .handler = restart_handler       },
        { .uri = "/api/ota",      .method = HTTP_POST, .handler = ota_post_handler      },
    };

    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++)
        httpd_register_uri_handler(server, &routes[i]);

    ESP_LOGI(TAG, "HTTP server started on port 80");
}
