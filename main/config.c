/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#include "config.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>

static const char *TAG    = "config";
static const char *NVS_NS = "app_cfg";      /* основные настройки */

#define NVS_NS_WIFI_PEND "wifi_pend"        /* кандидат WiFi */
#define NVS_NS_WG_PEND   "wg_pend"          /* кандидат WireGuard */

/* Текущая конфигурация в RAM — единственная копия, все модули читают её */
static app_config_t s_cfg;

/* ── Вспомогательные функции чтения NVS ──────────────────────────────────── */

/*
 * Все load_* молча игнорируют ошибку чтения: «ключа нет» — штатная ситуация
 * (первый запуск или поле, добавленное в новой версии прошивки). В dst остаётся
 * значение из set_defaults(), поэтому после OTA-обновления старые настройки не
 * теряются, а новые поля получают значения по умолчанию.
 */
static void load_str(nvs_handle_t h, const char *key, char *dst, size_t max_len)
{
    size_t len = max_len;
    if (nvs_get_str(h, key, dst, &len) != ESP_OK)
        dst[0] = '\0';
}

static void load_u16(nvs_handle_t h, const char *key, uint16_t *dst)
{
    nvs_get_u16(h, key, dst);
}

/* ── Заводские значения ──────────────────────────────────────────────────── */

static void set_wg_defaults(wg_config_t *wg)
{
    memset(wg, 0, sizeof(*wg));
    wg->port      = CONFIG_WG_PORT_DEFAULT;
    wg->keepalive = CONFIG_WG_KEEPALIVE_DEFAULT;
    strlcpy(wg->netmask, CONFIG_WG_NETMASK_DEFAULT, sizeof(wg->netmask));
}

static void set_defaults(app_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    set_wg_defaults(&cfg->wg);
}

/* ── Загрузка/сохранение настроек туннеля (общие для основного и кандидата) ─ */

/*
 * Имена ключей NVS ограничены 15 символами, отсюда сокращения.
 * Одна пара функций обслуживает оба пространства (app_cfg и wg_pend), чтобы
 * набор полей не разъезжался.
 */
static void wg_load(nvs_handle_t h, wg_config_t *wg)
{
    load_str(h, "wg_priv",     wg->private_key,     sizeof(wg->private_key));
    load_str(h, "wg_pub",      wg->peer_public_key, sizeof(wg->peer_public_key));
    load_str(h, "wg_psk",      wg->preshared_key,   sizeof(wg->preshared_key));
    load_str(h, "wg_endpoint", wg->endpoint,        sizeof(wg->endpoint));
    load_u16(h, "wg_port",     &wg->port);
    load_str(h, "wg_addr",     wg->address,         sizeof(wg->address));
    /* load_str при отсутствии ключа обнулил бы маску по умолчанию — вернём её */
    char mask[CONFIG_IPV4_STR_LEN];
    load_str(h, "wg_mask", mask, sizeof(mask));
    if (mask[0] != '\0') strlcpy(wg->netmask, mask, sizeof(wg->netmask));
    load_u16(h, "wg_keepalive", &wg->keepalive);
}

static void wg_store(nvs_handle_t h, const wg_config_t *wg)
{
    nvs_set_str(h, "wg_priv",     wg->private_key);
    nvs_set_str(h, "wg_pub",      wg->peer_public_key);
    nvs_set_str(h, "wg_psk",      wg->preshared_key);
    nvs_set_str(h, "wg_endpoint", wg->endpoint);
    nvs_set_u16(h, "wg_port",     wg->port);
    nvs_set_str(h, "wg_addr",     wg->address);
    nvs_set_str(h, "wg_mask",     wg->netmask);
    nvs_set_u16(h, "wg_keepalive", wg->keepalive);
}

/* Ключи правил прокси: px0_lp / px0_ip / px0_tp (listen port / target ip / target port) */
static void rule_key(char *dst, size_t n, int idx, const char *suffix)
{
    snprintf(dst, n, "px%d_%s", idx, suffix);
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void settings_init(void)
{
    /* Сначала заводские значения, затем поверх них — всё, что нашлось в NVS */
    set_defaults(&s_cfg);

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "No saved config, using defaults");
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS open failed (%s), using defaults", esp_err_to_name(err));
        return;
    }

    load_str(h, "wifi_ssid", s_cfg.wifi_ssid, sizeof(s_cfg.wifi_ssid));
    load_str(h, "wifi_pass", s_cfg.wifi_pass, sizeof(s_cfg.wifi_pass));
    load_str(h, "auth_user", s_cfg.auth_user, sizeof(s_cfg.auth_user));
    load_str(h, "auth_pass", s_cfg.auth_pass, sizeof(s_cfg.auth_pass));
    wg_load(h, &s_cfg.wg);

    for (int i = 0; i < PROXY_MAX_RULES; i++) {
        char key[16];
        rule_key(key, sizeof(key), i, "lp");
        load_u16(h, key, &s_cfg.rules[i].listen_port);
        rule_key(key, sizeof(key), i, "ip");
        load_str(h, key, s_cfg.rules[i].target_ip, sizeof(s_cfg.rules[i].target_ip));
        rule_key(key, sizeof(key), i, "tp");
        load_u16(h, key, &s_cfg.rules[i].target_port);
    }

    nvs_close(h);

    ESP_LOGI(TAG, "Config loaded: wifi='%s'  wg endpoint='%s:%u'  tunnel ip='%s'",
             s_cfg.wifi_ssid, s_cfg.wg.endpoint, s_cfg.wg.port, s_cfg.wg.address);
}

/*
 * Возвращает указатель на живую копию в RAM, а не снимок. Читатели из разных
 * задач (web_server, wifi_manager, wg_tunnel) видят изменения сразу после
 * settings_save(). Блокировок нет: запись происходит редко и только из
 * HTTP-обработчика.
 */
const app_config_t *settings_get(void)
{
    return &s_cfg;
}

void settings_save(const app_config_t *cfg)
{
    s_cfg = *cfg;   /* сначала RAM: настройки действуют сразу, даже если запись в NVS не удастся */

    /* Если NVS недоступен совсем, дальше работать бессмысленно — паника допустима.
       Отдельные nvs_set_* не проверяются: при сбое теряется одно поле, остальное
       сохранится, а при следующем сохранении всё запишется заново. */
    nvs_handle_t h;
    ESP_ERROR_CHECK(nvs_open(NVS_NS, NVS_READWRITE, &h));

    nvs_set_str(h, "wifi_ssid", cfg->wifi_ssid);
    nvs_set_str(h, "wifi_pass", cfg->wifi_pass);
    nvs_set_str(h, "auth_user", cfg->auth_user);
    nvs_set_str(h, "auth_pass", cfg->auth_pass);
    wg_store(h, &cfg->wg);

    for (int i = 0; i < PROXY_MAX_RULES; i++) {
        char key[16];
        rule_key(key, sizeof(key), i, "lp");
        nvs_set_u16(h, key, cfg->rules[i].listen_port);
        rule_key(key, sizeof(key), i, "ip");
        nvs_set_str(h, key, cfg->rules[i].target_ip);
        rule_key(key, sizeof(key), i, "tp");
        nvs_set_u16(h, key, cfg->rules[i].target_port);
    }

    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Config saved");
}

/* Сброс по долгому нажатию BOOT: стираются основные настройки и оба кандидата */
void settings_reset(void)
{
    ESP_LOGI(TAG, "Resetting config to defaults");
    const char *namespaces[] = { NVS_NS, NVS_NS_WIFI_PEND, NVS_NS_WG_PEND };
    for (size_t i = 0; i < sizeof(namespaces) / sizeof(namespaces[0]); i++) {
        nvs_handle_t h;
        if (nvs_open(namespaces[i], NVS_READWRITE, &h) == ESP_OK) {
            nvs_erase_all(h);
            nvs_commit(h);
            nvs_close(h);
        }
    }
    set_defaults(&s_cfg);
}

bool settings_wg_is_configured(const wg_config_t *wg)
{
    return wg->private_key[0] && wg->peer_public_key[0] &&
           wg->endpoint[0]    && wg->address[0] && wg->netmask[0] && wg->port;
}

/* ── Кандидат WiFi ───────────────────────────────────────────────────────── */

void settings_save_pending_wifi(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_WIFI_PEND, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_str(h, "ssid", ssid);
    nvs_set_str(h, "pass", pass);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Pending WiFi saved: ssid='%s'", ssid);
}

bool settings_load_pending_wifi(char *ssid, size_t ssid_len,
                                char *pass, size_t pass_len)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_WIFI_PEND, NVS_READONLY, &h) != ESP_OK) return false;
    /* nvs_get_str принимает длину по указателю и перезаписывает её, поэтому каждый
       раз передаётся временная копия (compound literal), а не ssid_len/pass_len */
    bool ok = nvs_get_str(h, "ssid", ssid, &(size_t){ssid_len}) == ESP_OK &&
              nvs_get_str(h, "pass", pass, &(size_t){pass_len}) == ESP_OK;
    nvs_close(h);
    return ok && ssid[0] != '\0';
}

void settings_clear_pending_wifi(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_WIFI_PEND, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Pending WiFi cleared");
}

/* ── Кандидат WireGuard ──────────────────────────────────────────────────── */

void settings_save_pending_wg(const wg_config_t *wg)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_WG_PEND, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_all(h);       /* не оставляем ключи от предыдущего кандидата */
    wg_store(h, wg);
    nvs_set_u8(h, "valid", 1);  /* признак «кандидат есть»: ключи сами по себе могут быть пустыми */
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Pending WireGuard config saved: endpoint='%s:%u'", wg->endpoint, wg->port);
}

bool settings_load_pending_wg(wg_config_t *wg)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_WG_PEND, NVS_READONLY, &h) != ESP_OK) return false;
    uint8_t valid = 0;
    if (nvs_get_u8(h, "valid", &valid) != ESP_OK || !valid) {
        nvs_close(h);
        return false;
    }
    set_wg_defaults(wg);
    wg_load(h, wg);
    nvs_close(h);
    return true;
}

void settings_clear_pending_wg(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_WG_PEND, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Pending WireGuard config cleared");
}

void settings_promote_pending_wg(void)
{
    wg_config_t wg;
    if (!settings_load_pending_wg(&wg)) return;

    app_config_t cfg = s_cfg;
    cfg.wg = wg;
    settings_save(&cfg);
    settings_clear_pending_wg();
    ESP_LOGI(TAG, "Pending WireGuard config promoted to main");
}
