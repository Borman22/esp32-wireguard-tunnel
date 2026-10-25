/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * config.h — хранение и загрузка настроек устройства в NVS (Non-Volatile Storage).
 *
 * Все настройки переживают перезагрузку и отключение питания.
 * При первом включении (пустой NVS) используются значения по умолчанию.
 *
 * Группы настроек:
 *   - WiFi:  SSID и пароль сети, к которой подключается устройство
 *   - Auth:  логин/пароль веб-интерфейса (HTTP Basic Auth)
 *   - WireGuard: параметры туннеля до VPN-сервера
 *   - Proxy: правила проброса TCP-портов из туннеля в локальную сеть
 *
 * Два набора данных применяются «в два этапа» (кандидат → основной), чтобы
 * ошибка в удалённой настройке не лишила доступа к устройству:
 *   - WiFi (namespace "wifi_pend")
 *   - WireGuard (namespace "wg_pend")
 */

/* ── Размеры строк (с учётом завершающего '\0') ──────────────────────────── */

#define CONFIG_WIFI_SSID_MAX_LEN     33
#define CONFIG_WIFI_PASS_MAX_LEN     65
#define CONFIG_AUTH_USER_MAX_LEN     33
#define CONFIG_AUTH_PASS_MAX_LEN     65

#define CONFIG_WG_KEY_LEN            45   /* ключ WireGuard в base64: 44 символа + '\0' */
#define CONFIG_WG_ENDPOINT_MAX_LEN   64   /* IP-адрес или имя хоста VPN-сервера */
#define CONFIG_IPV4_STR_LEN          16   /* "255.255.255.255" + '\0' */

/* ── Значения по умолчанию ────────────────────────────────────────────────── */

#define CONFIG_WG_PORT_DEFAULT        51820
#define CONFIG_WG_KEEPALIVE_DEFAULT   25            /* с; держит открытым NAT-соединение у провайдера */
#define CONFIG_WG_NETMASK_DEFAULT     "255.255.255.0"

/* ══════════════════════════════════════════════════════════════════════════
 * WireGuard
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char     private_key[CONFIG_WG_KEY_LEN];           /* приватный ключ ЭТОГО устройства */
    char     peer_public_key[CONFIG_WG_KEY_LEN];      /* публичный ключ VPN-сервера */
    char     preshared_key[CONFIG_WG_KEY_LEN];        /* необязательный; пусто = не используется */
    char     endpoint[CONFIG_WG_ENDPOINT_MAX_LEN];    /* адрес VPN-сервера (IP или DNS-имя) */
    uint16_t port;                                    /* UDP-порт VPN-сервера */
    char     address[CONFIG_IPV4_STR_LEN];            /* адрес устройства внутри туннеля, напр. 10.8.0.2 */
    char     netmask[CONFIG_IPV4_STR_LEN];            /* маска туннельной сети, напр. 255.255.255.0 */
    uint16_t keepalive;                               /* с; 0 = выключено */
} wg_config_t;

/* ══════════════════════════════════════════════════════════════════════════
 * TCP-прокси
 * ══════════════════════════════════════════════════════════════════════════ */

#define PROXY_MAX_RULES  3   /* предел задан числом сокетов lwIP, см. sdkconfig.defaults */

/*
 * Одно правило: соединение на listen_port (принимается только через туннель)
 * пересылается на target_ip:target_port в локальной сети за роутером.
 * listen_port == 0 — слот не используется.
 */
typedef struct {
    uint16_t listen_port;
    char     target_ip[CONFIG_IPV4_STR_LEN];
    uint16_t target_port;
} proxy_rule_t;

/* ══════════════════════════════════════════════════════════════════════════
 * Общая структура конфигурации
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* WiFi */
    char wifi_ssid[CONFIG_WIFI_SSID_MAX_LEN];
    char wifi_pass[CONFIG_WIFI_PASS_MAX_LEN];

    /* Auth (HTTP Basic Auth; пустой auth_pass = без авторизации) */
    char auth_user[CONFIG_AUTH_USER_MAX_LEN];
    char auth_pass[CONFIG_AUTH_PASS_MAX_LEN];

    /* Основная (подтверждённая) конфигурация туннеля */
    wg_config_t wg;

    /* Правила проброса портов */
    proxy_rule_t rules[PROXY_MAX_RULES];
} app_config_t;

/* ══════════════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * Инициализировать модуль настроек.
 * Загружает сохранённые настройки из NVS или заводские значения, если NVS пуст.
 * Должна вызываться один раз после nvs_flash_init().
 */
void settings_init(void);

/**
 * Текущие настройки (живая копия в RAM, только для чтения).
 * Изменения от settings_save() видны сразу всем модулям.
 */
const app_config_t *settings_get(void);

/** Сохранить настройки в NVS и обновить копию в RAM. */
void settings_save(const app_config_t *cfg);

/**
 * Сбросить все настройки на заводские (долгое нажатие BOOT).
 * Стираются основные настройки, кандидаты WiFi и WireGuard.
 */
void settings_reset(void);

/** true, если заданы все обязательные поля туннеля (иначе WireGuard не запускается). */
bool settings_wg_is_configured(const wg_config_t *wg);

/* ── Кандидат WiFi (двухэтапная фиксация) ─────────────────────────────────── */

/*
 * Новая WiFi-сеть сначала кладётся в отдельное пространство NVS. После
 * перезагрузки wifi_manager пробует её первой: успех → она становится основной,
 * провал → удаляется и устройство возвращается к старой сети.
 */
void settings_save_pending_wifi(const char *ssid, const char *pass);
bool settings_load_pending_wifi(char *ssid, size_t ssid_len, char *pass, size_t pass_len);
void settings_clear_pending_wifi(void);

/* ── Кандидат WireGuard (двухэтапная фиксация) ────────────────────────────── */

/*
 * Аналогично WiFi: новая конфигурация туннеля при следующей загрузке запускается
 * «на пробу». Если рукопожатие с сервером не состоялось за WG_TRIAL_TIMEOUT_S,
 * кандидат удаляется и прошивка перезагружается со старой конфигурацией.
 */
void settings_save_pending_wg(const wg_config_t *wg);
bool settings_load_pending_wg(wg_config_t *wg);
void settings_clear_pending_wg(void);

/** Кандидат подтверждён: сделать его основным и удалить из пространства кандидатов. */
void settings_promote_pending_wg(void);
