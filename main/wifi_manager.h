/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * wifi_manager.h — управление WiFi-подключением.
 *
 * Логика запуска:
 *
 *   1. Есть кандидат WiFi (новая сеть ждёт проверки)?
 *      - подключились → кандидат становится основным;
 *      - не подключились → кандидат удаляется, идём к старой сети.
 *   2. Нет сохранённого SSID (первое включение) → скан + точка доступа (AP).
 *   3. SSID есть → подключаемся (WIFI_CONNECT_TIMEOUT_MS, MAX_RETRY попыток).
 *      - успех → режим STA;
 *      - провал → скан + APSTA: AP для локальной настройки, а STA в фоне
 *        бесконечно пробует подключиться к роутеру.
 *   4. После первого успешного подключения STA переподключается бесконечно.
 *
 * Точка доступа:
 *   SSID:   "WG-Setup-XXXXXX" (последние 3 байта MAC)
 *   Пароль: WIFI_AP_PASSWORD (WPA2). Сеть закрыта паролем: через страницу
 *           настроек можно сменить ключи VPN, а устройство стоит без присмотра
 *           и AP в режиме APSTA остаётся доступной постоянно.
 *   IP:     192.168.4.1
 */

#define WIFI_CONNECT_TIMEOUT_MS  15000   /* таймаут подключения к STA, мс */
#define WIFI_AP_SSID_PREFIX      "WG-Setup"
#define WIFI_AP_PASSWORD         "wg-setup-1234"   /* минимум 8 символов (требование WPA2) */
#define WIFI_HOSTNAME            "esp32-wireguard-tunnel"   /* имя в списке DHCP-клиентов роутера */

/**
 * Инициализировать WiFi-менеджер: определить режим (STA или AP) и подключиться.
 * Блокирует выполнение до получения IP (STA) или поднятия AP.
 * Вызывать после settings_init().
 */
void wifi_manager_init(void);

/** true, если устройство подключено как станция (STA) и имеет IP-адрес. */
bool wifi_manager_is_connected(void);

/** true, если поднята точка доступа (режимы AP и APSTA); страница настроек — 192.168.4.1. */
bool wifi_manager_is_ap_mode(void);

/* ── Состояние для страницы «Статус» ─────────────────────────────────────── */

typedef struct {
    bool   connected;      /* STA имеет IP */
    bool   ap_mode;        /* поднята AP */
    char   ssid[33];       /* сеть, к которой подключена STA ("" если нет) */
    char   ip[16];         /* IP станции ("" если нет) */
    int8_t rssi;           /* уровень сигнала, дБм (0 если нет) */
} wifi_status_t;

void wifi_manager_get_status(wifi_status_t *out);

/* ── WiFi scan ───────────────────────────────────────────────────────────── */

#define WIFI_SCAN_MAX 20

typedef struct {
    char   ssid[33];
    int8_t rssi;
    bool   secured;
} wifi_ap_t;

/**
 * Результаты скана, выполненного при запуске (до поднятия AP, пока нет клиентов).
 * Отсортированы по убыванию RSSI. Готовы после wifi_manager_init().
 */
int wifi_get_scanned_aps(wifi_ap_t *out, int max_count);

/**
 * Выполнить скан прямо сейчас (~2 с блокировки).
 * Работает только в STA или APSTA режиме.
 */
int wifi_scan_aps(wifi_ap_t *out, int max_count);
