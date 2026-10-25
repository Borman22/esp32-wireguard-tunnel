/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#pragma once

/*
 * board_config.h — параметры конкретной платы и чипа.
 *
 * Чип выбирается автоматически по CONFIG_IDF_TARGET_* (idf.py set-target ...),
 * поэтому для переноса между ESP32-C3 и ESP32-S3 править код не нужно.
 * Параметры flash и PSRAM лежат в sdkconfig.defaults(.esp32s3), а не здесь.
 */

#include "sdkconfig.h"

#if CONFIG_IDF_TARGET_ESP32C3
    /* Кнопка BOOT. GPIO9 — strapping pin: если он LOW при сбросе, чип уходит в
     * загрузчик, поэтому состояние кнопки читается только во время работы. */
    #define BOARD_BOOT_BUTTON_GPIO  9
    /* Светодиод платы: GPIO8, включается НИЗКИМ уровнем (LOW = горит). Тот же вывод, что на плате BMS. */
    #define BOARD_LED_GPIO          8
    #define BOARD_LED_ACTIVE_LEVEL  0
#elif CONFIG_IDF_TARGET_ESP32S3
    /* Кнопка BOOT на DevKit-платах ESP32-S3 — GPIO0 (тоже strapping pin). */
    #define BOARD_BOOT_BUTTON_GPIO  0
    /* Светодиод платы S3: GPIO48 (обычный светодиод, не WS2812: мигает от gpio_set_level).
     * Полярность (HIGH = горит) подтвердите на плате: если индикация инвертирована
     * (горит без Wi-Fi и гаснет при работающем туннеле), поменяйте значение на 0. */
    #define BOARD_LED_GPIO          48
    #define BOARD_LED_ACTIVE_LEVEL  1
#else
    #error "Неподдерживаемый чип: добавьте его в board_config.h (кнопка BOOT, светодиод)"
#endif
