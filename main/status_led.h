/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#pragma once

/*
 * status_led.h — индикация состояния светодиодом платы.
 *
 *   нет питания или нет WiFi    светодиод не горит
 *   WiFi есть, туннеля нет       короткие вспышки (STATUS_LED_FLASH_ON_MS раз в STATUS_LED_FLASH_PERIOD_MS)
 *   туннель работает             горит постоянно
 *
 * «Туннель работает» = состояние WG_STATE_UP (рукопожатие есть и свежее). Если рукопожатие устарело
 * или туннель пересоздаётся, светодиод снова вспыхивает, поэтому по нему видно проблемы на ходу.
 */

#define STATUS_LED_FLASH_PERIOD_MS  1500
#define STATUS_LED_FLASH_ON_MS      100

/** Настроить вывод (светодиод погашен) и запустить задачу индикации. Вызывать один раз, как можно раньше. */
void status_led_start(void);
