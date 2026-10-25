/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#include "status_led.h"
#include "board_config.h"
#include "wifi_manager.h"
#include "wg_tunnel.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define LED_TICK_MS  50

static void led_set(bool on)
{
    gpio_set_level(BOARD_LED_GPIO, on ? BOARD_LED_ACTIVE_LEVEL : !BOARD_LED_ACTIVE_LEVEL);
}

static void led_task(void *arg)
{
    const uint32_t period_ticks = STATUS_LED_FLASH_PERIOD_MS / LED_TICK_MS;
    const uint32_t on_ticks     = STATUS_LED_FLASH_ON_MS / LED_TICK_MS;
    uint32_t tick = 0;

    for (;;) {
        bool on;
        if (!wifi_manager_is_connected())
            on = false;                                  /* нет WiFi: погашен */
        else if (wg_tunnel_get_state() == WG_STATE_UP)
            on = true;                                   /* туннель работает: горит постоянно */
        else
            on = (tick % period_ticks) < on_ticks;       /* WiFi есть, туннеля нет: вспышки */

        led_set(on);
        tick++;
        vTaskDelay(pdMS_TO_TICKS(LED_TICK_MS));
    }
}

void status_led_start(void)
{
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << BOARD_LED_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);
    led_set(false);                                      /* сразу определённое состояние: погашен */
    xTaskCreate(led_task, "status_led", 2048, NULL, 2, NULL);
}
