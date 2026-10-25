/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "board_config.h"
#include "config.h"
#include "log_buffer.h"
#include "proxy.h"
#include "web_server.h"
#include "wg_tunnel.h"
#include "wifi_manager.h"
#include "status_led.h"

static const char *TAG = "main";

#define BOOT_HOLD_MS  3000   /* удержание кнопки BOOT для сброса настроек, мс */

/*
 * Удерживать BOOT 3 секунды во время работы прошивки → сброс настроек.
 * Проверка при старте (пока кнопка зажата на сбросе) невозможна: GPIO9 у ESP32-C3
 * и GPIO0 у ESP32-S3 — strapping pins, чип уйдёт в загрузчик. Поэтому кнопка
 * опрашивается в отдельной задаче непрерывно.
 */
static void boot_monitor_task(void *arg)
{
    int held_ms = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(100));
        if (gpio_get_level(BOARD_BOOT_BUTTON_GPIO) == 0) {
            held_ms += 100;
            if (held_ms >= BOOT_HOLD_MS) {
                ESP_LOGI(TAG, "BOOT held %d ms - resetting all settings", held_ms);
                settings_reset();
                vTaskDelay(pdMS_TO_TICKS(200));
                esp_restart();
            }
        } else {
            held_ms = 0;
        }
    }
}

void app_main(void)
{
    /* Перехватить лог-вывод в кольцевой буфер как можно раньше */
    log_buffer_init();

    /* Подавить debug-спам системных компонентов, оставить INFO для наших */
    esp_log_level_set("*",            ESP_LOG_WARN);
    esp_log_level_set("main",         ESP_LOG_INFO);
    esp_log_level_set("config",       ESP_LOG_INFO);
    esp_log_level_set("wifi_manager", ESP_LOG_INFO);
    esp_log_level_set("wg_tunnel",    ESP_LOG_INFO);
    esp_log_level_set("esp_wireguard", ESP_LOG_INFO);
    esp_log_level_set("proxy",        ESP_LOG_INFO);
    esp_log_level_set("web_server",   ESP_LOG_INFO);
    /* Подавить штатные WARN от httpd: 404 favicon, EAGAIN на отправке, оборванные запросы */
    esp_log_level_set("httpd_uri",    ESP_LOG_ERROR);
    esp_log_level_set("httpd_txrx",   ESP_LOG_ERROR);
    esp_log_level_set("httpd_parse",  ESP_LOG_ERROR);

    /* NVS должен быть инициализирован первым — от него зависят config и WiFi */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Загрузить настройки из NVS (или заводские значения при первом запуске) */
    settings_init();

    /* Настроить GPIO кнопки BOOT и запустить задачу мониторинга */
    gpio_config_t boot_io = {
        .pin_bit_mask = (1ULL << BOARD_BOOT_BUTTON_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&boot_io);
    xTaskCreate(boot_monitor_task, "boot_btn", 2048, NULL, 3, NULL);

    /* Светодиод состояния: сначала погашен, задача включает его по WiFi и туннелю */
    status_led_start();

    /* Подключиться к WiFi или поднять AP для первоначальной настройки */
    wifi_manager_init();

    /* Туннель: выбирает активную конфигурацию (кандидат/основная) и запускает супервайзер */
    wg_tunnel_start();

    /* Прокси слушает порты сразу, а соединения принимает, только когда они пришли через туннель */
    proxy_start(settings_get()->rules, wg_tunnel_active_config()->address);

    /* Страница настроек и состояния */
    web_server_start();

    if (wifi_manager_is_ap_mode()) {
        ESP_LOGI(TAG, "Setup mode: connect to WiFi '" WIFI_AP_SSID_PREFIX "-XXXXXX', open 192.168.4.1");
    } else {
        ESP_LOGI(TAG, "Running in STA mode");
    }
}
