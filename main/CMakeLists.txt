idf_component_register(
    SRCS "main.c" "config.c" "wifi_manager.c" "wg_tunnel.c" "proxy.c"
         "web_server.c" "log_buffer.c" "b64.c" "status_led.c"
    INCLUDE_DIRS "."
    EMBED_FILES "index.html"
    REQUIRES nvs_flash esp_wifi esp_http_server esp_netif esp_event lwip
             esp_driver_gpio app_update esp_timer
)
