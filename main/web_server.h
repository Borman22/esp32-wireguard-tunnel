/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#pragma once

/*
 * web_server.h — HTTP-сервер: страница настроек и состояния.
 *
 * Эндпоинты (все, кроме /favicon.ico, закрыты авторизацией, если она включена):
 *   GET  /                → index.html (веб-интерфейс, встроен в прошивку)
 *   GET  /api/status      → состояние WiFi, туннеля, прокси (JSON)
 *   GET  /api/settings    → текущие настройки (ключи и пароли не возвращаются)
 *   POST /api/settings    → сохранить настройки (JSON, частичное обновление)
 *   GET  /api/wifi/scan   → список WiFi-сетей (кэш, снятый при старте)
 *   GET  /api/logs?from=N → строки лога начиная с номера N
 *   POST /api/time        → время браузера (если часы ещё не установлены)
 *   POST /api/restart     → перезагрузка через 500 мс
 *   POST /api/ota         → бинарный образ прошивки, затем перезагрузка
 */

#define HTTP_MAX_OPEN_SOCKETS  2   /* бюджет сокетов lwIP — см. proxy.h */

/**
 * Запустить HTTP-сервер на порту 80.
 * Вызывать после wifi_manager_init().
 */
void web_server_start(void);
