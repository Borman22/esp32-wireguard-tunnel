/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * log_buffer.h — кольцевой буфер последних строк лога для вкладки «Логи».
 *
 * log_buffer_init() подменяет вывод ESP_LOG: строка уходит и в UART, и в буфер.
 * Каждая строка получает сквозной номер seq; браузер запрашивает «всё, начиная
 * с N» и так получает только новое.
 */

#define LOG_BUF_COUNT  80    /* сколько последних строк хранится */
#define LOG_BUF_LEN    160   /* максимальная длина строки */

/**
 * Перехватить вывод ESP_LOG*. Вызывать первой в app_main: перехватываются
 * только сообщения, появившиеся после установки хука.
 */
void log_buffer_init(void);

/** Номер, который получит следующая строка (то есть число строк, записанных с момента старта). */
uint32_t log_buffer_next_seq(void);

/**
 * Прочитать строку с номером seq в text (размер LOG_BUF_LEN).
 * false — строка уже затёрта кольцом или ещё не записана.
 */
bool log_buffer_get(uint32_t seq, char *text);
