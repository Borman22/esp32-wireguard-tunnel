/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#include "log_buffer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Слот строки = seq % LOG_BUF_COUNT */
typedef struct { uint32_t seq; char text[LOG_BUF_LEN]; } log_entry_t;

static log_entry_t s_buf[LOG_BUF_COUNT];
static uint32_t    s_seq = 0;

/*
 * Именно spinlock (portMUX), а не мьютекс — не менять. Хук вызывается из любого
 * контекста, включая системные задачи WiFi/lwIP и прерывания, где блокирующий
 * мьютекс FreeRTOS приводит к дедлоку. Критические секции поэтому предельно
 * короткие: форматирование строки делается ДО захвата, внутри только memcpy.
 */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

/* Вырезать ANSI-цвета ("\033[0;32m"), которыми ESP_LOG раскрашивает уровни, — в вебе они мусор */
static void strip_ansi(char *s)
{
    char *dst = s;
    while (*s) {
        if (*s == '\033' && *(s + 1) == '[') {
            s += 2;
            while (*s && *s != 'm') s++;
            if (*s) s++;
        } else {
            *dst++ = *s++;
        }
    }
    *dst = '\0';
}

/* Подмена vprintf для ESP_LOG: пишет и в UART, и в кольцевой буфер */
static int log_vprintf_hook(const char *fmt, va_list args)
{
    /* va_list можно пройти только один раз: vprintf исчерпывает args,
     * поэтому копируем до его вызова для последующего vsnprintf. */
    va_list args2;
    va_copy(args2, args);
    int ret = vprintf(fmt, args);

    char tmp[LOG_BUF_LEN];
    vsnprintf(tmp, sizeof(tmp), fmt, args2);
    va_end(args2);

    strip_ansi(tmp);
    int len = (int)strlen(tmp);
    while (len > 0 && (tmp[len - 1] == '\n' || tmp[len - 1] == '\r'))
        tmp[--len] = '\0';
    if (len == 0) return ret;

    portENTER_CRITICAL(&s_mux);
    uint32_t idx = s_seq % LOG_BUF_COUNT;
    s_buf[idx].seq = s_seq;
    memcpy(s_buf[idx].text, tmp, (size_t)len + 1);
    s_seq++;
    portEXIT_CRITICAL(&s_mux);

    return ret;
}

void log_buffer_init(void)
{
    esp_log_set_vprintf(log_vprintf_hook);
}

uint32_t log_buffer_next_seq(void)
{
    portENTER_CRITICAL(&s_mux);
    uint32_t seq = s_seq;
    portEXIT_CRITICAL(&s_mux);
    return seq;
}

bool log_buffer_get(uint32_t seq, char *text)
{
    uint32_t idx = seq % LOG_BUF_COUNT;
    uint32_t actual;

    portENTER_CRITICAL(&s_mux);
    actual = s_buf[idx].seq;
    memcpy(text, s_buf[idx].text, LOG_BUF_LEN);
    portEXIT_CRITICAL(&s_mux);

    /* Слот мог быть перезаписан более новой строкой, пока мы читали, или ещё не заполнен */
    return actual == seq && seq < log_buffer_next_seq();
}
