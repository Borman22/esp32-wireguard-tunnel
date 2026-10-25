#pragma once
#include "FreeRTOS.h"
static inline void vTaskDelay(int ms) { usleep(ms * 1000); }
typedef void (*TaskFunction_t)(void *);

/* Задача FreeRTOS → обычный поток; для теста прокси этого достаточно */
struct shim_task { TaskFunction_t f; void *a; };
static void *shim_task_main(void *p) {
    struct shim_task t = *(struct shim_task *)p;
    free(p);
    t.f(t.a);
    return 0;
}
static inline int xTaskCreate(TaskFunction_t f, const char *n, int st, void *a, int p, void *h) {
    struct shim_task *t = malloc(sizeof(*t));
    t->f = f; t->a = a;
    pthread_t th;
    pthread_create(&th, 0, shim_task_main, t);
    pthread_detach(th);
    return 1;
}
