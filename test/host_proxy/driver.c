/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2026 Borman22 */

#include "proxy.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    proxy_rule_t r[PROXY_MAX_RULES]; memset(r, 0, sizeof(r));
    r[0].listen_port = 18080; strcpy(r[0].target_ip, "127.0.0.1"); r[0].target_port = 19000;
    proxy_start(r, argc > 1 ? argv[1] : "127.0.0.1");
    for (;;) { sleep(1); proxy_stats_t s; proxy_get_stats(&s);
        fprintf(stderr, "STATS active=%u total=%u rej=%u fail=%u\n", s.active_conns, s.total_conns, s.rejected_conns, s.failed_target); }
}
