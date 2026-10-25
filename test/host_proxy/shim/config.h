#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define CONFIG_IPV4_STR_LEN 16
#define PROXY_MAX_RULES 3
typedef struct { uint16_t listen_port; char target_ip[CONFIG_IPV4_STR_LEN]; uint16_t target_port; } proxy_rule_t;
