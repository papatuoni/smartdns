/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FAST_PING_H
#define FAST_PING_H

#include <net/if.h>
#include <netdb.h>
#include <sys/time.h>
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

typedef enum {
	PING_TYPE_ICMP = 1,
	PING_TYPE_TCP = 2,
	PING_TYPE_TCP_SYN = 3,
	PING_TYPE_DNS = 4,
} PING_TYPE;

/*
 * 探测包的出口绑定描述。
 *
 * so_mark < 0        : 不设置 SO_MARK
 * ifname[0] == '\0'  : 不设置 SO_BINDTODEVICE
 * 两者都不设置时（或整个结构为零）: 不调用任何 setsockopt，走默认路由，行为与改造前完全一致。
 */
struct ping_bind {
	int so_mark;
	char ifname[IFNAMSIZ];
};

typedef enum {
	PING_RESULT_RESPONSE = 1,
	PING_RESULT_TIMEOUT = 2,
	PING_RESULT_ERROR = 3,
	PING_RESULT_END = 4,
} FAST_PING_RESULT;

struct ping_host_struct;
typedef void (*fast_ping_result)(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
								 struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
								 int error, void *userptr);

/* start ping */
struct ping_host_struct *fast_ping_start(PING_TYPE type, const char *host, int count, int interval, int timeout,
										 fast_ping_result ping_callback, void *userptr);

/*
 * 带出口绑定的 ping。bind 为 NULL 时等价于 fast_ping_start()。
 * 目前绑定只对 FAST_PING_TCP（tcp:port 测速）生效；icmp / tcp-syn 仍走默认路由，
 * 原因是它们的 socket 是全局共享的，详见 fast_ping.c 注释。
 */
struct ping_host_struct *fast_ping_start_bind(PING_TYPE type, const char *host, int count, int interval, int timeout,
											  fast_ping_result ping_callback, void *userptr,
											  const struct ping_bind *bind);

int fast_ping_fake_ip_add(PING_TYPE type, const char *host, int ttl, float time);

int fast_ping_fake_ip_remove(PING_TYPE type, const char *host);

/* stop ping */
int fast_ping_stop(struct ping_host_struct *ping_host);

int fast_ping_init(void);

void fast_ping_exit(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */

#endif // !FAST_PING_H
