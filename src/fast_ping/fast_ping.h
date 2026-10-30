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

#ifndef _FAST_PING_H_
#define _FAST_PING_H_

#define _GNU_SOURCE

#include "smartdns/fast_ping.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"
#include "smartdns/tlog.h"

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#define PING_MAX_EVENTS 128
#define PING_MAX_HOSTLEN 128
#define ICMP_PACKET_SIZE (1024 * 64)
#define ICMP_INPACKET_SIZE 1024
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16
#define SOCKET_PRIORITY (6)

#ifndef ICMP_FILTER
#define ICMP_FILTER 1
struct icmp_filter {
	uint32_t data;
};
#endif

struct ping_dns_head {
	unsigned short id;
	unsigned short flag;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short nrcount;
	char qd_name;
	unsigned short q_qtype;
	unsigned short q_qclass;
} __attribute__((packed));

typedef enum FAST_PING_TYPE {
	FAST_PING_ICMP = 1,
	FAST_PING_ICMP6 = 2,
	FAST_PING_TCP,
	FAST_PING_TCP_SYN,
	FAST_PING_UDP,
	FAST_PING_UDP6,
	FAST_PING_END,
} FAST_PING_TYPE;

struct fast_ping_packet_msg {
	struct timeval tv;
	unsigned int sid;
	unsigned int seq;
};

struct fast_ping_packet {
	union {
		struct icmp icmp;
		struct icmp6_hdr icmp6;
	};
	unsigned int ttl;
	struct fast_ping_packet_msg msg;
};

struct fast_ping_fake_ip {
	struct hlist_node node;
	atomic_t ref;
	PING_TYPE type;
	FAST_PING_TYPE ping_type;
	char host[PING_MAX_HOSTLEN];
	int ttl;
	float time;
	struct sockaddr_storage addr;
	int addr_len;
};

struct ping_host_struct {
	atomic_t ref;
	atomic_t notified;
	struct hlist_node addr_node;
	struct list_head action_list;
	FAST_PING_TYPE type;

	void *userptr;
	int error;
	fast_ping_result ping_callback;
	char host[PING_MAX_HOSTLEN];

	int fd;
	unsigned short seq;
	/* 出口绑定，仅在有配置时生效；so_mark < 0 且 ifname 为空表示不绑定 */
	struct ping_bind bind;
	int ttl;
	struct timeval last;
	int interval;
	int timeout;
	int count;
	int send;
	int run;
	unsigned short sid;
	unsigned short port;
	unsigned short tcp_local_port;
	unsigned short ss_family;
	union {
		struct sockaddr addr;
		struct sockaddr_in6 in6;
		struct sockaddr_in in;
	};
	socklen_t addr_len;
	struct fast_ping_packet packet;

	struct fast_ping_packet recv_packet_buffer;

	struct fast_ping_fake_ip *fake;
	int fake_time_fd;
};

/*
 * 按出口绑定的 ICMP / ICMP6 socket 池。
 *
 * 背景：ICMP 探测用的是 ping.fd_icmp 这一个【全局共享】socket，
 * 无法像 TCP 那样在 per-host socket 上 setsockopt(SO_MARK/SO_BINDTODEVICE)，
 * 所以双 WAN 下 ICMP 测速包永远走默认路由，测出来的延迟是错的。
 *
 * 解决：给每个不同的出口绑定组合单独开一个 ICMP socket。
 * 组合数等于物理出口数（双 WAN 就是 2），数量可控。
 *
 * 收包端不需要改：ICMP 应答是靠 payload 里的 sid 回表找 ping_host 的
 * （见 ping_icmp.c:_fast_ping_process_icmp），与从哪个 socket 收到无关。
 * 所以只要把池里的 socket 也注册进 epoll、data.ptr 指向池内嵌的 owner，
 * 接收逻辑自动生效。
 */
#define PING_BIND_MAX 8

struct ping_bind_sock {
	int fd;		  /* -1 表示槽位未使用 */
	int in_use;	  /* 槽位占用标记 */
	struct ping_bind bind;
	struct ping_host_struct host; /* epoll 的 owner，仅用于收包分发 */
};

struct fast_ping_notify_event {
	struct list_head list;
	struct ping_host_struct *ping_host;
	FAST_PING_RESULT ping_result;
	unsigned int seq;
	int ttl;
	struct timeval tvresult;
};

struct fast_ping_struct {
	atomic_t run;
	pthread_t tid;
	pthread_mutex_t lock;
	unsigned short ident;

	int epoll_fd;
	int no_unprivileged_ping;
	int fd_icmp;
	struct ping_host_struct icmp_host;
	int fd_icmp6;
	struct ping_host_struct icmp6_host;
	int fd_udp;
	struct ping_host_struct udp_host;
	int fd_udp6;
	struct ping_host_struct udp6_host;
	int fd_tcp_syn;
	struct ping_host_struct tcp_syn_host;
	int fd_tcp_syn6;
	struct ping_host_struct tcp_syn6_host;
	int fd_tcp_syn_bind;
	uint16_t tcp_syn_bind_port;
	struct sockaddr_in tcp_syn_bind_addr;
	int fd_tcp_syn6_bind;
	uint16_t tcp_syn6_bind_port;
	struct sockaddr_in6 tcp_syn6_bind_addr;

	/* 按出口绑定的 ICMP socket 池（见 struct ping_bind_sock 注释） */
	struct ping_bind_sock icmp_bind[PING_BIND_MAX];
	struct ping_bind_sock icmp6_bind[PING_BIND_MAX];

	int event_fd;
	pthread_t notify_tid;
	pthread_cond_t notify_cond;
	pthread_mutex_t notify_lock;
	struct list_head notify_event_list;

	pthread_mutex_t map_lock;
	DECLARE_HASHTABLE(addrmap, 6);
	DECLARE_HASHTABLE(fake, 6);
	int fake_ip_num;
};

extern struct fast_ping_struct ping;
extern int bool_print_log;

uint32_t _fast_ping_hash_key(unsigned int sid, struct sockaddr *addr);

/* 将 ping_host 的出口绑定应用到 socket，必须在 connect()/sendto() 之前调用 */
int fast_ping_bind_apply(int fd, const struct ping_bind *bind);

/* bind 里是否含有有效出口信息（mark 或 ifname 任一有效即算） */
int _fast_ping_bind_is_valid(const struct ping_bind *bind);

/*
 * 取「绑定到指定出口」的 ICMP / ICMP6 socket fd，没有就创建一个放进池。
 * 失败返回 -1，调用方应当按原逻辑报错，不要退化成无绑定 socket ——
 * 那样测出来的延迟属于错误出口，比失败更糟。
 */

int _fast_ping_icmp_bind_fd(FAST_PING_TYPE type, const struct ping_bind *bind);
	
struct addrinfo *_fast_ping_getaddr(const char *host, const char *port, int type, int protocol);

int _fast_ping_get_addr_by_type(PING_TYPE type, const char *ip_str, int port, struct addrinfo **out_gai,
								FAST_PING_TYPE *out_ping_type);

void tv_sub(struct timeval *out, struct timeval *in);

int _fast_ping_getdomain(const char *host);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif // !_FAST_PING_H_
