/*************************************************************************
 * route_cache.c -- DNS cache driven, in-process direct-route table
 *
 * 纯源码实现，无守护进程 / 外部脚本 / 配置文件 / 自启项。
 *
 * 事件来源（dns_cache.c 的 remove hook 与 dns_server/cache.c 的写缓存挂点）：
 *   insert / replace -> on_insert   差集更新（新 IP 写 /32，消失的 IP 引用减一）
 *   insert / prefetch -> on_insert  差集更新（新 IP 写 /32，消失的 IP 引用减一）
 *   hit               -> on_hit     只刷新 TTL；pending 为空时零命令零扫描
 *   del               -> on_del     引用归零，O(1) 挂 pending 链，不扫表、不发命令
 *   exit              -> exit       清空全部 /32
 *
 * 不卡死的三条硬约束：
 *   1. 无线程、无定时器、无队列；一把 RECURSIVE trylock，拿不到就跳过事件
 *   2. 锁内只有纯内存哈希表操作 + sendmsg(MSG_DONTWAIT)；不等 ACK、不设超时
 *   3. on_del 在 dns_cache_head.lock 内被调用，必须保持 O(1)：
 *      dns_cache_flush() 会连续调 N 次，任何全表扫描或 netlink 都会把全局
 *      缓存锁拉长成可见停顿。/32 的实际删除推迟到缓存锁外的 on_insert/on_hit，
 *      且只遍历 pending 链，不再扫 1024 个桶。
 *
 * 出口归属：同一 IP 被多个域名引用时先到先得；但某域名自身更换出口仍允许
 * REPLACE（判据见 on_insert），不会被"先到"卡死。on_del 拿不到 g_lock 时不
 * 静默丢 DEL：置 g_force_default，由缓存锁外事件清空全部 /32 回落默认路由。
 *
 * 地址过滤：只滤 loopback / link-local / 组播 / 广播 / 198.18 fake-ip / ULA。
 * RFC1918 不滤——手动 address 指定的内网 IP 也应能走 -interface 出口。
 * cache-persist 恢复的条目不触发 on_insert，其 /32 不重建，属已知可接受行为。
 *************************************************************************/

#include "route_cache.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifdef ROUTE_CACHE_UNIT_TEST
char route_cache_test_log[ROUTE_CACHE_TEST_LOG_MAX][ROUTE_CACHE_TEST_CMD_LEN];
int route_cache_test_n = 0;
const char *route_cache_test_proc_route = "/proc/net/route";
#define PROC_NET_ROUTE_PATH route_cache_test_proc_route

void route_cache_test_reset(void)
{
	memset(route_cache_test_log, 0, sizeof(route_cache_test_log));
	route_cache_test_n = 0;
}
#else
#define PROC_NET_ROUTE_PATH "/proc/net/route"
#endif

#define DNS_ROUTE_DOMAIN_LEN 256
#define ROUTE_IP_BUCKETS 1024
#define ROUTE_OWNER_BUCKETS 1024
#define ROUTE_GW_CACHE_MAX 8
#define ROUTE_TRYLOCK_RETRY 3
#define ROUTE_DRAIN_MAX 32
#define ROUTE_SWEEP_BUCKETS 8
#define ROUTE_ORPHAN_KEEP 3600
#define ROUTE_MIN_TTL 60

struct route_ip {
	struct route_ip *hnext;
	struct route_ip *lru_prev;
	struct route_ip *lru_next;
	unsigned char ip[16];
	int family;
	char ifname[IFNAMSIZ];
	int oif;
	unsigned char gw[4];
	int has_gw;
	int in_kernel;
	int ref;
	time_t expire;
	unsigned long born_seq; /* 0 = not pending delete */
	struct route_ip *pending_prev;
	struct route_ip *pending_next;
};

struct route_owner {
	struct route_owner *hnext;
	struct route_owner *lru_prev;
	struct route_owner *lru_next;
	char group[64];
	char domain[DNS_ROUTE_DOMAIN_LEN];
	int qtype;
	uint32_t query_flag;
	int n;
	struct route_cache_addr addrs[ROUTE_CACHE_MAX_ADDR];
	time_t expire;
};

struct gw_ent {
	char ifname[IFNAMSIZ];
	unsigned char gw[4];
	int has_gw;
};

static pthread_mutex_t g_lock;
static int g_inited = 0;
#ifndef ROUTE_CACHE_UNIT_TEST
static int g_fd = -1;
#endif
static unsigned long g_seq = 0;
static unsigned int g_nl_seq = 0;
static unsigned int g_sweep_bucket = 0;

static struct route_ip *g_ip_bucket[ROUTE_IP_BUCKETS];
static struct route_owner *g_owner_bucket[ROUTE_OWNER_BUCKETS];
static struct route_ip *g_ip_lru_head;
static struct route_ip *g_ip_lru_tail;
static struct route_owner *g_owner_lru_head;
static struct route_owner *g_owner_lru_tail;
static int g_ip_num = 0;
static int g_owner_num = 0;
static struct gw_ent g_gw[ROUTE_GW_CACHE_MAX];
static int g_gw_num = 0;

/* pending delete 双向链表。_flush_pending 只遍历它，不再扫 1024 个桶。
 * 链上条目数就是待删条目数：计数与内容天然一致，不需要单独维护计数器，
 * 也就没有"计数归零但桶里仍有残留"这类并发不一致窗口。 */
static struct route_ip *g_pending_head;
static struct route_ip *g_pending_tail;

/* on_del 拿不到 g_lock 时置位；缓存锁外事件清空全部 /32 回落默认路由。 */
static volatile int g_force_default = 0;

/* ------------------------------------------------------------------ helpers */

static unsigned int _hash_bytes(const void *data, int len, unsigned int h)
{
	const unsigned char *p = data;
	int i;

	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= 16777619U;
	}
	return h;
}

static unsigned int _ip_hash(int family, const unsigned char *ip)
{
	int len = (family == AF_INET) ? 4 : 16;
	return _hash_bytes(ip, len, (unsigned int)family) & (ROUTE_IP_BUCKETS - 1);
}

static unsigned int _owner_hash(const char *group, const char *domain, int qtype, uint32_t flag)
{
	unsigned int h = 2166136261U;

	h = _hash_bytes(domain, (int)strlen(domain), h);
	h = _hash_bytes(group, (int)strlen(group), h);
	h = _hash_bytes(&qtype, sizeof(qtype), h);
	h = _hash_bytes(&flag, sizeof(flag), h);
	return h & (ROUTE_OWNER_BUCKETS - 1);
}

static void _str_copy(char *dst, size_t len, const char *src)
{
	if (len == 0) {
		return;
	}
	snprintf(dst, len, "%s", (src != NULL && src[0] != '\0') ? src : "-");
}

static struct route_ip *_ip_find(int family, const unsigned char *ip)
{
	struct route_ip *e;

	for (e = g_ip_bucket[_ip_hash(family, ip)]; e != NULL; e = e->hnext) {
		if (e->family == family && memcmp(e->ip, ip, (family == AF_INET) ? 4 : 16) == 0) {
			return e;
		}
	}
	return NULL;
}

static void _lru_ip_append(struct route_ip *e)
{
	e->lru_prev = g_ip_lru_tail;
	e->lru_next = NULL;
	if (g_ip_lru_tail != NULL) {
		g_ip_lru_tail->lru_next = e;
	} else {
		g_ip_lru_head = e;
	}
	g_ip_lru_tail = e;
}

static void _lru_ip_unlink(struct route_ip *e)
{
	if (e->lru_prev != NULL) {
		e->lru_prev->lru_next = e->lru_next;
	} else {
		g_ip_lru_head = e->lru_next;
	}
	if (e->lru_next != NULL) {
		e->lru_next->lru_prev = e->lru_prev;
	} else {
		g_ip_lru_tail = e->lru_prev;
	}
	e->lru_prev = NULL;
	e->lru_next = NULL;
}

static void _lru_ip_touch(struct route_ip *e)
{
	_lru_ip_unlink(e);
	_lru_ip_append(e);
}

static void _lru_owner_append(struct route_owner *o)
{
	o->lru_prev = g_owner_lru_tail;
	o->lru_next = NULL;
	if (g_owner_lru_tail != NULL) {
		g_owner_lru_tail->lru_next = o;
	} else {
		g_owner_lru_head = o;
	}
	g_owner_lru_tail = o;
}

static void _lru_owner_unlink(struct route_owner *o)
{
	if (o->lru_prev != NULL) {
		o->lru_prev->lru_next = o->lru_next;
	} else {
		g_owner_lru_head = o->lru_next;
	}
	if (o->lru_next != NULL) {
		o->lru_next->lru_prev = o->lru_prev;
	} else {
		g_owner_lru_tail = o->lru_prev;
	}
	o->lru_prev = NULL;
	o->lru_next = NULL;
}

static void _lru_owner_touch(struct route_owner *o)
{
	_lru_owner_unlink(o);
	_lru_owner_append(o);
}

static void _pending_link(struct route_ip *e)
{
	if (e == NULL || e->born_seq != 0) {
		return;
	}
	e->born_seq = g_seq;
	e->pending_prev = g_pending_tail;
	e->pending_next = NULL;
	if (g_pending_tail != NULL) {
		g_pending_tail->pending_next = e;
	} else {
		g_pending_head = e;
	}
	g_pending_tail = e;
}

/* 摘链同时清 born_seq。所有"取消待删 / 已删 / 释放前"路径都必须走这里，
 * 否则 g_pending_head/tail 会指向已 free 的内存。 */
static void _pending_unlink(struct route_ip *e)
{
	if (e == NULL || e->born_seq == 0) {
		return;
	}
	if (e->pending_prev != NULL) {
		e->pending_prev->pending_next = e->pending_next;
	} else if (g_pending_head == e) {
		g_pending_head = e->pending_next;
	}
	if (e->pending_next != NULL) {
		e->pending_next->pending_prev = e->pending_prev;
	} else if (g_pending_tail == e) {
		g_pending_tail = e->pending_prev;
	}
	e->pending_prev = NULL;
	e->pending_next = NULL;
	e->born_seq = 0;
}

static void _ip_free(struct route_ip *e)
{
	unsigned int b = _ip_hash(e->family, e->ip);
	struct route_ip **pp = &g_ip_bucket[b];

	while (*pp != NULL && *pp != e) {
		pp = &(*pp)->hnext;
	}
	if (*pp == e) {
		*pp = e->hnext;
	}
	_pending_unlink(e);
	_lru_ip_unlink(e);
	g_ip_num--;
	free(e);
}

static void _owner_free(struct route_owner *o)
{
	unsigned int b = _owner_hash(o->group, o->domain, o->qtype, o->query_flag);
	struct route_owner **pp = &g_owner_bucket[b];

	while (*pp != NULL && *pp != o) {
		pp = &(*pp)->hnext;
	}
	if (*pp == o) {
		*pp = o->hnext;
	}
	_lru_owner_unlink(o);
	g_owner_num--;
	free(o);
}

/* ------------------------------------------------------------- gateway probe */
/* /proc/net/route 纯文件读取，无 netlink 查询、无阻塞风险。
 * Gateway 列是 __be32 的十六进制打印（小端目标下值即字节反转），
 * memcpy 回 4 字节即为网络序。找不到或非 0.0.0.0 都不加 via。 */

static void _gw_lookup(const char *ifname, unsigned char gw[4], int *has_gw)
{
	char line[256];
	char iface[32];
	char dst[32];
	char gwhex[32];
	FILE *f;
	int i;

	memset(gw, 0, 4);
	*has_gw = 0;

	for (i = 0; i < g_gw_num; i++) {
		if (strncmp(g_gw[i].ifname, ifname, IFNAMSIZ) == 0) {
			memcpy(gw, g_gw[i].gw, 4);
			*has_gw = g_gw[i].has_gw;
			return;
		}
	}

	f = fopen(PROC_NET_ROUTE_PATH, "r");
	if (f == NULL) {
		return;
	}
	if (fgets(line, sizeof(line), f) == NULL) { /* header */
		fclose(f);
		return;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long v;
		if (sscanf(line, "%31s %31s %31s", iface, dst, gwhex) != 3) {
			continue;
		}
		if (strcmp(dst, "00000000") != 0 || strcmp(iface, ifname) != 0) {
			continue;
		}
		v = strtoul(gwhex, NULL, 16);
		if (v != 0) {
			memcpy(gw, &v, 4);
			*has_gw = 1;
		}
		break;
	}
	fclose(f);

	if (g_gw_num < ROUTE_GW_CACHE_MAX) {
		_str_copy(g_gw[g_gw_num].ifname, sizeof(g_gw[g_gw_num].ifname), ifname);
		memcpy(g_gw[g_gw_num].gw, gw, 4);
		g_gw[g_gw_num].has_gw = *has_gw;
		g_gw_num++;
	}
}

/* ------------------------------------------------------------- netlink write */

static void _drain_ack(void)
{
#ifdef ROUTE_CACHE_UNIT_TEST
	return;
#else
	char buf[1024];
	struct sockaddr_nl sa;
	struct iovec iov;
	struct msghdr msg;
	int i;

	if (g_fd < 0) {
		return;
	}
	for (i = 0; i < ROUTE_DRAIN_MAX; i++) {
		memset(&sa, 0, sizeof(sa));
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		msg.msg_name = &sa;
		msg.msg_namelen = sizeof(sa);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		if (recvmsg(g_fd, &msg, MSG_DONTWAIT) <= 0) {
			break;
		}
	}
#endif
}

#ifndef ROUTE_CACHE_UNIT_TEST
static void _add_attr(struct nlmsghdr *nlh, int type, const void *data, int alen)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(alen);
	memcpy(RTA_DATA(rta), data, alen);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}
#endif

/* 单条 RTM_NEWROUTE(REPLACE) / RTM_DELROUTE，send 即忘，不等 ACK */
static void _kern_cmd(struct route_ip *e, int is_del)
{
#ifdef ROUTE_CACHE_UNIT_TEST
	char ipstr[INET6_ADDRSTRLEN];
	char gwstr[INET_ADDRSTRLEN + 8];
	char gwbuf[INET_ADDRSTRLEN];

	if (route_cache_test_n >= ROUTE_CACHE_TEST_LOG_MAX) {
		return;
	}
	inet_ntop(e->family, e->ip, ipstr, sizeof(ipstr));
	if (is_del) {
		snprintf(route_cache_test_log[route_cache_test_n], ROUTE_CACHE_TEST_CMD_LEN, "DEL %s", ipstr);
	} else {
		gwstr[0] = '\0';
		if (e->has_gw) {
			inet_ntop(AF_INET, e->gw, gwbuf, sizeof(gwbuf));
			snprintf(gwstr, sizeof(gwstr), " via %s", gwbuf);
		}
		snprintf(route_cache_test_log[route_cache_test_n], ROUTE_CACHE_TEST_CMD_LEN, "ADD %s dev %s%s", ipstr,
				 e->ifname, gwstr);
	}
	route_cache_test_n++;
	return;
#else
	char buf[512];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	struct sockaddr_nl sa;
	struct iovec iov;
	struct msghdr msg;
	int addr_len = (e->family == AF_INET) ? 4 : 16;

	if (g_fd < 0) {
		return;
	}

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlh->nlmsg_type = is_del ? RTM_DELROUTE : RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	if (!is_del) {
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	}
	nlh->nlmsg_seq = ++g_nl_seq;
	nlh->nlmsg_pid = 0;

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family = (e->family == AF_INET) ? AF_INET : AF_INET6;
	rtm->rtm_dst_len = (e->family == AF_INET) ? 32 : 128;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;

	_add_attr(nlh, RTA_DST, e->ip, addr_len);
	if (!is_del) {
		if (e->oif > 0) {
			_add_attr(nlh, RTA_OIF, &e->oif, sizeof(e->oif));
		}
		if (e->has_gw && e->family == AF_INET) {
			_add_attr(nlh, RTA_GATEWAY, e->gw, 4);
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buf;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	(void)sendmsg(g_fd, &msg, MSG_DONTWAIT);
#endif
}

/* -------------------------------------------------------------- addr filter */

int route_cache_addr_ignored(const unsigned char *ip, int family)
{
	const unsigned char *a = ip;
	int i;

	if (a == NULL) {
		return 1;
	}
	if (family == AF_INET) {
		/* RFC1918 故意不滤：address /domain/10.x 手动指定的内网 IP 也要能
		 * 走 -interface 出口。上游正常不会返回内网地址；真出现就按出口写 /32。 */
		if (a[0] == 0 || a[0] == 127) {
			return 1;
		}
		if (a[0] == 169 && a[1] == 254) {
			return 1;
		}
		if ((a[0] & 0xF0) == 0xE0) {
			return 1;
		}
		if (a[0] == 198 && (a[1] == 18 || a[1] == 19)) {
			return 1; /* RFC2544, clash fake-ip 198.18.0.0/15 */
		}
		if (a[0] == 255 && a[1] == 255 && a[2] == 255 && a[3] == 255) {
			return 1;
		}
		if ((a[0] & 0xF0) == 0xF0) {
			return 1;
		}
		return 0;
	}
	if (family == AF_INET6) {
		int all_zero = 1;
		for (i = 0; i < 16; i++) {
			if (a[i] != 0) {
				all_zero = 0;
				break;
			}
		}
		if (all_zero) {
			return 1;
		}
		if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) {
			return 1;
		}
		if ((a[0] & 0xFE) == 0xFC) {
			return 1;
		}
		if (a[0] == 0xFF) {
			return 1;
		}
		for (i = 0; i < 15; i++) {
			if (a[i] != 0) {
				return 0;
			}
		}
		if (a[15] == 1) {
			return 1; /* ::1 */
		}
		return 0;
	}
	return 1;
}

static int _normalize(const struct route_cache_addr *in, int n, struct route_cache_addr *out)
{
	int i;
	int j;
	int cnt = 0;

	for (i = 0; i < n && cnt < ROUTE_CACHE_MAX_ADDR; i++) {
		int ip_len;
		if (in[i].family != AF_INET && in[i].family != AF_INET6) {
			continue;
		}
		if (in[i].ifname[0] == '\0') {
			continue; /* 默认出口：不写 /32 */
		}
		if (route_cache_addr_ignored(in[i].ip, in[i].family)) {
			continue;
		}
		ip_len = (in[i].family == AF_INET) ? 4 : 16;
		for (j = 0; j < cnt; j++) {
			if (out[j].family == in[i].family && memcmp(out[j].ip, in[i].ip, ip_len) == 0) {
				break;
			}
		}
		if (j < cnt) {
			continue;
		}
		memcpy(&out[cnt], &in[i], sizeof(out[cnt]));
		cnt++;
	}
	return cnt;
}

static struct route_cache_addr *_find_addr(struct route_cache_addr *set, int n, int family, const unsigned char *ip)
{
	int i;
	int ip_len = (family == AF_INET) ? 4 : 16;

	for (i = 0; i < n; i++) {
		if (set[i].family == family && memcmp(set[i].ip, ip, ip_len) == 0) {
			return &set[i];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------ state helpers */

static struct route_owner *_owner_find(const struct route_cache_key *key)
{
	struct route_owner *o;
	unsigned int b = _owner_hash(key->group ? key->group : "-", key->domain ? key->domain : "-", key->qtype,
								 key->query_flag);

	for (o = g_owner_bucket[b]; o != NULL; o = o->hnext) {
		if (o->qtype != key->qtype || o->query_flag != key->query_flag) {
			continue;
		}
		if (strncmp(o->domain, key->domain ? key->domain : "-", sizeof(o->domain)) != 0) {
			continue;
		}
		if (strncmp(o->group, key->group ? key->group : "-", sizeof(o->group)) != 0) {
			continue;
		}
		return o;
	}
	return NULL;
}

static struct route_owner *_owner_new(const struct route_cache_key *key)
{
	struct route_owner *o = (struct route_owner *)calloc(1, sizeof(*o));
	unsigned int b;

	if (o == NULL) {
		return NULL;
	}
	_str_copy(o->group, sizeof(o->group), key->group);
	_str_copy(o->domain, sizeof(o->domain), key->domain);
	o->qtype = key->qtype;
	o->query_flag = key->query_flag;
	b = _owner_hash(o->group, o->domain, o->qtype, o->query_flag);
	o->hnext = g_owner_bucket[b];
	g_owner_bucket[b] = o;
	_lru_owner_append(o);
	g_owner_num++;
	return o;
}

static struct route_ip *_ip_get(int family, const unsigned char *ip, const char *ifname)
{
	struct route_ip *e = _ip_find(family, ip);
	unsigned int b;

	if (e != NULL) {
		return e;
	}
	if (g_ip_num >= ROUTE_CACHE_MAX_IP) {
		struct route_ip *victim = g_ip_lru_head;
		/* 淘汰仍被域名引用的条目会让 owner->addrs 悬空、内核 /32 却被删。
		 * 找不到可淘汰项就跳过本次路由（回落默认），比破坏引用表安全。 */
		while (victim != NULL && victim->ref > 0) {
			victim = victim->lru_next;
		}
		if (victim == NULL) {
			return NULL;
		}
		if (victim->in_kernel) {
			_kern_cmd(victim, 1);
		}
		_ip_free(victim);
	}
	e = (struct route_ip *)calloc(1, sizeof(*e));
	if (e == NULL) {
		return NULL;
	}
	e->family = family;
	memcpy(e->ip, ip, (family == AF_INET) ? 4 : 16);
	_str_copy(e->ifname, sizeof(e->ifname), ifname);
	e->oif = (int)if_nametoindex(ifname);
	_gw_lookup(ifname, e->gw, &e->has_gw);
	b = _ip_hash(family, ip);
	e->hnext = g_ip_bucket[b];
	g_ip_bucket[b] = e;
	_lru_ip_append(e);
	g_ip_num++;
	return e;
}

static void _apply_ifname(struct route_ip *e, const char *ifname)
{
	_str_copy(e->ifname, sizeof(e->ifname), ifname);
	e->oif = (int)if_nametoindex(ifname);
	_gw_lookup(ifname, e->gw, &e->has_gw);
}

static void _ip_unref(struct route_ip *e)
{
	if (e == NULL || e->ref <= 0) {
		return;
	}
	e->ref--;
	if (e->ref == 0) {
		/* 延迟一个事件再删，抵消 dns_cache_insert() 同 key 覆盖的 DEL->SET 抖动。
		 * 只挂 pending 链：on_del 在 dns_cache_head.lock 内，必须保持 O(1)。 */
		_pending_link(e);
	}
}

static void _flush_pending(void)
{
	struct route_ip *e = g_pending_head;

	/* O(pending)，不再是 O(1024 桶)。pending 为空时连循环体都不进。 */
	while (e != NULL) {
		struct route_ip *next = e->pending_next;
		if (e->ref > 0) {
			_pending_unlink(e); /* 已被新 insert 复活，无需删除 */
		} else if (e->born_seq < g_seq && e->in_kernel) {
			_kern_cmd(e, 1);
			e->in_kernel = 0;
			_pending_unlink(e);
		}
		e = next;
	}
}

/* 只在缓存锁外的 on_insert / on_hit 调用，极端情况下才发生一次。
 * 清空全部 /32 让流量回落默认路由，避免拿不到锁的那次 DEL 把流量
 * 一直导向一个已经不该用的指定出口。 */
static void _drain_force_default(void)
{
	int b;

	if (__atomic_exchange_n(&g_force_default, 0, __ATOMIC_ACQ_REL) == 0) {
		return;
	}
	for (b = 0; b < ROUTE_IP_BUCKETS; b++) {
		struct route_ip *e;
		for (e = g_ip_bucket[b]; e != NULL; e = e->hnext) {
			if (e->in_kernel) {
				_kern_cmd(e, 1);
				e->in_kernel = 0;
			}
			_pending_unlink(e);
		}
	}
}

static void _sweep(time_t now)
{
	int k;

	for (k = 0; k < ROUTE_SWEEP_BUCKETS; k++) {
		int b = (int)((g_sweep_bucket + (unsigned int)k) % ROUTE_IP_BUCKETS);
		struct route_ip *e = g_ip_bucket[b];
		while (e != NULL) {
			struct route_ip *next = e->hnext;
			if (e->ref == 0 && e->in_kernel && e->expire <= now) {
				_kern_cmd(e, 1);
				e->in_kernel = 0;
				_pending_unlink(e);
			}
			if (e->ref == 0 && !e->in_kernel && e->expire + ROUTE_ORPHAN_KEEP <= now) {
				_ip_free(e);
			}
			e = next;
		}
	}
	g_sweep_bucket = (g_sweep_bucket + ROUTE_SWEEP_BUCKETS) % ROUTE_IP_BUCKETS;
}

static void _enforce_limits(void)
{
	while (g_owner_num > ROUTE_CACHE_MAX_OWNER) {
		struct route_owner *o = g_owner_lru_head;
		int i;
		if (o == NULL) {
			break;
		}
		for (i = 0; i < o->n; i++) {
			struct route_ip *e = _ip_find(o->addrs[i].family, o->addrs[i].ip);
			if (e != NULL) {
				_ip_unref(e);
				if (e->ref == 0 && e->in_kernel) {
					_kern_cmd(e, 1);
					e->in_kernel = 0;
					_pending_unlink(e);
				}
			}
		}
		_owner_free(o);
	}
	while (g_ip_num > ROUTE_CACHE_MAX_IP) {
		struct route_ip *e = g_ip_lru_head;
		while (e != NULL && e->ref > 0) {
			e = e->lru_next;
		}
		if (e == NULL) {
			break; /* 全部仍被引用，不破坏 owner->addrs，也不死循环 */
		}
		if (e->in_kernel) {
			_kern_cmd(e, 1);
		}
		_ip_free(e);
	}
}

static int _trylock(void)
{
	int i;

	if (g_inited == 0) {
		return 0;
	}
	for (i = 0; i < ROUTE_TRYLOCK_RETRY; i++) {
		if (pthread_mutex_trylock(&g_lock) == 0) {
			return 1;
		}
	}
	return 0; /* 绝不无限等待 */
}

/* ----------------------------------------------------------------- lifecycle */

int route_cache_init(void)
{
	pthread_mutexattr_t attr;

	if (g_inited != 0) {
		return 0;
	}
	memset(g_ip_bucket, 0, sizeof(g_ip_bucket));
	memset(g_owner_bucket, 0, sizeof(g_owner_bucket));
	g_ip_lru_head = g_ip_lru_tail = NULL;
	g_owner_lru_head = g_owner_lru_tail = NULL;
	g_ip_num = g_owner_num = 0;
	g_pending_head = g_pending_tail = NULL;
	g_force_default = 0;
	g_gw_num = 0;
	g_seq = 0;
	g_nl_seq = 0;
	g_sweep_bucket = 0;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&g_lock, &attr);
	pthread_mutexattr_destroy(&attr);

#ifndef ROUTE_CACHE_UNIT_TEST
	g_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (g_fd >= 0) {
		int fl = fcntl(g_fd, F_GETFL, 0);
		fcntl(g_fd, F_SETFL, fl | O_NONBLOCK);
	}
#endif
	g_inited = 1;
	return 0;
}

void route_cache_exit(void)
{
	int b;

	if (g_inited == 0) {
		return;
	}
	pthread_mutex_lock(&g_lock); /* 退出流程，工作线程已停 */
	for (b = 0; b < ROUTE_IP_BUCKETS; b++) {
		struct route_ip *e = g_ip_bucket[b];
		while (e != NULL) {
			struct route_ip *next = e->hnext;
			if (e->in_kernel) {
				_kern_cmd(e, 1);
			}
			free(e);
			e = next;
		}
		g_ip_bucket[b] = NULL;
	}
	for (b = 0; b < ROUTE_OWNER_BUCKETS; b++) {
		struct route_owner *o = g_owner_bucket[b];
		while (o != NULL) {
			struct route_owner *next = o->hnext;
			free(o);
			o = next;
		}
		g_owner_bucket[b] = NULL;
	}
	g_ip_lru_head = g_ip_lru_tail = NULL;
	g_owner_lru_head = g_owner_lru_tail = NULL;
	g_pending_head = g_pending_tail = NULL;
	g_ip_num = g_owner_num = 0;
	g_force_default = 0;
#ifndef ROUTE_CACHE_UNIT_TEST
	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}
#endif
	g_inited = 0;
	pthread_mutex_unlock(&g_lock);
	pthread_mutex_destroy(&g_lock);
}

void route_cache_on_insert(const struct route_cache_key *key, const struct route_cache_addr *addrs, int addr_num,
						   int ttl)
{
	struct route_cache_addr nv[ROUTE_CACHE_MAX_ADDR];
	struct route_cache_addr old[ROUTE_CACHE_MAX_ADDR];
	struct route_owner *o;
	time_t now;
	time_t expire;
	int nn;
	int on = 0;
	int i;

	if (key == NULL || addrs == NULL || addr_num <= 0) {
		return;
	}
	/* _normalize() 只填 nv[0..nn-1]，下面 memcpy 会把整块写进 owner->addrs。
	 * 清零，避免把未初始化栈字节存进长期存活的 owner。 */
	memset(nv, 0, sizeof(nv));
	memset(old, 0, sizeof(old));
	nn = _normalize(addrs, addr_num, nv);
	if (nn == 0) {
		/* 全被过滤/默认出口：仍要处理旧集合的清理 */
	}
	if (_trylock() == 0) {
		return;
	}
	g_seq++;
	_drain_ack();
	_drain_force_default();
	now = time(NULL);
	expire = now + ((ttl > 0) ? ttl : ROUTE_MIN_TTL);

	_enforce_limits();
	o = _owner_find(key);
	if (o != NULL) {
		on = o->n;
		memcpy(old, o->addrs, sizeof(o->addrs));
	}

	for (i = 0; i < nn; i++) {
		struct route_ip *e = _ip_get(nv[i].family, nv[i].ip, nv[i].ifname);
		struct route_cache_addr *m;
		int was_first;
		int may_replace;
		if (e == NULL) {
			continue;
		}
		was_first = (e->ref == 0);
		_pending_unlink(e); /* 复活上轮 DEL 的 pending 条目 */
		m = _find_addr(old, on, nv[i].family, nv[i].ip);
		if (m == NULL || was_first) {
			e->ref++;
		}
		if (expire > e->expire) {
			e->expire = expire;
		}
		_lru_ip_touch(e);
		/* 先来先得：e->ref>1 说明已有别的域名引用同一 IP，保留首个出口。
		 * 例外（不能吞掉 owner 自身的出口迁移）：
		 *   - was_first：引用从 0 复活 / 孤儿重新被引用，没有活跃 owner；
		 *   - m != NULL && e->ref <= 1：当前 owner 是唯一引用且它换了出口。
		 * 出口没变时一律不发命令，DEL->SET 抖动抵消保持零命令。 */
		may_replace = was_first || (m != NULL && e->ref <= 1);
		if (!e->in_kernel) {
			_apply_ifname(e, nv[i].ifname);
			_kern_cmd(e, 0);
			e->in_kernel = 1;
		} else if (may_replace && strncmp(e->ifname, nv[i].ifname, IFNAMSIZ) != 0) {
			_apply_ifname(e, nv[i].ifname);
			_kern_cmd(e, 0);
		}
	}

	for (i = 0; i < on; i++) {
		struct route_ip *e;
		if (_find_addr(nv, nn, old[i].family, old[i].ip) != NULL) {
			continue;
		}
		e = _ip_find(old[i].family, old[i].ip);
		_ip_unref(e);
	}

	if (o == NULL) {
		o = _owner_new(key);
	}
	if (o != NULL) {
		o->n = nn;
		memcpy(o->addrs, nv, sizeof(o->addrs));
		o->expire = expire;
		_lru_owner_touch(o);
	}

	_flush_pending(); /* 只走 pending 链，删上一事件遗留且未被复活的 */
	_sweep(now);
	pthread_mutex_unlock(&g_lock);
}

void route_cache_on_hit(const struct route_cache_key *key, int ttl)
{
	struct route_owner *o;
	time_t now;
	time_t expire;
	int i;

	if (key == NULL || _trylock() == 0) {
		return;
	}
	g_seq++;
	_drain_force_default();
	now = time(NULL);
	expire = now + ((ttl > 0) ? ttl : ROUTE_MIN_TTL);
	o = _owner_find(key);
	if (o != NULL) {
		o->expire = expire;
		_lru_owner_touch(o);
		for (i = 0; i < o->n; i++) {
			struct route_ip *e = _ip_find(o->addrs[i].family, o->addrs[i].ip);
			if (e != NULL && expire > e->expire) {
				e->expire = expire;
			}
		}
	}
	/* 命中零命令、零扫描：pending 链为空时连 _flush_pending 都不调。
	 * 只有前面确实发生过 DEL 才补一次删除，避免 /32 残留。 */
	if (g_pending_head != NULL) {
		_flush_pending();
	}
	pthread_mutex_unlock(&g_lock);
}

void route_cache_on_del(const struct route_cache_key *key)
{
	struct route_owner *o;
	int i;

	if (key == NULL) {
		return;
	}
	if (_trylock() == 0) {
		/* 绝不无限等待，但也不静默丢 DEL：置降级标志，由缓存锁外的
		 * on_insert / on_hit 清空全部 /32，让流量回落默认路由。 */
		__atomic_store_n(&g_force_default, 1, __ATOMIC_RELEASE);
		return;
	}
	g_seq++;
	o = _owner_find(key);
	if (o != NULL) {
		for (i = 0; i < o->n; i++) {
			_ip_unref(_ip_find(o->addrs[i].family, o->addrs[i].ip));
		}
		_owner_free(o);
	}
	/* 故意不 _flush_pending / 不 _sweep：本函数运行在 dns_cache_head.lock 内，
	 * dns_cache_flush() 会连续调用 N 次，任何全表扫描或 netlink 都会把全局
	 * 缓存锁拉长成一次可见停顿。/32 删除推迟到缓存锁外的 on_insert/on_hit。 */
	pthread_mutex_unlock(&g_lock);
}

#ifdef ROUTE_CACHE_UNIT_TEST
int route_cache_test_ip_num(void)
{
	return g_ip_num;
}

int route_cache_test_owner_num(void)
{
	return g_owner_num;
}

int route_cache_test_pending_num(void)
{
	int n = 0;
	struct route_ip *e;
	for (e = g_pending_head; e != NULL; e = e->pending_next) {
		n++;
	}
	return n;
}

/* owner->addrs 尾部（n 之后）的非零字节数。配合
 * -ftrivial-auto-var-init=pattern 编译可验证 on_insert 的 memset 修复。 */
int route_cache_test_owner_tail(void)
{
	int b;
	int i;
	int dirty = 0;
	for (b = 0; b < ROUTE_OWNER_BUCKETS; b++) {
		struct route_owner *o;
		for (o = g_owner_bucket[b]; o != NULL; o = o->hnext) {
			for (i = o->n; i < ROUTE_CACHE_MAX_ADDR; i++) {
				unsigned char *p = (unsigned char *)&o->addrs[i];
				int j;
				for (j = 0; j < (int)sizeof(o->addrs[i]); j++) {
					if (p[j] != 0) {
						dirty++;
					}
				}
			}
		}
	}
	return dirty;
}
#endif
