/*************************************************************************
 *
 * route_mgr.c -- 双 WAN 主机路由管理（内置于 smartdns）
 *
 * 为什么做在源码里：
 *   测速完成那一刻就知道「这个 IP 该走哪条路」，直接在应答路径上下发，
 *   零轮询延迟，也不依赖外部守护进程。
 *
 * 五条实测依据（都是踩过的坑）：
 *   1. 内核对路由是集合语义。重复 add 完全相同的一条返回 EEXIST，不会堆积；
 *      但 (table,dst/前缀,tos,metric) 才是主键 —— metric 不同就会共存，
 *      所以下发时绝不指定 metric。
 *   2. NLM_F_CREATE|NLM_F_REPLACE 是原子的，选路变化时用它迁移，
 *      不产生「先删后加」的空窗，正在传输的连接不会断。
 *   3. 接口 down 时内核会静默删除所有依赖它的路由，up 后不自动恢复。
 *      PPPoE 每次重拨都触发一次，所以必须订阅 RTMGRP_LINK。
 *   4. ifindex 在接口删除重建后会变（down/up 不变），所以每次下发前
 *      用 if_nametoindex() 重查。
 *   5. RTM_GETROUTE dump 需要循环 recv 到 NLMSG_DONE，3000 条约 8 次 recv。
 *
 * 回收用两级判据（避免 conntrack 扫描太频繁）：
 *   一级：DNS 侧空闲时长 —— 内部表 O(1) 查询，免费
 *   二级：只有空闲超阈值的候选，才去查 conntrack（昂贵）
 *
 *************************************************************************/

#include "smartdns/route_mgr.h"
#include "smartdns/tlog.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ROUTE_MGR_HASH_SIZE 4096
#define ROUTE_MGR_MAX_ROUTES 5000

/* 多久没有被解析引用，才进入二级判据（秒） */
#define ROUTE_MGR_DNS_IDLE_SEC 300
/* 连续多少轮既无 DNS 引用又无连接，才真正删除 */
#define ROUTE_MGR_GC_IDLE_ROUNDS 3
/* 路由标记：只认自己加的，不碰 netifd / kernel 的 */
#define ROUTE_MGR_PROTO RTPROT_BOOT

struct route_entry {
	struct route_entry *next;
	struct in_addr addr; /* 网络序 */
	int egress_idx;
	unsigned int ifindex;
	unsigned long last_dns_ref; /* 秒，最近一次被解析引用 */
	int idle_rounds;
	int kernel_present; /* 最近一次 dump 里是否真的还在 */
};

struct route_mgr {
	int epoll_fd;
	int fd_cmd;   /* 阻塞（带超时）：dump / add / del */
	int fd_event; /* 非阻塞 + 组播：事件 */
	unsigned int seq;

	struct route_egress egress[ROUTE_MGR_MAX_EGRESS];
	int egress_num;

	struct route_entry *hash[ROUTE_MGR_HASH_SIZE];
	int route_num;

	int gc_rounds;
	int test_no_conntrack;
	int enabled;
};

static struct route_mgr g_mgr;

static unsigned long now_sec(void)
{
	return (unsigned long)time(NULL);
}

/* ---------------------------------------------------------------- 工具 */

static unsigned int hash_addr(const struct in_addr *a)
{
	unsigned int h = a->s_addr;
	h ^= h >> 16;
	h *= 0x7feb352dU;
	h ^= h >> 15;
	return h & (ROUTE_MGR_HASH_SIZE - 1);
}

static struct route_entry *entry_find(const struct in_addr *a)
{
	struct route_entry *e = g_mgr.hash[hash_addr(a)];
	for (; e; e = e->next) {
		if (e->addr.s_addr == a->s_addr) {
			return e;
		}
	}
	return NULL;
}

static void entry_insert(struct route_entry *e)
{
	unsigned int h = hash_addr(&e->addr);
	e->next = g_mgr.hash[h];
	g_mgr.hash[h] = e;
	g_mgr.route_num++;
}

static void entry_remove(struct route_entry *e)
{
	unsigned int h = hash_addr(&e->addr);
	struct route_entry **pp = &g_mgr.hash[h];
	while (*pp) {
		if (*pp == e) {
			*pp = e->next;
			g_mgr.route_num--;
			return;
		}
		pp = &(*pp)->next;
	}
}

/* -------------------------------------------------------- netlink 收发 */

static void nl_add_attr(struct nlmsghdr *nlh, int maxlen, int type, const void *data, int len)
{
	struct rtattr *rta;
	int attrlen = RTA_LENGTH(len);

	if (NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(attrlen) > (unsigned int)maxlen) {
		return;
	}

	rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = attrlen;
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(attrlen);
}

static int nl_open_cmd(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	struct timeval tv;

	if (fd < 0) {
		return -1;
	}

	/* dump 要循环 recv，必须有超时兜底 */
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

/* ------------------------------------------------------- 下发 / 删除 */

static int route_nl_set(struct route_entry *e, int del)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char buf[512];
	} req;
	struct route_egress *eg;
	unsigned int oif;
	char ipstr[INET_ADDRSTRLEN];

	if (e->egress_idx < 0 || e->egress_idx >= g_mgr.egress_num) {
		return -1;
	}
	eg = &g_mgr.egress[e->egress_idx];

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_type = del ? RTM_DELROUTE : RTM_NEWROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (!del) {
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	}
	req.nlh.nlmsg_seq = ++g_mgr.seq;

	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_dst_len = 32; /* 只管主机路由 */
	req.rtm.rtm_table = RT_TABLE_MAIN;
	req.rtm.rtm_protocol = ROUTE_MGR_PROTO;
	req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rtm.rtm_type = RTN_UNICAST;

	nl_add_attr(&req.nlh, sizeof(req), RTA_DST, &e->addr, 4);

	if (!del) {
		/* ifindex 会变，每次重查 */
		oif = if_nametoindex(eg->dev);
		if (oif == 0) {
			tlog(TLOG_DEBUG, "route: dev %s not present, skip", eg->dev);
			return -1;
		}
		eg->ifindex = oif;
		e->ifindex = oif;

		if (eg->has_gw) {
			nl_add_attr(&req.nlh, sizeof(req), RTA_GATEWAY, &eg->gw, 4);
		}
		nl_add_attr(&req.nlh, sizeof(req), RTA_OIF, &oif, 4);
	}

	if (send(g_mgr.fd_cmd, &req, req.nlh.nlmsg_len, 0) < 0) {
		return -1;
	}

	/* 读掉 ACK / 错误，否则会淤积在 socket 上 */
	{
		char buf[1024];
		ssize_t len;
		while ((len = recv(g_mgr.fd_cmd, buf, sizeof(buf), 0)) > 0) {
			struct nlmsghdr *nh = (struct nlmsghdr *)buf;
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(nh);
				if (err->error != 0) {
					return -1;
				}
			}
			if (nh->nlmsg_type == NLMSG_DONE) {
				break;
			}
		}
	}

	if (inet_ntop(AF_INET, &e->addr, ipstr, sizeof(ipstr)) == NULL) {
		ipstr[0] = '\0';
	}
	tlog(TLOG_DEBUG, "route: %s %s -> %s", del ? "del" : "set", ipstr, eg->dev);

	return 0;
}

/* ------------------------------------------------------------ dump 解析 */

/*
 * 只认领：(family=AF_INET) && (table=main) && (dst_len=32)
 *          && (protocol=BOOT) && (oif 属于已登记出口)
 * 否则绝不碰 —— netifd 的默认路由是 proto=static/kernel 且 dst_len=0。
 */
static int parse_route_msg(struct nlmsghdr *nh, struct in_addr *out_addr, unsigned int *out_oif)
{
	struct rtmsg *rtm = NLMSG_DATA(nh);
	struct rtattr *rta;
	int attrlen;
	unsigned int oif = 0;
	int has_dst = 0;
	struct in_addr addr;
	int i;

	if (rtm->rtm_family != AF_INET) {
		return -1;
	}
	if (rtm->rtm_table != RT_TABLE_MAIN) {
		return -1;
	}
	if (rtm->rtm_dst_len != 32) {
		return -1;
	}
	if (rtm->rtm_protocol != ROUTE_MGR_PROTO) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	attrlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	rta = (struct rtattr *)((char *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg)));

	for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == RTA_DST && RTA_PAYLOAD(rta) >= 4) {
			memcpy(&addr, RTA_DATA(rta), 4);
			has_dst = 1;
		} else if (rta->rta_type == RTA_OIF && RTA_PAYLOAD(rta) >= 4) {
			memcpy(&oif, RTA_DATA(rta), 4);
		}
	}

	if (!has_dst || oif == 0) {
		return -1;
	}

	/* 出口必须是自己登记过的，避免误伤 */
	for (i = 0; i < g_mgr.egress_num; i++) {
		if (g_mgr.egress[i].ifindex == oif) {
			*out_addr = addr;
			*out_oif = oif;
			return 0;
		}
	}

	return -1;
}

static void route_dump_adopt(void)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} req;
	char buf[8192];
	ssize_t len;
	int i;

	/* 先全部标记为「内核里没有」，dump 命中再翻回来 */
	for (i = 0; i < ROUTE_MGR_HASH_SIZE; i++) {
		struct route_entry *e = g_mgr.hash[i];
		for (; e; e = e->next) {
			e->kernel_present = 0;
		}
	}

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_type = RTM_GETROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = ++g_mgr.seq;
	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_table = RT_TABLE_MAIN;

	if (send(g_mgr.fd_cmd, &req, req.nlh.nlmsg_len, 0) < 0) {
		return;
	}

	/* 3000 条实测要 8 次 recv，必须循环到 NLMSG_DONE */
	while ((len = recv(g_mgr.fd_cmd, buf, sizeof(buf), 0)) > 0) {
		struct nlmsghdr *nh;
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)len); nh = NLMSG_NEXT(nh, len)) {
			struct in_addr addr;
			unsigned int oif = 0;

			if (nh->nlmsg_type == NLMSG_DONE) {
				return;
			}
			if (nh->nlmsg_type != RTM_NEWROUTE) {
				continue;
			}
			if (parse_route_msg(nh, &addr, &oif) != 0) {
				continue;
			}

			{
				struct route_entry *e = entry_find(&addr);
				if (e == NULL) {
					/* 收养：smartdns 重启后内核路由还在 */
					if (g_mgr.route_num >= ROUTE_MGR_MAX_ROUTES) {
						continue;
					}
					e = calloc(1, sizeof(*e));
					if (e == NULL) {
						continue;
					}
					e->addr = addr;
					e->egress_idx = -1;
					e->last_dns_ref = 0; /* 视为长期未引用，交给 GC 判断 */
					e->idle_rounds = 0;
					{
						int k;
						for (k = 0; k < g_mgr.egress_num; k++) {
							if (g_mgr.egress[k].ifindex == oif) {
								e->egress_idx = k;
								break;
							}
						}
					}
					e->ifindex = oif;
					e->kernel_present = 1;
					entry_insert(e);
				} else {
					e->kernel_present = 1;
					e->ifindex = oif;
				}
			}
		}
	}
}

/* --------------------------------------------------------- conntrack */

/*
 * 二级判据：这个 IP 还有没有连接在用。
 * 内核不同版本对 IPv4 的打印格式不一致（点分十进制 或 十六进制），
 * 所以两种都找，避免误判。
 */
static int conntrack_has(const struct in_addr *a)
{
	FILE *fp;
	char line[1024];
	char dotted[INET_ADDRSTRLEN];
	char hex[16];
	unsigned char *b = (unsigned char *)&a->s_addr;

	if (g_mgr.test_no_conntrack) {
		return 0;
	}

	if (inet_ntop(AF_INET, a, dotted, sizeof(dotted)) == NULL) {
		return 0;
	}
	snprintf(hex, sizeof(hex), "%02X%02X%02X%02X", b[0], b[1], b[2], b[3]);

	fp = fopen("/proc/net/nf_conntrack", "r");
	if (fp == NULL) {
		/* 读不到就保守认为「还在用」，绝不误删 */
		return 1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, dotted) != NULL || strstr(line, hex) != NULL) {
			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return 0;
}

/* ----------------------------------------------------------------- GC */

static void route_gc(void)
{
	unsigned long now = now_sec();
	struct route_entry *pending[ROUTE_MGR_MAX_ROUTES];
	int pending_num = 0;
	int i;

	/* 一级：DNS 侧空闲时长（O(1)，免费） */
	for (i = 0; i < ROUTE_MGR_HASH_SIZE; i++) {
		struct route_entry *e = g_mgr.hash[i];
		for (; e; e = e->next) {
			if (e->last_dns_ref == 0 || (now - e->last_dns_ref) < ROUTE_MGR_DNS_IDLE_SEC) {
				e->idle_rounds = 0;
				continue;
			}
			if (pending_num < ROUTE_MGR_MAX_ROUTES) {
				pending[pending_num++] = e;
			}
		}
	}

	if (pending_num == 0) {
		return;
	}

	/* 二级：只对候选查 conntrack */
	for (i = 0; i < pending_num; i++) {
		struct route_entry *e = pending[i];
		char ipstr[INET_ADDRSTRLEN];

		if (conntrack_has(&e->addr)) {
			e->idle_rounds = 0; /* 还在用，宽限重置 */
			continue;
		}

		e->idle_rounds++;
		if (e->idle_rounds < ROUTE_MGR_GC_IDLE_ROUNDS) {
			continue;
		}

		if (inet_ntop(AF_INET, &e->addr, ipstr, sizeof(ipstr)) == NULL) {
			ipstr[0] = '\0';
		}
		tlog(TLOG_INFO, "route: gc %s (idle %d rounds, no conntrack)", ipstr, e->idle_rounds);
		route_nl_set(e, 1);
		entry_remove(e);
		free(e);
	}
}

/* -------------------------------------------------------------- 对外 API */

int route_mgr_egress_set(int so_mark, const char *dev, const char *gw)
{
	int i;

	if (dev == NULL || dev[0] == '\0') {
		return -1;
	}

	for (i = 0; i < g_mgr.egress_num; i++) {
		if (g_mgr.egress[i].so_mark == so_mark) {
			snprintf(g_mgr.egress[i].dev, sizeof(g_mgr.egress[i].dev), "%s", dev);
			g_mgr.egress[i].has_gw = 0;
			if (gw != NULL && inet_pton(AF_INET, gw, &g_mgr.egress[i].gw) == 1) {
				g_mgr.egress[i].has_gw = 1;
			}
			g_mgr.egress[i].ifindex = if_nametoindex(dev);
			return 0;
		}
	}

	if (g_mgr.egress_num >= ROUTE_MGR_MAX_EGRESS) {
		return -1;
	}

	i = g_mgr.egress_num;
	g_mgr.egress[i].so_mark = so_mark;
	snprintf(g_mgr.egress[i].dev, sizeof(g_mgr.egress[i].dev), "%s", dev);
	g_mgr.egress[i].has_gw = 0;
	if (gw != NULL && inet_pton(AF_INET, gw, &g_mgr.egress[i].gw) == 1) {
		g_mgr.egress[i].has_gw = 1;
	}
	g_mgr.egress[i].ifindex = if_nametoindex(dev);
	g_mgr.egress_num++;

	return 0;
}

int route_mgr_apply(const unsigned char *addr, int addr_len, const struct ping_bind *bind)
{
	struct in_addr a;
	struct route_entry *e;
	int eg_idx = -1;
	int i;

	if (g_mgr.enabled == 0 || addr == NULL || addr_len != 4 || bind == NULL) {
		return 0;
	}

	/* 按来源线路的 mark 找出口 */
	for (i = 0; i < g_mgr.egress_num; i++) {
		if (g_mgr.egress[i].so_mark == bind->so_mark) {
			eg_idx = i;
			break;
		}
	}
	if (eg_idx < 0) {
		/* 来源未知（hosts / 未配 mark）→ 不写路由，交给默认路由 */
		return 0;
	}

	memcpy(&a, addr, 4);

	e = entry_find(&a);
	if (e == NULL) {
		if (g_mgr.route_num >= ROUTE_MGR_MAX_ROUTES) {
			tlog(TLOG_WARN, "route: table full (%d), skip", g_mgr.route_num);
			return -1;
		}
		e = calloc(1, sizeof(*e));
		if (e == NULL) {
			return -1;
		}
		e->addr = a;
		e->egress_idx = eg_idx;
		e->idle_rounds = 0;
		entry_insert(e);
	} else if (e->egress_idx == eg_idx) {
		/* 出口没变，只刷新引用时间，不下发（避免无意义的内核写入） */
		e->last_dns_ref = now_sec();
		e->idle_rounds = 0;
		return 0;
	} else {
		/* 选路变化：replace 迁移，不是 del+add */
		e->egress_idx = eg_idx;
	}

	e->last_dns_ref = now_sec();
	e->idle_rounds = 0;

	if (route_nl_set(e, 0) != 0) {
		return -1;
	}
	e->kernel_present = 1;

	return 0;
}

int route_mgr_event_fd(void)
{
	return g_mgr.fd_event;
}

void route_mgr_process_event(int fd)
{
	char buf[8192];
	ssize_t len;
	struct nlmsghdr *nh;

	(void)fd;

	while ((len = recv(g_mgr.fd_event, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)len); nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == RTM_DELROUTE) {
				struct in_addr addr;
				unsigned int oif = 0;
				struct route_entry *e;

				if (parse_route_msg(nh, &addr, &oif) != 0) {
					continue;
				}
				e = entry_find(&addr);
				if (e == NULL) {
					continue;
				}
				e->kernel_present = 0;
				/* 有人（netifd / 接口 down）删了，立刻补回 */
				if (route_nl_set(e, 0) == 0) {
					e->kernel_present = 1;
				}
			} else if (nh->nlmsg_type == RTM_NEWLINK) {
				/* 接口回来了（PPPoE 重拨 / up），重下发该出口的全部路由 */
				struct ifinfomsg *ifi = NLMSG_DATA(nh);
				int i;

				for (i = 0; i < ROUTE_MGR_HASH_SIZE; i++) {
					struct route_entry *e = g_mgr.hash[i];
					for (; e; e = e->next) {
						if (e->ifindex != (unsigned int)ifi->ifi_index && e->egress_idx >= 0 &&
							g_mgr.egress[e->egress_idx].ifindex != (unsigned int)ifi->ifi_index) {
							continue;
						}
						if (e->kernel_present == 0) {
							if (route_nl_set(e, 0) == 0) {
								e->kernel_present = 1;
							}
						}
					}
				}
			}
		}
	}
}

void route_mgr_period_run(void)
{
	if (g_mgr.enabled == 0) {
		return;
	}

	g_mgr.gc_rounds++;

	/* 全量校正：内部表是「缓存」，真相在内核，定期用 dump 对齐 */
	route_dump_adopt();

	/* 丢失的路由（接口 down 且没收到事件）补回 */
	{
		int i;
		for (i = 0; i < ROUTE_MGR_HASH_SIZE; i++) {
			struct route_entry *e = g_mgr.hash[i];
			for (; e; e = e->next) {
				if (e->kernel_present == 0) {
					if (route_nl_set(e, 0) == 0) {
						e->kernel_present = 1;
					}
				}
			}
		}
	}

	route_gc();
}

int route_mgr_init(int epoll_fd)
{
	struct sockaddr_nl sa;
	struct epoll_event ev;
	int i;

	/* 注意：只重置运行时状态，不能 memset 整个结构体 ——
	 * egress[] 是配置期登记的，属于「配置」，init 之后注册也应当保留。 */
	for (i = 0; i < ROUTE_MGR_HASH_SIZE; i++) {
		struct route_entry *e = g_mgr.hash[i];
		while (e) {
			struct route_entry *next = e->next;
			free(e);
			e = next;
		}
		g_mgr.hash[i] = NULL;
	}
	g_mgr.route_num = 0;
	g_mgr.seq = 0;
	g_mgr.gc_rounds = 0;
	g_mgr.enabled = 0;
	g_mgr.epoll_fd = epoll_fd;
	g_mgr.fd_cmd = -1;
	g_mgr.fd_event = -1;

	/* 配置期可能早于接口就绪，这里重查一次 ifindex */
	for (i = 0; i < g_mgr.egress_num; i++) {
		g_mgr.egress[i].ifindex = if_nametoindex(g_mgr.egress[i].dev);
	}

	/* 没有登记任何出口就不启用，行为与改造前完全一致 */
	if (g_mgr.egress_num == 0) {
		return 0;
	}

	g_mgr.fd_cmd = nl_open_cmd();
	if (g_mgr.fd_cmd < 0) {
		tlog(TLOG_WARN, "route: create cmd netlink failed, %s", strerror(errno));
		return -1;
	}

	g_mgr.fd_event = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (g_mgr.fd_event < 0) {
		tlog(TLOG_WARN, "route: create event netlink failed, %s", strerror(errno));
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_LINK;
	if (bind(g_mgr.fd_event, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		tlog(TLOG_WARN, "route: bind netlink failed, %s", strerror(errno));
		return -1;
	}

	if (epoll_fd >= 0) {
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLERR;
		ev.data.fd = g_mgr.fd_event;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_mgr.fd_event, &ev) != 0) {
			tlog(TLOG_WARN, "route: epoll_ctl failed, %s", strerror(errno));
			return -1;
		}
	}

	g_mgr.enabled = 1;

	/* 启动收养：把内核里已有的路由接进来，避免重启后变孤儿 */
	route_dump_adopt();

	return 0;
}

void route_mgr_exit(void)
{
	if (g_mgr.fd_cmd >= 0) {
		close(g_mgr.fd_cmd);
		g_mgr.fd_cmd = -1;
	}
	if (g_mgr.fd_event >= 0) {
		close(g_mgr.fd_event);
		g_mgr.fd_event = -1;
	}
	g_mgr.enabled = 0;
}

int route_mgr_test_enable(int enable)
{
	g_mgr.test_no_conntrack = enable ? 1 : 0;
	return 0;
}
