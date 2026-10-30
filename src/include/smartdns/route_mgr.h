/*************************************************************************
 *
 * route_mgr.h -- 双 WAN 主机路由管理（内置于 smartdns）
 *
 * 职责边界：
 *   本模块只负责「测速选出的 IP 该从哪条线路走」这个决策的落地与回收。
 *   它不参与选路决策本身（那是 speed_check.c 的事），也不管 DNS 缓存。
 *
 *************************************************************************/
#ifndef SMARTDNS_ROUTE_MGR_H
#define SMARTDNS_ROUTE_MGR_H

#include "smartdns/fast_ping.h"

#include <net/if.h>
#include <netinet/in.h>

#define ROUTE_MGR_MAX_EGRESS 4

/* 一条物理出口。so_mark 是与上游 server 配置的 -set-mark 对应的键。 */
struct route_egress {
	int so_mark;
	char dev[IFNAMSIZ];
	unsigned int table; /* 策略路由表号，默认取 so_mark；由 route_mgr 自行下发，无需外部脚本 */
	struct in_addr gw; /* 网络序；点对点口（PPPoE）不需要 */
	int has_gw;
	unsigned int ifindex; /* 每次下发前重查，接口删除重建会变 */
};

int route_mgr_init(int epoll_fd);
void route_mgr_exit(void);

/* 配置期调用：登记 mark -> 出口 的映射。gw 可为 NULL（点对点口）。 */
int route_mgr_egress_set(int so_mark, const char *dev, const char *gw);

/* 运行时调用（context.c 测速完成后）：把 IP 绑定到它来源线路的出口。 */
int route_mgr_apply(const unsigned char *addr, int addr_len, const struct ping_bind *bind);

/* epoll 事件：路由被他人删除 / 接口 up-down。 */
/* 事件 fd，供 epoll 分发判断；未启用时返回 -1 */
int route_mgr_event_fd(void);
void route_mgr_process_event(int fd);

/* 周期校正 + 回收。 */
void route_mgr_period_run(void);

/* 仅测试用 */
int route_mgr_test_enable(int enable);

#endif /* SMARTDNS_ROUTE_MGR_H */
