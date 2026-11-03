/*************************************************************************
 * route_cache.h -- DNS cache driven, in-process direct-route table
 *
 * 纯源码实现：不依赖守护进程、Unix socket、外部脚本、配置文件或自启项。
 * 全部状态与 netlink 写操作都在 smartdns 进程内完成。
 *
 * 生命周期完全由 DNS 缓存事件驱动：
 *   写缓存成功 (miss / prefetch)      -> route_cache_on_insert  差集更新 /32
 *   缓存命中                          -> route_cache_on_hit     只刷新 TTL，零内核写入
 *   缓存删除 (过期 / LRU / flush)     -> route_cache_on_del     引用归零后延迟删 /32
 *   进程退出                          -> route_cache_exit       清空全部 /32
 *
 * 约束（针对此前 futex 死锁）：
 *   - 无线程、无定时器、无队列；只有一把 trylock 保护纯内存哈希表
 *   - 拿不到锁立即跳过事件，绝不无限等待
 *   - netlink fd 非阻塞，只 sendmsg，不等 ACK、不设 SO_RCVTIMEO
 *
 * 指定出口：只写 main 表 IP/32 dev <ifname> [via <gw>]，FIB 直查，兼容硬件卸载。
 * ifname 为空 = 默认出口，不写任何主机路由。
 *************************************************************************/

#ifndef SMARTDNS_ROUTE_CACHE_H
#define SMARTDNS_ROUTE_CACHE_H

#include <net/if.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct route_cache_key {
	const char *group;
	const char *domain;
	int qtype;
	uint32_t query_flag;
};

struct route_cache_addr {
	unsigned char ip[16];
	int family; /* AF_INET or AF_INET6 */
	char ifname[IFNAMSIZ];
};

#define ROUTE_CACHE_MAX_ADDR 32

/* 上限与 DNS 缓存同量级，满了按 LRU 淘汰并删内核 /32 */
#ifndef ROUTE_CACHE_MAX_IP
#define ROUTE_CACHE_MAX_IP 4096
#endif
#ifndef ROUTE_CACHE_MAX_OWNER
#define ROUTE_CACHE_MAX_OWNER 8192
#endif

int route_cache_init(void);
void route_cache_exit(void);

/* 仅在 dns_cache_insert()/dns_cache_replace() 真正成功后调用 */
void route_cache_on_insert(const struct route_cache_key *key, const struct route_cache_addr *addrs, int addr_num,
						   int ttl);

/* 缓存命中：刷新 TTL 与 LRU，绝不产生内核命令 */
void route_cache_on_hit(const struct route_cache_key *key, int ttl);

/* 缓存条目真正移除（过期 DEL / LRU 淘汰 / flush / replace 删旧） */
void route_cache_on_del(const struct route_cache_key *key);

/* 保留段过滤：返回 1 表示永不建主机路由（fake-ip、loopback、ULA ...） */
int route_cache_addr_ignored(const unsigned char *ip, int family);

#ifdef ROUTE_CACHE_UNIT_TEST
/* 单元实测用：记录应该下发的 ip 命令，不碰内核 */
#define ROUTE_CACHE_TEST_LOG_MAX 256
#define ROUTE_CACHE_TEST_CMD_LEN 160
extern char route_cache_test_log[ROUTE_CACHE_TEST_LOG_MAX][ROUTE_CACHE_TEST_CMD_LEN];
extern int route_cache_test_n;
void route_cache_test_reset(void);
int route_cache_test_ip_num(void);
int route_cache_test_owner_num(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SMARTDNS_ROUTE_CACHE_H */
