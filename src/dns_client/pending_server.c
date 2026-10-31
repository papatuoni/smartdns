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

#define _GNU_SOURCE

#include "pending_server.h"
#include "group.h"
#include "server_info.h"
#include "wake_event.h"

#include "smartdns/dns_server.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <pthread.h>

static LIST_HEAD(pending_servers);
static pthread_mutex_t pending_server_mutex = PTHREAD_MUTEX_INITIALIZER;
static int dns_client_has_bootstrap_dns = 0;

/* get addr info */
struct addrinfo *_dns_client_getaddr(const char *host, char *port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int ret = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret != 0) {
		tlog(TLOG_WARN, "get addr info failed. %s\n", gai_strerror(ret));
		tlog(TLOG_WARN, "host = %s, port = %s, type = %d, protocol = %d", host, port, type, protocol);
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

static int _dns_client_resolv_ip_by_host(const char *host, char *ip, int ip_len)
{
	struct addrinfo *gai = NULL;
	gai = _dns_client_getaddr(host, NULL, SOCK_STREAM, 0);
	if (gai == NULL) {
		return -1;
	}

	if (get_host_by_addr(ip, ip_len, gai->ai_addr) == NULL) {
		freeaddrinfo(gai);
		return -1;
	}

	freeaddrinfo(gai);
	return 0;
}

int _dns_client_add_to_pending_group(const char *group_name, const char *server_ip, int port,
									 dns_server_type_t server_type, const struct client_dns_server_flags *flags)
{
	struct dns_server_pending *item = NULL;
	struct dns_server_pending *tmp = NULL;
	struct dns_server_pending *pending = NULL;
	struct dns_server_pending_group *group = NULL;

	if (group_name == NULL || server_ip == NULL) {
		goto errout;
	}

	pthread_mutex_lock(&pending_server_mutex);
	list_for_each_entry_safe(item, tmp, &pending_servers, list)
	{
		if (memcmp(&item->flags, flags, sizeof(*flags)) != 0) {
			continue;
		}

		if (strncmp(item->host, server_ip, DNS_HOSTNAME_LEN) == 0 && item->port == port && item->type == server_type) {
			pending = item;
			break;
		}
	}
	pthread_mutex_unlock(&pending_server_mutex);

	if (pending == NULL) {
		tlog(TLOG_ERROR, "cannot found server for group %s: %s, %d, %d", group_name, server_ip, port, server_type);
		goto errout;
	}

	group = zalloc(1, sizeof(*group));
	if (group == NULL) {
		goto errout;
	}
	safe_strncpy(group->group_name, group_name, DNS_GROUP_NAME_LEN);

	pthread_mutex_lock(&pending_server_mutex);
	list_add_tail(&group->list, &pending->group_list);
	pthread_mutex_unlock(&pending_server_mutex);

	return 0;

errout:
	if (group) {
		free(group);
	}
	return -1;
}

static void _dns_client_server_pending_get(struct dns_server_pending *pending)
{
	if (atomic_inc_return(&pending->refcnt) <= 0) {
		BUG("pending ref is invalid");
	}
}

static void _dns_client_server_pending_release(struct dns_server_pending *pending)
{
	struct dns_server_pending_group *group = NULL;
	struct dns_server_pending_group *tmp = NULL;

	int refcnt = atomic_dec_return(&pending->refcnt);

	if (refcnt) {
		if (refcnt < 0) {
			BUG("BUG: pending refcnt is %d", refcnt);
		}
		return;
	}

	pthread_mutex_lock(&pending_server_mutex);
	list_for_each_entry_safe(group, tmp, &pending->group_list, list)
	{
		list_del_init(&group->list);
		free(group);
	}

	list_del_init(&pending->list);
	pthread_mutex_unlock(&pending_server_mutex);
	free(pending);
}

static void _dns_client_server_pending_remove(struct dns_server_pending *pending)
{
	pthread_mutex_lock(&pending_server_mutex);
	list_del_init(&pending->list);
	pthread_mutex_unlock(&pending_server_mutex);
	_dns_client_server_pending_release(pending);
}

static int _dns_client_server_pending(const char *server_ip, int port, dns_server_type_t server_type,
									  const struct client_dns_server_flags *flags)
{
	struct dns_server_pending *pending = NULL;

	pending = zalloc(1, sizeof(*pending));
	if (pending == NULL) {
		tlog(TLOG_ERROR, "malloc failed");
		goto errout;
	}

	safe_strncpy(pending->host, server_ip, DNS_HOSTNAME_LEN);
	pending->port = port;
	pending->type = server_type;
	pending->ping_time_v4 = -1;
	pending->ping_time_v6 = -1;
	pending->ipv4[0] = 0;
	pending->ipv6[0] = 0;
	pending->has_v4 = 0;
	pending->has_v6 = 0;
	_dns_client_server_pending_get(pending);
	INIT_LIST_HEAD(&pending->group_list);
	INIT_LIST_HEAD(&pending->retry_list);
	memcpy(&pending->flags, flags, sizeof(struct client_dns_server_flags));

	pthread_mutex_lock(&pending_server_mutex);
	list_add_tail(&pending->list, &pending_servers);
	atomic_set(&client.run_period, 1);
	pthread_mutex_unlock(&pending_server_mutex);

	_dns_client_do_wakeup_event();

	return 0;
errout:
	if (pending) {
		free(pending);
	}

	return -1;
}

int _dns_client_add_server_pending(const char *server_ip, const char *server_host, int port,
								   dns_server_type_t server_type, struct client_dns_server_flags *flags, int is_pending)
{
	int ret = 0;
	char server_ip_tmp[DNS_HOSTNAME_LEN] = {0};

	if (server_type >= DNS_SERVER_TYPE_END) {
		tlog(TLOG_ERROR, "server type is invalid.");
		return -1;
	}

	if (check_is_ipaddr(server_ip) && is_pending) {
		ret = _dns_client_server_pending(server_ip, port, server_type, flags);
		if (ret == 0) {
			tlog(TLOG_INFO, "add pending server %s", server_ip);
			return 0;
		}
	} else if (check_is_ipaddr(server_ip) && is_pending == 0) {
		if (_dns_client_resolv_ip_by_host(server_ip, server_ip_tmp, sizeof(server_ip_tmp)) != 0) {
			tlog(TLOG_ERROR, "resolve %s failed.", server_ip);
			return -1;
		}

		tlog(TLOG_INFO, "resolve %s to %s.", server_ip, server_ip_tmp);
		server_ip = server_ip_tmp;
	}

	/* add server */
	ret = _dns_client_server_add(server_ip, server_host, port, server_type, flags);
	if (ret != 0) {
		goto errout;
	}

	if ((flags->server_flag & SERVER_FLAG_EXCLUDE_DEFAULT) == 0 || dns_conf_exist_bootstrap_dns) {
		dns_client_has_bootstrap_dns = 1;
	}

	return 0;
errout:
	return -1;
}

static int _dns_client_pending_server_resolve(const struct dns_result *result, void *user_ptr)
{
	struct dns_server_pending *pending = user_ptr;
	int ret = 0;
	int has_soa = 0;

	if (result->rtcode == DNS_RC_NXDOMAIN || result->has_soa == 1 || result->rtcode == DNS_RC_REFUSED ||
		(result->rtcode == DNS_RC_NOERROR && result->ip_num == 0 && result->ip == NULL)) {
		has_soa = 1;
	}

	if (result->addr_type == DNS_T_A) {
		pending->ping_time_v4 = -1;
		if (result->rtcode == DNS_RC_NOERROR && result->ip_num > 0) {
			pending->has_v4 = 1;
			pending->ping_time_v4 = result->ping_time;
			pending->has_soa_v4 = 0;
			safe_strncpy(pending->ipv4, result->ip, DNS_HOSTNAME_LEN);
		} else if (has_soa) {
			pending->has_v4 = 0;
			pending->ping_time_v4 = -1;
			pending->has_soa_v4 = 1;
		}
	} else if (result->addr_type == DNS_T_AAAA) {
		pending->ping_time_v6 = -1;
		if (result->rtcode == DNS_RC_NOERROR && result->ip_num > 0) {
			pending->has_v6 = 1;
			pending->ping_time_v6 = result->ping_time;
			pending->has_soa_v6 = 0;
			safe_strncpy(pending->ipv6, result->ip, DNS_HOSTNAME_LEN);
		} else if (has_soa) {
			pending->has_v6 = 0;
			pending->ping_time_v6 = -1;
			pending->has_soa_v6 = 1;
		}
	} else {
		ret = -1;
	}

	_dns_client_server_pending_release(pending);
	return ret;
}

/* add server to group */
int _dns_client_add_to_group_pending(const char *group_name, const char *server_ip, int port,
									 dns_server_type_t server_type, const struct client_dns_server_flags *flags,
									 int is_pending)
{
	struct dns_server_info *server_info = NULL;

	if (group_name == NULL || server_ip == NULL) {
		return -1;
	}

	server_info = _dns_client_get_server(server_ip, port, server_type, flags);
	if (server_info == NULL) {
		if (is_pending == 0) {
			tlog(TLOG_ERROR, "add server %s:%d to group %s failed", server_ip, port, group_name);
			return -1;
		}
		return _dns_client_add_to_pending_group(group_name, server_ip, port, server_type, flags);
	}

	return _dns_client_add_to_group(group_name, server_info);
}

static int _dns_client_add_pendings(struct dns_server_pending *pending, char *ip)
{
	struct dns_server_pending_group *group = NULL;
	struct dns_server_pending_group *tmp = NULL;
	char ip_tmp[DNS_HOSTNAME_LEN] = {0};

	if (check_is_ipaddr(ip) != 0) {
		if (_dns_client_resolv_ip_by_host(ip, ip_tmp, sizeof(ip_tmp)) != 0) {
			tlog(TLOG_WARN, "resolv %s failed.", ip);
			return -1;
		}

		tlog(TLOG_INFO, "resolv %s to %s.", ip, ip_tmp);

		ip = ip_tmp;
	}

	if (_dns_client_add_server_pending(ip, pending->host, pending->port, pending->type, &pending->flags, 0) != 0) {
		return -1;
	}
	
	/* 摘链模式：加锁把 group_list 整体搬到临时链表，脱锁后再逐个处理。
	 * 不能在遍历时持锁 —— _dns_client_add_to_group_pending() 会间接调用
	 * _dns_client_add_to_pending_group()，后者会对同一把 pending_server_mutex
	 * 再次加锁（非递归 mutex），将造成自死锁。 */
	LIST_HEAD(local_group_list);
	pthread_mutex_lock(&pending_server_mutex);
	list_for_each_entry_safe(group, tmp, &pending->group_list, list)
	{
		list_del_init(&group->list);
		list_add(&group->list, &local_group_list);
	}
	pthread_mutex_unlock(&pending_server_mutex);

	list_for_each_entry_safe(group, tmp, &local_group_list, list)
	{
		if (_dns_client_add_to_group_pending(group->group_name, ip, pending->port, pending->type, &pending->flags, 0) !=
			0) {
			tlog(TLOG_WARN, "add server to group failed, skip add.");
		}

		list_del_init(&group->list);
		free(group);
	}

	return 0;
}

void _dns_client_remove_all_pending_servers(void)
{
	struct dns_server_pending *pending = NULL;
	struct dns_server_pending *tmp = NULL;
	LIST_HEAD(remove_list);

	pthread_mutex_lock(&pending_server_mutex);
	list_for_each_entry_safe(pending, tmp, &pending_servers, list)
	{
		list_del_init(&pending->list);
		list_add(&pending->retry_list, &remove_list);
		_dns_client_server_pending_get(pending);
	}
	pthread_mutex_unlock(&pending_server_mutex);

	list_for_each_entry_safe(pending, tmp, &remove_list, retry_list)
	{
		list_del_init(&pending->retry_list);
		_dns_client_server_pending_remove(pending);
		_dns_client_server_pending_release(pending);
	}
}

void _dns_client_add_pending_servers(void)
{
#ifdef TEST
	const int delay_value = 1;
#else
	const int delay_value = 3;
#endif
	struct dns_server_pending *pending = NULL;
	struct dns_server_pending *tmp = NULL;
	static int delay = delay_value;
	LIST_HEAD(retry_list);

	/* add pending server after 3 seconds */
	if (++delay < delay_value) {
		return;
	}
	delay = 0;

	pthread_mutex_lock(&pending_server_mutex);
	if (list_empty(&pending_servers)) {
		atomic_set(&client.run_period, 0);
	} else {
		atomic_set(&client.run_period, 1);
	}

	list_for_each_entry_safe(pending, tmp, &pending_servers, list)
	{
		list_add(&pending->retry_list, &retry_list);
		_dns_client_server_pending_get(pending);
	}
	pthread_mutex_unlock(&pending_server_mutex);

	list_for_each_entry_safe(pending, tmp, &retry_list, retry_list)
	{
		/* send dns type A, AAAA query to bootstrap DNS server */
		int add_success = 0;
		char *dnsserver_ip = NULL;

		/* if has no bootstrap DNS, just call getaddrinfo to get address */
		if (dns_client_has_bootstrap_dns == 0) {
			list_del_init(&pending->retry_list);
			_dns_client_server_pending_release(pending);
			pending->retry_cnt++;
			if (_dns_client_add_pendings(pending, pending->host) != 0) {
				tlog(TLOG_INFO, "add pending DNS server %s from resolv.conf failed, retry %d...", pending->host,
					 pending->retry_cnt - 1);
				if (pending->retry_cnt - 1 > DNS_PENDING_SERVER_RETRY) {
					tlog(TLOG_WARN, "add pending DNS server %s from resolv.conf failed, exit...", pending->host);
					exit(1);
				}
				continue;
			}
			_dns_client_server_pending_release(pending);
			continue;
		}

		if (pending->query_v4 == 0) {
			pending->query_v4 = 1;
			_dns_client_server_pending_get(pending);
			if (dns_server_query(pending->host, DNS_T_A, NULL, _dns_client_pending_server_resolve, pending) != 0) {
				_dns_client_server_pending_release(pending);
				pending->query_v4 = 0;
			}
		}

		if (pending->query_v6 == 0) {
			pending->query_v6 = 1;
			_dns_client_server_pending_get(pending);
			if (dns_server_query(pending->host, DNS_T_AAAA, NULL, _dns_client_pending_server_resolve, pending) != 0) {
				_dns_client_server_pending_release(pending);
				pending->query_v6 = 0;
			}
		}

		list_del_init(&pending->retry_list);
		_dns_client_server_pending_release(pending);

		/* if both A, AAAA has query result, select fastest IP address */
		if (pending->has_v4 && pending->has_v6) {
			if (pending->ping_time_v4 <= pending->ping_time_v6 && pending->ipv4[0]) {
				dnsserver_ip = pending->ipv4;
			} else {
				dnsserver_ip = pending->ipv6;
			}
		} else if (pending->has_v4) {
			dnsserver_ip = pending->ipv4;
		} else if (pending->has_v6) {
			dnsserver_ip = pending->ipv6;
		}

		if (dnsserver_ip && dnsserver_ip[0]) {
			if (_dns_client_add_pendings(pending, dnsserver_ip) == 0) {
				add_success = 1;
			}
		}

		pending->retry_cnt++;
		if (pending->retry_cnt == 1) {
			continue;
		}
		
		/* 统计无响应轮次：既无 IP 也无 SOA，说明查询根本没回来（超时/被丢弃），
		 * 与"明确回复 SOA（无此主机）"是两回事，需分开计。 */
		if (pending->has_v4 == 0 && pending->has_soa_v4 == 0) {
			pending->no_resp_v4++;
		} else {
			pending->no_resp_v4 = 0;
		}
		if (pending->has_v6 == 0 && pending->has_soa_v6 == 0) {
			pending->no_resp_v6++;
		} else {
			pending->no_resp_v6 = 0;
		}

		if (dnsserver_ip == NULL && pending->has_soa_v4 && pending->has_soa_v6) {
			tlog(TLOG_WARN, "add pending DNS server %s failed, no such host.", pending->host);
			_dns_client_server_pending_remove(pending);
			continue;
		}

		/* 一族明确返回 SOA（域名不存在，或被 force-aaaa-soa 这类客户端策略改写），
		 * 另一族连续多轮毫无响应 —— 已经不是"慢"，而是根本拿不到地址。
		 *
		 * 原逻辑要求两族都 SOA 才放弃，于是「AAAA 被 force-aaaa-soa 强制成 SOA、
		 * A 却超时无回调」时 has_soa_v4 恒为 0，条件永远不成立，只能硬刷到
		 * DNS_PENDING_SERVER_RETRY(60) 次 ≈ 3 分钟，期间每 3 秒重发一轮查询并刷日志。 */
		if (dnsserver_ip == NULL && (pending->has_soa_v4 || pending->has_soa_v6) &&
			(pending->no_resp_v4 > DNS_PENDING_NO_RESP_GIVEUP ||
			 pending->no_resp_v6 > DNS_PENDING_NO_RESP_GIVEUP)) {
			tlog(TLOG_WARN, "add pending DNS server %s failed, %s no response, give up.", pending->host,
				 pending->has_soa_v4 ? "AAAA" : "A");
			_dns_client_server_pending_remove(pending);
			continue;
		}

		if (pending->retry_cnt - 1 > DNS_PENDING_SERVER_RETRY || add_success) {
			if (add_success == 0) {
				tlog(TLOG_WARN, "add pending DNS server %s failed.", pending->host);
			}
			_dns_client_server_pending_remove(pending);
		} else {
			tlog(TLOG_INFO, "add pending DNS server %s failed, retry %d...", pending->host, pending->retry_cnt - 1);
			pending->query_v4 = 0;
			pending->query_v6 = 0;
		}
	}
}
