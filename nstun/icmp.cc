#include "icmp.h"

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core.h"
#include "logs.h"
#include "macros.h"
#include "policy.h"
#include "tun.h"

namespace nstun {

static constexpr time_t ICMP_TIMEOUT = 10;

static IcmpFlow* find_ipv4_icmp_flow(Context* ctx, const IcmpFlowKey4& key4) {
	size_t active_seen = 0;
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		IcmpFlow& flow = ctx->c_ipv4_icmp_flows[i];
		if (flow.header.active) {
			if (memcmp(&flow.header.icmp_key4, &key4, sizeof(key4)) == 0) {
				flow.header.last_active = time(nullptr);
				return &flow;
			}
			active_seen++;
			if (active_seen >= ctx->num_c_ipv4_icmp_flows) {
				break;
			}
		}
	}
	return nullptr;
}

static IcmpFlow* find_ipv6_icmp_flow(Context* ctx, const IcmpFlowKey6& key6) {
	size_t active_seen = 0;
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		IcmpFlow& flow = ctx->c_ipv6_icmp_flows[i];
		if (flow.header.active) {
			if (memcmp(&flow.header.icmp_key6, &key6, sizeof(key6)) == 0) {
				flow.header.last_active = time(nullptr);
				return &flow;
			}
			active_seen++;
			if (active_seen >= ctx->num_c_ipv6_icmp_flows) {
				break;
			}
		}
	}
	return nullptr;
}

static IcmpFlow* alloc_icmp_flow(IcmpFlow* flows, size_t max_flows) {
	for (size_t i = 0; i < max_flows; ++i) {
		if (!flows[i].header.active) {
			return &flows[i];
		}
	}
	return nullptr;
}

static IcmpFlow* alloc_ipv4_icmp_flow(Context* ctx) {
	return alloc_icmp_flow(ctx->c_ipv4_icmp_flows, NSTUN_MAX_FLOWS);
}

static IcmpFlow* alloc_ipv6_icmp_flow(Context* ctx) {
	return alloc_icmp_flow(ctx->c_ipv6_icmp_flows, NSTUN_MAX_FLOWS);
}

static void init_icmp_flow_zero(IcmpFlow* flow) {
	*flow = IcmpFlow{};
	flow->header.type = FlowType::ICMP;
	flow->header.host_fd = -1;
}

/* Maximum frame size for an ICMP error packet we will generate.
 * RFC 792 / RFC 4443 require including the original IP header + 8 bytes
 * of the triggering datagram. We cap total frame size conservatively. */
static constexpr size_t ICMP_ERROR_MAX_FRAME = 128;

static void icmp_destroy_flow(Context* ctx, IcmpFlow* flow) {
	if (!flow->header.active) {
		return;
	}

	if (flow->header.host_fd != -1) {
		if (!monitor::removeFd(flow->header.host_fd)) {
			LOG_W("Failed to remove host_fd from monitor");
		}
		close(flow->header.host_fd);
		if (flow->header.host_fd >= 0 &&
		    static_cast<size_t>(flow->header.host_fd) < nstun::NSTUN_MAX_FDS) {
			ctx->c_icmp_flows_by_fd[flow->header.host_fd] = nullptr;
		}
		flow->header.host_fd = -1;
	}
	flow->header.active = false;
	if (flow->header.is_ipv6) {
		ctx->num_c_ipv6_icmp_flows--;
	} else {
		ctx->num_c_ipv4_icmp_flows--;
	}
}

[[nodiscard]] static bool icmp_send_packet4(Context* ctx, uint32_t saddr, uint32_t daddr,
    uint8_t type, uint8_t code, uint16_t id, uint16_t seq, const void* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("icmp_send_packet4: data length too large");
		return false;
	}

	size_t frame_len = sizeof(ip4_hdr) + sizeof(icmp4_hdr) + len;
	uint8_t header_buf[sizeof(ip4_hdr) + sizeof(icmp4_hdr)];
	memset(header_buf, 0, sizeof(header_buf));

	ip4_hdr ip = {};
	icmp4_hdr icmp = {};

	/* IPv4 */
	ip4_set_ihl_version(&ip, 4, sizeof(ip4_hdr) / 4);
	ip.tos = 0;
	ip.tot_len = htons(frame_len);
	ip.id = 0;
	ip.frag_off = 0;
	ip.ttl = 64;
	ip.protocol = IPPROTO_ICMP;
	ip.saddr = saddr;
	ip.daddr = daddr;
	ip.check = 0;
	ip.check = compute_checksum(&ip, sizeof(ip4_hdr));

	/* ICMP */
	icmp.type = type;
	icmp.code = code;
	icmp.id = id;
	icmp.seq = seq;
	icmp.check = 0;

	/* Compute full ICMP4 checksum in userspace (no pseudo-header, and raw
	 * sockets like ping verify it themselves before kernel can complete it) */
	uint32_t sum = compute_checksum_part(&icmp, sizeof(icmp4_hdr), 0);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	icmp.check = finalize_checksum(sum);

	memcpy(header_buf, &ip, sizeof(ip));
	memcpy(header_buf + sizeof(ip), &icmp, sizeof(icmp));

	virtio_net_hdr vh = {};
	/* flags=0: checksum already complete, no offload needed */

	return send_to_guest_v(
	    ctx, &vh, header_buf, sizeof(header_buf), static_cast<const uint8_t*>(data), len);
}

[[nodiscard]] static bool icmp_send_packet6(Context* ctx, const uint8_t* saddr,
    const uint8_t* daddr, uint8_t type, uint8_t code, uint16_t id, uint16_t seq, const void* data,
    size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("icmp_send_packet6: data length too large");
		return false;
	}

	uint8_t header_buf[sizeof(ip6_hdr) + sizeof(icmp6_hdr)];
	memset(header_buf, 0, sizeof(header_buf));

	ip6_hdr ip6 = {};
	icmp6_hdr icmp6 = {};

	/* IPv6 */
	ip6.vtf = htonl(0x60000000); /* Version 6 */
	ip6.payload_len = htons(sizeof(icmp6_hdr) + len);
	ip6.next_header = IPPROTO_ICMPV6;
	ip6.hop_limit = 64;
	memcpy(ip6.saddr, saddr, sizeof(ip6.saddr));
	memcpy(ip6.daddr, daddr, sizeof(ip6.daddr));

	/* ICMPv6 */
	icmp6.type = type;
	icmp6.code = code;
	icmp6.id = id;
	icmp6.seq = seq;
	icmp6.check = 0;

	/* 40-byte IPv6 pseudo header */
	pseudo_hdr6 phdr = {};
	phdr.len = htonl(sizeof(icmp6_hdr) + len);
	phdr.next_header = IPPROTO_ICMPV6;
	memcpy(phdr.saddr, saddr, sizeof(phdr.saddr));
	memcpy(phdr.daddr, daddr, sizeof(phdr.daddr));

	/* Compute full ICMPv6 checksum in userspace (raw sockets verify it) */
	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(&icmp6, sizeof(icmp6_hdr), sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	icmp6.check = finalize_checksum(sum);

	memcpy(header_buf, &ip6, sizeof(ip6));
	memcpy(header_buf + sizeof(ip6), &icmp6, sizeof(icmp6));

	virtio_net_hdr vh = {};
	/* flags=0: checksum already complete, no offload needed */

	return send_to_guest_v(
	    ctx, &vh, header_buf, sizeof(header_buf), static_cast<const uint8_t*>(data), len);
}

void send_icmp4_error(
    Context* ctx, const ip4_hdr* req_ip, size_t tot_len, uint8_t type, uint8_t code) {
	size_t req_ihl = ip4_ihl(req_ip) * 4;
	/* RFC 792: include IP header + first 8 bytes of original datagram.
	 * Clamp to actual available data to prevent OOB read. */
	size_t icmp_data_len = req_ihl + 8;
	if (icmp_data_len > tot_len) {
		icmp_data_len = tot_len;
	}

	if (sizeof(ip4_hdr) + sizeof(icmp4_hdr) + icmp_data_len > ICMP_ERROR_MAX_FRAME) {
		return;
	}

	if (!icmp_send_packet4(
		ctx, req_ip->daddr, req_ip->saddr, type, code, 0, 0, req_ip, icmp_data_len)) {
		LOG_W("send_icmp4_error: failed to send ICMP error to guest");
	}
}

void send_icmp6_error(
    Context* ctx, const ip6_hdr* req_ip, size_t tot_len, uint8_t type, uint8_t code) {
	/* IPv6 header + first 8 bytes of original datagram.
	 * Clamp to actual available data to prevent OOB read. */
	size_t icmp_data_len = sizeof(ip6_hdr) + 8;
	if (icmp_data_len > tot_len) {
		icmp_data_len = tot_len;
	}

	if (sizeof(ip6_hdr) + sizeof(icmp6_hdr) + icmp_data_len > ICMP_ERROR_MAX_FRAME) {
		return;
	}

	if (!icmp_send_packet6(
		ctx, req_ip->daddr, req_ip->saddr, type, code, 0, 0, req_ip, icmp_data_len)) {
		LOG_W("send_icmp6_error: failed to send ICMPv6 error to guest");
	}
}

static void proxy_icmp6(Context* ctx, const ip6_hdr* ip, const icmp6_hdr* icmp,
    const uint8_t* payload, size_t len, const RuleResult& rule) {
	/* Attempt to proxy ICMP using unprivileged socket */
	IcmpFlowKey6 key6 = {};
	memcpy(key6.saddr6, ip->saddr, sizeof(key6.saddr6));
	memcpy(key6.daddr6, ip->daddr, sizeof(key6.daddr6));
	key6.id = icmp->id;

	IcmpFlow* flow = find_ipv6_icmp_flow(ctx, key6);

	if (!flow) {
		if (ctx->num_c_ipv6_icmp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of IPv6 ICMP flows reached, dropping");
			return;
		}

		flow = alloc_ipv6_icmp_flow(ctx);
		if (!flow) {
			LOG_E("Failed to allocate Flow (table full)");
			return;
		}

		int fd =
		    socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMPV6);
		if (fd == -1) {
			PLOG_W("socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) failed.");
			send_icmp6_error(ctx, ip, sizeof(ip6_hdr) + len, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_ADDR);
			return;
		}
		if (fd >= static_cast<int>(nstun::NSTUN_MAX_FDS)) {
			LOG_E("FD limit reached (fd=%d)", fd);
			close(fd);
			return;
		}

		if (!monitor::addFd(fd, EPOLLIN, host_callback, ctx)) {
			PLOG_E("monitor::addFd() for ICMPv6 failed");
			close(fd);
			return;
		}

		init_icmp_flow_zero(flow);
		flow->header.active = true;
		flow->header.host_fd = fd;
		flow->header.is_ipv6 = true;
		flow->header.icmp_key6 = key6;

		flow->header.last_active = time(nullptr);
		flow->header.is_redirected = rule.has_redirect_ip6;
		memcpy(flow->header.orig_dest_ip6, ip->daddr, sizeof(flow->header.orig_dest_ip6));
		if (rule.has_redirect_ip6) {
			memcpy(flow->header.redirect_ip6, rule.redirect_ip6,
			    sizeof(flow->header.redirect_ip6));
		}

		ctx->num_c_ipv6_icmp_flows++;
		if (fd >= 0 && static_cast<size_t>(fd) < nstun::NSTUN_MAX_FDS) {
			ctx->c_icmp_flows_by_fd[fd] = flow;
		}

		if (flow->header.is_redirected) {
			LOG_D("Created IPv6 ICMP flow for ID %u (fd=%d) [redirected]",
			    ntohs(key6.id), fd);
		} else {
			LOG_D("Created IPv6 ICMP flow for ID %u (fd=%d)", ntohs(key6.id), fd);
		}
	}
	struct sockaddr_in6 dest_addr = INIT_SOCKADDR_IN6(AF_INET6);
	if (flow->header.is_redirected) {
		memcpy(
		    &dest_addr.sin6_addr, flow->header.redirect_ip6, sizeof(dest_addr.sin6_addr));
	} else {
		/* ip.cc already rejected loopback/v4-mapped destinations */
		memcpy(
		    &dest_addr.sin6_addr, flow->header.orig_dest_ip6, sizeof(dest_addr.sin6_addr));
	}

	ssize_t sent = TEMP_FAILURE_RETRY(sendto(flow->header.host_fd, payload, len, MSG_NOSIGNAL,
	    reinterpret_cast<const sockaddr*>(&dest_addr), sizeof(dest_addr)));
	if (sent == -1) {
		PLOG_E("sendto(fd=%d) ICMPv6 failed", flow->header.host_fd);
	}
}

void handle_icmp6(Context* ctx, const ip6_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(icmp6_hdr)) {
		return;
	}

	icmp6_hdr icmp_storage;
	memcpy(&icmp_storage, payload, sizeof(icmp_storage));
	const icmp6_hdr* icmp = &icmp_storage;

	/* Validate ICMPv6 checksum (mandatory per RFC 4443) */
	pseudo_hdr6 phdr = {};
	phdr.len = htonl(len);
	phdr.next_header = IPPROTO_ICMPV6;
	memcpy(phdr.saddr, ip->saddr, sizeof(phdr.saddr));
	memcpy(phdr.daddr, ip->daddr, sizeof(phdr.daddr));
	uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	csum = compute_checksum_part(payload, len, csum);
	if (finalize_checksum(csum) != 0) {
		LOG_D("ICMPv6 checksum invalid, dropping");
		return;
	}

	/* ICMPv6 Echo Request is Type 128 */
	if (icmp->type == ICMP6_ECHO_REQUEST && icmp->code == 0) {
		RuleResult rule = evaluate_rules6(
		    ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_ICMP, ip->saddr, ip->daddr, 0, 0);

		switch (rule.action) {
		case NSTUN_ACTION_DROP:
			LOG_D("ICMPv6 dropped by policy");
			return;
		case NSTUN_ACTION_REJECT:
			LOG_D("ICMPv6 rejected by policy");
			send_icmp6_error(ctx, ip, sizeof(ip6_hdr) + len, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_NOPORT); /* Dest unreachable, port unreachable */
			return;
		default:
			break;
		}

		if (memcmp(ip->daddr, ctx->host_ip6, IPV6_ADDR_LEN) == 0 &&
		    rule.action != NSTUN_ACTION_REDIRECT) {
			/* Construct reply (Type 129, Code 0) */
			const uint8_t* icmp_payload = payload + sizeof(icmp6_hdr);
			size_t icmp_payload_len = len - sizeof(icmp6_hdr);
			if (!icmp_send_packet6(ctx, ip->daddr, ip->saddr, ICMP6_ECHO_REPLY, 0,
				icmp->id, icmp->seq, icmp_payload, icmp_payload_len)) {
				LOG_W("handle_icmp6: failed to send Echo Reply");
			}
		} else {
			proxy_icmp6(ctx, ip, icmp, payload, len, rule);
		}
	}
}

static void proxy_icmp4(Context* ctx, const ip4_hdr* ip, const icmp4_hdr* icmp,
    const uint8_t* payload, size_t len, const RuleResult& rule) {
	/* Attempt to proxy ICMP using unprivileged socket */
	IcmpFlowKey4 key4 = {ip->saddr, ip->daddr, icmp->id};
	LOG_D("handle_icmp4: looking up flow");
	IcmpFlow* flow = find_ipv4_icmp_flow(ctx, key4);
	LOG_D("handle_icmp4: flow lookup done, flow=%p", flow);

	if (!flow) {
		if (ctx->num_c_ipv4_icmp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of ICMP flows reached, dropping");
			return;
		}

		flow = alloc_ipv4_icmp_flow(ctx);
		if (!flow) {
			LOG_E("Failed to allocate Flow (table full)");
			return;
		}

		int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
		if (fd == -1) {
			PLOG_W("socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) failed. "
			       "You may need: sysctl -w net.ipv4.ping_group_range='0 2147483647'");
			send_icmp4_error(ctx, ip, ntohs(ip->tot_len), ICMP_DEST_UNREACH,
			    ICMP_HOST_UNREACH); /* host unreachable */
			return;
		}
		if (fd >= static_cast<int>(nstun::NSTUN_MAX_FDS)) {
			LOG_E("FD limit reached (fd=%d)", fd);
			close(fd);
			return;
		}

		if (!monitor::addFd(fd, EPOLLIN, host_callback, ctx)) {
			PLOG_E("monitor::addFd() for ICMP failed");
			close(fd);
			return;
		}

		/* Initialize flow */
		init_icmp_flow_zero(flow);
		flow->header.active = true;
		flow->header.host_fd = fd;
		flow->header.is_ipv6 = false;
		flow->header.icmp_key4 = key4;
		flow->header.last_active = time(nullptr);

		flow->header.is_redirected = (rule.redirect_ip4 != 0);
		flow->header.orig_dest_ip4 = ip->daddr;
		flow->header.redirect_ip4 = rule.redirect_ip4;

		ctx->num_c_ipv4_icmp_flows++;
		if (fd >= 0 && static_cast<size_t>(fd) < nstun::NSTUN_MAX_FDS) {
			ctx->c_icmp_flows_by_fd[fd] = flow;
		}

		if (flow->header.is_redirected) {
			LOG_D("Created ICMP flow for ID %u (fd=%d) [redirected to %s]",
			    ntohs(key4.id), fd, ip4_to_string(rule.redirect_ip4).c_str());
		} else {
			LOG_D("Created ICMP flow for ID %u (fd=%d)", ntohs(key4.id), fd);
		}
	}

	struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
	dest_addr.sin_addr.s_addr =
	    flow->header.is_redirected ? flow->header.redirect_ip4 : flow->header.orig_dest_ip4;

	ssize_t sent = TEMP_FAILURE_RETRY(sendto(flow->header.host_fd, payload, len, MSG_NOSIGNAL,
	    reinterpret_cast<const sockaddr*>(&dest_addr), sizeof(dest_addr)));
	if (sent == -1) {
		PLOG_E("sendto(fd=%d) ICMP failed", flow->header.host_fd);
	}
}

void handle_icmp4(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len) {
	LOG_D("handle_icmp4: started, payload size=%zu", len);
	if (len < sizeof(icmp4_hdr)) {
		LOG_D("handle_icmp4: payload too small");
		return;
	}

	icmp4_hdr icmp_storage;
	memcpy(&icmp_storage, payload, sizeof(icmp_storage));
	const icmp4_hdr* icmp = &icmp_storage;

	/* Validate ICMP checksum */
	LOG_D("handle_icmp4: validating checksum");
	if (compute_checksum(payload, len) != 0) {
		LOG_D("Invalid ICMP checksum, dropping");
		return;
	}

	/* We only handle Echo Request (Type 8, Code 0) */
	LOG_D("handle_icmp4: type=%u, code=%u", icmp->type, icmp->code);
	if (icmp->type == ICMP_ECHO && icmp->code == 0) {
		LOG_D("handle_icmp4: evaluating rules");
		RuleResult rule = evaluate_rules4(
		    ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_ICMP, ip->saddr, ip->daddr, 0, 0);

		LOG_D("handle_icmp4: rule action=%d", rule.action);
		switch (rule.action) {
		case NSTUN_ACTION_DROP:
			LOG_D("ICMP dropped by policy");
			return;
		case NSTUN_ACTION_REJECT:
			LOG_D("ICMP rejected by policy");
			send_icmp4_error(ctx, ip, ntohs(ip->tot_len), ICMP_DEST_UNREACH,
			    ICMP_PORT_UNREACH); /* Dest unreach, port unreach */
			return;
		default:
			break;
		}

		LOG_D("handle_icmp4: checking dest IP");
		if (ip->daddr == ctx->host_ip4 && rule.action != NSTUN_ACTION_REDIRECT) {
			LOG_D("handle_icmp4: sending echo reply");
			/* Construct reply (Type 0, Code 0) */
			const uint8_t* icmp_payload = payload + sizeof(icmp4_hdr);
			size_t icmp_payload_len = len - sizeof(icmp4_hdr);
			if (!icmp_send_packet4(ctx, ip->daddr, ip->saddr, ICMP_ECHOREPLY, 0,
				icmp->id, icmp->seq, icmp_payload, icmp_payload_len)) {
				LOG_W("handle_icmp4: failed to send Echo Reply");
			}
		} else {
			LOG_D("handle_icmp4: proxying ICMP");
			proxy_icmp4(ctx, ip, icmp, payload, len, rule);
		}
	}
}

static void handle_host_icmp(Context* ctx, IcmpFlow* flow) {
	int fd = flow->header.host_fd;
	flow->header.last_active = time(nullptr);

	memset(ctx->recvmmsg_msgs, 0, sizeof(ctx->recvmmsg_msgs));
	for (int i = 0; i < VLEN; ++i) {
		ctx->recvmmsg_iovecs[i].iov_base = ctx->recvmmsg_bufs[i];
		ctx->recvmmsg_iovecs[i].iov_len = sizeof(ctx->recvmmsg_bufs[i]);
		ctx->recvmmsg_msgs[i].msg_hdr.msg_iov = &ctx->recvmmsg_iovecs[i];
		ctx->recvmmsg_msgs[i].msg_hdr.msg_iovlen = 1;
		ctx->recvmmsg_msgs[i].msg_hdr.msg_name = &ctx->recvmmsg_addrs[i];
		ctx->recvmmsg_msgs[i].msg_hdr.msg_namelen = sizeof(ctx->recvmmsg_addrs[i]);
	}

	int retval =
	    TEMP_FAILURE_RETRY(recvmmsg(fd, ctx->recvmmsg_msgs, VLEN, MSG_DONTWAIT, nullptr));
	if (retval == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		PLOG_E("recvmmsg(fd=%d) ICMP failed", fd);
		icmp_destroy_flow(ctx, flow);
		return;
	}
	if (retval == 0) {
		return;
	}

	for (int i = 0; i < retval; ++i) {
		uint8_t* data_ptr = ctx->recvmmsg_bufs[i];
		size_t recv_len = ctx->recvmmsg_msgs[i].msg_len;
		const struct sockaddr_storage* src_addr_storage = &ctx->recvmmsg_addrs[i];

		if (flow->header.is_ipv6) {
			if ((size_t)recv_len >= sizeof(icmp6_hdr)) {
				icmp6_hdr icmp6;
				memcpy(&icmp6, data_ptr, sizeof(icmp6));
				const uint8_t* icmp_payload = data_ptr + sizeof(icmp6_hdr);
				size_t icmp_payload_len = recv_len - sizeof(icmp6_hdr);

				uint8_t saddr6[IPV6_ADDR_LEN];
				if (flow->header.is_redirected) {
					memcpy(saddr6, flow->header.orig_dest_ip6, sizeof(saddr6));
				} else {
					const struct sockaddr_in6* src6 =
					    reinterpret_cast<const struct sockaddr_in6*>(
						src_addr_storage);
					memcpy(saddr6, &src6->sin6_addr, sizeof(saddr6));
				}

				if (!icmp_send_packet6(ctx, saddr6, flow->header.icmp_key6.saddr6,
					icmp6.type, icmp6.code, flow->header.icmp_key6.id,
					icmp6.seq, icmp_payload, icmp_payload_len)) {
					LOG_W("handle_host_icmp: failed to send ICMPv6 packet to "
					      "guest");
				}
			}
		} else {
			const struct sockaddr_in* src_addr =
			    reinterpret_cast<const struct sockaddr_in*>(src_addr_storage);
			uint32_t saddr = flow->header.is_redirected ? flow->header.orig_dest_ip4
								    : src_addr->sin_addr.s_addr;
			uint32_t daddr = flow->header.icmp_key4.saddr4;

			if ((size_t)recv_len >= sizeof(icmp4_hdr)) {
				icmp4_hdr icmp4;
				memcpy(&icmp4, data_ptr, sizeof(icmp4));
				const uint8_t* icmp_payload = data_ptr + sizeof(icmp4_hdr);
				size_t icmp_payload_len = recv_len - sizeof(icmp4_hdr);

				if (!icmp_send_packet4(ctx, saddr, daddr, icmp4.type, icmp4.code,
					flow->header.icmp_key4.id, icmp4.seq, icmp_payload,
					icmp_payload_len)) {
					LOG_W("handle_host_icmp: failed to send ICMP packet to "
					      "guest");
				}
			}
		}
	}
}

void icmp_handle_host_event(Context* ctx, IcmpFlow* flow, int fd, uint32_t events) {
	if (fd == flow->header.host_fd) {
		handle_host_icmp(ctx, flow);
	}
}

bool icmp_is_stale(const IcmpFlow* flow, time_t now) {
	return (now - flow->header.last_active) > ICMP_TIMEOUT;
}

void icmp_destroy(Context* ctx, IcmpFlow* flow) {
	if (flow->header.is_ipv6) {
		LOG_D("GC: stale ICMP flow (IPv6, id=%u)", ntohs(flow->header.icmp_key6.id));
	} else {
		LOG_D("GC: stale ICMP flow (id=%u)", ntohs(flow->header.icmp_key4.id));
	}

	icmp_destroy_flow(ctx, flow);
}

} /* namespace nstun */
