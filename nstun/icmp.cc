#include "icmp.h"

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core.h"
#include "logs.h"
#include "macros.h"
#include "tun.h"

namespace nstun {

void icmp_destroy_flow(Context* ctx, IcmpFlow* flow) {
	if (flow->host_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->host_fd, nullptr);
		close(flow->host_fd);
	}
	if (flow->is_ipv6) {
		ctx->ipv6_icmp_flows_by_key.erase(flow->key6);
	} else {
		ctx->ipv4_icmp_flows_by_key.erase(flow->key4);
	}
	if (flow->host_fd != -1) {
		ctx->icmp_flows_by_host_fd.erase(flow->host_fd);
	}
	delete flow;
}

static void icmp_send_packet4(Context* ctx, uint32_t saddr, uint32_t daddr, uint8_t type,
    uint8_t code, uint16_t id, uint16_t seq, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("icmp_send_packet4: data length too large");
		return;
	}

	size_t frame_len = sizeof(ip4_hdr) + sizeof(icmp4_hdr) + len;
	static thread_local uint8_t header_buf[sizeof(ip4_hdr) + sizeof(icmp4_hdr)];
	memset(header_buf, 0, sizeof(header_buf));

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(header_buf);
	icmp4_hdr* r_icmp = reinterpret_cast<icmp4_hdr*>(header_buf + sizeof(ip4_hdr));

	/* IPv4 */
	r_ip->ihl_version = (4 << 4) | (sizeof(ip4_hdr) / 4);
	r_ip->tos = 0;
	r_ip->tot_len = htons(frame_len);
	r_ip->id = 0;
	r_ip->frag_off = 0;
	r_ip->ttl = 64;
	r_ip->protocol = IPPROTO_ICMP;
	r_ip->saddr = saddr;
	r_ip->daddr = daddr;
	r_ip->check = 0;
	r_ip->check = compute_checksum(r_ip, sizeof(ip4_hdr));

	/* ICMP */
	r_icmp->type = type;
	r_icmp->code = code;
	r_icmp->id = id;
	r_icmp->seq = seq;
	r_icmp->check = 0;

	uint32_t sum = compute_checksum_part(r_icmp, sizeof(icmp4_hdr), 0);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	r_icmp->check = finalize_checksum(sum);

	send_to_guest_v(ctx, header_buf, sizeof(header_buf), data, len);
}

static void icmp_send_packet6(Context* ctx, const uint8_t* saddr, const uint8_t* daddr,
    uint8_t type, uint8_t code, uint16_t id, uint16_t seq, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("icmp_send_packet6: data length too large");
		return;
	}

	static thread_local uint8_t header_buf[sizeof(ip6_hdr) + sizeof(icmp6_hdr)];
	memset(header_buf, 0, sizeof(header_buf));

	ip6_hdr* r_ip6 = reinterpret_cast<ip6_hdr*>(header_buf);
	icmp6_hdr* r_icmp6 = reinterpret_cast<icmp6_hdr*>(header_buf + sizeof(ip6_hdr));

	/* IPv6 */
	r_ip6->vtf = htonl(0x60000000); /* Version 6 */
	r_ip6->payload_len = htons(sizeof(icmp6_hdr) + len);
	r_ip6->next_header = IPPROTO_ICMPV6;
	r_ip6->hop_limit = 64;
	memcpy(r_ip6->saddr, saddr, sizeof(r_ip6->saddr));
	memcpy(r_ip6->daddr, daddr, sizeof(r_ip6->daddr));

	/* ICMPv6 */
	r_icmp6->type = type;
	r_icmp6->code = code;
	r_icmp6->id = id;
	r_icmp6->seq = seq;
	r_icmp6->check = 0;

	/* 40-byte IPv6 pseudo header */
	pseudo_hdr6 phdr = {};
	phdr.len = htonl(sizeof(icmp6_hdr) + len);
	phdr.next_header = IPPROTO_ICMPV6;
	memcpy(phdr.saddr, saddr, sizeof(phdr.saddr));
	memcpy(phdr.daddr, daddr, sizeof(phdr.daddr));

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(r_icmp6, sizeof(icmp6_hdr), sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	r_icmp6->check = finalize_checksum(sum);

	send_to_guest_v(ctx, header_buf, sizeof(header_buf), data, len);
}

void send_icmp4_error(Context* ctx, const ip4_hdr* req_ip, uint8_t type, uint8_t code) {
	size_t req_ihl = ip4_ihl(req_ip) * 4;
	size_t icmp_data_len = req_ihl + 8; /* IP header + 8 bytes of original datagram */

	if (sizeof(ip4_hdr) + sizeof(icmp4_hdr) + icmp_data_len > 128) return;

	icmp_send_packet4(ctx, req_ip->daddr, req_ip->saddr, type, code, 0, 0,
	    reinterpret_cast<const uint8_t*>(req_ip), icmp_data_len);
}

void send_icmp6_error(Context* ctx, const ip6_hdr* req_ip, uint8_t type, uint8_t code) {
	size_t icmp_data_len = sizeof(ip6_hdr) + 8; /* IPv6 header + 8 bytes of original datagram */

	if (sizeof(ip6_hdr) + sizeof(icmp6_hdr) + icmp_data_len > 128) return;

	icmp_send_packet6(ctx, req_ip->daddr, req_ip->saddr, type, code, 0, 0,
	    reinterpret_cast<const uint8_t*>(req_ip), icmp_data_len);
}

void handle_icmp6(Context* ctx, const ip6_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(icmp6_hdr)) {
		return;
	}

	const icmp6_hdr* icmp = reinterpret_cast<const icmp6_hdr*>(payload);

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

		if (rule.action == NSTUN_ACTION_DROP) {
			LOG_D("ICMPv6 dropped by policy");
			return;
		} else if (rule.action == NSTUN_ACTION_REJECT) {
			LOG_D("ICMPv6 rejected by policy");
			send_icmp6_error(ctx, ip, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_NOPORT); /* Dest unreachable, port unreachable */
			return;
		}

		if (memcmp(ip->daddr, ctx->host_ip6, 16) == 0 &&
		    rule.action != NSTUN_ACTION_REDIRECT) {
			/* Construct reply (Type 129, Code 0) */
			const uint8_t* icmp_payload = payload + sizeof(icmp6_hdr);
			size_t icmp_payload_len = len - sizeof(icmp6_hdr);
			icmp_send_packet6(ctx, ip->daddr, ip->saddr, ICMP6_ECHO_REPLY, 0, icmp->id,
			    icmp->seq, icmp_payload, icmp_payload_len);
		} else {
			/* Attempt to proxy ICMP using unprivileged socket */
			IcmpFlowKey6 key6 = {};
			memcpy(key6.saddr6, ip->saddr, sizeof(key6.saddr6));
			memcpy(key6.daddr6, ip->daddr, sizeof(key6.daddr6));
			key6.id = icmp->id;

			IcmpFlow* flow = nullptr;
			auto it = ctx->ipv6_icmp_flows_by_key.find(key6);

			if (it != ctx->ipv6_icmp_flows_by_key.end()) {
				flow = it->second;
				flow->last_active = time(NULL);
			} else {
				if (ctx->ipv6_icmp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
					LOG_W("Maximum number of IPv6 ICMP flows (%zu) reached, "
					      "dropping",
					    NSTUN_MAX_FLOWS);
					return;
				}

				int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
				    IPPROTO_ICMPV6);
				if (fd == -1) {
					PLOG_W("socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) "
					       "failed.");
					return;
				}

				bool success = false;
				defer {
					if (!success) {
						close(fd);
					}
				};

				struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = fd}};
				if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
					PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for ICMPv6 failed");
					return;
				}

				success = true;

				flow = new IcmpFlow();
				flow->host_fd = fd;
				flow->is_ipv6 = true;
				flow->key6 = key6;
				flow->last_active = time(NULL);
				flow->is_redirected = rule.has_redirect_ip6;
				memcpy(flow->orig_dest_ip6, ip->daddr, sizeof(flow->orig_dest_ip6));

				ctx->ipv6_icmp_flows_by_key[key6] = flow;
				ctx->icmp_flows_by_host_fd[fd] = flow;

				if (flow->is_redirected) {
					LOG_D(
					    "Created IPv6 ICMP flow for ID %u (fd=%d) [redirected]",
					    ntohs(key6.id), fd);
				} else {
					LOG_D("Created IPv6 ICMP flow for ID %u (fd=%d)",
					    ntohs(key6.id), fd);
				}
			}
			struct sockaddr_in6 dest_addr = INIT_SOCKADDR_IN6(AF_INET6);
			if (rule.has_redirect_ip6) {
				memcpy(&dest_addr.sin6_addr, rule.redirect_ip6,
				    sizeof(dest_addr.sin6_addr));
			} else {
				memcpy(
				    &dest_addr.sin6_addr, ip->daddr, sizeof(dest_addr.sin6_addr));
			}

			ssize_t sent = sendto(flow->host_fd, payload, len, MSG_NOSIGNAL,
			    (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			if (sent == -1) {
				PLOG_E("sendto(fd=%d) ICMPv6 failed", flow->host_fd);
			}
		}
	}
}

void handle_icmp4(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(icmp4_hdr)) {
		return;
	}

	const icmp4_hdr* icmp = reinterpret_cast<const icmp4_hdr*>(payload);

	/* We only handle Echo Request (Type 8, Code 0) */
	if (icmp->type == ICMP_ECHO && icmp->code == 0) {
		RuleResult rule = evaluate_rules4(
		    ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_ICMP, ip->saddr, ip->daddr, 0, 0);

		if (rule.action == NSTUN_ACTION_DROP) {
			LOG_D("ICMP dropped by policy");
			return;
		} else if (rule.action == NSTUN_ACTION_REJECT) {
			LOG_D("ICMP rejected by policy");
			send_icmp4_error(ctx, ip, ICMP_DEST_UNREACH,
			    ICMP_PORT_UNREACH); /* Dest unreach, port unreach */
			return;
		}

		if (ip->daddr == ctx->host_ip4 && rule.action != NSTUN_ACTION_REDIRECT) {
			/* Construct reply (Type 0, Code 0) */
			const uint8_t* icmp_payload = payload + sizeof(icmp4_hdr);
			size_t icmp_payload_len = len - sizeof(icmp4_hdr);
			icmp_send_packet4(ctx, ip->daddr, ip->saddr, ICMP_ECHOREPLY, 0, icmp->id,
			    icmp->seq, icmp_payload, icmp_payload_len);
		} else {
			/* Attempt to proxy ICMP using unprivileged socket */
			IcmpFlowKey4 key4 = {ip->saddr, ip->daddr, icmp->id};
			IcmpFlow* flow = nullptr;
			auto it = ctx->ipv4_icmp_flows_by_key.find(key4);

			if (it != ctx->ipv4_icmp_flows_by_key.end()) {
				flow = it->second;
				flow->last_active = time(NULL);
			} else {
				if (ctx->ipv4_icmp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
					LOG_W(
					    "Maximum number of ICMP flows (%zu) reached, dropping",
					    NSTUN_MAX_FLOWS);
					return;
				}

				int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
				    IPPROTO_ICMP);
				if (fd == -1) {
					PLOG_W(
					    "socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) "
					    "failed. "
					    "You may need: sysctl -w net.ipv4.ping_group_range='0 "
					    "2147483647'");
					send_icmp4_error(ctx, ip, ICMP_DEST_UNREACH,
					    ICMP_HOST_UNREACH); /* host unreachable */
					return;
				}

				bool success = false;
				defer {
					if (!success) {
						close(fd);
					}
				};

				struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = fd}};
				if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
					PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for ICMP failed");
					return;
				}

				success = true;

				flow = new IcmpFlow();
				flow->host_fd = fd;
				flow->is_ipv6 = false;
				flow->key4 = key4;
				flow->last_active = time(NULL);
				flow->is_redirected = (rule.redirect_ip4 != 0);
				flow->orig_dest_ip4 = ip->daddr;

				ctx->ipv4_icmp_flows_by_key[key4] = flow;
				ctx->icmp_flows_by_host_fd[fd] = flow;

				if (flow->is_redirected) {
					const uint8_t* rip =
					    reinterpret_cast<const uint8_t*>(&rule.redirect_ip4);
					LOG_D("Created ICMP flow for ID %u (fd=%d) [redirected to "
					      "%u.%u.%u.%u]",
					    ntohs(key4.id), fd, rip[0], rip[1], rip[2], rip[3]);
				} else {
					LOG_D("Created ICMP flow for ID %u (fd=%d)", ntohs(key4.id),
					    fd);
				}
			}
			struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
			dest_addr.sin_addr.s_addr =
			    (rule.redirect_ip4 != 0) ? rule.redirect_ip4 : ip->daddr;

			ssize_t sent = sendto(flow->host_fd, payload, len, MSG_NOSIGNAL,
			    (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			if (sent == -1) {
				PLOG_E("sendto(fd=%d) ICMP failed", flow->host_fd);
			}
		}
	}
}

void handle_host_icmp(Context* ctx, int fd) {
	auto it = ctx->icmp_flows_by_host_fd.find(fd);
	if (it == ctx->icmp_flows_by_host_fd.end()) {
		return;
	}
	IcmpFlow* flow = it->second;
	flow->last_active = time(NULL);

	constexpr int VLEN = 64;
	struct mmsghdr msgs[VLEN];
	struct iovec iovecs[VLEN];
	static uint8_t (*bufs)[NSTUN_MTU] = new uint8_t[VLEN][NSTUN_MTU];
	static struct sockaddr_storage* src_addrs = new struct sockaddr_storage[VLEN];

	for (int i = 0; i < VLEN; ++i) {
		iovecs[i].iov_base = bufs[i];
		iovecs[i].iov_len = sizeof(bufs[i]);
		msgs[i].msg_hdr.msg_iov = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_name = &src_addrs[i];
		msgs[i].msg_hdr.msg_namelen = sizeof(src_addrs[i]);
		msgs[i].msg_hdr.msg_control = nullptr;
		msgs[i].msg_hdr.msg_controllen = 0;
	}

	int retval = recvmmsg(fd, msgs, VLEN, MSG_DONTWAIT, nullptr);
	if (retval == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		PLOG_E("recvmmsg(fd=%d) ICMP failed", fd);
		icmp_destroy_flow(ctx, flow);
		return;
	}

	for (int i = 0; i < retval; ++i) {
		uint8_t* data_ptr = bufs[i];
		size_t recv_len = msgs[i].msg_len;
		struct sockaddr_storage* src_addr_storage = &src_addrs[i];

		if (flow->is_ipv6) {
			if ((size_t)recv_len >= sizeof(icmp6_hdr)) {
				icmp6_hdr* r_icmp6 = reinterpret_cast<icmp6_hdr*>(data_ptr);
				const uint8_t* icmp_payload = data_ptr + sizeof(icmp6_hdr);
				size_t icmp_payload_len = recv_len - sizeof(icmp6_hdr);

				uint8_t saddr6[16];
				if (flow->is_redirected) {
					memcpy(saddr6, flow->orig_dest_ip6, sizeof(saddr6));
				} else {
					struct sockaddr_in6* src6 =
					    reinterpret_cast<struct sockaddr_in6*>(
						src_addr_storage);
					memcpy(saddr6, &src6->sin6_addr, sizeof(saddr6));
				}

				icmp_send_packet6(ctx, saddr6, flow->key6.saddr6, r_icmp6->type,
				    r_icmp6->code, flow->key6.id, r_icmp6->seq, icmp_payload,
				    icmp_payload_len);
			}
		} else {
			struct sockaddr_in* src_addr =
			    reinterpret_cast<struct sockaddr_in*>(src_addr_storage);
			uint32_t saddr =
			    flow->is_redirected ? flow->orig_dest_ip4 : src_addr->sin_addr.s_addr;
			uint32_t daddr = flow->key4.saddr4;

			if ((size_t)recv_len >= sizeof(icmp4_hdr)) {
				icmp4_hdr* r_icmp = reinterpret_cast<icmp4_hdr*>(data_ptr);
				const uint8_t* icmp_payload = data_ptr + sizeof(icmp4_hdr);
				size_t icmp_payload_len = recv_len - sizeof(icmp4_hdr);

				icmp_send_packet4(ctx, saddr, daddr, r_icmp->type, r_icmp->code,
				    flow->key4.id, r_icmp->seq, icmp_payload, icmp_payload_len);
			}
		}
	}
}

} /* namespace nstun */
