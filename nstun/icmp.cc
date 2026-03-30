#include "icmp.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core.h"
#include "logs.h"
#include "macros.h"
#include "tun.h"

namespace nstun {

/* Extremely simple ICMP echo responder (ping). */
/* In the future, this could use socket(AF_INET, SOCK_DGRAM, NSTUN_IPPROTO_ICMP) */
/* to actually proxy pings to the outside world, but for now let's just */
/* answer them if they are directed at the gateway/host. */

void icmp_destroy_flow(Context* ctx, IcmpFlow* flow) {
	if (flow->host_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->host_fd, nullptr);
		close(flow->host_fd);
	}
	ctx->icmp_flows_by_key.erase(flow->key);
	if (flow->host_fd != -1) {
		ctx->icmp_flows_by_host_fd.erase(flow->host_fd);
	}
	delete flow;
}

static void icmp_send_packet(Context* ctx, uint32_t saddr, uint32_t daddr, uint8_t type,
    uint8_t code, uint16_t id, uint16_t seq, const uint8_t* data, size_t len) {
	size_t frame_len = sizeof(ip4_hdr) + sizeof(icmp_hdr) + len;
	uint8_t* frame_buf = new uint8_t[frame_len]();
	defer {
		delete[] frame_buf;
	};

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(frame_buf);
	icmp_hdr* r_icmp = reinterpret_cast<icmp_hdr*>(frame_buf + sizeof(ip4_hdr));
	uint8_t* r_data = frame_buf + sizeof(ip4_hdr) + sizeof(icmp_hdr);

	/* IPv4 */
	r_ip->ihl_version = (4 << 4) | (sizeof(ip4_hdr) / 4);
	r_ip->tos = 0;
	r_ip->tot_len = htons(frame_len);
	r_ip->id = 0;
	r_ip->frag_off = 0;
	r_ip->ttl = 64;
	r_ip->protocol = NSTUN_IPPROTO_ICMP;
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

	if (data && len > 0) {
		memcpy(r_data, data, len);
	}

	r_icmp->check = compute_checksum(r_icmp, sizeof(icmp_hdr) + len);

	send_to_guest(ctx, frame_buf, frame_len);
}

void send_icmp_error(Context* ctx, const ip4_hdr* req_ip, uint8_t type, uint8_t code) {
	size_t req_ihl = ip4_ihl(req_ip) * 4;
	size_t icmp_data_len = req_ihl + 8; /* IP header + 8 bytes of original datagram */

	if (sizeof(ip4_hdr) + sizeof(icmp_hdr) + icmp_data_len > 128) return;

	icmp_send_packet(ctx, req_ip->daddr, req_ip->saddr, type, code, 0, 0,
	    reinterpret_cast<const uint8_t*>(req_ip), icmp_data_len);
}

void handle_icmp(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(icmp_hdr)) {
		return;
	}

	const icmp_hdr* icmp = reinterpret_cast<const icmp_hdr*>(payload);

	/* We only handle Echo Request (Type 8, Code 0) */
	if (icmp->type == 8 && icmp->code == 0) {
		RuleResult rule = evaluate_rules(
		    ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_ICMP, ip->saddr, ip->daddr, 0, 0);

		if (rule.action == NSTUN_ACTION_DROP) {
			LOG_D("ICMP dropped by policy");
			return;
		} else if (rule.action == NSTUN_ACTION_REJECT) {
			LOG_D("ICMP rejected by policy");
			send_icmp_error(ctx, ip, 3, 3); /* Dest unreach, port unreach */
			return;
		}

		if (ip->daddr == ctx->host_ip && rule.action != NSTUN_ACTION_REDIRECT) {
			/* Construct reply (Type 0, Code 0) */
			const uint8_t* icmp_payload = payload + sizeof(icmp_hdr);
			size_t icmp_payload_len = len - sizeof(icmp_hdr);
			icmp_send_packet(ctx, ip->daddr, ip->saddr, 0, 0, icmp->id, icmp->seq,
			    icmp_payload, icmp_payload_len);
		} else {
			/* Attempt to proxy ICMP using unprivileged socket */
			IcmpFlowKey key = {ip->saddr, ip->daddr, icmp->id};
			IcmpFlow* flow = nullptr;
			auto it = ctx->icmp_flows_by_key.find(key);

			if (it != ctx->icmp_flows_by_key.end()) {
				flow = it->second;
				flow->last_active = time(NULL);
			} else {
				if (ctx->icmp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
					LOG_W(
					    "Maximum number of ICMP flows (%zu) reached, dropping",
					    NSTUN_MAX_FLOWS);
					return;
				}

				int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
				    NSTUN_IPPROTO_ICMP);
				if (fd == -1) {
					PLOG_W(
					    "socket(AF_INET, SOCK_DGRAM, NSTUN_IPPROTO_ICMP) "
					    "failed. "
					    "You may need: sysctl -w net.ipv4.ping_group_range='0 "
					    "2147483647'");
					send_icmp_error(ctx, ip, 3, 1); /* host unreachable */
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
				flow->key = key;
				flow->last_active = time(NULL);
				flow->is_redirected = (rule.redirect_ip != 0);
				flow->orig_dest_ip = ip->daddr;

				ctx->icmp_flows_by_key[key] = flow;
				ctx->icmp_flows_by_host_fd[fd] = flow;

				if (flow->is_redirected) {
					const uint8_t* rip =
					    reinterpret_cast<const uint8_t*>(&rule.redirect_ip);
					LOG_D("Created ICMP flow for ID %u (fd=%d) [redirected to "
					      "%u.%u.%u.%u]",
					    ntohs(key.id), fd, rip[0], rip[1], rip[2], rip[3]);
				} else {
					LOG_D("Created ICMP flow for ID %u (fd=%d)", ntohs(key.id),
					    fd);
				}
			}
			struct sockaddr_in dest_addr = {};
			dest_addr.sin_family = AF_INET;
			dest_addr.sin_addr.s_addr =
			    (rule.redirect_ip != 0) ? rule.redirect_ip : ip->daddr;

			ssize_t sent = sendto(flow->host_fd, payload, len, 0,
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

	uint8_t buf[65536];
	struct sockaddr_in src_addr = {};
	socklen_t addrlen = sizeof(src_addr);

	ssize_t recv_len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &addrlen);
	if (recv_len <= 0) {
		if (recv_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return;
		}
		PLOG_E("recvfrom(fd=%d) ICMP failed", fd);
		icmp_destroy_flow(ctx, flow);
		return;
	}

	uint32_t saddr = flow->is_redirected ? flow->orig_dest_ip : src_addr.sin_addr.s_addr;
	uint32_t daddr = flow->key.saddr;

	if ((size_t)recv_len >= sizeof(icmp_hdr)) {
		icmp_hdr* r_icmp = reinterpret_cast<icmp_hdr*>(buf);
		const uint8_t* icmp_payload = buf + sizeof(icmp_hdr);
		size_t icmp_payload_len = recv_len - sizeof(icmp_hdr);

		icmp_send_packet(ctx, saddr, daddr, r_icmp->type, r_icmp->code, flow->key.id,
		    r_icmp->seq, icmp_payload, icmp_payload_len);
	}
}

} /* namespace nstun */
