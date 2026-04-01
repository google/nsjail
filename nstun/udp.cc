#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core.h"
#include "encap.h"
#include "icmp.h"
#include "logs.h"
#include "macros.h"
#include "policy.h"
#include "tun.h"

namespace nstun {

static void udp_destroy_flow(Context* ctx, UdpFlow* flow) {
	if (flow->host_fd != -1 && !flow->host_fd_is_listener) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->host_fd, nullptr);
		ctx->flows_by_fd.erase(flow->host_fd);
	}
	if (flow->tcp_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->tcp_fd, nullptr);
		ctx->flows_by_fd.erase(flow->tcp_fd);
	}
	/* Erase from owning map last — unique_ptr runs ~UdpFlow() which closes fds */
	if (flow->is_ipv6) {
		ctx->ipv6_udp_flows_by_key.erase(flow->key6);
	} else {
		ctx->ipv4_udp_flows_by_key.erase(flow->key4);
	}
}

static void udp_send_packet4(Context* ctx, uint32_t saddr, uint32_t daddr, uint16_t sport,
    uint16_t dport, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("udp_send_packet4: data length too large");
		return;
	}

	static thread_local uint8_t header_buf[sizeof(ip4_hdr) + sizeof(udp_hdr)];

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(header_buf);
	udp_hdr* r_udp = reinterpret_cast<udp_hdr*>(header_buf + sizeof(ip4_hdr));

	/* IPv4 */
	ip4_set_ihl_version(r_ip, 4, sizeof(ip4_hdr) / 4);
	r_ip->tos = 0;
	r_ip->tot_len = htons(sizeof(ip4_hdr) + sizeof(udp_hdr) + len);
	r_ip->id = 0;
	r_ip->frag_off = 0;
	r_ip->ttl = 64;
	r_ip->protocol = IPPROTO_UDP;
	r_ip->saddr = saddr;
	r_ip->daddr = daddr;
	r_ip->check = 0;
	r_ip->check = compute_checksum(r_ip, sizeof(ip4_hdr));

	/* UDP */
	r_udp->source = sport;
	r_udp->dest = dport;
	r_udp->len = htons(sizeof(udp_hdr) + len);
	r_udp->check = 0;

	pseudo_hdr4 phdr = {.saddr = saddr,
	    .daddr = daddr,
	    .zero = 0,
	    .protocol = IPPROTO_UDP,
	    .len = htons(sizeof(udp_hdr) + len)};

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(r_udp, sizeof(udp_hdr), sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}

	r_udp->check = finalize_checksum(sum);
	if (r_udp->check == 0) {
		r_udp->check = 0xFFFF;
	}

	send_to_guest_v(ctx, header_buf, sizeof(header_buf), data, len);
}

/* Forward declare for use in handle_host_udp */
static void udp_send_packet6(Context* ctx, const uint8_t* saddr, const uint8_t* daddr,
    uint16_t sport, uint16_t dport, const uint8_t* data, size_t len);

static void udp_push_to_guest(Context* ctx, UdpFlow* flow, const uint8_t* data, size_t data_len,
    const struct sockaddr_storage* src_addr_storage) {
	if (flow->is_ipv6) {
		uint8_t saddr6[16];
		uint8_t daddr6[16];
		uint16_t sport, dport;

		memcpy(daddr6, flow->key6.saddr6, sizeof(daddr6));
		dport = flow->key6.sport;

		if (flow->is_redirected || flow->use_socks5) {
			memcpy(saddr6, flow->orig_dest_ip6, sizeof(saddr6));
			sport = htons(flow->orig_dest_port);
		} else if (src_addr_storage) {
			const struct sockaddr_in6* src6 =
			    reinterpret_cast<const struct sockaddr_in6*>(src_addr_storage);
			memcpy(saddr6, &src6->sin6_addr, sizeof(saddr6));
			sport = src6->sin6_port;
		} else {
			return;
		}

		udp_send_packet6(ctx, saddr6, daddr6, sport, dport, data, data_len);
	} else {
		uint32_t saddr, daddr;
		uint16_t sport, dport;

		daddr = flow->key4.saddr4;
		dport = flow->key4.sport;

		if (flow->is_redirected || flow->use_socks5) {
			saddr = flow->orig_dest_ip4;
			sport = htons(flow->orig_dest_port);
		} else if (src_addr_storage) {
			const struct sockaddr_in* src_addr =
			    reinterpret_cast<const struct sockaddr_in*>(src_addr_storage);
			saddr = src_addr->sin_addr.s_addr;
			sport = src_addr->sin_port;
		} else {
			return;
		}

		udp_send_packet4(ctx, saddr, daddr, sport, dport, data, data_len);
	}
}

static void handle_host_udp_control(Context* ctx, UdpFlow* flow, uint32_t events) {
	int fd = flow->tcp_fd;
	flow->last_active = time(NULL);

	switch (flow->state) {
	case UdpSocks5State::TCP_CONNECTING: {
		if (!(events & EPOLLOUT)) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		int err = 0;
		socklen_t errlen = sizeof(err);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
		if (err != 0) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		struct epoll_event ev = {
		    .events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);

		if (flow->use_socks5) {
			flow->state = UdpSocks5State::SOCKS5_GREETING;
			if (nstun::send_socks5_greeting(fd) < 0) {
				udp_destroy_flow(ctx, flow);
				return;
			}
		}
		return;
	}

	case UdpSocks5State::SOCKS5_GREETING: {
		socks5_auth_reply reply;
		ssize_t n = recv(fd, &reply, sizeof(reply), MSG_PEEK | MSG_DONTWAIT);
		if (n <= 0) {
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
			udp_destroy_flow(ctx, flow);
			return;
		}
		if (n < (ssize_t)sizeof(reply)) return;
		recv(fd, &reply, sizeof(reply), MSG_DONTWAIT);
		if (!nstun::parse_socks5_auth_reply(std::span<const uint8_t>(
			reinterpret_cast<const uint8_t*>(&reply), sizeof(reply)))) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		flow->state = UdpSocks5State::SOCKS5_ASSOCIATE;
		if (nstun::send_socks5_udp_associate(fd) < 0) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		return;
	}

	case UdpSocks5State::SOCKS5_ASSOCIATE: {
		socks5_req req = {};
		ssize_t n = recv(fd, &req, sizeof(req), MSG_PEEK | MSG_DONTWAIT);
		if (n <= 0) {
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
			udp_destroy_flow(ctx, flow);
			return;
		}
		if (n < 4) return;
		if (req.ver != SOCKS5_VERSION || req.cmd != SOCKS5_REP_SUCCESS) {
			udp_destroy_flow(ctx, flow);
			return;
		}

		size_t expected_len = 0;
		if (req.atyp == SOCKS5_ATYP_IPV4) {
			expected_len = 10;
		} else if (req.atyp == SOCKS5_ATYP_IPV6) {
			expected_len = 22;
		} else if (req.atyp == SOCKS5_ATYP_DOMAIN) {
			socks5_max_buf buf;
			n = recv(fd, &buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
			if (n < 5) return;
			socks5_req_domain* dreq = reinterpret_cast<socks5_req_domain*>(&buf);
			expected_len = 5 + dreq->domain_len + 2;
		} else {
			udp_destroy_flow(ctx, flow);
			return;
		}

		if ((size_t)n < expected_len) return;

		socks5_max_buf buf;
		recv(fd, &buf, expected_len, MSG_DONTWAIT);

		nstun::Socks5Reply res;
		if (!nstun::parse_socks5_connect_reply(
			std::span<const uint8_t>(
			    reinterpret_cast<const uint8_t*>(&buf), expected_len),
			&res)) {
			udp_destroy_flow(ctx, flow);
			return;
		}

		if (res.atyp == SOCKS5_ATYP_IPV4) {
			memcpy(&flow->bnd_ip, &res.bind_ip4, sizeof(flow->bnd_ip));
			memcpy(&flow->bnd_port, &res.bind_port, sizeof(flow->bnd_port));
		} else {
			LOG_E("SOCKS5 UDP proxy returned unsupported address type");
			udp_destroy_flow(ctx, flow);
			return;
		}

		int udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (udp_fd == -1) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		struct sockaddr_in bind_addr = INIT_SOCKADDR_IN(AF_INET);
		bind_addr.sin_addr.s_addr = INADDR_ANY;
		bind_addr.sin_port = 0;
		if (bind(udp_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1) {
			close(udp_fd);
			udp_destroy_flow(ctx, flow);
			return;
		}
		struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = udp_fd}};
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev) == -1) {
			close(udp_fd);
			udp_destroy_flow(ctx, flow);
			return;
		}
		flow->host_fd = udp_fd;
		ctx->flows_by_fd[udp_fd] = flow;
		flow->state = UdpSocks5State::ESTABLISHED;

		for (const auto& pkt : flow->tx_queue) {
			struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
			dest_addr.sin_addr.s_addr = flow->bnd_ip;
			dest_addr.sin_port = flow->bnd_port;

			if (flow->is_ipv6) {
				std::vector<uint8_t> s5_pkt(sizeof(socks5_udp_hdr6) + pkt.size());
				socks5_udp_hdr6* hdr =
				    reinterpret_cast<socks5_udp_hdr6*>(s5_pkt.data());
				hdr->rsv = 0;
				hdr->frag = 0;
				hdr->atyp = SOCKS5_ATYP_IPV6;
				memcpy(hdr->dst_ip6, flow->orig_dest_ip6, sizeof(hdr->dst_ip6));
				hdr->dst_port = htons(flow->orig_dest_port);
				memcpy(s5_pkt.data() + sizeof(socks5_udp_hdr6), pkt.data(),
				    pkt.size());
				sendto(flow->host_fd, s5_pkt.data(), s5_pkt.size(), MSG_NOSIGNAL,
				    (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			} else {
				std::vector<uint8_t> s5_pkt(sizeof(socks5_udp_hdr) + pkt.size());
				socks5_udp_hdr* hdr =
				    reinterpret_cast<socks5_udp_hdr*>(s5_pkt.data());
				hdr->rsv = 0;
				hdr->frag = 0;
				hdr->atyp = SOCKS5_ATYP_IPV4;
				hdr->dst_ip4 = flow->orig_dest_ip4;
				hdr->dst_port = htons(flow->orig_dest_port);
				memcpy(
				    s5_pkt.data() + sizeof(socks5_udp_hdr), pkt.data(), pkt.size());
				sendto(flow->host_fd, s5_pkt.data(), s5_pkt.size(), MSG_NOSIGNAL,
				    (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			}
		}
		flow->tx_queue.clear();
		return;
	}

	case UdpSocks5State::ESTABLISHED:
		/* Detect SOCKS5 TCP control channel death */
		if (events & (EPOLLERR | EPOLLHUP | EPOLLIN)) {
			uint8_t buf[1];
			ssize_t n = recv(fd, buf, 1, MSG_PEEK | MSG_DONTWAIT);
			if (n <= 0) {
				if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
				LOG_D("SOCKS5 TCP control channel died, destroying UDP flow");
				udp_destroy_flow(ctx, flow);
			}
		}
		break;
	}
}

void handle_udp4(Context* ctx, const ip4_hdr* ip, std::span<const uint8_t> payload) {
	if (payload.size() < sizeof(udp_hdr)) {
		return;
	}

	const udp_hdr* udp = reinterpret_cast<const udp_hdr*>(payload.data());
	uint16_t guest_port = ntohs(udp->source);
	uint16_t dest_port = ntohs(udp->dest);

	/* Validate UDP checksum (optional for IPv4 when field is 0) */
	if (udp->check != 0) {
		pseudo_hdr4 phdr = {.saddr = ip->saddr,
		    .daddr = ip->daddr,
		    .zero = 0,
		    .protocol = IPPROTO_UDP,
		    .len = htons(payload.size())};
		uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
		csum = compute_checksum_part(payload.data(), payload.size(), csum);
		if (finalize_checksum(csum) != 0) {
			LOG_D("Invalid IPv4 UDP checksum, dropping");
			return;
		}
	}

	FlowKey4 key4 = {ip->saddr, ip->daddr, udp->source, udp->dest};

	RuleResult rule = evaluate_rules4(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_UDP, ip->saddr,
	    ip->daddr, guest_port, dest_port);

	if (rule.action == NSTUN_ACTION_DROP) {
		LOG_D("UDP flow %u -> %s:%u dropped by policy", guest_port,
		    ip4_to_string(ip->daddr).c_str(), dest_port);
		return;
	} else if (rule.action == NSTUN_ACTION_REJECT) {
		LOG_D("UDP flow %u -> %s:%u rejected by policy", guest_port,
		    ip4_to_string(ip->daddr).c_str(), dest_port);
		send_icmp4_error(ctx, ip, ntohs(ip->tot_len), ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
		return;
	} else if (rule.action == NSTUN_ACTION_ENCAP_CONNECT) {
		LOG_W("HTTP CONNECT proxy not supported for UDP, dropping packet to port %u",
		    dest_port);
		return;
	}

	/* Find or create flow */
	UdpFlow* flow = nullptr;
	auto it = ctx->ipv4_udp_flows_by_key.find(key4);
	if (it != ctx->ipv4_udp_flows_by_key.end()) {
		flow = it->second.get();
		flow->last_active = time(NULL);
	} else {
		if (ctx->ipv4_udp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
			LOG_W(
			    "Maximum number of UDP flows (%zu) reached, dropping", NSTUN_MAX_FLOWS);
			return;
		}

		auto flow_ptr = std::make_unique<UdpFlow>();
		flow = flow_ptr.get();

		flow->host_fd = -1;
		flow->tcp_fd = -1;
		flow->is_ipv6 = false;
		flow->key4 = key4;
		flow->last_active = time(NULL);
		flow->is_redirected = (rule.redirect_ip4 != 0 || rule.redirect_port != 0);
		flow->orig_dest_ip4 = ip->daddr;
		flow->orig_dest_port = dest_port;
		flow->use_socks5 = (rule.action == NSTUN_ACTION_ENCAP_SOCKS5);

		if (flow->use_socks5) {
			int tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
			if (tcp_fd == -1) return;

			bool fd_success = false;
			defer {
				if (!fd_success) close(tcp_fd);
			};

			struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			    .data = {.fd = tcp_fd}};
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, tcp_fd, &ev) == -1) return;

			struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
			dest_addr.sin_addr.s_addr = rule.redirect_ip4;
			dest_addr.sin_port = htons(rule.redirect_port);
			connect(tcp_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			fd_success = true;

			flow->tcp_fd = tcp_fd;
			flow->state = UdpSocks5State::TCP_CONNECTING;
			ctx->ipv4_udp_flows_by_key[key4] = std::move(flow_ptr);
			ctx->flows_by_fd[tcp_fd] = flow;
			LOG_D("Created UDP Proxy flow (socks5=%d) for guest port %u -> tcp fd %d%s",
			    flow->use_socks5 ? 1 : 0, guest_port, tcp_fd,
			    flow->is_redirected ? " [redirected]" : "");
		} else {
			int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
			if (fd == -1) {
				PLOG_E("socket(AF_INET, SOCK_DGRAM) for UDP flow failed");
				return;
			}
			bool fd_success = false;
			defer {
				if (!fd_success) close(fd);
			};

			struct sockaddr_in bind_addr = INIT_SOCKADDR_IN(AF_INET);
			bind_addr.sin_addr.s_addr = INADDR_ANY;
			bind_addr.sin_port = 0; /* Let OS choose */
			if (bind(fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1) {
				PLOG_E("bind() UDP host socket failed");
				return;
			}

			struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = fd}};
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
				PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for UDP host socket failed");
				return;
			}
			fd_success = true;

			flow->host_fd = fd;
			flow->state = UdpSocks5State::ESTABLISHED;
			ctx->ipv4_udp_flows_by_key[key4] = std::move(flow_ptr);
			ctx->flows_by_fd[fd] = flow;
			LOG_D("Created UDP flow for guest port %u -> fd %d%s", guest_port, fd,
			    flow->is_redirected ? " [redirected]" : "");
		}
	}

	auto data_span = payload.subspan(sizeof(udp_hdr));
	const uint8_t* data = data_span.data();
	size_t data_len = data_span.size();

	if (flow->use_socks5 && flow->state != UdpSocks5State::ESTABLISHED) {
		/* Cap queued packet size to prevent memory exhaustion:
		 * 1024 flows * 50 packets * 1500 bytes = ~75MB worst case */
		if (data_len > 1500) {
			LOG_D("UDP proxy queue dropping oversized packet (%zu bytes)", data_len);
			return;
		}
		std::vector<uint8_t> pkt(data, data + data_len);
		flow->tx_queue.push_back(pkt);
		if (flow->tx_queue.size() > 50) {
			/* Do not buffer indefinitely */
			flow->tx_queue.pop_front();
		}
		return;
	}

	struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);

	if (flow->use_socks5) {
		dest_addr.sin_addr.s_addr = flow->bnd_ip;
		dest_addr.sin_port = flow->bnd_port;

		std::vector<uint8_t> s5_pkt(sizeof(socks5_udp_hdr) + data_len);
		socks5_udp_hdr* hdr = reinterpret_cast<socks5_udp_hdr*>(s5_pkt.data());
		hdr->rsv = 0;
		hdr->frag = 0;
		hdr->atyp = SOCKS5_ATYP_IPV4;
		hdr->dst_ip4 = flow->orig_dest_ip4;
		hdr->dst_port = htons(flow->orig_dest_port);
		memcpy(s5_pkt.data() + sizeof(socks5_udp_hdr), data, data_len);

		sendto(flow->host_fd, s5_pkt.data(), s5_pkt.size(), MSG_NOSIGNAL,
		    (struct sockaddr*)&dest_addr, sizeof(dest_addr));
	} else {
		if (rule.redirect_ip4 && rule.redirect_port) {
			dest_addr.sin_addr.s_addr = rule.redirect_ip4;
			dest_addr.sin_port = htons(rule.redirect_port);
		} else {
			dest_addr.sin_addr.s_addr = ip->daddr;
			dest_addr.sin_port = htons(dest_port);
		}
		sendto(flow->host_fd, data, data_len, MSG_NOSIGNAL, (struct sockaddr*)&dest_addr,
		    sizeof(dest_addr));
	}
}

static void handle_host_udp(Context* ctx, UdpFlow* flow) {
	int fd = flow->host_fd;
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
		PLOG_E("recvmmsg(fd=%d) failed", fd);
		udp_destroy_flow(ctx, flow);
		return;
	}

	for (int i = 0; i < retval; ++i) {
		uint8_t* data_ptr = bufs[i];
		size_t data_len = msgs[i].msg_len;
		struct sockaddr_storage* src_addr_storage = &src_addrs[i];

		if (flow->use_socks5) {
			if (data_len < 10) continue;
			socks5_udp_hdr* hdr = reinterpret_cast<socks5_udp_hdr*>(data_ptr);
			if (hdr->rsv != 0 || hdr->frag != 0) continue;

			size_t header_len = 0;
			if (hdr->atyp == SOCKS5_ATYP_IPV4) {
				header_len = 10;
			} else if (hdr->atyp == SOCKS5_ATYP_IPV6) {
				header_len = 22;
			} else if (hdr->atyp == SOCKS5_ATYP_DOMAIN) {
				if (data_len < 5) continue;
				socks5_udp_hdr_domain* dhdr =
				    reinterpret_cast<socks5_udp_hdr_domain*>(data_ptr);
				header_len = 5 + dhdr->domain_len + 2;
			} else {
				continue;
			}

			if (data_len < header_len) continue;

			data_ptr += header_len;
			data_len -= header_len;
		}

		udp_push_to_guest(ctx, flow, data_ptr, data_len, src_addr_storage);
	}
}

void handle_host_udp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule) {
	LOG_D("handle_host_udp_accept listen_fd=%d", listen_fd);

	constexpr int VLEN = 64;
	struct mmsghdr msgs[VLEN];
	struct iovec iovecs[VLEN];
	static uint8_t (*bufs)[NSTUN_MTU] = new uint8_t[VLEN][NSTUN_MTU];
	static struct sockaddr_storage* client_addrs = new struct sockaddr_storage[VLEN];

	for (int i = 0; i < VLEN; ++i) {
		iovecs[i].iov_base = bufs[i];
		iovecs[i].iov_len = sizeof(bufs[i]);
		msgs[i].msg_hdr.msg_iov = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_name = &client_addrs[i];
		msgs[i].msg_hdr.msg_namelen = sizeof(client_addrs[i]);
		msgs[i].msg_hdr.msg_control = nullptr;
		msgs[i].msg_hdr.msg_controllen = 0;
	}

	int retval = recvmmsg(listen_fd, msgs, VLEN, MSG_DONTWAIT, nullptr);
	if (retval == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		PLOG_E("recvmmsg(fd=%d) failed", listen_fd);
		return;
	}

	for (int i = 0; i < retval; ++i) {
		uint8_t* data_ptr = bufs[i];
		size_t data_len = msgs[i].msg_len;
		struct sockaddr_storage* client_ss = &client_addrs[i];

		if (rule.is_ipv6) {
			struct sockaddr_in6* client6 =
			    reinterpret_cast<struct sockaddr_in6*>(client_ss);
			struct sockaddr_in6 server6 = INIT_SOCKADDR_IN6(AF_INET6);
			if (i == 0) {
				socklen_t servlen6 = sizeof(server6);
				getsockname(listen_fd, (struct sockaddr*)&server6, &servlen6);
			}

			/* Loopback→gateway rewrite for IPv6: prevent martian drops in guest */
			uint8_t client_ip6[16];
			memcpy(client_ip6, &client6->sin6_addr, sizeof(client_ip6));
			if (IN6_IS_ADDR_LOOPBACK(&client6->sin6_addr)) {
				memcpy(client_ip6, ctx->host_ip6, sizeof(client_ip6));
			}

			FlowKey6 key6 = {};
			bool has_redirect_ip6 =
			    !IN6_IS_ADDR_UNSPECIFIED((const struct in6_addr*)rule.redirect_ip6);
			if (has_redirect_ip6) {
				memcpy(key6.saddr6, rule.redirect_ip6, sizeof(key6.saddr6));
			} else {
				memcpy(key6.saddr6, ctx->guest_ip6, sizeof(key6.saddr6));
			}
			memcpy(key6.daddr6, client_ip6, sizeof(key6.daddr6));
			key6.sport =
			    rule.redirect_port ? htons(rule.redirect_port) : server6.sin6_port;
			key6.dport = client6->sin6_port;

			UdpFlow* flow = nullptr;
			auto it = ctx->ipv6_udp_flows_by_key.find(key6);
			if (it != ctx->ipv6_udp_flows_by_key.end()) {
				flow = it->second.get();
				flow->last_active = time(NULL);
			} else {
				if (ctx->ipv6_udp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
					LOG_W("Maximum number of IPv6 UDP flows reached, dropping");
					continue;
				}
				auto flow_ptr = std::make_unique<UdpFlow>();
				flow = flow_ptr.get();
				flow->host_fd = listen_fd;
				flow->is_ipv6 = true;
				flow->key6 = key6;
				flow->last_active = time(NULL);
				flow->is_redirected = true;
				flow->use_socks5 = false;
				flow->state = UdpSocks5State::ESTABLISHED;
				flow->host_fd_is_listener = true;
				ctx->ipv6_udp_flows_by_key[key6] = std::move(flow_ptr);
			}

			udp_send_packet6(ctx, key6.daddr6, key6.saddr6, key6.dport, key6.sport,
			    data_ptr, data_len);
		} else {
			struct sockaddr_in* client4 =
			    reinterpret_cast<struct sockaddr_in*>(client_ss);
			struct sockaddr_in server_addr = INIT_SOCKADDR_IN(AF_INET);
			if (i == 0) {
				socklen_t servlen = sizeof(server_addr);
				getsockname(listen_fd, (struct sockaddr*)&server_addr, &servlen);
			}

			uint32_t client_ip = client4->sin_addr.s_addr;
			if (client_ip == htonl(INADDR_LOOPBACK)) {
				client_ip = ctx->host_ip4; /* Prevent martian drops in guest */
			}

			FlowKey4 key4 = {
			    .saddr4 = rule.redirect_ip4 ? rule.redirect_ip4 : ctx->guest_ip4,
			    .daddr4 = client_ip,
			    .sport = rule.redirect_port ? htons(rule.redirect_port)
							: server_addr.sin_port,
			    .dport = client4->sin_port,
			};

			UdpFlow* flow = nullptr;
			auto it = ctx->ipv4_udp_flows_by_key.find(key4);
			if (it != ctx->ipv4_udp_flows_by_key.end()) {
				flow = it->second.get();
				flow->last_active = time(NULL);
			} else {
				if (ctx->ipv4_udp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
					LOG_W("Maximum number of UDP flows reached, dropping");
					continue;
				}
				auto flow_ptr = std::make_unique<UdpFlow>();
				flow = flow_ptr.get();
				flow->is_ipv6 = false;
				flow->host_fd = listen_fd;
				flow->key4 = key4;
				flow->last_active = time(NULL);
				flow->is_redirected = true;
				flow->use_socks5 = false;
				flow->state = UdpSocks5State::ESTABLISHED;
				flow->host_fd_is_listener = true;
				ctx->ipv4_udp_flows_by_key[key4] = std::move(flow_ptr);
			}

			udp_send_packet4(ctx, key4.daddr4, key4.saddr4, key4.dport, key4.sport,
			    data_ptr, data_len);
		}
	}
}

static void udp_send_packet6(Context* ctx, const uint8_t* saddr, const uint8_t* daddr,
    uint16_t sport, uint16_t dport, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("udp_send_packet6: data length too large");
		return;
	}

	static thread_local uint8_t header_buf[sizeof(ip6_hdr) + sizeof(udp_hdr)];
	memset(header_buf, 0, sizeof(header_buf));

	ip6_hdr* r_ip = reinterpret_cast<ip6_hdr*>(header_buf);
	udp_hdr* r_udp = reinterpret_cast<udp_hdr*>(header_buf + sizeof(ip6_hdr));

	/* IPv6 */
	r_ip->vtf = htonl(0x60000000); /* Version 6 */
	r_ip->payload_len = htons(sizeof(udp_hdr) + len);
	r_ip->next_header = IPPROTO_UDP;
	r_ip->hop_limit = 64;
	memcpy(r_ip->saddr, saddr, sizeof(r_ip->saddr));
	memcpy(r_ip->daddr, daddr, sizeof(r_ip->daddr));

	/* UDP */
	r_udp->source = sport;
	r_udp->dest = dport;
	r_udp->len = htons(sizeof(udp_hdr) + len);
	r_udp->check = 0;

	/* 40-byte IPv6 pseudo header */
	pseudo_hdr6 phdr = {};
	phdr.len = htonl(sizeof(udp_hdr) + len);
	phdr.next_header = IPPROTO_UDP;
	memcpy(phdr.saddr, saddr, sizeof(phdr.saddr));
	memcpy(phdr.daddr, daddr, sizeof(phdr.daddr));

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(r_udp, sizeof(udp_hdr), sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	r_udp->check = finalize_checksum(sum);
	if (r_udp->check == 0) {
		r_udp->check = 0xFFFF;
	}

	send_to_guest_v(ctx, header_buf, sizeof(header_buf), data, len);
}

void handle_udp6(Context* ctx, const ip6_hdr* ip, std::span<const uint8_t> payload) {
	if (payload.size() < sizeof(udp_hdr)) return;

	const udp_hdr* udp = reinterpret_cast<const udp_hdr*>(payload.data());
	uint16_t guest_port = ntohs(udp->source);
	uint16_t dest_port = ntohs(udp->dest);

	/* Validate UDP checksum (mandatory for IPv6 per RFC 8200 §8.1) */
	{
		pseudo_hdr6 phdr = {};
		phdr.len = htonl(payload.size());
		phdr.next_header = IPPROTO_UDP;
		memcpy(phdr.saddr, ip->saddr, sizeof(phdr.saddr));
		memcpy(phdr.daddr, ip->daddr, sizeof(phdr.daddr));
		uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
		csum = compute_checksum_part(payload.data(), payload.size(), csum);
		if (finalize_checksum(csum) != 0) {
			LOG_D("Invalid IPv6 UDP checksum, dropping");
			return;
		}
	}

	FlowKey6 key6 = {};
	memcpy(key6.saddr6, ip->saddr, sizeof(key6.saddr6));
	memcpy(key6.daddr6, ip->daddr, sizeof(key6.daddr6));
	key6.sport = udp->source;
	key6.dport = udp->dest;

	RuleResult rule = evaluate_rules6(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_UDP, ip->saddr,
	    ip->daddr, guest_port, dest_port);

	if (rule.action == NSTUN_ACTION_DROP) {
		LOG_D("IPv6 UDP flow %u -> %u dropped by policy", guest_port, dest_port);
		return;
	} else if (rule.action == NSTUN_ACTION_REJECT) {
		LOG_D("IPv6 UDP flow %u -> %u rejected by policy", guest_port, dest_port);
		send_icmp6_error(ctx, ip, sizeof(ip6_hdr) + payload.size(), ICMP6_DST_UNREACH,
		    ICMP6_DST_UNREACH_NOPORT);
		return;
	} else if (rule.action == NSTUN_ACTION_ENCAP_CONNECT) {
		LOG_W("HTTP CONNECT proxy not supported for UDP, dropping packet to port %u",
		    dest_port);
		return;
	}

	UdpFlow* flow = nullptr;
	auto it = ctx->ipv6_udp_flows_by_key.find(key6);
	if (it != ctx->ipv6_udp_flows_by_key.end()) {
		flow = it->second.get();
		flow->last_active = time(NULL);
	} else {
		if (ctx->ipv6_udp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of IPv6 UDP flows (%zu) reached, dropping",
			    NSTUN_MAX_FLOWS);
			return;
		}

		auto flow_ptr = std::make_unique<UdpFlow>();
		flow = flow_ptr.get();

		flow->host_fd = -1;
		flow->tcp_fd = -1;
		flow->is_ipv6 = true;
		flow->key6 = key6;
		flow->last_active = time(NULL);
		flow->is_redirected = (rule.has_redirect_ip6 || rule.redirect_port != 0);
		memcpy(flow->orig_dest_ip6, ip->daddr, sizeof(flow->orig_dest_ip6));
		flow->orig_dest_port = dest_port;
		flow->use_socks5 = (rule.action == NSTUN_ACTION_ENCAP_SOCKS5);

		if (flow->use_socks5) {
			int tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
			if (tcp_fd == -1) return;

			bool fd_success = false;
			defer {
				if (!fd_success) close(tcp_fd);
			};

			struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			    .data = {.fd = tcp_fd}};
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, tcp_fd, &ev) == -1) return;

			struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
			dest_addr.sin_addr.s_addr = rule.redirect_ip4;
			dest_addr.sin_port = htons(rule.redirect_port);
			connect(tcp_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			fd_success = true;

			flow->tcp_fd = tcp_fd;
			flow->state = UdpSocks5State::TCP_CONNECTING;
			ctx->ipv6_udp_flows_by_key[key6] = std::move(flow_ptr);
			ctx->flows_by_fd[tcp_fd] = flow;
			LOG_D("Created IPv6 UDP Proxy flow (socks5=%d) for guest port %u -> tcp fd "
			      "%d%s",
			    flow->use_socks5 ? 1 : 0, guest_port, tcp_fd,
			    flow->is_redirected ? " [redirected]" : "");
		} else {
			int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
			if (fd == -1) {
				PLOG_E("socket(AF_INET6, SOCK_DGRAM) for IPv6 UDP flow failed");
				return;
			}
			bool fd_success = false;
			defer {
				if (!fd_success) close(fd);
			};

			struct sockaddr_in6 bind_addr = INIT_SOCKADDR_IN6(AF_INET6);
			if (bind(fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1) {
				PLOG_E("bind() IPv6 UDP host socket failed");
				return;
			}

			struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = fd}};
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
				PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for IPv6 UDP host socket failed");
				return;
			}
			fd_success = true;

			flow->host_fd = fd;
			flow->state = UdpSocks5State::ESTABLISHED;
			ctx->ipv6_udp_flows_by_key[key6] = std::move(flow_ptr);
			ctx->flows_by_fd[fd] = flow;
			LOG_D("Created IPv6 UDP flow for guest port %u -> fd %d%s", guest_port, fd,
			    flow->is_redirected ? " [redirected]" : "");
		}
	}

	auto data_span = payload.subspan(sizeof(udp_hdr));
	const uint8_t* data = data_span.data();
	size_t data_len = data_span.size();

	if (flow->use_socks5 && flow->state != UdpSocks5State::ESTABLISHED) {
		/* Cap queued packet size to prevent memory exhaustion */
		if (data_len > 1500) {
			LOG_D(
			    "IPv6 UDP proxy queue dropping oversized packet (%zu bytes)", data_len);
			return;
		}
		std::vector<uint8_t> pkt(data, data + data_len);
		flow->tx_queue.push_back(pkt);
		if (flow->tx_queue.size() > 50) {
			flow->tx_queue.pop_front();
		}
		return;
	}

	struct sockaddr_in6 dest_addr = INIT_SOCKADDR_IN6(AF_INET6);

	if (flow->use_socks5) {
		struct sockaddr_in dest_addr4 = INIT_SOCKADDR_IN(AF_INET);
		dest_addr4.sin_addr.s_addr = flow->bnd_ip;
		dest_addr4.sin_port = flow->bnd_port;

		std::vector<uint8_t> s5_pkt(sizeof(socks5_udp_hdr6) + data_len);
		socks5_udp_hdr6* hdr = reinterpret_cast<socks5_udp_hdr6*>(s5_pkt.data());
		hdr->rsv = 0;
		hdr->frag = 0;
		hdr->atyp = SOCKS5_ATYP_IPV6;
		memcpy(hdr->dst_ip6, flow->orig_dest_ip6, sizeof(hdr->dst_ip6));
		hdr->dst_port = htons(flow->orig_dest_port);
		memcpy(s5_pkt.data() + sizeof(socks5_udp_hdr6), data, data_len);

		sendto(flow->host_fd, s5_pkt.data(), s5_pkt.size(), MSG_NOSIGNAL,
		    (struct sockaddr*)&dest_addr4, sizeof(dest_addr4));
	} else {
		if (rule.has_redirect_ip6 && rule.redirect_port) {
			memcpy(
			    &dest_addr.sin6_addr, rule.redirect_ip6, sizeof(dest_addr.sin6_addr));
			dest_addr.sin6_port = htons(rule.redirect_port);
		} else {
			memcpy(&dest_addr.sin6_addr, ip->daddr, sizeof(dest_addr.sin6_addr));
			dest_addr.sin6_port = htons(dest_port);
		}
		sendto(flow->host_fd, data, data_len, MSG_NOSIGNAL, (struct sockaddr*)&dest_addr,
		    sizeof(dest_addr));
	}
}

void UdpFlow::handle_host_event(Context* ctx, int fd, uint32_t events) {
	if (fd == this->host_fd) {
		handle_host_udp(ctx, this);
	} else if (fd == this->tcp_fd) {
		handle_host_udp_control(ctx, this, events);
	} else {
		LOG_E("UdpFlow::handle_host_event: unknown fd=%d (host_fd=%d, tcp_fd=%d)", fd,
		    this->host_fd, this->tcp_fd);
	}
}

bool UdpFlow::is_stale(time_t now) const {
	time_t timeout = 60;
	if (this->use_socks5 && this->state != UdpSocks5State::ESTABLISHED) {
		timeout = 5;
	}
	return (now - this->last_active) > timeout;
}

void UdpFlow::destroy(Context* ctx) {
	if (is_ipv6) {
		LOG_D("GC: stale UDP flow (IPv6, sport=%u, socks5=%d)", ntohs(key6.sport),
		    use_socks5 ? 1 : 0);
	} else {
		LOG_D("GC: stale UDP flow (sport=%u, socks5=%d)", ntohs(key4.sport),
		    use_socks5 ? 1 : 0);
	}
	udp_destroy_flow(ctx, this);
}

} /* namespace nstun */
