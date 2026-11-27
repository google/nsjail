#ifndef NSTUN_UDP_PEER_H_
#define NSTUN_UDP_PEER_H_

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

#include <span>

#include "core.h"
#include "encap.h"

namespace nstun {

template <typename FlowT>
inline bool udp_peer_matches_flow(const FlowT& flow, const struct sockaddr_storage& peer) {
	if (flow.use_socks5) {
		if (peer.ss_family != AF_INET) return false;
		const auto* peer4 = reinterpret_cast<const struct sockaddr_in*>(&peer);
		return peer4->sin_addr.s_addr == flow.bnd_ip && peer4->sin_port == flow.bnd_port;
	}

	if (flow.is_ipv6) {
		if (peer.ss_family != AF_INET6) return false;
		const auto* peer6 = reinterpret_cast<const struct sockaddr_in6*>(&peer);
		const uint8_t* expected_ip = flow.key6.daddr6;
		uint16_t expected_port = flow.key6.dport;
		if (flow.is_redirected) {
			bool has_redirect_ip = false;
			for (size_t i = 0; i < IPV6_ADDR_LEN; i++) {
				if (flow.redirect_ip6[i] != 0) {
					has_redirect_ip = true;
					break;
				}
			}
			/* Current REDIRECT forwarding changes the peer only when both
			 * target components are present. */
			if (has_redirect_ip && flow.redirect_port != 0) {
				expected_ip = flow.redirect_ip6;
				expected_port = htons(flow.redirect_port);
			}
		}
		return memcmp(&peer6->sin6_addr, expected_ip, IPV6_ADDR_LEN) == 0 &&
		       peer6->sin6_port == expected_port;
	}

	if (peer.ss_family != AF_INET) return false;
	const auto* peer4 = reinterpret_cast<const struct sockaddr_in*>(&peer);
	uint32_t expected_ip = flow.key4.daddr4;
	uint16_t expected_port = flow.key4.dport;
	if (flow.is_redirected && flow.redirect_ip4 != 0 && flow.redirect_port != 0) {
		expected_ip = flow.redirect_ip4;
		expected_port = htons(flow.redirect_port);
	}
	return peer4->sin_addr.s_addr == expected_ip && peer4->sin_port == expected_port;
}

template <typename FlowT>
inline bool socks5_udp_unwrap_for_flow(
    const FlowT& flow, std::span<const uint8_t> datagram, std::span<const uint8_t>* payload_out) {
	if (!payload_out) return false;
	if (flow.is_ipv6) {
		if (datagram.size() < sizeof(socks5_udp_hdr6)) return false;
		socks5_udp_hdr6 hdr;
		memcpy(&hdr, datagram.data(), sizeof(hdr));
		if (hdr.rsv != 0 || hdr.frag != 0 || hdr.atyp != SOCKS5_ATYP_IPV6) return false;
		if (memcmp(hdr.dst_ip6, flow.orig_dest_ip6, IPV6_ADDR_LEN) != 0 ||
		    hdr.dst_port != htons(flow.orig_dest_port)) {
			return false;
		}
		*payload_out = datagram.subspan(sizeof(socks5_udp_hdr6));
		return true;
	}

	if (datagram.size() < sizeof(socks5_udp_hdr)) return false;
	socks5_udp_hdr hdr;
	memcpy(&hdr, datagram.data(), sizeof(hdr));
	if (hdr.rsv != 0 || hdr.frag != 0 || hdr.atyp != SOCKS5_ATYP_IPV4) return false;
	if (hdr.dst_ip4 != flow.orig_dest_ip4 || hdr.dst_port != htons(flow.orig_dest_port)) {
		return false;
	}
	*payload_out = datagram.subspan(sizeof(socks5_udp_hdr));
	return true;
}

} /* namespace nstun */

#endif /* NSTUN_UDP_PEER_H_ */
