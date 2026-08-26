#include "policy.h"

#include <arpa/inet.h>
#include <string.h>

#include <charconv>
#include <limits>
#include <string>

#include "core.h"
#include "logs.h"
#include "nstun.h"

/* Pull in the protobuf types for NstunRule enums */
#include "config.pb.h"
#include "nsjail.h"

namespace nstun {

static bool parse_prefix(const std::string& str, int max_bits, std::string* ip_str, int* bits) {
	*ip_str = str;
	*bits = max_bits;

	size_t pos = str.find('/');
	if (pos == std::string::npos) return true;

	*ip_str = str.substr(0, pos);
	const char* begin = str.data() + pos + 1;
	const char* end = str.data() + str.size();
	int parsed_bits = 0;
	auto [ptr, ec] = std::from_chars(begin, end, parsed_bits);
	if (begin == end || ec != std::errc() || ptr != end || parsed_bits < 0 ||
	    parsed_bits > max_bits) {
		LOG_E("Invalid CIDR prefix length: %s", str.c_str());
		return false;
	}

	*bits = parsed_bits;
	return true;
}

bool parse_ip4_cidr(const std::string& str, uint32_t* ip, uint32_t* mask) {
	std::string ip_str;
	int bits;
	if (!parse_prefix(str, 32, &ip_str, &bits)) return false;

	uint32_t parsed_ip;
	if (inet_pton(AF_INET, ip_str.c_str(), &parsed_ip) != 1) {
		LOG_E("Invalid IPv4 address: %s", str.c_str());
		return false;
	}

	uint32_t host_mask = bits == 0 ? 0 : std::numeric_limits<uint32_t>::max() << (32 - bits);
	*ip = parsed_ip;
	*mask = htonl(host_mask);
	return true;
}

bool parse_ip6_cidr(const std::string& str, uint8_t* ip6, uint8_t* mask6) {
	std::string ip_str;
	int bits;
	if (!parse_prefix(str, 128, &ip_str, &bits)) return false;

	uint8_t parsed_ip6[IPV6_ADDR_LEN];
	if (inet_pton(AF_INET6, ip_str.c_str(), parsed_ip6) != 1) {
		LOG_E("Invalid IPv6 address: %s", str.c_str());
		return false;
	}

	uint8_t parsed_mask6[IPV6_ADDR_LEN] = {};
	for (size_t i = 0; i < IPV6_ADDR_LEN; i++) {
		if (bits >= 8) {
			parsed_mask6[i] = 0xFF;
			bits -= 8;
		} else if (bits > 0) {
			parsed_mask6[i] = (uint8_t)(0xFF << (8 - bits));
			bits = 0;
		}
	}

	memcpy(ip6, parsed_ip6, IPV6_ADDR_LEN);
	memcpy(mask6, parsed_mask6, IPV6_ADDR_LEN);
	return true;
}

RuleResult evaluate_rules4(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    uint32_t src_ip4, uint32_t dst_ip4, uint16_t sport, uint16_t dport) {
	for (const auto& r : ctx->rules) {
		if (r.is_ipv6) continue;
		if (r.direction != dir) continue;
		if (r.proto != NSTUN_PROTO_ANY && r.proto != proto) continue;

		if (r.src_mask4 != 0 && (src_ip4 & r.src_mask4) != (r.src_ip4 & r.src_mask4))
			continue;
		if (r.dst_mask4 != 0 && (dst_ip4 & r.dst_mask4) != (r.dst_ip4 & r.dst_mask4))
			continue;

		if (r.sport_start != 0 && (sport < r.sport_start || sport > r.sport_end)) continue;
		if (r.dport_start != 0 && (dport < r.dport_start || dport > r.dport_end)) continue;

		RuleResult res = {r.action, 0, 0, false, {}};
		if (r.action == NSTUN_ACTION_REDIRECT || r.action == NSTUN_ACTION_ENCAP_SOCKS5 ||
		    r.action == NSTUN_ACTION_ENCAP_CONNECT) {
			res.redirect_ip4 = r.redirect_ip4;
			res.redirect_port = r.redirect_port;
		}
		return res;
	}
	return {NSTUN_ACTION_ALLOW, 0, 0, false, {}}; /* Default allow */
}

static bool ip6_masked_eq(const uint8_t* a, const uint8_t* b, const uint8_t* mask) {
	for (int i = 0; i < 16; i++) {
		if ((a[i] & mask[i]) != (b[i] & mask[i])) return false;
	}
	return true;
}

static bool ip6_is_zero(const uint8_t* addr) {
	for (int i = 0; i < 16; i++) {
		if (addr[i] != 0) return false;
	}
	return true;
}

RuleResult evaluate_rules6(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    const uint8_t* src_ip6, const uint8_t* dst_ip6, uint16_t sport, uint16_t dport) {
	for (const auto& r : ctx->rules) {
		if (!r.is_ipv6) continue;
		if (r.direction != dir) continue;
		if (r.proto != NSTUN_PROTO_ANY && r.proto != proto) continue;

		if (!ip6_is_zero(r.src_mask6) && !ip6_masked_eq(src_ip6, r.src_ip6, r.src_mask6))
			continue;
		if (!ip6_is_zero(r.dst_mask6) && !ip6_masked_eq(dst_ip6, r.dst_ip6, r.dst_mask6))
			continue;

		if (r.sport_start != 0 && (sport < r.sport_start || sport > r.sport_end)) continue;
		if (r.dport_start != 0 && (dport < r.dport_start || dport > r.dport_end)) continue;

		RuleResult res = {r.action, 0, 0, false, {}};
		if (r.action == NSTUN_ACTION_REDIRECT) {
			res.has_redirect_ip6 = true;
			memcpy(res.redirect_ip6, r.redirect_ip6, sizeof(res.redirect_ip6));
			res.redirect_port = r.redirect_port;
		} else if (r.action == NSTUN_ACTION_ENCAP_SOCKS5 ||
			   r.action == NSTUN_ACTION_ENCAP_CONNECT) {
			/* proxy is always IPv4 */
			res.redirect_ip4 = r.redirect_ip4;
			res.redirect_port = r.redirect_port;
		}
		return res;
	}
	return {NSTUN_ACTION_ALLOW, 0, 0, false, {}}; /* Default allow */
}

template <typename RuleMsg>
RuleParseStatus fill_rule_common(const RuleMsg& r, nstun_rule_t* nr) {
	auto set_port_range = [](const char* name, bool has_start, uint32_t start, bool has_end,
				  uint32_t end, uint16_t* out_start, uint16_t* out_end) {
		if (has_end && !has_start) {
			LOG_E("%s_end requires %s", name, name);
			return false;
		}
		if (!has_start) {
			*out_start = 0;
			*out_end = 0;
			return true;
		}
		if (start == 0 || start > std::numeric_limits<uint16_t>::max()) {
			LOG_E("Invalid %s: %u", name, start);
			return false;
		}
		uint32_t range_end = has_end ? end : start;
		if (range_end < start || range_end > std::numeric_limits<uint16_t>::max()) {
			LOG_E("Invalid %s range: %u-%u", name, start, range_end);
			return false;
		}
		*out_start = (uint16_t)start;
		*out_end = (uint16_t)range_end;
		return true;
	};

	if ((r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_SOCKS5 ||
		r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_CONNECT) &&
	    r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_ICMP) {
		LOG_E("Proxy encapsulation is not supported for ICMP/ICMPv6");
		return RuleParseStatus::ABORT;
	}

	if (r.direction() == nsjail::NsJailConfig_UserNet_NstunRule_Direction_HOST_TO_GUEST) {
		nr->direction = NSTUN_DIR_HOST_TO_GUEST;
	} else {
		nr->direction = NSTUN_DIR_GUEST_TO_HOST;
	}

	if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_DROP) {
		nr->action = NSTUN_ACTION_DROP;
	} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_REJECT) {
		nr->action = NSTUN_ACTION_REJECT;
	} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_ALLOW) {
		nr->action = NSTUN_ACTION_ALLOW;
	} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_REDIRECT) {
		nr->action = NSTUN_ACTION_REDIRECT;
	} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_SOCKS5) {
		nr->action = NSTUN_ACTION_ENCAP_SOCKS5;
	} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_CONNECT) {
		nr->action = NSTUN_ACTION_ENCAP_CONNECT;
	} else {
		return RuleParseStatus::IGNORE;
	}

	if (r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_TCP) {
		nr->proto = NSTUN_PROTO_TCP;
	} else if (r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_UDP) {
		nr->proto = NSTUN_PROTO_UDP;
	} else if (r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_ICMP) {
		nr->proto = NSTUN_PROTO_ICMP;
	} else {
		nr->proto = NSTUN_PROTO_ANY;
	}

	if (!set_port_range("sport", r.has_sport(), r.sport(), r.has_sport_end(), r.sport_end(),
		&nr->sport_start, &nr->sport_end)) {
		return RuleParseStatus::ABORT;
	}
	if (!set_port_range("dport", r.has_dport(), r.dport(), r.has_dport_end(), r.dport_end(),
		&nr->dport_start, &nr->dport_end)) {
		return RuleParseStatus::ABORT;
	}
	if (r.has_redirect_port() && r.redirect_port() > std::numeric_limits<uint16_t>::max()) {
		LOG_E("Invalid redirect_port: %u", r.redirect_port());
		return RuleParseStatus::ABORT;
	}

	return RuleParseStatus::OK;
}

/* Explicit template instantiation for the protobuf rule message type */
template RuleParseStatus fill_rule_common<nsjail::NsJailConfig_UserNet_NstunRule>(
    const nsjail::NsJailConfig_UserNet_NstunRule& r, nstun_rule_t* nr);

} /* namespace nstun */
