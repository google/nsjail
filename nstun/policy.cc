#include "policy.h"

#include <string.h>

#include "core.h"
#include "logs.h"
#include "nstun.h"

/* Pull in the protobuf types for NstunRule enums */
#include "config.pb.h"
#include "nsjail.h"

namespace nstun {

RuleResult evaluate_rules4(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    uint32_t src_ip4, uint32_t dst_ip4, uint16_t sport, uint16_t dport) {
	for (const auto& r : ctx->rules) {
		if (r.is_ipv6) continue;
		if (r.direction != dir) continue;
		if (r.proto != NSTUN_PROTO_ANY && r.proto != proto) continue;

		if (r.src_ip4 != 0 && (src_ip4 & r.src_mask4) != (r.src_ip4 & r.src_mask4))
			continue;
		if (r.dst_ip4 != 0 && (dst_ip4 & r.dst_mask4) != (r.dst_ip4 & r.dst_mask4))
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

		if (!ip6_is_zero(r.src_ip6) && !ip6_masked_eq(src_ip6, r.src_ip6, r.src_mask6))
			continue;
		if (!ip6_is_zero(r.dst_ip6) && !ip6_masked_eq(dst_ip6, r.dst_ip6, r.dst_mask6))
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

	nr->sport_start = r.has_sport() ? r.sport() : 0;
	nr->sport_end = r.has_sport_end() ? r.sport_end() : nr->sport_start;

	nr->dport_start = r.has_dport() ? r.dport() : 0;
	nr->dport_end = r.has_dport_end() ? r.dport_end() : nr->dport_start;

	return RuleParseStatus::OK;
}

/* Explicit template instantiation for the protobuf rule message type */
template RuleParseStatus fill_rule_common<nsjail::NsJailConfig_UserNet_NstunRule>(
    const nsjail::NsJailConfig_UserNet_NstunRule& r, nstun_rule_t* nr);

} /* namespace nstun */
