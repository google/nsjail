#include "policy.h"

#include <netinet/in.h>
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
	LOG_D("evaluate_rules4: rules count=%zu", ctx->c_rules_count);
	for (size_t i = 0; i < ctx->c_rules_count; ++i) {
		const auto& r = ctx->c_rules[i];
		if (r.is_ipv6) {
			continue;
		}
		if (r.direction != dir) {
			continue;
		}
		if (r.proto != NSTUN_PROTO_ANY && r.proto != proto) {
			continue;
		}

		if (r.src_mask4 != 0 && (src_ip4 & r.src_mask4) != (r.src_ip4 & r.src_mask4)) {
			continue;
		}
		if (r.dst_mask4 != 0 && (dst_ip4 & r.dst_mask4) != (r.dst_ip4 & r.dst_mask4)) {
			continue;
		}

		if (r.sport_start != 0 && (sport < r.sport_start || sport > r.sport_end)) {
			continue;
		}
		if (r.dport_start != 0 && (dport < r.dport_start || dport > r.dport_end)) {
			continue;
		}

		RuleResult res = {
		    .action = r.action,
		    .redirect_ip4 = 0,
		    .redirect_port = 0,
		    .has_redirect_ip6 = false,
		    .redirect_ip6 = {},
		};
		if (r.action == NSTUN_ACTION_REDIRECT || r.action == NSTUN_ACTION_ENCAP_SOCKS5 ||
		    r.action == NSTUN_ACTION_ENCAP_CONNECT) {
			res.redirect_ip4 = r.redirect_ip4;
			res.redirect_port = r.redirect_port;
		}
		return res;
	}
	return {
	    .action = NSTUN_ACTION_ALLOW,
	    .redirect_ip4 = 0,
	    .redirect_port = 0,
	    .has_redirect_ip6 = false,
	    .redirect_ip6 = {},
	};
}

static bool ip6_masked_eq(const uint8_t* a, const uint8_t* b, const uint8_t* mask) {
	for (int i = 0; i < 16; i++) {
		if ((a[i] & mask[i]) != (b[i] & mask[i])) {
			return false;
		}
	}
	return true;
}

RuleResult evaluate_rules6(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    const uint8_t* src_ip6, const uint8_t* dst_ip6, uint16_t sport, uint16_t dport) {
	static const uint8_t kZeroIp6[16] = {0};
	for (size_t i = 0; i < ctx->c_rules_count; ++i) {
		const auto& r = ctx->c_rules[i];
		if (!r.is_ipv6) {
			continue;
		}
		if (r.direction != dir) {
			continue;
		}
		if (r.proto != NSTUN_PROTO_ANY && r.proto != proto) {
			continue;
		}

		if (memcmp(r.src_mask6, kZeroIp6, 16) != 0 &&
		    !ip6_masked_eq(src_ip6, r.src_ip6, r.src_mask6)) {
			continue;
		}
		if (memcmp(r.dst_mask6, kZeroIp6, 16) != 0 &&
		    !ip6_masked_eq(dst_ip6, r.dst_ip6, r.dst_mask6)) {
			continue;
		}

		if (r.sport_start != 0 && (sport < r.sport_start || sport > r.sport_end)) {
			continue;
		}
		if (r.dport_start != 0 && (dport < r.dport_start || dport > r.dport_end)) {
			continue;
		}

		RuleResult res = {
		    .action = r.action,
		    .redirect_ip4 = 0,
		    .redirect_port = 0,
		    .has_redirect_ip6 = false,
		    .redirect_ip6 = {},
		};
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
	return {
	    .action = NSTUN_ACTION_ALLOW,
	    .redirect_ip4 = 0,
	    .redirect_port = 0,
	    .has_redirect_ip6 = false,
	    .redirect_ip6 = {},
	};
}

RuleParseStatus fill_rule_common(
    const nsjail::NsJailConfig_UserNet_NstunRule& r, nstun_rule_t* nr) {
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

	switch (r.action()) {
	case nsjail::NsJailConfig_UserNet_NstunRule_Action_DROP:
		nr->action = NSTUN_ACTION_DROP;
		break;
	case nsjail::NsJailConfig_UserNet_NstunRule_Action_REJECT:
		nr->action = NSTUN_ACTION_REJECT;
		break;
	case nsjail::NsJailConfig_UserNet_NstunRule_Action_ALLOW:
		nr->action = NSTUN_ACTION_ALLOW;
		break;
	case nsjail::NsJailConfig_UserNet_NstunRule_Action_REDIRECT:
		nr->action = NSTUN_ACTION_REDIRECT;
		break;
	case nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_SOCKS5:
		nr->action = NSTUN_ACTION_ENCAP_SOCKS5;
		break;
	case nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_CONNECT:
		nr->action = NSTUN_ACTION_ENCAP_CONNECT;
		break;
	default:
		return RuleParseStatus::IGNORE;
	}

	switch (r.proto()) {
	case nsjail::NsJailConfig_UserNet_NstunRule_Protocol_TCP:
		nr->proto = NSTUN_PROTO_TCP;
		break;
	case nsjail::NsJailConfig_UserNet_NstunRule_Protocol_UDP:
		nr->proto = NSTUN_PROTO_UDP;
		break;
	case nsjail::NsJailConfig_UserNet_NstunRule_Protocol_ICMP:
		nr->proto = NSTUN_PROTO_ICMP;
		break;
	default:
		nr->proto = NSTUN_PROTO_ANY;
		break;
	}

	nr->sport_start = r.has_sport() ? r.sport() : 0;
	nr->sport_end = r.has_sport_end() ? r.sport_end() : nr->sport_start;

	nr->dport_start = r.has_dport() ? r.dport() : 0;
	nr->dport_end = r.has_dport_end() ? r.dport_end() : nr->dport_start;

	if (nr->sport_end < nr->sport_start) {
		LOG_E("Invalid source port range: %u - %u", nr->sport_start, nr->sport_end);
		return RuleParseStatus::ABORT;
	}
	if (nr->dport_end < nr->dport_start) {
		LOG_E("Invalid destination port range: %u - %u", nr->dport_start, nr->dport_end);
		return RuleParseStatus::ABORT;
	}

	return RuleParseStatus::OK;
}

} /* namespace nstun */
