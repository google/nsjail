#ifndef NSTUN_POLICY_H_
#define NSTUN_POLICY_H_

#include <string>

#include "core.h"
#include "nstun.h"

namespace nstun {

enum class RuleParseStatus {
	OK,
	IGNORE,
	ABORT,
};

RuleResult evaluate_rules4(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    uint32_t src_ip4, uint32_t dst_ip4, uint16_t sport, uint16_t dport);

RuleResult evaluate_rules6(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    const uint8_t* src_ip6, const uint8_t* dst_ip6, uint16_t sport, uint16_t dport);

bool parse_ip4_cidr(const std::string& str, uint32_t* ip, uint32_t* mask);
bool parse_ip6_cidr(const std::string& str, uint8_t* ip6, uint8_t* mask6);

template <typename RuleMsg>
RuleParseStatus fill_rule_common(const RuleMsg& r, nstun_rule_t* nr);

} /* namespace nstun */

#endif /* NSTUN_POLICY_H_ */
