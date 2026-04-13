#ifndef NSTUN_POLICY_H_
#define NSTUN_POLICY_H_

#include "config.pb.h"
#include "core.h"
#include "nstun.h"

namespace nstun {

enum class RuleParseStatus {
	OK,
	IGNORE,
	ABORT,
};

[[nodiscard]] RuleResult evaluate_rules4(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    uint32_t src_ip4, uint32_t dst_ip4, uint16_t sport, uint16_t dport);

[[nodiscard]] RuleResult evaluate_rules6(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    const uint8_t* src_ip6, const uint8_t* dst_ip6, uint16_t sport, uint16_t dport);

[[nodiscard]] RuleParseStatus fill_rule_common(const nsjail::NsJailConfig_UserNet_NstunRule& r, nstun_rule_t* nr);

} /* namespace nstun */

#endif /* NSTUN_POLICY_H_ */
