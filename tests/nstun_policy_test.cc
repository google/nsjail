#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>

#include <algorithm>
#include <array>
#include <limits>

#include "config.pb.h"
#include "nstun/policy.h"
#include "nstun/tcp.h"

static uint32_t parse_ip4(const char* str) {
	uint32_t addr;
	assert(inet_pton(AF_INET, str, &addr) == 1);
	return addr;
}

static void test_ip4_cidr() {
	uint32_t ip = 0;
	uint32_t mask = 0;
	assert(nstun::parse_ip4_cidr("192.0.2.128/25", &ip, &mask));
	assert(ip == parse_ip4("192.0.2.128"));
	assert(mask == parse_ip4("255.255.255.128"));

	const uint32_t sentinel_ip = 0x11223344;
	const uint32_t sentinel_mask = 0x55667788;
	for (const char* invalid :
	    {"192.0.2.1/", "192.0.2.1/-1", "192.0.2.1/33", "192.0.2.1/24junk", "192.0.2.999/24"}) {
		ip = sentinel_ip;
		mask = sentinel_mask;
		assert(!nstun::parse_ip4_cidr(invalid, &ip, &mask));
		assert(ip == sentinel_ip);
		assert(mask == sentinel_mask);
	}
}

static void test_ip6_cidr() {
	std::array<uint8_t, 16> ip = {};
	std::array<uint8_t, 16> mask = {};
	assert(nstun::parse_ip6_cidr("2001:db8::/64", ip.data(), mask.data()));

	std::array<uint8_t, 16> expected_ip = {};
	assert(inet_pton(AF_INET6, "2001:db8::", expected_ip.data()) == 1);
	assert(ip == expected_ip);
	for (size_t i = 0; i < mask.size(); i++) {
		assert(mask[i] == (i < 8 ? 0xFF : 0));
	}

	for (const char* invalid : {"2001:db8::/", "2001:db8::/-1", "2001:db8::/129",
		 "2001:db8::/64junk", "2001:db8::xyz/64"}) {
		ip.fill(0x11);
		mask.fill(0x22);
		assert(!nstun::parse_ip6_cidr(invalid, ip.data(), mask.data()));
		assert(std::all_of(ip.begin(), ip.end(), [](uint8_t v) { return v == 0x11; }));
		assert(std::all_of(mask.begin(), mask.end(), [](uint8_t v) { return v == 0x22; }));
	}
}

static nstun::RuleParseStatus parse_common(
    const nsjail::NsJailConfig_UserNet_NstunRule& rule, nstun_rule_t* parsed) {
	*parsed = {};
	return nstun::fill_rule_common(rule, parsed);
}

static void test_ipv6_redirect_presence() {
	auto* ctx = new nstun::Context();
	nstun_rule_t rule = {};
	rule.direction = NSTUN_DIR_GUEST_TO_HOST;
	rule.action = NSTUN_ACTION_REDIRECT;
	rule.proto = NSTUN_PROTO_TCP;
	rule.is_ipv6 = true;
	rule.redirect_port = 8443;
	ctx->rules.push_back(rule);

	std::array<uint8_t, 16> src = {};
	std::array<uint8_t, 16> dst = {};
	auto result = nstun::evaluate_rules6(
	    ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP, src.data(), dst.data(), 12345, 443);
	assert(result.action == NSTUN_ACTION_REDIRECT);
	assert(!result.has_redirect_ip6);
	assert(result.redirect_port == 8443);

	std::array<uint8_t, 16> redirect = {};
	assert(inet_pton(AF_INET6, "2001:db8::1", redirect.data()) == 1);
	std::copy(redirect.begin(), redirect.end(), ctx->rules[0].redirect_ip6);
	result = nstun::evaluate_rules6(
	    ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP, src.data(), dst.data(), 12345, 443);
	assert(result.has_redirect_ip6);
	assert(std::equal(redirect.begin(), redirect.end(), result.redirect_ip6));
}

static void test_port_validation() {
	nsjail::NsJailConfig_UserNet_NstunRule rule;
	nstun_rule_t parsed = {};

	rule.set_dport(53);
	rule.set_dport_end(55);
	assert(parse_common(rule, &parsed) == nstun::RuleParseStatus::OK);
	assert(parsed.dport_start == 53);
	assert(parsed.dport_end == 55);

	rule.Clear();
	rule.set_dport(std::numeric_limits<uint16_t>::max() + 1U);
	assert(parse_common(rule, &parsed) == nstun::RuleParseStatus::ABORT);

	rule.Clear();
	rule.set_dport_end(80);
	assert(parse_common(rule, &parsed) == nstun::RuleParseStatus::ABORT);

	rule.Clear();
	rule.set_dport(100);
	rule.set_dport_end(99);
	assert(parse_common(rule, &parsed) == nstun::RuleParseStatus::ABORT);

	rule.Clear();
	rule.set_sport(0);
	assert(parse_common(rule, &parsed) == nstun::RuleParseStatus::ABORT);

	rule.Clear();
	rule.set_redirect_port(std::numeric_limits<uint16_t>::max() + 1U);
	assert(parse_common(rule, &parsed) == nstun::RuleParseStatus::ABORT);
}

int main() {
	test_ip4_cidr();
	test_ip6_cidr();
	test_ipv6_redirect_presence();
	test_port_validation();
	return 0;
}
