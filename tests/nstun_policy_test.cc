#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>

#include <algorithm>
#include <array>
#include <limits>

#include "config.pb.h"
#include "nstun/policy.h"

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

static void test_rule_matches4() {
	nstun_rule_t redirect = {};
	redirect.direction = NSTUN_DIR_HOST_TO_GUEST;
	redirect.action = NSTUN_ACTION_REDIRECT;
	redirect.proto = NSTUN_PROTO_TCP;
	assert(nstun::parse_ip4_cidr("192.0.2.0/24", &redirect.src_ip4, &redirect.src_mask4));
	assert(nstun::parse_ip4_cidr("127.0.0.1", &redirect.dst_ip4, &redirect.dst_mask4));
	redirect.sport_start = 40000;
	redirect.sport_end = 40010;
	redirect.dport_start = 8080;
	redirect.dport_end = 8080;

	assert(nstun::rule_matches4(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    parse_ip4("192.0.2.42"), parse_ip4("127.0.0.1"), 40000, 8080));
	assert(nstun::rule_matches4(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    parse_ip4("192.0.2.254"), parse_ip4("127.0.0.1"), 40010, 8080));
	assert(!nstun::rule_matches4(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    parse_ip4("198.51.100.1"), parse_ip4("127.0.0.1"), 40000, 8080));
	assert(!nstun::rule_matches4(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    parse_ip4("192.0.2.42"), parse_ip4("127.0.0.2"), 40000, 8080));
	assert(!nstun::rule_matches4(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_UDP,
	    parse_ip4("192.0.2.42"), parse_ip4("127.0.0.1"), 40000, 8080));
	assert(!nstun::rule_matches4(redirect, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP,
	    parse_ip4("192.0.2.42"), parse_ip4("127.0.0.1"), 40000, 8080));
	assert(!nstun::rule_matches4(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    parse_ip4("192.0.2.42"), parse_ip4("127.0.0.1"), 39999, 8080));

	nstun_rule_t exact_zero = {};
	exact_zero.direction = NSTUN_DIR_HOST_TO_GUEST;
	exact_zero.proto = NSTUN_PROTO_TCP;
	assert(nstun::parse_ip4_cidr("0.0.0.0/32", &exact_zero.dst_ip4, &exact_zero.dst_mask4));
	assert(nstun::rule_matches4(exact_zero, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    parse_ip4("192.0.2.1"), parse_ip4("0.0.0.0"), 1, 1));
	assert(!nstun::rule_matches4(exact_zero, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    parse_ip4("192.0.2.1"), parse_ip4("127.0.0.1"), 1, 1));
}

static void test_rule_matches6() {
	nstun_rule_t redirect = {};
	redirect.direction = NSTUN_DIR_HOST_TO_GUEST;
	redirect.action = NSTUN_ACTION_REDIRECT;
	redirect.proto = NSTUN_PROTO_UDP;
	redirect.is_ipv6 = true;
	assert(nstun::parse_ip6_cidr("2001:db8::/32", redirect.src_ip6, redirect.src_mask6));
	assert(nstun::parse_ip6_cidr("::1", redirect.dst_ip6, redirect.dst_mask6));
	redirect.dport_start = 5353;
	redirect.dport_end = 5353;

	std::array<uint8_t, 16> matching_src = {};
	std::array<uint8_t, 16> other_src = {};
	std::array<uint8_t, 16> loopback = {};
	std::array<uint8_t, 16> other_dst = {};
	assert(inet_pton(AF_INET6, "2001:db8::42", matching_src.data()) == 1);
	assert(inet_pton(AF_INET6, "2001:db9::42", other_src.data()) == 1);
	assert(inet_pton(AF_INET6, "::1", loopback.data()) == 1);
	assert(inet_pton(AF_INET6, "::2", other_dst.data()) == 1);

	assert(nstun::rule_matches6(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_UDP,
	    matching_src.data(), loopback.data(), 40000, 5353));
	assert(!nstun::rule_matches6(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_UDP,
	    other_src.data(), loopback.data(), 40000, 5353));
	assert(!nstun::rule_matches6(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_UDP,
	    matching_src.data(), other_dst.data(), 40000, 5353));
	assert(!nstun::rule_matches6(redirect, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_TCP,
	    matching_src.data(), loopback.data(), 40000, 5353));

	nstun_rule_t exact_zero = {};
	exact_zero.direction = NSTUN_DIR_HOST_TO_GUEST;
	exact_zero.proto = NSTUN_PROTO_UDP;
	exact_zero.is_ipv6 = true;
	assert(nstun::parse_ip6_cidr("::/128", exact_zero.dst_ip6, exact_zero.dst_mask6));
	std::array<uint8_t, 16> zero = {};
	assert(nstun::rule_matches6(exact_zero, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_UDP,
	    matching_src.data(), zero.data(), 1, 1));
	assert(!nstun::rule_matches6(exact_zero, NSTUN_DIR_HOST_TO_GUEST, NSTUN_PROTO_UDP,
	    matching_src.data(), loopback.data(), 1, 1));
}

int main() {
	test_ip4_cidr();
	test_ip6_cidr();
	test_port_validation();
	test_rule_matches4();
	test_rule_matches6();
	return 0;
}
