#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include <memory>
#include <vector>

#include "nstun/tcp.cc"

namespace {
struct SentPacket {
	uint8_t flags;
	uint32_t seq;
	uint32_t ack;
	size_t payload_len;
};

std::vector<SentPacket> sent_packets;

nstun::TcpFlow* add_ipv4_flow(nstun::Context* ctx, const nstun::FlowKey4& key) {
	auto owned = std::make_unique<nstun::TcpFlow>();
	nstun::TcpFlow* flow = owned.get();
	flow->is_ipv6 = false;
	flow->host_fd = -1;
	flow->key4 = key;
	ctx->ipv4_tcp_flows_by_key[key] = std::move(owned);
	return flow;
}

std::vector<uint8_t> make_tcp_segment(
    uint32_t seq, uint32_t ack, uint8_t flags, std::span<const uint8_t> data = {}) {
	std::vector<uint8_t> segment(sizeof(nstun::tcp_hdr) + data.size(), 0);
	auto* tcp = reinterpret_cast<nstun::tcp_hdr*>(segment.data());
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(ack);
	tcp->flags = flags;
	if (!data.empty()) {
		memcpy(segment.data() + sizeof(nstun::tcp_hdr), data.data(), data.size());
	}
	return segment;
}

void process_segment(nstun::Context* ctx, nstun::TcpFlow* flow, std::vector<uint8_t>* segment) {
	auto* tcp = reinterpret_cast<nstun::tcp_hdr*>(segment->data());
	nstun::tcp_process_data(
	    ctx, flow, tcp, std::span<const uint8_t>(*segment), sizeof(nstun::tcp_hdr));
}
} /* namespace */

namespace logs {
llevel_t getLogLevel() {
	return FATAL;
}

void logMsg(llevel_t, const char*, int, bool, const char*, ...) {}
} /* namespace logs */

namespace util {
uint64_t rnd64() {
	return 0x1000U;
}
} /* namespace util */

namespace nstun {
Context::~Context() = default;

void UdpFlow::handle_host_event(Context*, int, uint32_t) {}
bool UdpFlow::is_stale(time_t) const {
	return false;
}
void UdpFlow::destroy(Context*) {}

void IcmpFlow::handle_host_event(Context*, int, uint32_t) {}
bool IcmpFlow::is_stale(time_t) const {
	return false;
}
void IcmpFlow::destroy(Context*) {}

RuleResult evaluate_rules4(Context*, nstun_direction_t, nstun_proto_t, uint32_t, uint32_t,
    uint16_t, uint16_t) {
	return {};
}

RuleResult evaluate_rules6(Context*, nstun_direction_t, nstun_proto_t, const uint8_t*,
    const uint8_t*, uint16_t, uint16_t) {
	return {};
}

bool send_to_guest_v(
    Context*, const void* header, size_t header_len, const void*, size_t payload_len) {
	assert(header_len >= sizeof(ip4_hdr) + sizeof(tcp_hdr));
	const auto* bytes = reinterpret_cast<const uint8_t*>(header);
	assert((bytes[0] >> 4) == 4);
	const auto* tcp = reinterpret_cast<const tcp_hdr*>(bytes + sizeof(ip4_hdr));
	sent_packets.push_back({
	    .flags = tcp->flags,
	    .seq = ntohl(tcp->seq),
	    .ack = ntohl(tcp->ack_seq),
	    .payload_len = payload_len,
	});
	return true;
}

int send_http_connect(int, const uint8_t*, uint16_t, bool) {
	return 0;
}
size_t find_end_of_headers(const std::vector<uint8_t>&) {
	return 0;
}
bool parse_http_connect_reply(const std::vector<uint8_t>&) {
	return true;
}
int send_socks5_greeting(int) {
	return 0;
}
bool parse_socks5_auth_reply(std::span<const uint8_t>) {
	return true;
}
int send_socks5_connect(int, const uint8_t*, uint16_t, bool) {
	return 0;
}
} /* namespace nstun */

namespace {

void test_future_ack_drops_payload_without_mutation() {
	sent_packets.clear();
	nstun::Context ctx = {};
	ctx.epoll_fd = -1;
	ctx.tap_fd = -1;

	const nstun::FlowKey4 key = {};
	nstun::TcpFlow* flow = add_ipv4_flow(&ctx, key);
	flow->state = nstun::TcpState::ESTABLISHED;
	flow->syn_acked = true;
	flow->ack_from_guest = 0x1000U;
	flow->seq_to_guest = 0x1010U;
	flow->seq_from_guest = 0x2000U;
	flow->ack_to_guest = 0x2000U;
	flow->tx_buffer.resize(16, 0x41);

	const std::vector<uint8_t> original_tx_buffer = flow->tx_buffer;
	const uint8_t data[] = {'A', 'B', 'C'};
	/* Acceptable receive sequence with an ACK beyond SND.NXT. */
	std::vector<uint8_t> segment =
	    make_tcp_segment(0x2000U, 0x40001000U, nstun::NSTUN_TCP_FLAG_ACK, data);
	process_segment(&ctx, flow, &segment);

	auto it = ctx.ipv4_tcp_flows_by_key.find(key);
	assert(it != ctx.ipv4_tcp_flows_by_key.end());
	flow = it->second.get();
	assert(flow->ack_from_guest == 0x1000U);
	assert(flow->seq_to_guest == 0x1010U);
	assert(flow->tx_acked_offset == 0);
	assert(flow->tx_buffer == original_tx_buffer);
	assert(flow->rx_buffer.empty());
	assert(sent_packets.size() == 1);
	assert(sent_packets[0].flags == nstun::NSTUN_TCP_FLAG_ACK);
	assert(sent_packets[0].seq == 0x1010U);
	assert(sent_packets[0].ack == 0x2000U);
	assert(sent_packets[0].payload_len == 0);
}

void test_syn_sent_rejects_unacceptable_ack() {
	sent_packets.clear();
	nstun::Context ctx = {};
	const nstun::FlowKey4 key = {};
	nstun::TcpFlow* flow = add_ipv4_flow(&ctx, key);
	flow->state = nstun::TcpState::SYN_SENT;
	flow->inbound = true;
	flow->syn_acked = false;
	flow->ack_from_guest = 0x1000U;
	flow->seq_to_guest = 0x1001U;
	flow->ack_to_guest = 0x2000U;
	flow->tx_buffer = {0x41, 0x42};
	const std::vector<uint8_t> original_tx_buffer = flow->tx_buffer;

	std::vector<uint8_t> segment =
	    make_tcp_segment(0x2000U, 0x1002U, nstun::NSTUN_TCP_FLAG_ACK);
	process_segment(&ctx, flow, &segment);

	auto it = ctx.ipv4_tcp_flows_by_key.find(key);
	assert(it != ctx.ipv4_tcp_flows_by_key.end());
	flow = it->second.get();
	assert(flow->state == nstun::TcpState::SYN_SENT);
	assert(!flow->syn_acked);
	assert(flow->ack_from_guest == 0x1000U);
	assert(flow->seq_to_guest == 0x1001U);
	assert(flow->tx_buffer == original_tx_buffer);
	assert(sent_packets.size() == 1);
	assert(sent_packets[0].flags == nstun::NSTUN_TCP_FLAG_RST);
	assert(sent_packets[0].seq == 0x1002U);
	assert(sent_packets[0].payload_len == 0);
}

void test_valid_inbound_syn_ack_establishes_flow() {
	sent_packets.clear();
	nstun::Context ctx = {};
	const nstun::FlowKey4 key = {};
	nstun::TcpFlow* flow = add_ipv4_flow(&ctx, key);
	flow->state = nstun::TcpState::SYN_SENT;
	flow->inbound = true;
	flow->syn_acked = false;
	flow->ack_from_guest = 0x1000U;
	flow->seq_to_guest = 0x1001U;

	std::vector<uint8_t> segment = make_tcp_segment(
	    0x2000U, 0x1001U, nstun::NSTUN_TCP_FLAG_SYN | nstun::NSTUN_TCP_FLAG_ACK);
	process_segment(&ctx, flow, &segment);

	auto it = ctx.ipv4_tcp_flows_by_key.find(key);
	assert(it != ctx.ipv4_tcp_flows_by_key.end());
	flow = it->second.get();
	assert(flow->state == nstun::TcpState::ESTABLISHED);
	assert(flow->syn_acked);
	assert(flow->ack_from_guest == 0x1001U);
	assert(flow->seq_to_guest == 0x1001U);
	assert(flow->seq_from_guest == 0x2001U);
	assert(flow->ack_to_guest == 0x2001U);
	assert(sent_packets.size() == 1);
	assert(sent_packets[0].flags == nstun::NSTUN_TCP_FLAG_ACK);
	assert(sent_packets[0].seq == 0x1001U);
	assert(sent_packets[0].ack == 0x2001U);
	assert(sent_packets[0].payload_len == 0);
}

void test_push_to_guest_reports_destruction() {
	sent_packets.clear();

	nstun::Context invalid_ctx = {};
	const nstun::FlowKey4 key = {};
	nstun::TcpFlow* invalid_flow = add_ipv4_flow(&invalid_ctx, key);
	invalid_flow->state = nstun::TcpState::ESTABLISHED;
	invalid_flow->tx_buffer = {0x42};
	invalid_flow->tx_acked_offset = 2;
	assert(nstun::push_to_guest(&invalid_ctx, invalid_flow));
	assert(invalid_ctx.ipv4_tcp_flows_by_key.empty());
}

} /* namespace */

int main() {
	test_future_ack_drops_payload_without_mutation();
	test_syn_sent_rejects_unacceptable_ack();
	test_valid_inbound_syn_ack_establishes_flow();
	test_push_to_guest_reports_destruction();
	return 0;
}
