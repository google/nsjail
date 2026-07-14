#include <assert.h>
#include <stdint.h>

#include <vector>

#include "nstun/tcp.h"

namespace {

struct SendState {
	bool syn_acked = true;
	bool fin_sent = false;
	bool fin_acked = false;
	uint32_t seq_to_guest = 0;
	uint32_t ack_from_guest = 0;
	std::vector<uint8_t> tx_buffer;
	size_t tx_acked_offset = 0;
};

void test_ack_classification() {
	assert(nstun::tcp_classify_ack(100, 200, 99) == nstun::TcpAckDisposition::OLD);
	assert(nstun::tcp_classify_ack(100, 200, 100) ==
	       nstun::TcpAckDisposition::DUPLICATE);
	assert(nstun::tcp_classify_ack(100, 200, 150) ==
	       nstun::TcpAckDisposition::ADVANCING);
	assert(nstun::tcp_classify_ack(100, 200, 201) ==
	       nstun::TcpAckDisposition::FUTURE);
}

void test_wraparound_ack_and_retransmission_comparisons() {
	assert(nstun::tcp_has_outstanding_sequence(0xfffffff0U, 0x20U));
	assert(!nstun::tcp_has_outstanding_sequence(0x20U, 0xfffffff0U));
	assert(nstun::tcp_ack_in_send_window(0xfffffff0U, 0x20U, 0x10U));
	assert(!nstun::tcp_ack_in_send_window(0xfffffff0U, 0x20U, 0x30U));
}

void test_valid_ack_updates_send_state() {
	SendState state;
	state.ack_from_guest = 100;
	state.seq_to_guest = 116;
	state.tx_buffer.resize(16, 0x41);

	assert(nstun::tcp_apply_ack(&state, 108) == nstun::TcpAckUpdate::ADVANCED);
	assert(state.ack_from_guest == 108);
	assert(state.tx_acked_offset == 8);
	assert(state.tx_buffer.size() == 16);

	assert(nstun::tcp_apply_ack(&state, 116) == nstun::TcpAckUpdate::ADVANCED);
	assert(state.ack_from_guest == 116);
	assert(state.tx_acked_offset == 0);
	assert(state.tx_buffer.empty());
}

void test_forged_future_ack_drops_segment_without_mutation() {
	SendState state;
	state.ack_from_guest = 0x1000U;
	state.seq_to_guest = 0x1010U;
	state.tx_buffer.resize(16, 0x42);
	state.tx_acked_offset = 3;

	const uint32_t forged_acks[] = {
	    0x10001000U,
	    0x20001000U,
	    0x30001000U,
	    0x40001000U,
	    0x50001000U,
	    0x60001000U,
	    0x70001000U,
	};
	const SendState original = state;
	bool payload_delivered = false;
	for (uint32_t forged_ack : forged_acks) {
		nstun::TcpAckUpdate update = nstun::tcp_apply_ack(&state, forged_ack);
		assert(update == nstun::TcpAckUpdate::FUTURE);
		if (nstun::tcp_ack_allows_payload(update)) {
			payload_delivered = true;
		}
		assert(state.ack_from_guest == original.ack_from_guest);
		assert(state.seq_to_guest == original.seq_to_guest);
		assert(state.tx_acked_offset == original.tx_acked_offset);
		assert(state.tx_buffer == original.tx_buffer);
	}
	assert(!payload_delivered);
}

void test_invalid_buffer_state_is_not_partially_updated() {
	SendState state;
	state.ack_from_guest = 100;
	state.seq_to_guest = 108;
	state.tx_buffer.resize(4, 0x43);

	const SendState original = state;
	nstun::TcpAckUpdate update = nstun::tcp_apply_ack(&state, 108);
	assert(update == nstun::TcpAckUpdate::INVALID_BUFFER);
	assert(!nstun::tcp_ack_allows_payload(update));
	assert(state.ack_from_guest == original.ack_from_guest);
	assert(state.syn_acked == original.syn_acked);
	assert(state.fin_acked == original.fin_acked);
	assert(state.tx_acked_offset == original.tx_acked_offset);
	assert(state.tx_buffer == original.tx_buffer);
}

void test_syn_sent_ack_window() {
	/* A SYN consumes exactly one sequence number. */
	assert(nstun::tcp_ack_in_send_window(0xfffffff0U, 0xfffffff1U, 0xfffffff1U));
	assert(!nstun::tcp_ack_in_send_window(0xfffffff0U, 0xfffffff1U, 0xfffffff0U));
	assert(!nstun::tcp_ack_in_send_window(0xfffffff0U, 0xfffffff1U, 0xfffffff2U));

	SendState state;
	state.syn_acked = false;
	state.ack_from_guest = 0xfffffff0U;
	state.seq_to_guest = 0xfffffff1U;
	assert(nstun::tcp_apply_ack(&state, 0xfffffff1U) ==
	       nstun::TcpAckUpdate::ADVANCED);
	assert(state.syn_acked);
	assert(state.ack_from_guest == 0xfffffff1U);
	assert(state.tx_acked_offset == 0);
}

void test_fin_ack_accounts_only_for_buffered_data() {
	SendState state;
	state.fin_sent = true;
	state.ack_from_guest = 100;
	state.seq_to_guest = 105;
	state.tx_buffer.resize(4, 0x44);

	assert(nstun::tcp_apply_ack(&state, 105) == nstun::TcpAckUpdate::ADVANCED);
	assert(state.fin_acked);
	assert(state.ack_from_guest == 105);
	assert(state.tx_acked_offset == 0);
	assert(state.tx_buffer.empty());
}

} /* namespace */

int main() {
	test_ack_classification();
	test_wraparound_ack_and_retransmission_comparisons();
	test_valid_ack_updates_send_state();
	test_forged_future_ack_drops_segment_without_mutation();
	test_invalid_buffer_state_is_not_partially_updated();
	test_syn_sent_ack_window();
	test_fin_ack_accounts_only_for_buffered_data();
	return 0;
}
