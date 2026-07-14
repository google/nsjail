#ifndef NSTUN_TCP_SEQ_H_
#define NSTUN_TCP_SEQ_H_

#include <stdint.h>

namespace nstun {

/* TCP sequence numbers use modulo-2^32 serial arithmetic. */
inline bool tcp_seq_after(uint32_t lhs, uint32_t rhs) {
	return static_cast<int32_t>(lhs - rhs) > 0;
}

inline bool tcp_seq_before(uint32_t lhs, uint32_t rhs) {
	return tcp_seq_after(rhs, lhs);
}

inline bool tcp_has_outstanding_sequence(uint32_t ack_from_guest, uint32_t seq_to_guest) {
	return tcp_seq_after(seq_to_guest, ack_from_guest);
}

enum class TcpAckDisposition {
	OLD,
	DUPLICATE,
	ADVANCING,
	FUTURE,
};

inline TcpAckDisposition tcp_classify_ack(
    uint32_t ack_from_guest, uint32_t seq_to_guest, uint32_t ack) {
	if (ack == ack_from_guest) {
		return TcpAckDisposition::DUPLICATE;
	}
	if (tcp_seq_after(ack, seq_to_guest)) {
		return TcpAckDisposition::FUTURE;
	}
	if (tcp_seq_after(ack, ack_from_guest)) {
		return TcpAckDisposition::ADVANCING;
	}
	return TcpAckDisposition::OLD;
}

inline bool tcp_ack_in_send_window(uint32_t ack_from_guest, uint32_t seq_to_guest, uint32_t ack) {
	return tcp_classify_ack(ack_from_guest, seq_to_guest, ack) ==
	       TcpAckDisposition::ADVANCING;
}

} /* namespace nstun */

#endif /* NSTUN_TCP_SEQ_H_ */
