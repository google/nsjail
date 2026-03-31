#ifndef NSTUN_H_
#define NSTUN_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	NSTUN_ACTION_DROP,
	NSTUN_ACTION_REJECT,
	NSTUN_ACTION_ALLOW,
	NSTUN_ACTION_REDIRECT,
	NSTUN_ACTION_ENCAP_SOCKS5,
	NSTUN_ACTION_ENCAP_CONNECT
} nstun_action_t;

typedef enum { NSTUN_DIR_GUEST_TO_HOST, NSTUN_DIR_HOST_TO_GUEST } nstun_direction_t;

typedef enum { NSTUN_PROTO_ANY, NSTUN_PROTO_TCP, NSTUN_PROTO_UDP, NSTUN_PROTO_ICMP } nstun_proto_t;

typedef struct {
	nstun_direction_t direction;
	nstun_action_t action;
	nstun_proto_t proto;
	bool is_ipv6;

	uint32_t src_ip4;
	uint32_t src_mask4;
	uint32_t dst_ip4;
	uint32_t dst_mask4;

	uint8_t src_ip6[16];
	uint8_t src_mask6[16];
	uint8_t dst_ip6[16];
	uint8_t dst_mask6[16];

	uint16_t sport_start;
	uint16_t sport_end;
	uint16_t dport_start;
	uint16_t dport_end;

	/* For REDIRECT */
	uint32_t redirect_ip4;
	uint8_t redirect_ip6[16];
	uint16_t redirect_port;
} nstun_rule_t;
struct nsj_t;

bool nstun_init_child(int sock, struct nsj_t* nsj);
bool nstun_init_parent(int sock, struct nsj_t* nsj);

#ifdef __cplusplus
}
#endif

#endif /* NSTUN_H_ */