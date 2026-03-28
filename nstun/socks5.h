#ifndef NSTUN_SOCKS5_H_
#define NSTUN_SOCKS5_H_

#include <stdint.h>

namespace nstun {

constexpr uint8_t SOCKS5_VERSION = 0x05;

constexpr uint8_t SOCKS5_AUTH_NONE = 0x00;

constexpr uint8_t SOCKS5_CMD_CONNECT = 0x01;
constexpr uint8_t SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

constexpr uint8_t SOCKS5_ATYP_IPV4 = 0x01;
constexpr uint8_t SOCKS5_ATYP_DOMAIN = 0x03;
constexpr uint8_t SOCKS5_ATYP_IPV6 = 0x04;

constexpr uint8_t SOCKS5_REP_SUCCESS = 0x00;

} /* namespace nstun */

#endif /* NSTUN_SOCKS5_H_ */