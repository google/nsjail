#ifndef NSTUN_IPPARSE_H_
#define NSTUN_IPPARSE_H_

#include "byte_reader.h"

namespace nstun {

/*
 * Advance `r` past IPv6 extension headers until the first L4 protocol.
 * Returns that protocol number, or -1 if the chain is malformed, too deep,
 * or contains a fragment (nstun does not reassemble).
 */
int skip_ipv6_ext_headers(int next_header, ByteReader& r);

}  // namespace nstun

#endif	// NSTUN_IPPARSE_H_
