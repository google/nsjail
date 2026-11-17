#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include "logs.h"
#include "nstun/icmp.h"
#include "nstun/policy.h"
#include "nstun/tcp.h"
#include "nstun/tun.h"
#include "nstun/udp.h"

namespace {

#define CHECK(expr)                                                                    \
	do {                                                                           \
		if (!(expr)) {                                                         \
			std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
			std::exit(EXIT_FAILURE);                                       \
		}                                                                      \
	} while (false)

struct Fd {
	explicit Fd(int value) : value(value) { CHECK(value >= 0); }
	~Fd() { close(value); }
	Fd(const Fd&) = delete;
	Fd& operator=(const Fd&) = delete;

	int value;
};

struct Datagram {
	sockaddr_in destination;
	std::vector<uint8_t> bytes;
};

std::vector<Datagram> outgoing;
std::vector<uint8_t> guest_reply;
sockaddr_in mock_proxy;
sockaddr_in mock_relay;
bool deliver_to_mock_relay;
size_t socket_calls;

sockaddr_in endpoint(const char* address, uint16_t port) {
	sockaddr_in result{};
	result.sin_family = AF_INET;
	result.sin_port = htons(port);
	CHECK(inet_pton(AF_INET, address, &result.sin_addr) == 1);
	return result;
}

bool same_endpoint(const sockaddr_in& left, const sockaddr_in& right) {
	return left.sin_family == right.sin_family && left.sin_port == right.sin_port &&
	       left.sin_addr.s_addr == right.sin_addr.s_addr;
}

sockaddr_in bind_loopback(int fd, const char* ip = "127.0.0.1") {
	sockaddr_in address = endpoint(ip, 0);
	CHECK(IN_LOOPBACK(ntohl(address.sin_addr.s_addr)));
	CHECK(bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
	socklen_t size = sizeof(address);
	CHECK(getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) == 0);
	return address;
}

void ready(int fd, short event) {
	pollfd descriptor{fd, event, 0};
	CHECK(poll(&descriptor, 1, 1000) == 1);
	CHECK(descriptor.revents & event);
}

void send_control(int fd, std::span<const uint8_t> bytes) {
	CHECK(send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL) ==
	      static_cast<ssize_t>(bytes.size()));
}

void send_control_reply(int proxy, int client, std::span<const uint8_t> bytes) {
	// Dispatch only after a complete reply is readable. This test covers endpoints.
	const int reply_size = bytes.size();
	CHECK(setsockopt(client, SOL_SOCKET, SO_RCVLOWAT, &reply_size, sizeof(reply_size)) == 0);
	send_control(proxy, bytes);
	ready(client, POLLIN);
	const int default_low_water = 1;
	CHECK(setsockopt(client, SOL_SOCKET, SO_RCVLOWAT, &default_low_water,
	          sizeof(default_low_water)) == 0);
}

void expect_control(int fd, std::span<const uint8_t> expected) {
	std::vector<uint8_t> actual(expected.size());
	size_t received = 0;
	while (received < actual.size()) {
		ready(fd, POLLIN);
		ssize_t length =
		    recv(fd, actual.data() + received, actual.size() - received, MSG_DONTWAIT);
		CHECK(length > 0);
		received += length;
	}
	CHECK(std::ranges::equal(actual, expected));
}

nstun::RuleResult proxy_rule() {
	nstun::RuleResult rule{};
	rule.action = NSTUN_ACTION_ENCAP_SOCKS5;
	rule.redirect_ip4 = mock_proxy.sin_addr.s_addr;
	rule.redirect_port = ntohs(mock_proxy.sin_port);
	return rule;
}

constexpr std::array<uint8_t, 2> marker{0x52, 0x31};
constexpr uint16_t guest_destination_port = 42001;

void guest_datagram(nstun::Context& ctx, bool ipv6, uint8_t sequence) {
	std::array<uint8_t, sizeof(nstun::udp_hdr) + marker.size() + 1> packet{};
	nstun::udp_hdr udp{};
	udp.source = htons(41000);
	udp.dest = htons(guest_destination_port);
	udp.len = htons(packet.size());
	std::memcpy(packet.data(), &udp, sizeof(udp));
	std::ranges::copy(marker, packet.begin() + sizeof(udp));
	packet.back() = sequence;

	if (ipv6) {
		nstun::ip6_hdr ip{};
		CHECK(inet_pton(AF_INET6, "2001:db8::10", ip.saddr) == 1);
		CHECK(inet_pton(AF_INET6, "2001:db8::20", ip.daddr) == 1);
		nstun::pseudo_hdr6 pseudo{};
		std::memcpy(pseudo.saddr, ip.saddr, sizeof(ip.saddr));
		std::memcpy(pseudo.daddr, ip.daddr, sizeof(ip.daddr));
		pseudo.len = htonl(packet.size());
		pseudo.next_header = IPPROTO_UDP;
		uint32_t sum = nstun::compute_checksum_part(&pseudo, sizeof(pseudo));
		udp.check = nstun::compute_checksum(packet.data(), packet.size(), sum);
		if (udp.check == 0) udp.check = 0xffff;
		std::memcpy(packet.data(), &udp, sizeof(udp));
		nstun::handle_udp6(&ctx, &ip, packet);
	} else {
		nstun::ip4_hdr ip{};
		ip.saddr = endpoint("192.0.2.10", 0).sin_addr.s_addr;
		ip.daddr = endpoint("192.0.2.20", 0).sin_addr.s_addr;
		nstun::handle_udp4(&ctx, &ip, packet);
	}
}

void check_encapsulation(const Datagram& datagram, bool ipv6, uint8_t sequence) {
	std::vector<uint8_t> expected{0, 0, 0, static_cast<uint8_t>(ipv6 ? 4 : 1)};
	std::array<uint8_t, 16> address{};
	CHECK(inet_pton(ipv6 ? AF_INET6 : AF_INET, ipv6 ? "2001:db8::20" : "192.0.2.20",
	          address.data()) == 1);
	expected.insert(expected.end(), address.begin(), address.begin() + (ipv6 ? 16 : 4));
	expected.push_back(guest_destination_port >> 8);
	expected.push_back(guest_destination_port & 0xff);
	expected.insert(expected.end(), marker.begin(), marker.end());
	expected.push_back(sequence);
	CHECK(datagram.bytes == expected);
}

}  // namespace

extern "C" int __real_connect(int, const sockaddr*, socklen_t);
extern "C" int __real_socket(int, int, int);
extern "C" ssize_t __real_sendto(int, const void*, size_t, int, const sockaddr*, socklen_t);

extern "C" int __wrap_socket(int domain, int type, int protocol) {
	++socket_calls;
	return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_connect(int fd, const sockaddr* address, socklen_t size) {
	CHECK(size == sizeof(sockaddr_in));
	sockaddr_in destination{};
	std::memcpy(&destination, address, sizeof(destination));
	CHECK(same_endpoint(destination, mock_proxy));
	return __real_connect(fd, address, size);
}

extern "C" ssize_t __wrap_sendto(
    int fd, const void* data, size_t length, int flags, const sockaddr* address, socklen_t size) {
	CHECK(size == sizeof(sockaddr_in));
	sockaddr_in destination{};
	std::memcpy(&destination, address, sizeof(destination));
	CHECK(destination.sin_family == AF_INET);
	const auto* bytes = static_cast<const uint8_t*>(data);
	outgoing.push_back({destination, {bytes, bytes + length}});
	if (deliver_to_mock_relay) {
		CHECK(same_endpoint(destination, mock_relay));
		return __real_sendto(fd, data, length, flags, address, size);
	}

	// Record the endpoint at the call boundary without invoking kernel routing.
	return static_cast<ssize_t>(length);
}

namespace logs {
llevel_t getLogLevel() { return FATAL; }
void logMsg(llevel_t, const char*, int, bool, const char*, ...) {}
}  // namespace logs

namespace nstun {
Context::~Context() = default;

// Context owns these flow types, but this harness only creates UDP flows.
void IcmpFlow::handle_host_event(Context*, int, uint32_t) { CHECK(false); }
bool IcmpFlow::is_stale(time_t) const { CHECK(false); }
void IcmpFlow::destroy(Context*) { CHECK(false); }
void TcpFlow::handle_host_event(Context*, int, uint32_t) { CHECK(false); }
void TcpFlow::periodic_check(Context*, time_t) { CHECK(false); }
bool TcpFlow::is_stale(time_t) const { CHECK(false); }
void TcpFlow::destroy(Context*) { CHECK(false); }

RuleResult evaluate_rules4(Context*, nstun_direction_t, nstun_proto_t, uint32_t, uint32_t,
    uint16_t, uint16_t) {
	return proxy_rule();
}
RuleResult evaluate_rules6(Context*, nstun_direction_t, nstun_proto_t, const uint8_t*,
    const uint8_t*, uint16_t, uint16_t) {
	return proxy_rule();
}
bool send_to_guest_v(Context*, const void*, size_t, const void* payload, size_t len) {
	const auto* bytes = static_cast<const uint8_t*>(payload);
	guest_reply.assign(bytes, bytes + len);
	return true;
}
void send_icmp4_error(Context*, const ip4_hdr*, size_t, uint8_t, uint8_t) { CHECK(false); }
void send_icmp6_error(Context*, const ip6_hdr*, size_t, uint8_t, uint8_t) { CHECK(false); }
}  // namespace nstun

namespace {

void check_live_relay(nstun::Context& ctx, nstun::UdpFlow& flow, int relay_fd, uint8_t sequence) {
	sockaddr_in client{};
	for (const auto& datagram : outgoing) {
		ready(relay_fd, POLLIN);
		std::array<uint8_t, 128> buffer{};
		socklen_t size = sizeof(client);
		ssize_t length = recvfrom(relay_fd, buffer.data(), buffer.size(), MSG_DONTWAIT,
		    reinterpret_cast<sockaddr*>(&client), &size);
		CHECK(length == static_cast<ssize_t>(datagram.bytes.size()));
		CHECK(std::ranges::equal(datagram.bytes, std::span(buffer).first(length)));
	}
	CHECK(client.sin_family == AF_INET);
	CHECK(IN_LOOPBACK(ntohl(client.sin_addr.s_addr)));
	CHECK(client.sin_port != 0);
	const auto& reply = outgoing.back().bytes;
	Fd other_peer(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
	char ip[INET_ADDRSTRLEN];
	CHECK(inet_ntop(AF_INET, &mock_relay.sin_addr, ip, sizeof(ip)) != nullptr);
	sockaddr_in other = bind_loopback(other_peer.value, ip);
	CHECK(other.sin_port != mock_relay.sin_port);
	for (int sender : {other_peer.value, relay_fd}) {
		CHECK(__real_sendto(sender, reply.data(), reply.size(), 0,
		          reinterpret_cast<const sockaddr*>(&client), sizeof(client)) ==
		      static_cast<ssize_t>(reply.size()));
		ready(flow.host_fd, POLLIN);
		flow.handle_host_event(&ctx, flow.host_fd, EPOLLIN);
		if (sender == other_peer.value) CHECK(guest_reply.empty());
	}
	CHECK((guest_reply == std::vector<uint8_t>{marker[0], marker[1], sequence}));
}

int begin_association(nstun::Context& ctx, int listener, bool ipv6, uint8_t sequence) {
	guest_datagram(ctx, ipv6, sequence);
	ready(listener, POLLIN);
	return accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

nstun::UdpFlow* negotiate(nstun::Context& ctx, int proxy) {
	CHECK(ctx.flows_by_fd.size() == 1);
	auto* flow = static_cast<nstun::UdpFlow*>(ctx.flows_by_fd.begin()->second);
	CHECK(flow->state == nstun::UdpSocks5State::TCP_CONNECTING);
	CHECK(flow->tx_queue.size() == 1 && outgoing.empty());

	ready(flow->tcp_fd, POLLOUT);
	flow->handle_host_event(&ctx, flow->tcp_fd, EPOLLOUT);
	expect_control(proxy, std::array<uint8_t, 3>{5, 1, 0});
	send_control_reply(proxy, flow->tcp_fd, std::array<uint8_t, 2>{5, 0});
	flow->handle_host_event(&ctx, flow->tcp_fd, EPOLLIN);
	expect_control(proxy, std::array<uint8_t, 10>{5, 3, 0, 1, 0, 0, 0, 0, 0, 0});
	CHECK(flow->state == nstun::UdpSocks5State::SOCKS5_ASSOCIATE);
	return flow;
}

void send_relay_reply(nstun::Context& ctx, nstun::UdpFlow& flow, int proxy,
    const sockaddr_in& advertised) {
	std::array<uint8_t, 10> reply{5, 0, 0, 1};
	std::memcpy(reply.data() + 4, &advertised.sin_addr, 4);
	std::memcpy(reply.data() + 8, &advertised.sin_port, 2);
	send_control_reply(proxy, flow.tcp_fd, reply);
	flow.handle_host_event(&ctx, flow.tcp_fd, EPOLLIN);
}

bool run_case(const char* name, const char* advertised_ip, uint16_t advertised_port, bool live,
    bool ipv6, bool reject = false) {
	outgoing.clear();
	guest_reply.clear();
	deliver_to_mock_relay = live;

	Fd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
	mock_proxy = bind_loopback(listener.value);
	CHECK(listen(listener.value, 1) == 0);
	Fd relay(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
	mock_relay = bind_loopback(relay.value, live ? advertised_ip : "127.0.0.1");
	sockaddr_in advertised = live ? mock_relay : endpoint(advertised_ip, advertised_port);

	Fd epoll(epoll_create1(EPOLL_CLOEXEC));
	nstun::Context ctx{};
	ctx.epoll_fd = epoll.value;
	Fd proxy(begin_association(ctx, listener.value, ipv6, 1));
	auto* flow = negotiate(ctx, proxy.value);
	const int old_control_fd = flow->tcp_fd;
	socket_calls = 0;
	send_relay_reply(ctx, *flow, proxy.value, advertised);
	uint8_t first_sequence = 1;
	std::optional<Fd> recovery_proxy;

	if (reject) {
		if (socket_calls || !outgoing.empty() || !ctx.flows_by_fd.empty()) {
			std::printf("FAIL %-23s guest IPv%d  socket calls=%zu  send attempts=%zu  "
			            "registered fds=%zu\n", name, ipv6 ? 6 : 4, socket_calls,
			        outgoing.size(), ctx.flows_by_fd.size());
			return false;
		}
		CHECK(ctx.ipv4_udp_flows_by_key.empty() && ctx.ipv6_udp_flows_by_key.empty());
		CHECK(fcntl(old_control_fd, F_GETFD) == -1 && errno == EBADF);
		epoll_event event{};
		CHECK(epoll_wait(epoll.value, &event, 1, 0) == 0);
		ready(proxy.value, POLLIN);
		uint8_t byte{};
		CHECK(recv(proxy.value, &byte, sizeof(byte), MSG_DONTWAIT) == 0);

		// Retry the same flow with a concrete endpoint and a new payload.
		deliver_to_mock_relay = true;
		advertised = mock_relay;
		first_sequence = 2;
		recovery_proxy.emplace(begin_association(ctx, listener.value, ipv6, first_sequence));
		flow = negotiate(ctx, recovery_proxy->value);
		send_relay_reply(ctx, *flow, recovery_proxy->value, advertised);
	}

	CHECK(ctx.flows_by_fd.size() == 2);
	CHECK(flow->state == nstun::UdpSocks5State::ESTABLISHED);
	CHECK(flow->bnd_ip == advertised.sin_addr.s_addr && flow->bnd_port == advertised.sin_port);
	CHECK(flow->tx_queue.empty() && outgoing.size() == 1);

	guest_datagram(ctx, ipv6, first_sequence + 1);
	CHECK(outgoing.size() == 2);
	for (size_t i = 0; i < outgoing.size(); ++i) {
		CHECK(same_endpoint(outgoing[i].destination, advertised));
		check_encapsulation(outgoing[i], ipv6, first_sequence + i);
	}
	if (deliver_to_mock_relay) check_live_relay(ctx, *flow, relay.value, first_sequence + 1);

	if (reject) {
		std::printf("PASS %-23s guest IPv%d  rejected  zero socket/send attempts  "
		            "resources released  recovery delivered only new data\n",
		    name, ipv6 ? 6 : 4);
		return true;
	}

	const auto& destination = outgoing[0].destination;
	char ip[INET_ADDRSTRLEN];
	CHECK(inet_ntop(AF_INET, &destination.sin_addr, ip, sizeof(ip)) != nullptr);
	if (live) {
		std::printf("PASS %-23s guest IPv%d  established  queued/steady=%s:<bound port>"
		            "  mock delivery and peer match verified\n", name, ipv6 ? 6 : 4, ip);
	} else {
		std::printf("PASS %-23s guest IPv%d  established  queued/steady=%s:%u"
		            "  intercepted\n", name, ipv6 ? 6 : 4, ip, ntohs(destination.sin_port));
	}
	return true;
}

}  // namespace

int main() {
	size_t passed = 0;
	for (bool ipv6 : {false, true}) {
		passed += run_case("explicit loopback", "127.0.0.1", 0, true, ipv6);
		passed += run_case("separate loopback relay", "127.0.0.2", 0, true, ipv6);
		passed += run_case("distinct IPv4 relay", "198.51.100.50", 43001, false, ipv6);
		passed += run_case("unspecified address", "0.0.0.0", 43001, false, ipv6, true);
		passed += run_case("zero port", "198.51.100.50", 0, false, ipv6, true);
		passed += run_case("unspecified + zero port", "0.0.0.0", 0, false, ipv6, true);
	}
	constexpr size_t total = 12;
	std::printf("%zu passed, %zu failed\n", passed, total - passed);
	return passed == total ? EXIT_SUCCESS : EXIT_FAILURE;
}
