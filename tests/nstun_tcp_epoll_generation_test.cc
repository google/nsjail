// A queued epoll event must not be delivered to a new owner of the same fd.
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <memory>

#include "nstun/tcp.h"

namespace nstun {
void handle_host_events(Context* ctx, uint64_t event_data, uint32_t events);
}

namespace {

struct Fixture {
	nstun::Context ctx{};

	Fixture() {
		ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
		ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	}

	~Fixture() {
		if (ctx.tap_fd >= 0) close(ctx.tap_fd);
		if (ctx.epoll_fd >= 0) close(ctx.epoll_fd);
	}

	bool valid() const { return ctx.epoll_fd >= 0 && ctx.tap_fd >= 0; }
};

uint64_t tagged_data(const nstun::TcpFlow* flow) {
	return (static_cast<uint64_t>(flow->epoll_generation) << 32) |
	    static_cast<uint32_t>(flow->host_fd);
}

nstun::TcpFlow* add_tcp_flow(nstun::Context* ctx, int fd, uint16_t port) {
	auto owned = std::make_unique<nstun::TcpFlow>();
	auto* flow = owned.get();
	flow->host_fd = fd;
	flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
	    .sport = htons(port), .dport = htons(18080)};
	flow->state = nstun::TcpState::ESTABLISHED;
	flow->seq_to_guest = flow->ack_from_guest = 1000;
	flow->syn_acked = true;
	flow->epoll_generation = ++ctx->next_tcp_epoll_generation;
	ctx->flows_by_fd.emplace(fd, flow);
	ctx->ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
	epoll_event event = {.events = EPOLLIN | EPOLLHUP | EPOLLERR,
	    .data = {.u64 = tagged_data(flow)}};
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) return nullptr;
	return flow;
}

bool expect_stale_hup(int epoll_fd, int fd, epoll_event* event) {
	return epoll_wait(epoll_fd, event, 1, 1000) == 1 &&
	    static_cast<int>(static_cast<uint32_t>(event->data.u64)) == fd &&
	    (event->events & EPOLLHUP) != 0;
}

bool expect_fresh_read(nstun::Context* ctx, nstun::TcpFlow* flow, int peer, char byte) {
	if (send(peer, &byte, 1, MSG_DONTWAIT) != 1) return false;
	epoll_event event{};
	if (epoll_wait(ctx->epoll_fd, &event, 1, 1000) != 1 ||
	    (event.events & EPOLLIN) == 0 || event.data.u64 != tagged_data(flow)) {
		return false;
	}
	nstun::handle_host_events(ctx, event.data.u64, event.events);
	return flow->tx_buffer.size() == 1 && flow->tx_buffer[0] == byte;
}

int tcp_to_tcp() {
	Fixture fixture;
	if (!fixture.valid()) return 1;
	int old_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, old_pair)) return 2;
	auto* old_flow = add_tcp_flow(&fixture.ctx, old_pair[0], 19011);
	if (!old_flow) return 3;
	close(old_pair[1]);
	epoll_event stale{};
	if (!expect_stale_hup(fixture.ctx.epoll_fd, old_pair[0], &stale)) return 4;
	nstun::tcp_destroy_flow(&fixture.ctx, old_flow);
	int new_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, new_pair)) return 5;
	if (new_pair[0] != old_pair[0]) return 6;
	auto* fresh = add_tcp_flow(&fixture.ctx, new_pair[0], 19012);
	if (!fresh || stale.data.u64 == tagged_data(fresh)) return 7;
	nstun::handle_host_events(&fixture.ctx, stale.data.u64, stale.events);
	if (fixture.ctx.flows_by_fd.find(new_pair[0]) == fixture.ctx.flows_by_fd.end() ||
	    fresh->last_active != 0 || fresh->host_eof || !fresh->tx_buffer.empty()) return 8;
	if (!expect_fresh_read(&fixture.ctx, fresh, new_pair[1], 'T')) return 9;
	close(new_pair[1]);
	return 0;
}

int untagged_to_tcp() {
	Fixture fixture;
	if (!fixture.valid()) return 1;
	int old_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, old_pair)) return 2;
	epoll_event old_event = {.events = EPOLLIN | EPOLLHUP | EPOLLERR,
	    .data = {.u64 = static_cast<uint32_t>(old_pair[0])}};
	if (epoll_ctl(fixture.ctx.epoll_fd, EPOLL_CTL_ADD, old_pair[0], &old_event)) return 3;
	close(old_pair[1]);
	epoll_event stale{};
	if (!expect_stale_hup(fixture.ctx.epoll_fd, old_pair[0], &stale)) return 4;
	if (epoll_ctl(fixture.ctx.epoll_fd, EPOLL_CTL_DEL, old_pair[0], nullptr)) return 5;
	close(old_pair[0]);
	int new_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, new_pair)) return 6;
	if (new_pair[0] != old_pair[0]) return 7;
	auto* fresh = add_tcp_flow(&fixture.ctx, new_pair[0], 19013);
	if (!fresh || stale.data.u64 == tagged_data(fresh)) return 8;
	nstun::handle_host_events(&fixture.ctx, stale.data.u64, stale.events);
	if (fresh->last_active != 0 || fresh->host_eof || !fresh->tx_buffer.empty()) return 9;
	if (!expect_fresh_read(&fixture.ctx, fresh, new_pair[1], 'U')) return 10;
	close(new_pair[1]);
	return 0;
}

struct CountingUntaggedFlow : nstun::Flow {
	int calls = 0;
	char received = 0;
	void handle_host_event(nstun::Context*, int fd, uint32_t) override {
		++calls;
		(void)recv(fd, &received, 1, MSG_DONTWAIT);
	}
	bool is_stale(time_t) const override { return false; }
	void destroy(nstun::Context*) override {}
};

int tcp_to_untagged() {
	Fixture fixture;
	if (!fixture.valid()) return 1;
	int old_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, old_pair)) return 2;
	auto* old_flow = add_tcp_flow(&fixture.ctx, old_pair[0], 19014);
	if (!old_flow) return 3;
	close(old_pair[1]);
	epoll_event stale{};
	if (!expect_stale_hup(fixture.ctx.epoll_fd, old_pair[0], &stale)) return 4;
	nstun::tcp_destroy_flow(&fixture.ctx, old_flow);
	int new_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, new_pair)) return 5;
	if (new_pair[0] != old_pair[0]) return 6;
	CountingUntaggedFlow fresh;
	fixture.ctx.flows_by_fd.emplace(new_pair[0], &fresh);
	epoll_event event = {.events = EPOLLIN | EPOLLHUP | EPOLLERR,
	    .data = {.u64 = static_cast<uint32_t>(new_pair[0])}};
	if (epoll_ctl(fixture.ctx.epoll_fd, EPOLL_CTL_ADD, new_pair[0], &event)) return 7;
	nstun::handle_host_events(&fixture.ctx, stale.data.u64, stale.events);
	if (fresh.calls != 0) return 8;
	if (send(new_pair[1], "N", 1, MSG_DONTWAIT) != 1) return 9;
	epoll_event fresh_event{};
	if (epoll_wait(fixture.ctx.epoll_fd, &fresh_event, 1, 1000) != 1 ||
	    fresh_event.data.u64 != event.data.u64 || (fresh_event.events & EPOLLIN) == 0) {
		return 10;
	}
	nstun::handle_host_events(&fixture.ctx, fresh_event.data.u64, fresh_event.events);
	if (fresh.calls != 1 || fresh.received != 'N') return 11;
	fixture.ctx.flows_by_fd.erase(new_pair[0]);
	close(new_pair[0]);
	close(new_pair[1]);
	return 0;
}

} // namespace

int main() {
	const struct {
		const char* name;
		int (*test)();
	} cases[] = {{"tcp_to_tcp", tcp_to_tcp},
	    {"untagged_to_tcp", untagged_to_tcp},
	    {"tcp_to_untagged", tcp_to_untagged}};
	for (const auto& test_case : cases) {
		int result = test_case.test();
		if (result != 0) {
			std::fprintf(stderr, "%s failed at check %d\n", test_case.name, result);
			return result;
		}
		std::printf("%s=pass\n", test_case.name);
	}
	return 0;
}
