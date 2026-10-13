#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <vector>

#include "logs.h"
#include "nstun/core.h"
#include "nstun/tcp.h"

namespace {

int descriptor_count() {
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return -1;

    int count = 0;
    while (auto* entry = readdir(dir)) {
        if (entry->d_name[0] != '.') ++count;
    }
    closedir(dir);
    return count;
}

bool listener_ready(int epfd, int listener) {
    epoll_event events[64]{};
    int n = epoll_wait(epfd, events, 64, 0);
    if (n < 0) return false;

    for (int i = 0; i < n; ++i) {
        if (events[i].data.fd == listener &&
            (events[i].events & EPOLLIN)) {
            return true;
        }
    }
    return false;
}

int connect_local(const sockaddr_in& addr) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    if (connect(fd,
            reinterpret_cast<const sockaddr*>(&addr),
            sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

int main() {
    logs::setLogLevel(logs::ERROR);

    rlimit lim{};
    if (getrlimit(RLIMIT_NOFILE, &lim) != 0) return 2;

    rlim_t target = 4096;
    if (lim.rlim_max != RLIM_INFINITY && lim.rlim_max < target)
        target = lim.rlim_max;
    if (target < 3072) return 77;

    lim.rlim_cur = target;
    if (setrlimit(RLIMIT_NOFILE, &lim) != 0) return 77;

    nstun::Context ctx{};
    ctx.nsj = nullptr;
    ctx.guest_ip4 = htonl(0x0a000002U);
    ctx.host_ip4 = htonl(0x0a000001U);

    ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    ctx.stop_fd = -1;

    if (ctx.epoll_fd < 0 || ctx.tap_fd < 0) return 2;

    std::vector<int> clients;

    struct Cleanup {
        nstun::Context& ctx;
        std::vector<int>& clients;
        ~Cleanup() {
            for (int fd : clients) close(fd);
            close(ctx.tap_fd);
            close(ctx.epoll_fd);
        }
    } cleanup{ctx, clients};

    int listener = socket(
        AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) return 2;

    ctx.host_listener_fd_to_rule[listener] = {};

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listener, reinterpret_cast<sockaddr*>(&addr),
             sizeof(addr)) != 0 ||
        listen(listener, 32) != 0) return 2;

    socklen_t addrlen = sizeof(addr);
    if (getsockname(listener,
            reinterpret_cast<sockaddr*>(&addr),
            &addrlen) != 0) return 2;

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listener;

    if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD,
                  listener, &ev) != 0) return 2;

    nstun_rule_t rule{};
    rule.direction = NSTUN_DIR_HOST_TO_GUEST;
    rule.action = NSTUN_ACTION_REDIRECT;
    rule.proto = NSTUN_PROTO_TCP;
    rule.is_ipv6 = false;

    // Populate real TCP flows, rather than inserting synthetic
    // objects directly into NSTUN's flow maps.
    for (size_t i = 0; i < nstun::NSTUN_MAX_FLOWS; ++i) {
        int client = connect_local(addr);
        if (client < 0) return 2;

        clients.push_back(client);
        nstun::handle_host_tcp_accept(&ctx, listener, rule);

        if (ctx.ipv4_tcp_flows_by_key.size() != i + 1)
            return 2;
    }

    const size_t initial = ctx.ipv4_tcp_flows_by_key.size();

    int overflow = connect_local(addr);
    if (overflow < 0) return 2;
    clients.push_back(overflow);

    const bool readable_before =
        listener_ready(ctx.epoll_fd, listener);

    const int fds_before = descriptor_count();

    nstun::handle_host_tcp_accept(&ctx, listener, rule);

    const int fds_after = descriptor_count();

    const bool readable_after =
        listener_ready(ctx.epoll_fd, listener);

    const size_t final_flows =
        ctx.ipv4_tcp_flows_by_key.size();

    const bool cap_preserved =
        initial == nstun::NSTUN_MAX_FLOWS &&
        final_flows == nstun::NSTUN_MAX_FLOWS &&
        ctx.flows_by_fd.size() == nstun::NSTUN_MAX_FLOWS;

    const bool no_fd_leak =
        fds_before >= 0 && fds_after == fds_before;

    const bool passed =
        readable_before &&
        !readable_after &&
        cap_preserved &&
        no_fd_leak;

    printf("REAL_TCP_FLOWS=%zu\n", initial);
    printf("LISTENER_READY_BEFORE=%s\n",
           readable_before ? "true" : "false");
    printf("LISTENER_READY_AFTER=%s\n",
           readable_after ? "true" : "false");
    printf("CAPACITY_PRESERVED=%s\n",
           cap_preserved ? "true" : "false");
    printf("NO_FD_LEAK=%s\n",
           no_fd_leak ? "true" : "false");
    printf("REGRESSION_RESULT=%s\n",
           passed ? "PASS" : "FAIL");

    return passed ? 0 : 1;
}
