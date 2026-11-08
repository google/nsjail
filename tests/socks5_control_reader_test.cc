#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cassert>
#include <cstdint>
#include <ctime>
#include <vector>
#include <cstdio>
#include "nstun/socks5_control_reader.h"
static void test_partial(const std::vector<uint8_t>& first,
    const std::vector<uint8_t>& rest, size_t length) {
    int fds[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds)==0);
    int ep=epoll_create1(EPOLL_CLOEXEC); assert(ep>=0);
    epoll_event reg{}; reg.events=EPOLLIN|EPOLLERR|EPOLLHUP;reg.data.fd=fds[0];
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &reg)==0);
    std::vector<uint8_t> received; time_t last_active=0;
    assert(write(fds[1], first.data(), first.size())==(ssize_t)first.size());
    epoll_event ready{};assert(epoll_wait(ep, &ready, 1, 0)==1);
    auto s=nstun::read_socks5_control(fds[0], &received, length, &last_active);
    assert(s==nstun::Socks5ControlRead::PENDING);
    assert(received==first);
    for(int i=0;i<1000;i++)assert(epoll_wait(ep, &ready, 1, 0)==0);
    assert(write(fds[1], rest.data(), rest.size())==(ssize_t)rest.size());
    assert(epoll_wait(ep, &ready, 1, 0)==1);
    s=nstun::read_socks5_control(fds[0], &received, length, &last_active);
    assert(s==nstun::Socks5ControlRead::READY);
    assert(received.size()==length);
    close(ep);close(fds[0]);close(fds[1]);
}
int main() {
    test_partial({5}, {0}, 2);
    test_partial({5,0,0,1}, {0,0,0,0,0,0}, 10);
    test_partial({5,0,0,4}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 22);
    int fds[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);
    std::vector<uint8_t> v;time_t stamp=0;close(fds[1]);
    assert(nstun::read_socks5_control(fds[0], &v, 2, &stamp)==nstun::Socks5ControlRead::CLOSED);
    close(fds[0]);puts("SOCKS5 control-reader regression: PASS");
}
