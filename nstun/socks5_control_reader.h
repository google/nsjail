#ifndef NSTUN_SOCKS5_CONTROL_READER_H_
#define NSTUN_SOCKS5_CONTROL_READER_H_
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <sys/socket.h>
#include <vector>
namespace nstun {
enum class Socks5ControlRead { READY, PENDING, CLOSED };
inline Socks5ControlRead read_socks5_control(int fd, std::vector<uint8_t>* pending,
    size_t required, time_t* last_active) {
    if (pending == nullptr || last_active == nullptr || required > 512 ||
        pending->size() > required) return Socks5ControlRead::CLOSED;
    while (pending->size() < required) {
        uint8_t buf[512];
        const size_t want = std::min(sizeof(buf), required - pending->size());
        const ssize_t n = recv(fd, buf, want, MSG_DONTWAIT);
        if (n > 0) {
            pending->insert(pending->end(), buf, buf + n);
            *last_active = time(nullptr);
            continue;
        }
        if (n == 0) return Socks5ControlRead::CLOSED;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return Socks5ControlRead::PENDING;
        return Socks5ControlRead::CLOSED;
    }
    return Socks5ControlRead::READY;
}
}
#endif
