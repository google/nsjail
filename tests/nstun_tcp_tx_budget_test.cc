// Bounded local integration oracle for the pinned nsjail nstun TCP path.
// Host endpoints use loopback TCP or AF_UNIX; guest-bound frames go to a pipe
// or /dev/null.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "nstun/tcp.h"

namespace nstun { bool flush_to_host(Context* ctx, TcpFlow* flow); }
namespace nstun { void handle_host_tcp_data_eof(Context* ctx, TcpFlow* flow, int fd); }

// A guest half-close shuts down the host socket's write side. When the peer
// sends data and closes, Linux reports EPOLLIN|EPOLLHUP together. Under a full
// shared budget we retain the unread response without a false FIN or reset.
// A one-byte remainder covers
// the case where the first read succeeds but cannot consume the whole reply.
static int half_closed_host_hup_test(size_t remainder) {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  int tap[2];
  if (ctx.epoll_fd < 0 || pipe2(tap, O_NONBLOCK | O_CLOEXEC)) return 201;
  ctx.tap_fd = tap[1];

  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) return 202;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
      listen(listener, 1)) return 203;
  socklen_t address_len = sizeof(address);
  if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_len)) return 204;
  int host = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (host < 0 || connect(host, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return 205;
  int peer = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
  close(listener);
  if (peer < 0 || fcntl(host, F_SETFL, fcntl(host, F_GETFL) | O_NONBLOCK)) return 206;

  auto owned = std::make_unique<nstun::TcpFlow>();
  auto* flow = owned.get();
  flow->host_fd = host;
  flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                .sport = htons(static_cast<uint16_t>(19000 + remainder)),
                .dport = htons(18080)};
  flow->state = nstun::TcpState::CLOSE_WAIT;
  flow->guest_eof = true;
  flow->seq_to_guest = flow->ack_from_guest = 1000;
  flow->syn_acked = true;
  ctx.flows_by_fd.emplace(host, flow);
  ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
  epoll_event registration{.events = EPOLLIN | EPOLLERR | EPOLLHUP,
                           .data = {.fd = host}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, host, &registration) ||
      shutdown(host, SHUT_WR)) return 207;
  constexpr char payload[] = "Z1234567";
  if (send(peer, payload, sizeof(payload) - 1, MSG_DONTWAIT) !=
      static_cast<ssize_t>(sizeof(payload) - 1)) return 208;
  close(peer);
  epoll_event event{};
  if (epoll_wait(ctx.epoll_fd, &event, 1, 100) != 1 ||
      (event.events & (EPOLLIN | EPOLLHUP)) != (EPOLLIN | EPOLLHUP)) return 209;

  const size_t occupied = ctx.tcp_tx_buffer_budget.limit() - remainder;
  if (!ctx.tcp_tx_buffer_budget.try_reserve(occupied)) return 210;
  nstun::handle_host_tcp(&ctx, flow, event.events);
  if (!ctx.flows_by_fd.count(host) || flow->tx_buffer.size() != remainder ||
      ctx.tcp_tx_buffer_budget.used() != occupied + remainder ||
      ctx.tcp_tx_budget_waiters.size() != (remainder < sizeof(payload) - 1 ? 1u : 0u))
    return 211;
  if (!ctx.tcp_tx_buffer_budget.release(occupied)) return 216;
  if (remainder < sizeof(payload) - 1) {
    nstun::tcp_resume_tx_budget_blocked_flows(&ctx);
    if (epoll_wait(ctx.epoll_fd, &event, 1, 100) != 1) return 218;
    nstun::handle_host_tcp(&ctx, flow, event.events);
  }
  if (!ctx.flows_by_fd.count(host) || flow->tx_buffer.size() != sizeof(payload) - 1 ||
      ctx.tcp_tx_buffer_budget.used() != sizeof(payload) - 1) return 219;

  uint8_t frames[256]{};
  ssize_t bytes = read(tap[0], frames, sizeof(frames));
  if (bytes <= 0) return 212;
  bool saw_rst = false, saw_fin = false;
  size_t payload_bytes = 0;
  size_t offset = 0;
  while (offset < static_cast<size_t>(bytes)) {
    if (static_cast<size_t>(bytes) - offset < sizeof(nstun::ip4_hdr) +
          sizeof(nstun::tcp_hdr)) return 213;
    const auto* ip = reinterpret_cast<const nstun::ip4_hdr*>(frames + offset);
    size_t packet_bytes = ntohs(ip->tot_len);
    if (packet_bytes < sizeof(nstun::ip4_hdr) + sizeof(nstun::tcp_hdr) ||
        packet_bytes > static_cast<size_t>(bytes) - offset) return 214;
    const auto* tcp = reinterpret_cast<const nstun::tcp_hdr*>(
        frames + offset + sizeof(nstun::ip4_hdr));
    saw_rst |= (tcp->flags & nstun::NSTUN_TCP_FLAG_RST) != 0;
    saw_fin |= (tcp->flags & nstun::NSTUN_TCP_FLAG_FIN) != 0;
    size_t data_bytes = packet_bytes - sizeof(nstun::ip4_hdr) - sizeof(nstun::tcp_hdr);
    if (data_bytes > sizeof(payload) - 1 - payload_bytes ||
        memcmp(frames + offset + sizeof(nstun::ip4_hdr) + sizeof(nstun::tcp_hdr),
               payload + payload_bytes, data_bytes) != 0) return 215;
    payload_bytes += data_bytes;
    offset += packet_bytes;
  }
  if (saw_rst || saw_fin || payload_bytes != sizeof(payload) - 1) return 217;
  nstun::tcp_destroy_flow(&ctx, flow);
  if (ctx.tcp_tx_buffer_budget.used() != 0) return 220;
  close(tap[0]);
  close(tap[1]);
  close(ctx.epoll_fd);
  return 0;
}

// A host FIN leaves its read side closed but can still receive guest data.
// Once the peer drains a full send queue, the queued byte must wake promptly.
static int half_closed_host_write_test(bool queue_before_eof) {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  int pair[2];
  if (ctx.epoll_fd < 0 || ctx.tap_fd < 0 ||
      socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair))
    return 180;
  auto owned = std::make_unique<nstun::TcpFlow>();
  auto* flow = owned.get();
  flow->host_fd = pair[0];
  flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                .sport = htons(19072), .dport = htons(18080)};
  flow->state = nstun::TcpState::ESTABLISHED;
  flow->seq_to_guest = flow->ack_from_guest = 1000;
  ctx.flows_by_fd.emplace(pair[0], flow);
  ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
  epoll_event registration{.events = EPOLLIN | EPOLLHUP | EPOLLERR,
                           .data = {.fd = pair[0]}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, pair[0], &registration) ||
      shutdown(pair[1], SHUT_WR)) return 181;
  if (!queue_before_eof) nstun::handle_host_tcp_data_eof(&ctx, flow, pair[0]);
  char block[4096]{};
  bool blocked = false;
  for (int i = 0; i < 512; ++i) {
    ssize_t n = send(pair[0], block, sizeof(block), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      blocked = true;
      break;
    }
    if (n <= 0) return 182;
  }
  if (!blocked || !ctx.tcp_rx_buffer_budget.try_reserve(1)) return 183;
  flow->rx_buffer.push_back('Q');
  if (nstun::flush_to_host(&ctx, flow) || !flow->epoll_out_registered) return 184;
  if (queue_before_eof) nstun::handle_host_tcp_data_eof(&ctx, flow, pair[0]);
  while (recv(pair[1], block, sizeof(block), MSG_DONTWAIT) > 0) {}
  epoll_event wake{};
  if (epoll_wait(ctx.epoll_fd, &wake, 1, 250) != 1) return 185;
  nstun::handle_host_tcp(&ctx, flow, wake.events);
  char got = 0;
  if (recv(pair[1], &got, 1, MSG_DONTWAIT) != 1 || got != 'Q' ||
      !flow->rx_buffer.empty() || !flow->epoll_detached) return 186;
  nstun::tcp_destroy_flow(&ctx, flow);
  close(pair[1]);
  close(ctx.tap_fd);
  close(ctx.epoll_fd);
  return 0;
}

// A valid CONNECT response may be coalesced with tunnel bytes. The handshake
// consumes only headers; the normal read path waits for shared TX capacity.
static int connect_tail_at_budget_test() {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  int pair[2];
  if (ctx.epoll_fd < 0 || ctx.tap_fd < 0 ||
      socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair))
    return 187;
  auto owned = std::make_unique<nstun::TcpFlow>();
  auto* flow = owned.get();
  flow->host_fd = pair[0];
  flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                .sport = htons(19073), .dport = htons(18080)};
  flow->state = nstun::TcpState::HTTP_CONNECT_WAIT;
  flow->seq_to_guest = flow->ack_from_guest = 1000;
  ctx.flows_by_fd.emplace(pair[0], flow);
  ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
  epoll_event registration{.events = EPOLLIN | EPOLLHUP | EPOLLERR,
                           .data = {.fd = pair[0]}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, pair[0], &registration)) return 188;
  constexpr char response[] = "HTTP/1.1 200 Connection established\r\n\r\nX";
  if (send(pair[1], response, sizeof(response) - 1, MSG_DONTWAIT) !=
      sizeof(response) - 1) return 189;
  const size_t full = ctx.tcp_tx_buffer_budget.limit();
  if (!ctx.tcp_tx_buffer_budget.try_reserve(full)) return 190;
  nstun::handle_host_tcp(&ctx, flow, EPOLLIN);
  if (!ctx.flows_by_fd.count(pair[0]) || flow->state != nstun::TcpState::ESTABLISHED ||
      !flow->tx_buffer.empty()) return 191;
  epoll_event pending{};
  if (epoll_wait(ctx.epoll_fd, &pending, 1, 250) != 1) return 192;
  nstun::handle_host_tcp(&ctx, flow, pending.events);
  if (!flow->tx_budget_blocked || !ctx.tcp_tx_buffer_budget.release(full)) return 193;
  nstun::tcp_resume_tx_budget_blocked_flows(&ctx);
  epoll_event resumed{};
  if (epoll_wait(ctx.epoll_fd, &resumed, 1, 250) != 1) return 194;
  nstun::handle_host_tcp(&ctx, flow, resumed.events);
  if (!ctx.flows_by_fd.count(pair[0]) || flow->tx_buffer.size() != 1 ||
      flow->tx_buffer[0] != 'X' || ctx.tcp_tx_buffer_budget.used() != 1) return 195;
  nstun::tcp_destroy_flow(&ctx, flow);
  close(pair[1]);
  close(ctx.tap_fd);
  close(ctx.epoll_fd);
  return 0;
}

// Freeing a small amount of shared budget resumes only the first waiter. The
// next waiter still has EPOLLIN disabled even though the budget is no longer
// exactly full. Its HUP must consume an available reply, not silently lose it.
static int second_waiter_hup_test() {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  int tap[2];
  if (ctx.epoll_fd < 0 || pipe2(tap, O_NONBLOCK | O_CLOEXEC)) return 220;
  ctx.tap_fd = tap[1];
  struct Pair { nstun::TcpFlow* flow; int host; int peer; };
  auto add_pair = [&](uint16_t port) -> Pair {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds))
      return {nullptr, -1, -1};
    auto owned = std::make_unique<nstun::TcpFlow>();
    auto* flow = owned.get();
    flow->host_fd = fds[0];
    flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                  .sport = htons(port), .dport = htons(18080)};
    flow->state = nstun::TcpState::CLOSE_WAIT;
    flow->guest_eof = true;
    flow->seq_to_guest = flow->ack_from_guest = 1000;
    flow->syn_acked = true;
    ctx.flows_by_fd.emplace(fds[0], flow);
    ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
    epoll_event ev{.events = EPOLLIN | EPOLLERR | EPOLLHUP,
                   .data = {.fd = fds[0]}};
    if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fds[0], &ev) ||
        shutdown(fds[0], SHUT_WR)) return {nullptr, -1, -1};
    return {flow, fds[0], fds[1]};
  };
  Pair first = add_pair(19010);
  Pair second = add_pair(19011);
  if (!first.flow || !second.flow) return 221;
  if (send(first.peer, "A1234567", 8, MSG_DONTWAIT) != 8 ||
      send(second.peer, "B1234567", 8, MSG_DONTWAIT) != 8) return 222;
  size_t limit = ctx.tcp_tx_buffer_budget.limit();
  // Model the other saturated flows as one charged reservoir and a real
  // eight-byte flow whose teardown releases the one available wake slot.
  if (!ctx.tcp_tx_buffer_budget.try_reserve(limit - 8) ||
      !ctx.tcp_tx_buffer_budget.try_reserve(8)) return 223;
  auto filler_owned = std::make_unique<nstun::TcpFlow>();
  auto* filler = filler_owned.get();
  filler->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                  .sport = htons(19012), .dport = htons(18080)};
  filler->tx_buffer.assign(8, 'F');
  ctx.ipv4_tcp_flows_by_key.emplace(filler->key4, std::move(filler_owned));
  nstun::handle_host_tcp(&ctx, first.flow, EPOLLIN);
  nstun::handle_host_tcp(&ctx, second.flow, EPOLLIN);
  if (!first.flow->tx_budget_blocked || !second.flow->tx_budget_blocked ||
      ctx.tcp_tx_budget_waiters.size() != 2) return 224;
  nstun::tcp_destroy_flow(&ctx, filler);
  if (first.flow->epoll_in_disabled || first.flow->tx_budget_blocked ||
      !second.flow->epoll_in_disabled || !second.flow->tx_budget_blocked ||
      ctx.tcp_tx_buffer_budget.used() != limit - 8) return 226;

  close(second.peer);
  epoll_event events[4]{};
  uint32_t second_events = 0;
  for (int turn = 0; turn < 4 && !second_events; ++turn) {
    int count = epoll_wait(ctx.epoll_fd, events, 4, 100);
    if (count < 0) return 227;
    for (int i = 0; i < count; ++i)
      if (events[i].data.fd == second.host) second_events = events[i].events;
  }
  if (!(second_events & EPOLLHUP) || (second_events & EPOLLIN)) return 228;
  char pending[8];
  if (recv(second.host, pending, sizeof(pending), MSG_PEEK | MSG_DONTWAIT) != 8 ||
      memcmp(pending, "B1234567", 8) != 0) return 229;
  nstun::handle_host_tcp(&ctx, second.flow, second_events);
  if (!ctx.flows_by_fd.count(second.host) || second.flow->tx_buffer.size() != 8 ||
      !second.flow->host_eof || ctx.tcp_tx_budget_waiters.size() != 0 ||
      ctx.tcp_tx_buffer_budget.used() != limit) return 230;
  uint8_t frame[128]{};
  ssize_t bytes = read(tap[0], frame, sizeof(frame));
  if (bytes != static_cast<ssize_t>(sizeof(nstun::ip4_hdr) + sizeof(nstun::tcp_hdr) + 8))
    return 231;
  const auto* tcp = reinterpret_cast<const nstun::tcp_hdr*>(frame + sizeof(nstun::ip4_hdr));
  if ((tcp->flags & (nstun::NSTUN_TCP_FLAG_RST | nstun::NSTUN_TCP_FLAG_FIN)) ||
      memcmp(frame + sizeof(nstun::ip4_hdr) + sizeof(nstun::tcp_hdr),
             "B1234567", 8) != 0) return 232;
  nstun::tcp_destroy_flow(&ctx, first.flow);
  if (!ctx.tcp_tx_buffer_budget.release(limit - 8)) return 233;
  nstun::tcp_destroy_flow(&ctx, second.flow);
  if (ctx.tcp_tx_buffer_budget.used() != 0) return 234;
  close(first.peer);
  close(tap[0]);
  close(tap[1]);
  close(ctx.epoll_fd);
  return 0;
}

// epoll_wait returns a snapshot. A TAP ACK earlier in that batch can release
// budget and re-enable EPOLLIN after this HUP-only event was captured. The
// handler must inspect the socket, not its now-changed epoll registration.
static int stale_hup_batch_test() {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  int tap[2];
  if (ctx.epoll_fd < 0 || pipe2(tap, O_NONBLOCK | O_CLOEXEC)) return 240;
  ctx.tap_fd = tap[1];
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds))
    return 241;
  auto owned = std::make_unique<nstun::TcpFlow>();
  auto* flow = owned.get();
  flow->host_fd = fds[0];
  flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                .sport = htons(19020), .dport = htons(18080)};
  flow->state = nstun::TcpState::CLOSE_WAIT;
  flow->guest_eof = true;
  flow->seq_to_guest = flow->ack_from_guest = 1000;
  flow->syn_acked = true;
  ctx.flows_by_fd.emplace(fds[0], flow);
  ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
  epoll_event ev{.events = EPOLLIN | EPOLLERR | EPOLLHUP,
                 .data = {.fd = fds[0]}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fds[0], &ev) ||
      shutdown(fds[0], SHUT_WR)) return 242;
  const size_t limit = ctx.tcp_tx_buffer_budget.limit();
  if (!ctx.tcp_tx_buffer_budget.try_reserve(limit - 8) ||
      !ctx.tcp_tx_buffer_budget.try_reserve(8)) return 243;
  auto filler_owned = std::make_unique<nstun::TcpFlow>();
  auto* filler = filler_owned.get();
  filler->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                  .sport = htons(19021), .dport = htons(18080)};
  filler->tx_buffer.assign(8, 'F');
  ctx.ipv4_tcp_flows_by_key.emplace(filler->key4, std::move(filler_owned));
  if (send(fds[1], "C1234567", 8, MSG_DONTWAIT) != 8) return 244;
  nstun::handle_host_tcp(&ctx, flow, EPOLLIN);
  if (!flow->epoll_in_disabled || !flow->tx_budget_blocked) return 245;
  close(fds[1]);
  epoll_event stale{};
  if (epoll_wait(ctx.epoll_fd, &stale, 1, 100) != 1 ||
      stale.data.fd != fds[0] || !(stale.events & EPOLLHUP) ||
      (stale.events & EPOLLIN)) return 246;
  nstun::tcp_destroy_flow(&ctx, filler);
  if (flow->epoll_in_disabled || flow->tx_budget_blocked ||
      ctx.tcp_tx_buffer_budget.used() != limit - 8) return 247;
  nstun::handle_host_tcp(&ctx, flow, stale.events);
  if (!ctx.flows_by_fd.count(fds[0]) || flow->tx_buffer.size() != 8 ||
      !flow->host_eof || ctx.tcp_tx_buffer_budget.used() != limit) return 248;
  uint8_t frame[128]{};
  ssize_t bytes = read(tap[0], frame, sizeof(frame));
  if (bytes != static_cast<ssize_t>(sizeof(nstun::ip4_hdr) + sizeof(nstun::tcp_hdr) + 8))
    return 249;
  const auto* tcp = reinterpret_cast<const nstun::tcp_hdr*>(frame + sizeof(nstun::ip4_hdr));
  if ((tcp->flags & (nstun::NSTUN_TCP_FLAG_RST | nstun::NSTUN_TCP_FLAG_FIN)) ||
      memcmp(frame + sizeof(nstun::ip4_hdr) + sizeof(nstun::tcp_hdr),
             "C1234567", 8) != 0) return 250;
  if (!ctx.tcp_tx_buffer_budget.release(limit - 8)) return 251;
  nstun::tcp_destroy_flow(&ctx, flow);
  if (ctx.tcp_tx_buffer_budget.used() != 0) return 252;
  close(tap[0]);
  close(tap[1]);
  close(ctx.epoll_fd);
  return 0;
}

// A closing host can have more than one recv chunk pending when its receive
// buffer is large. HUP must not discard the remaining ordinary response while
// this flow and the shared budget both have enough room to hold it.
static int coalesced_hup_response_test() {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (ctx.epoll_fd < 0 || ctx.tap_fd < 0) return 260;
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  int host = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0 || host < 0) return 261;
  int rcvbuf = 1024 * 1024;
  if (setsockopt(host, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf))) return 262;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
      listen(listener, 1)) return 263;
  socklen_t address_len = sizeof(address);
  if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_len) ||
      connect(host, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return 264;
  int peer = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
  close(listener);
  if (peer < 0 || fcntl(host, F_SETFL, fcntl(host, F_GETFL) | O_NONBLOCK)) return 265;
  auto owned = std::make_unique<nstun::TcpFlow>();
  auto* flow = owned.get();
  flow->host_fd = host;
  flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                .sport = htons(19030), .dport = htons(18080)};
  flow->state = nstun::TcpState::ESTABLISHED;
  flow->seq_to_guest = flow->ack_from_guest = 1000;
  flow->syn_acked = true;
  ctx.flows_by_fd.emplace(host, flow);
  ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
  epoll_event registration{.events = EPOLLIN | EPOLLERR | EPOLLHUP,
                           .data = {.fd = host}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, host, &registration) ||
      shutdown(host, SHUT_WR)) return 266;
  std::array<uint8_t, 192 * 1024> payload{};
  payload.fill('D');
  size_t offered = 0;
  while (offered < payload.size()) {
    ssize_t n = send(peer, payload.data() + offered, payload.size() - offered, MSG_NOSIGNAL);
    if (n <= 0) return 267;
    offered += static_cast<size_t>(n);
  }
  close(peer);
  epoll_event event{};
  uint32_t observed = 0;
  for (int attempt = 0; attempt < 10 && !(observed & EPOLLHUP); ++attempt) {
    if (epoll_wait(ctx.epoll_fd, &event, 1, 100) != 1) return 268;
    observed = event.events;
  }
  if (!(observed & EPOLLHUP)) return 269;
  nstun::handle_host_tcp(&ctx, flow, observed);
  if (!ctx.flows_by_fd.count(host) ||
      flow->tx_buffer.size() != payload.size() ||
      memcmp(flow->tx_buffer.data(), payload.data(), payload.size()) != 0)
    return 270;
  nstun::tcp_destroy_flow(&ctx, flow);
  if (ctx.tcp_tx_buffer_budget.used() != 0) return 271;
  close(ctx.tap_fd);
  close(ctx.epoll_fd);
  return 0;
}

// Guest-to-host writes must not silently re-enable host reads while the shared
// host-to-guest budget has paused EPOLLIN on this flow.
static int epoll_write_transition_test() {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (ctx.epoll_fd < 0 || ctx.tap_fd < 0) return 101;
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds)) return 102;
  auto owned = std::make_unique<nstun::TcpFlow>();
  auto* flow = owned.get();
  flow->host_fd = fds[0];
  flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                .sport = htons(9001), .dport = htons(18080)};
  flow->state = nstun::TcpState::ESTABLISHED;
  flow->seq_to_guest = flow->ack_from_guest = 1000;
  flow->syn_acked = true;
  ctx.flows_by_fd.emplace(fds[0], flow);
  ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
  epoll_event ev{.events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fds[0]}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fds[0], &ev)) return 103;
  if (send(fds[1], "x", 1, MSG_DONTWAIT) != 1) return 104;
  if (!ctx.tcp_tx_buffer_budget.try_reserve(ctx.tcp_tx_buffer_budget.limit())) return 105;
  nstun::handle_host_tcp(&ctx, flow, EPOLLIN);
  if (!flow->epoll_in_disabled || !flow->tx_budget_blocked) return 106;

  char chunk[8192]{};
  bool saturated = false;
  for (int i = 0; i < 1024; ++i) {
    ssize_t n = send(fds[0], chunk, sizeof(chunk), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0 && errno == EAGAIN) { saturated = true; break; }
    if (n < 0) return 107;
  }
  if (!saturated || !ctx.tcp_rx_buffer_budget.try_reserve(1)) return 108;
  flow->rx_buffer.push_back('r');
  if (nstun::flush_to_host(&ctx, flow)) return 109;
  epoll_event out[4]{};
  int count = epoll_wait(ctx.epoll_fd, out, 4, 0);
  for (int i = 0; i < count; ++i) if (out[i].events & EPOLLIN) return 110;

  for (;;) {
    ssize_t n = recv(fds[1], chunk, sizeof(chunk), MSG_DONTWAIT);
    if (n < 0 && errno == EAGAIN) break;
    if (n <= 0) return 111;
  }
  if (nstun::flush_to_host(&ctx, flow)) return 112;
  count = epoll_wait(ctx.epoll_fd, out, 4, 0);
  for (int i = 0; i < count; ++i) if (out[i].events & EPOLLIN) return 113;
  if (!flow->epoll_in_disabled) return 114;
  nstun::tcp_destroy_flow(&ctx, flow);
  if (!ctx.tcp_tx_buffer_budget.release(ctx.tcp_tx_buffer_budget.limit())) return 115;
  close(fds[1]);
  close(ctx.tap_fd);
  close(ctx.epoll_fd);
  return 0;
}

static void guest_ack(nstun::Context* ctx, nstun::TcpFlow* flow, uint32_t ack_number) {
  nstun::ip4_hdr ip{};
  ip.saddr = flow->key4.saddr4;
  ip.daddr = flow->key4.daddr4;
  nstun::tcp_hdr tcp{};
  tcp.source = flow->key4.sport;
  tcp.dest = flow->key4.dport;
  tcp.seq = htonl(flow->ack_to_guest);
  tcp.ack_seq = htonl(ack_number);
  nstun::tcp_set_doff(&tcp, sizeof(tcp) / 4);
  tcp.flags = nstun::NSTUN_TCP_FLAG_ACK;
  nstun::pseudo_hdr4 pseudo{.saddr = ip.saddr, .daddr = ip.daddr,
                            .zero = 0, .protocol = IPPROTO_TCP,
                            .len = htons(sizeof(tcp))};
  uint32_t sum = nstun::compute_checksum_part(&pseudo, sizeof(pseudo));
  sum = nstun::compute_checksum_part(&tcp, sizeof(tcp), sum);
  tcp.check = nstun::finalize_checksum(sum);
  nstun::handle_tcp4(ctx, &ip,
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&tcp), sizeof(tcp)));
}

// Idle waiters must not consume the only wake slot ahead of a readable flow.
// The short ACK prefix is still charged, as in the normal guest ACK path.
static int idle_waiter_fairness_test() {
  constexpr int kFlows = 70;
  constexpr size_t kChargedPerFlow = 132096;
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (ctx.epoll_fd < 0 || ctx.tap_fd < 0) return 228;
  std::vector<int> peers;
  nstun::TcpFlow* ready_flow = nullptr;
  int ready_fd = -1;
  for (int i = 0; i < kFlows; ++i) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair))
      return 229;
    peers.push_back(pair[1]);
    auto owned = std::make_unique<nstun::TcpFlow>();
    auto* flow = owned.get();
    flow->host_fd = pair[0];
    flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                  .sport = htons(static_cast<uint16_t>(21000 + i)),
                  .dport = htons(18080)};
    flow->state = nstun::TcpState::CLOSE_WAIT;
    flow->guest_eof = true;
    flow->last_active = time(nullptr);
    flow->tx_buffer.resize(kChargedPerFlow);
    flow->tx_acked_offset = 2048;
    flow->seq_to_guest = kChargedPerFlow;
    flow->ack_from_guest = 2048;
    flow->syn_acked = true;
    flow->epoll_in_disabled = true;
    flow->tx_budget_blocked = true;
    ctx.flows_by_fd.emplace(pair[0], flow);
    ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
    ctx.tcp_tx_budget_waiters.push_back(flow);
    epoll_event event{.events = EPOLLERR | EPOLLHUP,
                      .data = {.fd = pair[0]}};
    if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, pair[0], &event)) return 230;
    if (i == kFlows - 1) {
      ready_flow = flow;
      ready_fd = pair[0];
    }
  }
  if (send(peers.back(), "X", 1, MSG_DONTWAIT) != 1) return 231;
  const size_t full = ctx.tcp_tx_buffer_budget.limit();
  const size_t waiter_bytes = kFlows * kChargedPerFlow;
  if (!ctx.tcp_tx_buffer_budget.try_reserve(waiter_bytes) ||
      !ctx.tcp_tx_buffer_budget.try_reserve(full - waiter_bytes) ||
      !ctx.tcp_tx_buffer_budget.release(1)) return 232;
  nstun::tcp_resume_tx_budget_blocked_flows(&ctx);
  epoll_event event{};
  int ready = epoll_wait(ctx.epoll_fd, &event, 1, 0);
  if (ready != 1 || event.data.fd != ready_fd || !(event.events & EPOLLIN) ||
      ready_flow->tx_budget_blocked || ready_flow->epoll_in_disabled ||
      !ctx.tcp_tx_budget_waiters.empty()) return 233;
  while (!ctx.ipv4_tcp_flows_by_key.empty())
    nstun::tcp_destroy_flow(&ctx, ctx.ipv4_tcp_flows_by_key.begin()->second.get());
  if (!ctx.tcp_tx_buffer_budget.release(full - waiter_bytes - 1) ||
      ctx.tcp_tx_buffer_budget.used() != 0) return 234;
  for (int peer : peers) close(peer);
  close(ctx.tap_fd);
  close(ctx.epoll_fd);
  return 0;
}

// A short host read frees most of its 64-KiB reservation after the ACK wake
// slot was already spent on that flow. The next blocked flow must be rearmed
// before the network loop enters its next epoll_wait.
static int underfilled_read_wakes_waiter_at_batch_end() {
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (ctx.epoll_fd < 0 || ctx.tap_fd < 0) return 235;
  int peers[2] = {-1, -1};
  nstun::TcpFlow* flows[2] = {nullptr, nullptr};
  for (int i = 0; i < 2; ++i) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair))
      return 236;
    peers[i] = pair[1];
    auto owned = std::make_unique<nstun::TcpFlow>();
    auto* flow = owned.get();
    flow->host_fd = pair[0];
    flow->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                  .sport = htons(static_cast<uint16_t>(19110 + i)), .dport = htons(18080)};
    flow->state = nstun::TcpState::ESTABLISHED;
    flow->seq_to_guest = flow->ack_from_guest = 1000;
    flow->syn_acked = true;
    flow->epoll_generation = ++ctx.next_tcp_epoll_generation;
    ctx.flows_by_fd.emplace(pair[0], flow);
    ctx.ipv4_tcp_flows_by_key.emplace(flow->key4, std::move(owned));
    epoll_event registration{.events = EPOLLIN | EPOLLERR | EPOLLHUP,
        .data = {.u64 = (static_cast<uint64_t>(flow->epoll_generation) << 32) |
                         static_cast<uint32_t>(pair[0])}};
    if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, pair[0], &registration) ||
        send(peers[i], i == 0 ? "A" : "B", 1, MSG_DONTWAIT) != 1) return 237;
    flows[i] = flow;
  }
  const size_t limit = ctx.tcp_tx_buffer_budget.limit();
  if (!ctx.tcp_tx_buffer_budget.try_reserve(limit)) return 238;
  for (auto* flow : flows) nstun::handle_host_tcp(&ctx, flow, EPOLLIN);
  if (ctx.tcp_tx_budget_waiters.size() != 2 ||
      !ctx.tcp_tx_buffer_budget.release(65536)) return 239;
  nstun::tcp_resume_tx_budget_blocked_flows(&ctx);
  if (ctx.tcp_tx_budget_waiters.size() != 1 || !flows[1]->epoll_in_disabled)
    return 240;
  epoll_event event{};
  if (epoll_wait(ctx.epoll_fd, &event, 1, 100) != 1 ||
      static_cast<int>(static_cast<uint32_t>(event.data.u64)) != flows[0]->host_fd ||
      !(event.events & EPOLLIN)) return 241;
  nstun::handle_host_tcp(&ctx, flows[0], event.events);
  if (flows[0]->tx_buffer.size() != 1 ||
      ctx.tcp_tx_buffer_budget.limit() - ctx.tcp_tx_buffer_budget.used() != 65535 ||
      !ctx.tcp_tx_waiter_resume_pending || !flows[1]->epoll_in_disabled ||
      epoll_wait(ctx.epoll_fd, &event, 1, 0) != 0) return 242;
  nstun::tcp_finish_host_event_batch(&ctx);
  if (ctx.tcp_tx_waiter_resume_pending || ctx.tcp_tx_budget_waiters.size() != 0 ||
      epoll_wait(ctx.epoll_fd, &event, 1, 100) != 1 ||
      static_cast<int>(static_cast<uint32_t>(event.data.u64)) != flows[1]->host_fd ||
      !(event.events & EPOLLIN)) return 243;
  nstun::handle_host_tcp(&ctx, flows[1], event.events);
  if (flows[1]->tx_buffer.size() != 1 || flows[1]->tx_buffer[0] != 'B') return 244;
  nstun::tcp_finish_host_event_batch(&ctx); // No pending release: constant-time no-op.
  nstun::tcp_destroy_flow(&ctx, flows[0]);
  nstun::tcp_destroy_flow(&ctx, flows[1]);
  if (!ctx.tcp_tx_buffer_budget.release(limit - 65536) ||
      ctx.tcp_tx_buffer_budget.used() != 0) return 245;
  close(peers[0]);
  close(peers[1]);
  close(ctx.tap_fd);
  close(ctx.epoll_fd);
  return 0;
}

int main() {
  if (int result = underfilled_read_wakes_waiter_at_batch_end()) return result;
  if (int result = half_closed_host_hup_test(0)) return result;
  if (int result = half_closed_host_hup_test(1)) return result;
  if (int result = half_closed_host_hup_test(8)) return result;
  if (int result = half_closed_host_write_test(false)) return result;
  if (int result = half_closed_host_write_test(true)) return result;
  if (int result = connect_tail_at_budget_test()) return result;
  if (int result = second_waiter_hup_test()) return result;
  if (int result = stale_hup_batch_test()) return result;
  if (int result = coalesced_hup_response_test()) return result;
  if (int result = epoll_write_transition_test()) return result;
  if (int result = idle_waiter_fairness_test()) return result;
  constexpr int kFlows = 256;
  constexpr int kChunks = 5;
  constexpr size_t kChunkBytes = 65536;
  nstun::Context ctx{};
  ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx.tap_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (ctx.epoll_fd < 0 || ctx.tap_fd < 0) return 1;
  std::vector<int> peers;
  peers.reserve(kFlows);
  std::array<uint8_t, kChunkBytes> chunk{};
  chunk.fill('A');
  for (int i = 0; i < kFlows; ++i) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) < 0) return 2;
    peers.push_back(fds[1]);
    auto flow = std::make_unique<nstun::TcpFlow>();
    auto* raw = flow.get();
    raw->host_fd = fds[0];
    raw->key4 = {.saddr4 = htonl(0x0a000002), .daddr4 = htonl(0x0a000001),
                 .sport = htons(static_cast<uint16_t>(10000 + i)), .dport = htons(18080)};
    raw->state = nstun::TcpState::ESTABLISHED;
    raw->seq_to_guest = 1000;
    raw->ack_from_guest = 1000;
    raw->syn_acked = true;
    raw->last_active = time(nullptr);
    nstun::FlowKey4 key = raw->key4;
    ctx.ipv4_tcp_flows_by_key.emplace(key, std::move(flow));
    ctx.flows_by_fd.emplace(fds[0], raw);
    epoll_event ev{.events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fds[0]}};
    if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fds[0], &ev) != 0) return 3;
    for (int j = 0; j < kChunks; ++j) {
      ssize_t sent = send(fds[1], chunk.data(), chunk.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
      if (sent < 0 && errno == EAGAIN) break;
      if (sent < 0) return 4;
      nstun::handle_host_tcp(&ctx, raw, EPOLLIN);
      if (ctx.flows_by_fd.count(fds[0]) == 0) return 5;
      if (sent != static_cast<ssize_t>(chunk.size())) break;
    }
  }

  // Both address families share the same budget: a new IPv6 flow cannot
  // bypass the exhausted allocation held by IPv4 flows.
  int v6_fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, v6_fds) < 0) return 14;
  peers.push_back(v6_fds[1]);
  auto v6_flow = std::make_unique<nstun::TcpFlow>();
  auto* v6 = v6_flow.get();
  v6->host_fd = v6_fds[0];
  v6->is_ipv6 = true;
  nstun::FlowKey6 v6_key{};
  v6_key.saddr6[15] = 2;
  v6_key.daddr6[15] = 1;
  v6_key.sport = htons(20000);
  v6_key.dport = htons(18080);
  v6->key6 = v6_key;
  v6->state = nstun::TcpState::ESTABLISHED;
  v6->seq_to_guest = 1000;
  v6->ack_from_guest = 1000;
  v6->syn_acked = true;
  v6->last_active = time(nullptr);
  ctx.ipv6_tcp_flows_by_key.emplace(v6_key, std::move(v6_flow));
  ctx.flows_by_fd.emplace(v6_fds[0], v6);
  epoll_event v6_ev{.events = EPOLLIN | EPOLLERR | EPOLLHUP,
                    .data = {.fd = v6_fds[0]}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, v6_fds[0], &v6_ev) != 0) return 15;
  if (send(v6_fds[1], chunk.data(), chunk.size(), MSG_DONTWAIT | MSG_NOSIGNAL) !=
      static_cast<ssize_t>(chunk.size())) return 16;
  nstun::handle_host_tcp(&ctx, v6, EPOLLIN);
  if (!v6->tx_buffer.empty() || !v6->tx_budget_blocked || !v6->epoll_in_disabled) return 17;

  // HUP/EOF removes a blocked flow from the wake queue without freeing bytes
  // owned by other flows or leaving a dangling waiter.
  int eof_fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, eof_fds) < 0) return 20;
  peers.push_back(eof_fds[1]);
  auto eof_flow = std::make_unique<nstun::TcpFlow>();
  auto* eof = eof_flow.get();
  eof->host_fd = eof_fds[0];
  eof->is_ipv6 = true;
  nstun::FlowKey6 eof_key = v6_key;
  eof_key.sport = htons(20001);
  eof->key6 = eof_key;
  eof->state = nstun::TcpState::ESTABLISHED;
  eof->seq_to_guest = 1000;
  eof->ack_from_guest = 1000;
  eof->syn_acked = true;
  ctx.ipv6_tcp_flows_by_key.emplace(eof_key, std::move(eof_flow));
  ctx.flows_by_fd.emplace(eof_fds[0], eof);
  epoll_event eof_ev{.events = EPOLLIN | EPOLLERR | EPOLLHUP,
                     .data = {.fd = eof_fds[0]}};
  if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, eof_fds[0], &eof_ev) != 0) return 21;
  nstun::handle_host_tcp(&ctx, eof, EPOLLIN);
  if (!eof->tx_budget_blocked) return 22;
  size_t queue_before_eof = ctx.tcp_tx_budget_waiters.size();
  if (shutdown(eof_fds[1], SHUT_WR) != 0) return 23;
  nstun::handle_host_tcp(&ctx, eof, EPOLLHUP);
  if (!eof->host_eof || eof->tx_budget_blocked ||
      ctx.tcp_tx_budget_waiters.size() != queue_before_eof - 1) return 24;
  nstun::tcp_destroy_flow(&ctx, eof);

  size_t bytes = 0, capacity = 0, disabled = 0;
  for (auto const& [key, flow] : ctx.ipv4_tcp_flows_by_key) {
    bytes += flow->tx_buffer.size();
    capacity += flow->tx_buffer.capacity();
    disabled += flow->epoll_in_disabled ? 1 : 0;
  }
  rusage usage{};
  getrusage(RUSAGE_SELF, &usage);
  std::printf("flows=%zu bytes=%zu capacity=%zu epoll_in_disabled=%zu peak_rss_kib=%ld\n",
              ctx.ipv4_tcp_flows_by_key.size(), bytes, capacity, disabled, usage.ru_maxrss);

  if (bytes != ctx.tcp_tx_buffer_budget.used() ||
      bytes > ctx.tcp_tx_buffer_budget.limit()) return 6;
  size_t blocked_before = ctx.tcp_tx_budget_waiters.size();
  nstun::TcpFlow* acked = nullptr;
  nstun::TcpFlow* partial = nullptr;
  nstun::TcpFlow* blocked = nullptr;
  for (auto* waiter : ctx.tcp_tx_budget_waiters) {
    if (waiter->tx_buffer.size() - waiter->tx_acked_offset < 131072) {
      blocked = waiter;
      break;
    }
  }
  for (auto const& [key, flow] : ctx.ipv4_tcp_flows_by_key) {
    if (flow->tx_buffer.size() > 65536 && !acked) acked = flow.get();
    else if (flow->tx_buffer.size() > 65536 && !partial) partial = flow.get();
  }
  if (!acked || !partial || !blocked || blocked_before == 0) return 7;
  size_t release_bytes = acked->tx_buffer.size();
  size_t used_before = ctx.tcp_tx_buffer_budget.used();
  guest_ack(&ctx, acked, acked->seq_to_guest);
  if (acked->tx_buffer.size() != 0 || acked->tx_buffer.capacity() != 0 ||
      ctx.tcp_tx_buffer_budget.used() != used_before - release_bytes) return 8;
  if (blocked->tx_budget_blocked || blocked->epoll_in_disabled ||
      ctx.tcp_tx_budget_waiters.size() >= blocked_before) {
    std::fprintf(stderr, "wake_gate: blocked_flag=%d epoll_disabled=%d queue=%zu before=%zu\n",
        blocked->tx_budget_blocked, blocked->epoll_in_disabled,
        ctx.tcp_tx_budget_waiters.size(), blocked_before);
    return 9;
  }
  size_t blocked_bytes_before = blocked->tx_buffer.size();
  nstun::handle_host_tcp(&ctx, blocked, EPOLLIN);
  if (blocked->tx_buffer.size() <= blocked_bytes_before) return 10;
  std::printf("after_ack_budget_used=%zu resumed_flow_bytes=%zu blocked_before=%zu blocked_after=%zu\n",
              ctx.tcp_tx_buffer_budget.used(), blocked->tx_buffer.size(),
              blocked_before, ctx.tcp_tx_budget_waiters.size());
  size_t partial_before = partial->tx_buffer.size();
  size_t budget_before_partial = ctx.tcp_tx_buffer_budget.used();
  guest_ack(&ctx, partial, partial->seq_to_guest - 1);
  if (partial->tx_buffer.size() != 1 ||
      partial->tx_buffer.capacity() > 65536 ||
      ctx.tcp_tx_buffer_budget.used() != budget_before_partial - partial_before + 1) return 12;
  std::printf("after_partial_ack_live=%zu capacity=%zu budget_used=%zu\n",
              partial->tx_buffer.size(), partial->tx_buffer.capacity(),
              ctx.tcp_tx_buffer_budget.used());
  while (!ctx.ipv4_tcp_flows_by_key.empty()) {
    nstun::tcp_destroy_flow(&ctx, ctx.ipv4_tcp_flows_by_key.begin()->second.get());
  }
  nstun::tcp_resume_tx_budget_blocked_flows(&ctx);
  if (v6->tx_budget_blocked || v6->epoll_in_disabled ||
      ctx.tcp_tx_buffer_budget.used() != 0) return 18;
  nstun::handle_host_tcp(&ctx, v6, EPOLLIN);
  if (v6->tx_buffer.size() != kChunkBytes ||
      ctx.tcp_tx_buffer_budget.used() != kChunkBytes) return 19;
  nstun::tcp_destroy_flow(&ctx, v6);
  if (ctx.tcp_tx_buffer_budget.used() != 0 || !ctx.tcp_tx_budget_waiters.empty()) return 11;
  for (int fd : peers) close(fd);
  close(ctx.tap_fd);
  close(ctx.epoll_fd);
  return 0;
}
