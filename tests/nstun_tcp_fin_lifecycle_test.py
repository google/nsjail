#!/usr/bin/env python3
"""Regression checks for TCP FIN handling using actual extracted timer method bodies.
These checks mock networking and do not substitute for the nsjail integration suite.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile

def extract(text, signature):
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise RuntimeError("Unbalanced braces in " + signature)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, nargs="?", default=Path("nstun/tcp.cc"))
    args = parser.parse_args()
    source = args.source.read_text()
    assert 'acked_bytes == 0 && data_len == 0 && !flow->fin_sent' in source
    assert 'data_len == 0 && !flow->fin_sent' in source
    assert 'if (!flow->host_eof && (events & (EPOLLIN | EPOLLOUT)))' in source
    assert source.count('tcp_host_events(flow,') >= 3
    events_helper = extract(source, 'static uint32_t tcp_host_events(const TcpFlow* flow, bool want_out) {')
    periodic = extract(source, 'void TcpFlow::periodic_check(Context* ctx, time_t now) {')
    stale = extract(source, 'bool TcpFlow::is_stale(time_t now) const {')
    cpp = r'''#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static constexpr time_t TCP_TIMEOUT_ESTABLISHED = 3600;
static constexpr time_t TCP_TIMEOUT_CONNECTING = 10;
static constexpr time_t TCP_TIMEOUT_FIN = 60;
static constexpr time_t TCP_TIMEOUT_CLOSING = 5;
constexpr uint8_t NSTUN_TCP_FLAG_FIN = 0x01;
constexpr uint8_t NSTUN_TCP_FLAG_ACK = 0x10;
#define LOG_D(...) ((void)0)

namespace nstun {
enum class TcpState {SYN_SENT,SOCKS5_INIT,SOCKS5_CONNECTING,HTTP_CONNECT_WAIT,ESTABLISHED,FIN_WAIT_1,FIN_WAIT_2,CLOSING,TIME_WAIT,CLOSE_WAIT};
struct Context {int sends=0;uint8_t flags=0;uint32_t sequence=0;int pushes=0;};
struct TcpFlow {
    TcpState state=TcpState::ESTABLISHED;
    bool fin_sent=false,fin_acked=false;
    bool host_eof=false,epoll_in_disabled=false;
    time_t last_active=0,last_retransmit=0;
    uint32_t seq_to_guest=1001,ack_from_guest=1000;
    int host_fd=10;
    void periodic_check(Context*,time_t);
    bool is_stale(time_t) const;
};
void push_to_guest(Context* c,TcpFlow*) { c->pushes++; }
void tcp_send_packet(Context* c,TcpFlow* f,uint8_t flags) {
    c->sends++; c->flags=flags; c->sequence=f->seq_to_guest;
}
'''
    cpp += events_helper + '\n' + periodic + '\n' + stale + '\n'
    cpp += r'''
} // namespace nstun
using namespace nstun;
int main() {
    const time_t now=5000;
    TcpFlow normal;
    normal.last_active=now-3599;
    assert(!normal.is_stale(now));
    normal.last_active=now-3601;
    assert(normal.is_stale(now));

    TcpFlow fin;
    fin.last_active=now-59;fin.fin_sent=true;
    assert(!fin.is_stale(now));
    fin.last_active=now-61;
    assert(fin.is_stale(now));

    TcpFlow wait;
    wait.state=TcpState::FIN_WAIT_1;wait.last_active=now-61;
    assert(wait.is_stale(now));
    wait.state=TcpState::TIME_WAIT;wait.last_active=now-6;
    assert(wait.is_stale(now));
    wait.state=TcpState::SYN_SENT;wait.last_active=now-11;
    assert(wait.is_stale(now));

    TcpFlow pending;
    pending.fin_sent=true;pending.last_active=now-10;
    pending.last_retransmit=now-3;
    Context context;
    pending.periodic_check(&context,now);
    assert(context.sends==1);
    assert(context.flags==(NSTUN_TCP_FLAG_FIN|NSTUN_TCP_FLAG_ACK));
    assert(context.sequence==1000);
    assert(pending.seq_to_guest==1001);
    assert(pending.last_active==now-10);
    assert(pending.last_retransmit==now);
    pending.periodic_check(&context,now+1);
    assert(context.sends==1);
    pending.periodic_check(&context,now+2);
    assert(context.sends==2);
    pending.last_active=now-61;
    assert(pending.is_stale(now));

    TcpFlow data;
    data.last_active=now-3;
    Context datactx;
    data.periodic_check(&datactx,now);
    assert(datactx.pushes==1 && datactx.sends==0);
    assert(data.last_active==now-3 && data.last_retransmit==now);

    TcpFlow wrap;
    wrap.fin_sent=true;wrap.last_active=now-10;
    wrap.seq_to_guest=0;wrap.ack_from_guest=UINT32_MAX;
    Context wrapctx;
    wrap.periodic_check(&wrapctx,now);
    assert(wrapctx.sends==1);
    assert(wrapctx.sequence==UINT32_MAX);
    assert(wrap.seq_to_guest==0);

    TcpFlow already_ack;
    already_ack.fin_sent=true;already_ack.fin_acked=true;
    already_ack.seq_to_guest=1001;already_ack.ack_from_guest=1001;
    already_ack.last_active=now-10;
    Context ackctx;
    already_ack.periodic_check(&ackctx,now);
    assert(ackctx.sends==0 && ackctx.pushes==0);

    // Test real Linux readiness semantics using the actual nstun event mask helper.
    TcpFlow epflow;
    assert(tcp_host_events(&epflow,false)==(EPOLLERR|EPOLLHUP|EPOLLIN));
    epflow.epoll_in_disabled=true;
    assert(tcp_host_events(&epflow,true)==(EPOLLERR|EPOLLHUP|EPOLLOUT));
    epflow.host_eof=true;
    assert(tcp_host_events(&epflow,false)==(EPOLLERR|EPOLLHUP|EPOLLET));

    int sock[2];
    assert(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,sock)==0);
    int epollfd=epoll_create1(EPOLL_CLOEXEC);
    assert(epollfd>=0);
    epoll_event ev={};
    ev.events=EPOLLIN|EPOLLERR|EPOLLHUP;
    ev.data.fd=sock[0];
    assert(epoll_ctl(epollfd,EPOLL_CTL_ADD,sock[0],&ev)==0);
    close(sock[1]);
    char scratch=0;
    assert(recv(sock[0],&scratch,1,0)==0);
    ev.events=tcp_host_events(&epflow,false);
    assert(epoll_ctl(epollfd,EPOLL_CTL_MOD,sock[0],&ev)==0);
    epoll_event ready={};
    int count=epoll_wait(epollfd,&ready,1,100);
    assert(count==1 && (ready.events & EPOLLHUP)!=0);
    // EPOLLET prevents a permanently readable HUP from spinning the event loop.
    for(int i=0;i<3;i++) {
        count=epoll_wait(epollfd,&ready,1,15);
        assert(count==0);
    }
    close(sock[0]);
    close(epollfd);

    std::cout << "PASS: extracted production TCP timers and Linux EOF/HUP regression checks\n";
}
'''
    with tempfile.TemporaryDirectory() as tmp:
        filename=Path(tmp)/"tcp_fin_test.cc"
        filename.write_text(cpp)
        binary=Path(tmp)/"tcp_fin_test"
        subprocess.run(["g++","-std=c++20","-O1","-Wall","-Wextra","-Werror",
                        "-Wno-unused-parameter","-fsanitize=address,undefined",
                        "-fno-omit-frame-pointer",str(filename),"-o",str(binary)],check=True)
        subprocess.run([str(binary)],check=True)

if __name__=="__main__":
    main()
