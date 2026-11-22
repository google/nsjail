#!/usr/bin/env python3

import http.server
import socket
import threading


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"nstun host-to-guest\n")

    def log_message(self, _format, *_args):
        pass


class DualStackHTTPServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def udp_echo(family, address):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, 53535))
    while True:
        data, peer = sock.recvfrom(65535)
        print(data.decode("ascii", errors="replace"), flush=True)
        sock.sendto(data, peer)


threading.Thread(target=udp_echo, args=(socket.AF_INET, "0.0.0.0"), daemon=True).start()
threading.Thread(target=udp_echo, args=(socket.AF_INET6, "::"), daemon=True).start()
DualStackHTTPServer(("::", 8000), QuietHandler).serve_forever()
