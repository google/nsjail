#ifndef NS_SOCKPROXY_H
#define NS_SOCKPROXY_H

namespace sockproxy {

/*
 * Start a socket proxy between an external TCP connection and the
 * child process's stdin/stdout pipes.
 *
 * Takes FD pointers: on success, the proxy owns the FDs and sets
 * them to -1 in the caller.  On failure, FDs are untouched and
 * the caller remains responsible for closing them.
 *
 * When both channels finish, the proxy tears itself down and
 * calls monitor::stop() to exit the event loop.
 */
typedef void (*on_close_cb_t)(void* data);
bool start(int* connfd, int* pipe_in, int* pipe_out, on_close_cb_t cb, void* data);
void stop();

}  // namespace sockproxy

#endif /* NS_SOCKPROXY_H */
