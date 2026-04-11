#   nsjail - Makefile
#   -----------------------------------------

PKG_CONFIG := $(shell command -v pkg-config 2> /dev/null)
ifeq ($(PKG_CONFIG),)
$(error "Install pkg-config to make it work")
endif

CC ?= gcc
CXX ?= g++

# pkg-config for protobuf can be expensive/slow
# Skip pkg-config for: clean, indent, kafel_init, and kafel-only builds
ifneq ($(filter-out clean indent kafel_init kafel/libkafel.a,$(MAKECMDGOALS)),)
PROTOBUF_CFLAGS := $(shell pkg-config --cflags protobuf)
PROTOBUF_LIBS   := $(shell pkg-config --libs protobuf)
else ifeq ($(MAKECMDGOALS),)
# Default target (all) requires protobuf
PROTOBUF_CFLAGS := $(shell pkg-config --cflags protobuf)
PROTOBUF_LIBS   := $(shell pkg-config --libs protobuf)
endif

NL3_EXISTS := $(shell pkg-config --exists libnl-route-3.0 && echo yes)

COMMON_FLAGS += -O2 -c \
	-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
	-fPIE \
	-Wformat -Wformat-security -Wno-format-nonliteral \
	-Wall -Wextra -Werror \
	-Ikafel/include

CXXFLAGS += $(USER_DEFINES) $(COMMON_FLAGS) $(PROTOBUF_CFLAGS) -I. \
	-std=c++20 -fno-exceptions -Wno-unused -Wno-unused-parameter -Wno-c99-designator

LDFLAGS += -pie -Wl,-z,noexecstack -lpthread $(PROTOBUF_LIBS)

ifeq ($(NL3_EXISTS), yes)
	CXXFLAGS += $(shell pkg-config --cflags libnl-route-3.0)
	LDFLAGS += $(shell pkg-config --libs libnl-route-3.0)
endif

ifdef DEBUG
	CXXFLAGS += -g -ggdb -gdwarf-4
endif

BIN = nsjail
LIBS = kafel/libkafel.a

# If PASTA_BIN_PATH is not provided in env, dynamically search for it if EMBED_PASTA is requested
# or fallback to it naturally.
ifdef EMBED_PASTA
	ifeq ($(PASTA_BIN_PATH),)
		PASTA_BIN_PATH := $(shell which pasta)
	endif
ifeq ($(PASTA_BIN_PATH),)
$(error "'pasta' binary not found. Provide location with PASTA_BIN_PATH")
endif
endif

ifneq ($(PASTA_BIN_PATH),)
	CXXFLAGS += -DPASTA_BIN_PATH='"$(PASTA_BIN_PATH)"'
endif

SRCS_CXX = caps.cc cgroup.cc cgroup2.cc cmdline.cc config.cc contain.cc cpu.cc logs.cc mnt.cc mnt_legacy.cc mnt_newapi.cc net.cc nsjail.cc pid.cc sandbox.cc subproc.cc uts.cc user.cc unotify/unotify.cc unotify/stats.cc unotify/syscall.cc util.cc nstun/nstun.cc nstun/policy.cc nstun/encap.cc nstun/iface.cc nstun/tun.cc nstun/ip.cc nstun/icmp.cc nstun/udp.cc nstun/tcp.cc
SRCS_PROTO = config.proto unotify/unotify.proto

SRCS_PB_CXX = $(SRCS_PROTO:.proto=.pb.cc)
SRCS_PB_H = $(SRCS_PROTO:.proto=.pb.h)
SRCS_PB_O = $(SRCS_PROTO:.proto=.pb.o)

OBJS = $(SRCS_CXX:.cc=.o) $(SRCS_PB_CXX:.cc=.o)

# 4. TARGETS

.PHONY: all clean depend indent kafel_init

all: $(BIN)

# Main Binary Linkage
$(BIN): $(LIBS) $(OBJS)
ifneq ($(NL3_EXISTS), yes)
	$(warning "You probably miss libnl3(-dev)/libnl-route-3(-dev) libraries")
endif
	$(CXX) -o $(BIN) $(OBJS) $(LIBS) $(LDFLAGS)

# Standard Object Compilation
# The | $(SRCS_PB_H) ensures headers exist before we try to compile .cc files
%.o: %.cc | $(SRCS_PB_H)
	$(CXX) $(CXXFLAGS) $< -o $@

# Protobuf Generation
# We only define the recipe for the .cc file to prevent race conditions.
$(SRCS_PB_CXX): $(SRCS_PROTO)
	protoc --cpp_out=. $(SRCS_PROTO)

# The .h file is a side-effect of the .cc rule
$(SRCS_PB_H): $(SRCS_PB_CXX)

# Kafel Submodule Handling
kafel_init:
ifeq ("$(wildcard kafel/Makefile)","")
	git submodule update --init
endif

kafel/include/kafel.h: kafel_init

kafel/libkafel.a: kafel_init
	+LDFLAGS="" CFLAGS=-fPIE $(MAKE) -C kafel

# Utilities
clean:
	$(RM) core Makefile.bak $(OBJS) $(SRCS_PB_CXX) $(SRCS_PB_H) $(SRCS_PB_O) $(BIN)
ifneq ("$(wildcard kafel/Makefile)","")
	+$(MAKE) -C kafel clean
endif

depend: all
	makedepend -Y -Ykafel/include -- -- $(SRCS_CXX) $(SRCS_PB_CXX)

indent:
	clang-format -i -sort-includes $(SRCS_CXX:.cc=.h) macros.h $(SRCS_CXX) $(SRCS_PROTO) configs/*.json

# Install
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: install
install: $(BIN)
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BIN) $(DESTDIR)$(BINDIR)
	install -m 755 -d $(DESTDIR)$(MANDIR)
	install -m 644 nsjail.1 $(DESTDIR)$(MANDIR)

define run_test
	@echo "Testing: $(1) (expecting exit code $(2))"; \
	($(1)); ret=$$?; \
	if [ "$$ret" -ne "$(2)" ]; then \
		echo "❌ FAIL: '$(1)' returned $$ret, expected $(2)"; \
		exit 1; \
	else \
		echo "✅ PASS: '$(1)' returned $$ret"; \
	fi
endef

OLD_EF := --experimental_mnt=old
NEW_EF := --experimental_mnt=new
UID := $(shell id -u)

.PHONY: test
test: $(BIN)
	# --- Basic sanity tests ---
	$(call run_test, ./nsjail -q -Mo --chroot / --user 99999 --group 99999 -- /bin/true, 0)
	$(call run_test, ./nsjail -q -Mo --chroot / --user 99999 --group 99999 -- /bin/false, 1)
	$(call run_test, ./nsjail --config tests/seccomp.cfg -q -t 2 -- /bin/bash -c 'strace -o /dev/null /bin/true || exit 77', 77)
	$(call run_test, ./nsjail --config tests/basic.cfg -q -t 2 -- /bin/bash -c 'strace -o /dev/null /bin/true && exit 77', 77)
	$(call run_test, ./nsjail --config tests/pasta-nat.cfg -q -t 3 -- /bin/bash -c 'sleep 0.2; ping -W 1 -c 1 8.8.8.8 && exit 77', 77)
	$(call run_test, ./nsjail --config tests/pasta-port-mappings.cfg -q -t 3 -- /bin/bash -c 'sleep 0.2; { netstat -tan | grep LISTEN; } && exit 77', 77)

	# --- Traffic rules tests ---
	$(call run_test, ./nsjail --config tests/traffic-rules.cfg -q -t 1 -- /bin/bash -c 'sleep 10', 137)
	$(call run_test, ./nsjail --config tests/traffic-drop-tcp4.cfg -q -t 1 -- /bin/bash -c 'sleep 10', 137)
	$(call run_test, ./nsjail --config tests/traffic-drop-udp6.cfg -q -t 1 -- /bin/bash -c 'sleep 10', 137)
	$(call run_test, ./nsjail --config tests/traffic-mixed.cfg -q -t 1 -- /bin/bash -c 'sleep 10', 137)

	# --- IPv4-only NAT tests ---
	$(call run_test, ./nsjail --config tests/nat-ip4-only.cfg -q -t 3 --cap CAP_NET_RAW -- /bin/bash -c 'ping -4 -W 1 -c 1 8.8.8.8 && exit 77', 77)

	# --- IPv6-only NAT tests ---
	$(call run_test, ./nsjail --config tests/nat-ip6-only.cfg -q -t 3 -- /bin/true, 0)

	# --- SOCKS5 proxy test ---
	$(call run_test, ./nsjail --config tests/socks5.cfg -q -t 3 -- /bin/bash -c 'wget -4 https://dns.google -O /dev/null && exit 77', 77)
	$(call run_test, ./nsjail --config tests/socks5.cfg -q -t 3 -- /bin/bash -c 'wget -6 https://dns.google -O /dev/null && exit 77', 77)
	# SOCKS5 UDP (DNS over UDP) and TCP (DNS over TCP) via IPv4 and IPv6 resolvers
	$(call run_test, ./nsjail --config tests/socks5.cfg -q -t 3 -- /bin/bash -c 'host -U dns.google 8.8.8.8 && exit 77', 77)
	$(call run_test, ./nsjail --config tests/socks5.cfg -q -t 3 -- /bin/bash -c 'host -T dns.google 8.8.8.8 && exit 77', 77)
	$(call run_test, ./nsjail --config tests/socks5.cfg -q -t 3 -- /bin/bash -c 'host -U dns.google 2001:4860:4860::8888 && exit 77', 77)
	$(call run_test, ./nsjail --config tests/socks5.cfg -q -t 3 -- /bin/bash -c 'host -T dns.google 2001:4860:4860::8888 && exit 77', 77)

	# --- HTTP CONNECT proxy test ---
	$(call run_test, ./nsjail --config tests/connect.cfg -q -t 3 -- /bin/bash -c 'wget -4 https://dns.google -O /dev/null && exit 77', 77)
	$(call run_test, ./nsjail --config tests/connect.cfg -q -t 3 -- /bin/bash -c 'wget -6 https://dns.google -O /dev/null && exit 77', 77)
	# HTTP CONNECT DNS over TCP via IPv4 and IPv6 resolvers
	$(call run_test, ./nsjail --config tests/connect.cfg -q -t 3 -- /bin/bash -c 'host -T dns.google 8.8.8.8 && exit 77', 77)
	$(call run_test, ./nsjail --config tests/connect.cfg -q -t 3 -- /bin/bash -c 'host -T dns.google 2001:4860:4860::8888 && exit 77', 77)

	# --- HOST_TO_GUEST TCP inbound proxy test (IPv4 + IPv6) ---
	$(call run_test, { ./nsjail --config tests/dns_http_host_to_guest.cfg -q -t 3 & }; sleep 1; wget -4 -q -O /dev/null --timeout=5 http://127.0.0.1:8080/ && wget -6 -q -O /dev/null --timeout=5 http://[::1]:8080/ && exit 77, 77)

	# --- --experimental_mnt=old ---
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --rw --chroot / --user 99999 --group 99999 -- /bin/bash -c 'touch $(HOME)/nsjail_test && exit 77', 77)
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / --user 99999 --group 99999 -- /bin/bash -c 'touch $(HOME)/nsjail_test || exit 77', 77)
	$(call run_test, rm -f $(HOME)/nsjail_test, 0)
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / -m none:/tmp:tmpfs --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test && rm -f /tmp/nsjail_test', 0)
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / -m none:/tmp:tmpfs:rw --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test && rm -f /tmp/nsjail_test', 0)
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / -m none:/tmp:tmpfs:ro --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test || exit 77', 77)
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / -R /tmp --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test || exit 77', 77)
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / -B /tmp --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test && rm -f /tmp/nsjail_test', 0)
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / --user 99999 --group 99999 -- /bin/bash -c 'touch /run/user/$(UID)/nsjail_test2 && exit 77', 77) # --rw (or lack of thereof) doesn't change already mounted tmpfs
	$(call run_test, ./nsjail $(OLD_EF) -q -Mo --chroot / --user 99999 --group 99999 --rw -- /bin/bash -c 'touch /run/user/$(UID)/nsjail_test2 && exit 77', 77) # --rw (or lack of thereof) doesn't affect already mounted tmpfs
	$(call run_test, rm -f /run/user/$(UID)/nsjail_test2, 0)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/bash-with-fake-geteuid.cfg -q -t 1 < /dev/null, 0)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/bash-with-fake-geteuid.json -q -t 1 < /dev/null, 0)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/static-busybox-with-execveat.cfg -q -t 1, 137)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/home-documents-with-xorg-no-net.cfg -q -- /bin/true, 0)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/home-documents-with-xorg-no-net.cfg -q -- /bin/false, 1)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/firefox-with-net-X11.cfg -q -t 2, 137)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/firefox-with-net-wayland.cfg -q -t 2, 137)
	$(call run_test, ./nsjail $(OLD_EF) --config configs/chromium-with-net-wayland.cfg -q -t 2, 137)

	# --- --experimental_mnt=new ---
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --rw --chroot / --user 99999 --group 99999 -- /bin/bash -c 'touch $(HOME)/nsjail_test && exit 77', 77)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / --user 99999 --group 99999 -- /bin/bash -c 'touch $(HOME)/nsjail_test || exit 77', 77)
	$(call run_test, rm -f $(HOME)/nsjail_test, 0)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / -m none:/tmp:tmpfs --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test && rm -f /tmp/nsjail_test', 0)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / -m none:/tmp:tmpfs:rw --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test && rm -f /tmp/nsjail_test', 0)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / -m none:/tmp:tmpfs:ro --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test || exit 77', 77)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / -R /tmp --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test || exit 77', 77)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / -B /tmp --user 99999 --group 99999 -- /bin/bash -c 'touch /tmp/nsjail_test && rm -f /tmp/nsjail_test', 0)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / --user 99999 --group 99999 -- /bin/bash -c 'touch /run/user/$(UID)/nsjail_test2 || exit 77', 77)
	$(call run_test, ./nsjail $(NEW_EF) -q -Mo --chroot / --user 99999 --group 99999 --rw -- /bin/bash -c 'touch /run/user/$(UID)/nsjail_test2 && exit 77', 77)
	$(call run_test, rm -f /run/user/$(UID)/nsjail_test2, 0)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/bash-with-fake-geteuid.cfg -q -t 1 < /dev/null, 0)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/bash-with-fake-geteuid.json -q -t 1 < /dev/null, 0)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/static-busybox-with-execveat.cfg -q -t 1, 137)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/home-documents-with-xorg-no-net.cfg -q -- /bin/true, 0)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/home-documents-with-xorg-no-net.cfg -q -- /bin/false, 1)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/firefox-with-net-X11.cfg -q -t 2, 137)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/firefox-with-net-wayland.cfg -q -t 2, 137)
	$(call run_test, ./nsjail $(NEW_EF) --config configs/chromium-with-net-wayland.cfg -q -t 2, 137)

	@echo ""
	@echo "========================================"
	@echo "  ✅ All tests passed!"
	@echo "========================================"
	@echo ""

# Dependencies (Generated by makedepend)
# DO NOT DELETE THIS LINE -- make depend depends on it.

caps.o: caps.h nsjail.h config.pb.h logs.h macros.h util.h
cgroup.o: cgroup.h nsjail.h config.pb.h logs.h util.h
cgroup2.o: cgroup2.h nsjail.h config.pb.h logs.h util.h
cmdline.o: cmdline.h nsjail.h config.pb.h caps.h config.h logs.h macros.h
cmdline.o: mnt.h mnt_newapi.h user.h util.h
config.o: config.h nsjail.h config.pb.h caps.h cmdline.h logs.h macros.h
config.o: mnt.h user.h util.h
contain.o: contain.h nsjail.h config.pb.h caps.h cgroup.h cgroup2.h config.h
contain.o: cpu.h logs.h macros.h mnt.h net.h pid.h user.h util.h uts.h
cpu.o: cpu.h nsjail.h config.pb.h logs.h util.h
logs.o: logs.h macros.h util.h nsjail.h config.pb.h
mnt.o: mnt.h nsjail.h config.pb.h logs.h macros.h mnt_legacy.h mnt_newapi.h
mnt.o: subproc.h util.h
mnt_legacy.o: mnt_legacy.h mnt.h nsjail.h config.pb.h logs.h macros.h util.h
mnt_newapi.o: mnt_newapi.h mnt.h nsjail.h config.pb.h logs.h util.h
net.o: net.h nsjail.h config.pb.h logs.h macros.h nstun/nstun.h util.h
nsjail.o: nsjail.h config.pb.h cgroup2.h cmdline.h logs.h macros.h net.h
nsjail.o: sandbox.h subproc.h unotify/unotify.h util.h
pid.o: pid.h nsjail.h config.pb.h logs.h subproc.h
sandbox.o: sandbox.h nsjail.h config.pb.h subproc.h kafel/include/kafel.h
sandbox.o: logs.h unotify/syscall_defs.h util.h
subproc.o: subproc.h nsjail.h config.pb.h cgroup.h cgroup2.h contain.h logs.h
subproc.o: macros.h net.h nstun/nstun.h sandbox.h unotify/unotify.h user.h
subproc.o: util.h
uts.o: uts.h nsjail.h config.pb.h logs.h
user.o: user.h nsjail.h config.pb.h logs.h macros.h subproc.h util.h
unotify/unotify.o: unotify/unotify.h nsjail.h config.pb.h logs.h
unotify/unotify.o: unotify/record.h unotify/unotify.pb.h unotify/stats.h
unotify/unotify.o: unotify/syscall.h util.h
unotify/stats.o: unotify/stats.h nsjail.h config.pb.h unotify/record.h
unotify/stats.o: unotify/unotify.pb.h logs.h util.h
unotify/syscall.o: unotify/syscall.h unotify/record.h unotify/unotify.pb.h
unotify/syscall.o: logs.h macros.h unotify/syscall_defs.h util.h nsjail.h
unotify/syscall.o: config.pb.h
util.o: util.h nsjail.h config.pb.h logs.h macros.h missing_defs.h
nstun/nstun.o: nstun/nstun.h nstun/core.h nstun/net_defs.h nstun/icmp.h
nstun/nstun.o: nstun/iface.h nstun/ip.h logs.h macros.h nstun/policy.h
nstun/nstun.o: nstun/tcp.h nstun/tun.h nstun/udp.h util.h nsjail.h
nstun/nstun.o: config.pb.h
nstun/policy.o: nstun/policy.h nstun/core.h nstun/net_defs.h nstun/nstun.h
nstun/policy.o: logs.h config.pb.h nsjail.h
nstun/encap.o: nstun/encap.h nstun/net_defs.h logs.h
nstun/iface.o: nstun/iface.h logs.h macros.h nstun/net_defs.h nsjail.h
nstun/iface.o: config.pb.h nstun/nstun.h
nstun/tun.o: nstun/tun.h nstun/core.h nstun/net_defs.h nstun/nstun.h
nstun/tun.o: nstun/icmp.h nstun/ip.h logs.h
nstun/ip.o: nstun/ip.h nstun/core.h nstun/net_defs.h nstun/nstun.h
nstun/ip.o: nstun/icmp.h logs.h nstun/tcp.h nstun/udp.h
nstun/icmp.o: nstun/icmp.h nstun/core.h nstun/net_defs.h nstun/nstun.h logs.h
nstun/icmp.o: macros.h nstun/policy.h nstun/tun.h
nstun/udp.o: nstun/udp.h nstun/core.h nstun/net_defs.h nstun/nstun.h
nstun/udp.o: nstun/encap.h nstun/icmp.h logs.h macros.h nstun/policy.h
nstun/udp.o: nstun/tun.h
nstun/tcp.o: nstun/tcp.h nstun/core.h nstun/net_defs.h nstun/nstun.h
nstun/tcp.o: nstun/encap.h logs.h macros.h nstun/policy.h nstun/tun.h util.h
nstun/tcp.o: nsjail.h config.pb.h
config.pb.o: config.pb.h
unotify/unotify.pb.o: unotify/unotify.pb.h
