#
#   nsjail - Makefile
#   -----------------------------------------
#
#   Copyright 2014 Google Inc. All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

CC ?= gcc

CFLAGS += -O2 -c -std=gnu11 \
	-D_GNU_SOURCE \
	-fstack-protector-all -Wformat -Wformat=2 -Wformat-security -fPIE \
	-Wall -Wextra -Werror

LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie -Wl,-z,noexecstack

SRCS = nsjail.c cmdline.c contain.c log.c mount.c net.c sandbox.c subproc.c user.c util.c uts.c seccomp/bpf-helper.c
OBJS = $(SRCS:.c=.o)
BIN = nsjail

ifdef DEBUG
	CFLAGS += -g -ggdb -gdwarf-4
endif

COMPILER = $(shell $(CC) -v 2>&1 | grep -E '(gcc|clang) version' | grep -oE '(clang|gcc)')
ifeq ($(COMPILER),clang)
	CFLAGS += -fblocks
	LDFLAGS += -lBlocksRuntime
endif

ifeq ("$(wildcard /usr/include/libnl3/netlink/route/link/macvlan.h)","/usr/include/libnl3/netlink/route/link/macvlan.h")
	CFLAGS += -DNSJAIL_NL3_WITH_MACVLAN -I/usr/include/libnl3
	LDFLAGS += -lnl-3 -lnl-route-3
endif

.c.o: %.c
	$(CC) $(CFLAGS) $< -o $@

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(LDFLAGS)

clean:
	$(RM) core Makefile.bak $(OBJS) $(BIN)

depend:
	makedepend -Y. -- $(CFLAGS) -- $(SRCS)

indent:
	indent -linux -l100 -lc100 *.c *.h seccomp/*.c seccomp/*.h; rm -f *~ seccomp/*~

# DO NOT DELETE THIS LINE -- make depend depends on it.

nsjail.o: nsjail.h common.h cmdline.h log.h net.h subproc.h
cmdline.o: cmdline.h common.h log.h util.h
contain.o: contain.h common.h log.h mount.h net.h util.h uts.h
log.o: log.h common.h
mount.o: mount.h common.h log.h
net.o: net.h common.h log.h
sandbox.o: sandbox.h common.h log.h seccomp/bpf-helper.h
subproc.o: subproc.h common.h contain.h log.h net.h sandbox.h user.h util.h
user.o: user.h common.h log.h util.h
util.o: util.h common.h log.h
uts.o: uts.h common.h log.h
seccomp/bpf-helper.o: seccomp/bpf-helper.h
