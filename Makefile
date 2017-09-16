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
CXX ?= g++

COMMON_FLAGS += -O2 -c \
	-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
	-Wformat -Wformat=2 -Wformat-security -fPIE \
	-Wno-format-nonliteral \
	-Wall -Wextra -Werror \
	-Ikafel/include

CFLAGS += $(COMMON_FLAGS) -std=gnu11
CXXFLAGS += $(COMMON_FLAGS) $(shell pkg-config --cflags protobuf) -std=c++11 -Wno-unused
LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie -Wl,-z,noexecstack -lpthread -lcap $(shell pkg-config --libs protobuf)

BIN = nsjail
LIBS = kafel/libkafel.a
SRCS_C = nsjail.c caps.c cmdline.c contain.c log.c cgroup.c mount.c net.c pid.c sandbox.c subproc.c user.c util.c uts.c cpu.c
SRCS_CXX = config.cc
SRCS_PROTO = config.proto
SRCS_PB_CXX = $(SRCS_PROTO:.proto=.pb.cc)
SRCS_PB_H = $(SRCS_PROTO:.proto=.pb.h)
SRCS_PB_O = $(SRCS_PROTO:.proto=.pb.o)
OBJS = $(SRCS_C:.c=.o) $(SRCS_CXX:.cc=.o) $(SRCS_PB_CXX:.cc=.o)

ifdef DEBUG
	CFLAGS += -g -ggdb -gdwarf-4
	CXXFLAGS += -g -ggdb -gdwarf-4
endif

USE_NL3 ?= yes
ifeq ($(USE_NL3), yes)
NL3_EXISTS := $(shell pkg-config --exists libnl-route-3.0 && echo yes)
ifeq ($(NL3_EXISTS), yes)
	CFLAGS += -DNSJAIL_NL3_WITH_MACVLAN $(shell pkg-config --cflags libnl-route-3.0)
	LDFLAGS += $(shell pkg-config --libs libnl-route-3.0)
endif
endif

.PHONY: all clear depend indent

.c.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.cc.o: %.cc
	$(CXX) $(CXXFLAGS) $< -o $@

all: $(BIN)

$(BIN): $(LIBS) $(OBJS)
	$(CXX) -o $(BIN) $(OBJS) $(LIBS) $(LDFLAGS)

kafel/libkafel.a:
ifeq ("$(wildcard kafel/Makefile)","")
	git submodule update --init
endif
	$(MAKE) -C kafel

$(SRCS_PB_O): $(SRCS_PB_CXX) $(SRCS_PB_H)

$(SRCS_PB_CXX) $(SRCS_PB_H): $(SRCS_PROTO)
	protoc --cpp_out=. $(SRCS_PROTO)

clean:
	$(RM) core Makefile.bak $(OBJS) $(SRCS_PB_CXX) $(SRCS_PB_H) $(BIN)
ifneq ("$(wildcard kafel/Makefile)","")
	$(MAKE) -C kafel clean
endif

depend:
	makedepend -Y -Ykafel/include -- -- $(SRCS_C) $(SRCS_CXX) $(SRCS_PB)

indent:
	clang-format --style=WebKit -i -sort-includes *.c *.h $(SRCS_CXX)
	indent -linux -l100 -lc100 *.c *.h; rm -f *~

# DO NOT DELETE THIS LINE -- make depend depends on it.

nsjail.o: nsjail.h common.h caps.h cmdline.h log.h net.h subproc.h util.h
caps.o: caps.h common.h log.h util.h
cmdline.o: cmdline.h common.h caps.h config.h log.h mount.h user.h util.h
contain.o: contain.h common.h caps.h cgroup.h cpu.h log.h mount.h net.h pid.h
contain.o: user.h util.h uts.h
log.o: log.h common.h
cgroup.o: cgroup.h common.h log.h util.h
mount.o: mount.h common.h log.h subproc.h util.h
net.o: net.h common.h log.h subproc.h
pid.o: pid.h common.h log.h subproc.h
sandbox.o: sandbox.h common.h kafel/include/kafel.h log.h
subproc.o: subproc.h common.h cgroup.h contain.h log.h net.h sandbox.h user.h
subproc.o: util.h
user.o: user.h common.h log.h subproc.h util.h
util.o: util.h common.h log.h
uts.o: uts.h common.h log.h
cpu.o: cpu.h common.h log.h util.h
config.o: common.h caps.h config.h log.h mount.h user.h util.h config.pb.h
config.pb.o: config.pb.h
