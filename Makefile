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

CFLAGS += $(COMMON_FLAGS) \
	-std=gnu11
CXXFLAGS += $(COMMON_FLAGS) $(shell pkg-config --cflags protobuf) \
	-std=c++14 -fno-exceptions -Wno-unused -Wno-unused-parameter
LDFLAGS += -pie -Wl,-z,noexecstack -lpthread $(shell pkg-config --libs protobuf)

BIN = nsjail
LIBS = kafel/libkafel.a
SRCS_C =
SRCS_CXX = caps.cc cgroup.cc cmdline.cc config.cc contain.cc cpu.cc log.cc mnt.cc net.cc nsjail.cc pid.cc sandbox.cc subproc.cc uts.cc user.cc util.cc
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

.PHONY: all clean depend indent

.c.o: %.c
	$(CXX) -xc $(CFLAGS) $< -o $@

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

# Sequence of proto deps, which doesn't fit automatic make rules
config.o: $(SRCS_PB_O) $(SRCS_PB_H)
$(SRCS_PB_O): $(SRCS_PB_CXX) $(SRCS_PB_H)
$(SRCS_PB_CXX) $(SRCS_PB_H): $(SRCS_PROTO)
	protoc --cpp_out=. $(SRCS_PROTO)

clean:
	$(RM) core Makefile.bak $(OBJS) $(SRCS_PB_CXX) $(SRCS_PB_H) $(BIN)
ifneq ("$(wildcard kafel/Makefile)","")
	$(MAKE) -C kafel clean
endif

depend:
	makedepend -Y -Ykafel/include -- -- $(SRCS_C) $(SRCS_CXX) $(SRCS_PB_CXX)

indent:
	clang-format -style="{BasedOnStyle: google, IndentWidth: 8, UseTab: Always, IndentCaseLabels: false, ColumnLimit: 100, AlignAfterOpenBracket: false}" -i -sort-includes *.h $(SRCS_CXX)
	clang-format -style="{BasedOnStyle: google, IndentWidth: 4, UseTab: Always, ColumnLimit: 100}" -i $(SRCS_PROTO)

# DO NOT DELETE THIS LINE -- make depend depends on it.

caps.o: caps.h nsjail.h common.h log.h util.h
cgroup.o: cgroup.h nsjail.h log.h util.h
cmdline.o: cmdline.h nsjail.h caps.h common.h config.h log.h mnt.h sandbox.h
cmdline.o: user.h util.h
config.o: caps.h nsjail.h cmdline.h common.h config.h log.h mnt.h user.h
config.o: util.h
contain.o: contain.h nsjail.h caps.h cgroup.h cpu.h log.h mnt.h net.h pid.h
contain.o: user.h uts.h
cpu.o: cpu.h nsjail.h log.h util.h
log.o: log.h nsjail.h
mnt.o: mnt.h nsjail.h common.h log.h subproc.h util.h
net.o: net.h nsjail.h log.h subproc.h
nsjail.o: nsjail.h cmdline.h common.h log.h net.h subproc.h util.h
pid.o: pid.h nsjail.h log.h subproc.h
sandbox.o: sandbox.h nsjail.h kafel/include/kafel.h log.h
subproc.o: subproc.h nsjail.h cgroup.h common.h contain.h log.h net.h
subproc.o: sandbox.h user.h util.h
uts.o: uts.h nsjail.h log.h
user.o: user.h nsjail.h common.h log.h subproc.h util.h
util.o: util.h nsjail.h common.h log.h
