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

PKG_CONFIG=$(shell which pkg-config)
ifeq ($(PKG_CONFIG),)
$(error "Install pkg-config to make it work")
endif

CC ?= gcc
CXX ?= g++

COMMON_FLAGS += -O2 -c \
	-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
	-fPIE \
	-Wformat -Wformat-security -Wno-format-nonliteral \
	-Wall -Wextra -Werror \
	-Ikafel/include

CXXFLAGS += $(COMMON_FLAGS) $(shell pkg-config --cflags protobuf) \
	-std=c++11 -fno-exceptions -Wno-unused -Wno-unused-parameter
LDFLAGS += -pie -Wl,-z,noexecstack -lpthread $(shell pkg-config --libs protobuf)

BIN = nsjail
LIBS = kafel/libkafel.a
SRCS_CXX = caps.cc cgroup.cc cgroup2.cc cmdline.cc config.cc contain.cc cpu.cc logs.cc mnt.cc net.cc nsjail.cc pid.cc sandbox.cc subproc.cc uts.cc user.cc util.cc
SRCS_PROTO = config.proto
SRCS_PB_CXX = $(SRCS_PROTO:.proto=.pb.cc)
SRCS_PB_H = $(SRCS_PROTO:.proto=.pb.h)
SRCS_PB_O = $(SRCS_PROTO:.proto=.pb.o)
OBJS = $(SRCS_CXX:.cc=.o) $(SRCS_PB_CXX:.cc=.o)

ifdef DEBUG
	CXXFLAGS += -g -ggdb -gdwarf-4
endif

NL3_EXISTS := $(shell pkg-config --exists libnl-route-3.0 && echo yes)
ifeq ($(NL3_EXISTS), yes)
	CXXFLAGS += $(shell pkg-config --cflags libnl-route-3.0)
	LDFLAGS += $(shell pkg-config --libs libnl-route-3.0)
endif

.PHONY: all clean depend indent

.cc.o: %.cc
	$(CXX) $(CXXFLAGS) $< -o $@

all: $(BIN)

$(BIN): $(LIBS) $(OBJS)
ifneq ($(NL3_EXISTS), yes)
	$(warning "============================================================")
	$(warning "You probably miss libnl3(-dev)/libnl-route-3(-dev) libraries")
	$(warning "============================================================")
endif
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

.PHONY: clean
clean:
	$(RM) core Makefile.bak $(OBJS) $(SRCS_PB_CXX) $(SRCS_PB_H) $(BIN)
ifneq ("$(wildcard kafel/Makefile)","")
	$(MAKE) -C kafel clean
endif

.PHONY: depend
depend: all
	makedepend -Y -Ykafel/include -- -- $(SRCS_CXX) $(SRCS_PB_CXX)

.PHONY: indent
indent:
	clang-format -style="{BasedOnStyle: google, IndentWidth: 8, UseTab: Always, IndentCaseLabels: false, ColumnLimit: 100, AlignAfterOpenBracket: false, AllowShortFunctionsOnASingleLine: false}" -i -sort-includes *.h $(SRCS_CXX)
	clang-format -style="{BasedOnStyle: google, IndentWidth: 4, UseTab: Always, ColumnLimit: 100}" -i $(SRCS_PROTO)

# DO NOT DELETE THIS LINE -- make depend depends on it.

caps.o: caps.h nsjail.h logs.h macros.h util.h
cgroup.o: cgroup.h nsjail.h logs.h util.h
cgroup2.o: cgroup2.h nsjail.h logs.h util.h
cmdline.o: cmdline.h nsjail.h caps.h config.h logs.h macros.h mnt.h user.h
cmdline.o: util.h
config.o: config.h nsjail.h caps.h cmdline.h config.pb.h logs.h macros.h
config.o: mnt.h user.h util.h
contain.o: contain.h nsjail.h caps.h cgroup.h cpu.h logs.h macros.h mnt.h
contain.o: net.h pid.h user.h util.h uts.h
cpu.o: cpu.h nsjail.h logs.h util.h
logs.o: logs.h macros.h util.h nsjail.h
mnt.o: mnt.h nsjail.h logs.h macros.h subproc.h util.h
net.o: net.h nsjail.h logs.h subproc.h
nsjail.o: nsjail.h cmdline.h logs.h macros.h net.h sandbox.h subproc.h util.h
pid.o: pid.h nsjail.h logs.h subproc.h
sandbox.o: sandbox.h nsjail.h kafel/include/kafel.h logs.h util.h
subproc.o: subproc.h nsjail.h cgroup.h cgroup2.h contain.h logs.h macros.h
subproc.o: net.h sandbox.h user.h util.h
uts.o: uts.h nsjail.h logs.h
user.o: user.h nsjail.h logs.h macros.h subproc.h util.h
util.o: util.h nsjail.h logs.h macros.h
config.pb.o: config.pb.h
