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

EXTRA_CFLAGS := $(CFLAGS)

CFLAGS += -O2 -c -std=gnu11 \
	-D_GNU_SOURCE \
	-Wformat -Wformat=2 -Wformat-security -fPIE \
	-Wno-format-nonliteral \
	-Wall -Wextra -Werror \
	-Ikafel/include

LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie -Wl,-z,noexecstack -lpthread -lcap

BIN = nsjail
LIBS = kafel/libkafel.a
SRCS = nsjail.c caps.c cmdline.c config.c contain.c log.c cgroup.c mount.c net.c pid.c sandbox.c subproc.c user.c util.c uts.c cpu.c
OBJS = $(SRCS:.c=.o)

ifdef DEBUG
	CFLAGS += -g -ggdb -gdwarf-4
endif

USE_NL3 ?= yes
ifeq ($(USE_NL3), yes)
NL3_EXISTS := $(shell pkg-config --exists libnl-route-3.0 && echo yes)
ifeq ($(NL3_EXISTS), yes)
	CFLAGS += -DNSJAIL_NL3_WITH_MACVLAN $(shell pkg-config --cflags libnl-route-3.0)
	LDFLAGS += $(shell pkg-config --libs libnl-route-3.0)
endif
endif

USE_PROTOBUF ?= yes
ifeq ($(USE_PROTOBUF), yes)
ifeq ("$(shell which protoc-c)", "")
	USE_PROTOBUF := no
	PROTOC_WARNING := yes
endif
endif

ifeq ($(USE_PROTOBUF), no)
else ifeq ($(shell pkg-config --exists libprotobuf-c && echo yes), yes)
	PROTO_DEPS = config.pb-c.h config.pb-c.c
	SRCS += config.pb-c.c
	CFLAGS += -DNSJAIL_WITH_PROTOBUF -Iprotobuf-c-text/protobuf-c-text $(shell pkg-config --cflags libprotobuf-c)
	LIBS += protobuf-c-text/protobuf-c-text/.libs/libprotobuf-c-text.a
	LDFLAGS += $(shell pkg-config --libs libprotobuf-c)
else ifneq ("$(wildcard /usr/include/google/protobuf-c/protobuf-c.h)", "")
	PROTO_DEPS = config.pb-c.h config.pb-c.c
	SRCS += config.pb-c.c
	CFLAGS += -DNSJAIL_WITH_PROTOBUF -Iprotobuf-c-text/protobuf-c-text -I/usr/include/google
	LIBS += protobuf-c-text/protobuf-c-text/.libs/libprotobuf-c-text.a
	LDFLAGS += -Wl,-lprotobuf-c
else ifneq ("$(wildcard /usr/local/include/google/protobuf-c/protobuf-c.h)", "")
	PROTO_DEPS = config.pb-c.h config.pb-c.c
	SRCS += config.pb-c.c
	CFLAGS += -DNSJAIL_WITH_PROTOBUF -Iprotobuf-c-text/protobuf-c-text -I/usr/local/include/google
	LIBS += protobuf-c-text/protobuf-c-text/.libs/libprotobuf-c-text.a
	LDFLAGS += -Wl,--library-path=/usr/local/lib -Wl,-lprotobuf-c
else
	USE_PROTOBUF := no
endif

.PHONY: all clear depend indent

.c.o: %.c
	$(CC) $(CFLAGS) $< -o $@

all: $(PROTO_DEPS) $(BIN)
ifeq ($(PROTOC_WARNING), yes)
	$(info *********************************************************)
	$(info *        'protoc-c' is missing on your system           *)
	$(info *  Install 'protobuf-c-compiler' or a similar package   *)
	$(info *********************************************************)
endif
ifeq ($(USE_PROTOBUF), no)
	$(info *********************************************************)
	$(info * Code compiled without libprotobuf-c/libprotobuf-c-dev *)
	$(info *  The --config commandline option will be unavailable  *)
	$(info *********************************************************)
endif

$(BIN): $(LIBS) $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(LIBS) $(LDFLAGS)

kafel/libkafel.a:
ifeq ("$(wildcard kafel/Makefile)","")
	git submodule update --init
endif
	$(MAKE) -C kafel

protobuf-c-text/protobuf-c-text/.libs/libprotobuf-c-text.a:
ifeq ("$(wildcard protobuf-c-text/configure)","")
	git submodule update --init
endif
ifeq ("$(wildcard protobuf-c-text/Makefile)","")
	sh -c "cd protobuf-c-text; CFLAGS=\"-fPIC -I/usr/include/google $(EXTRA_CFLAGS)\" ./autogen.sh --enable-shared=no --disable-doxygen-doc;"
endif
	$(MAKE) -C protobuf-c-text

$(PROTO_DEPS): config.proto
	protoc-c --c_out=. config.proto

clean:
	$(RM) core Makefile.bak $(OBJS) $(BIN) $(PROTO_DEPS)
ifneq ("$(wildcard kafel/Makefile)","")
	$(MAKE) -C kafel clean
endif
ifneq ("$(wildcard protobuf-c-text/Makefile)","")
	$(MAKE) -C protobuf-c-text clean
endif

depend:
	makedepend -Y -Ykafel/include -- -- $(SRCS)

indent:
	indent -linux -l100 -lc100 *.c *.h; rm -f *~

# DO NOT DELETE THIS LINE -- make depend depends on it.

nsjail.o: nsjail.h common.h caps.h cmdline.h log.h net.h subproc.h util.h
caps.o: caps.h common.h log.h
cmdline.o: cmdline.h common.h caps.h config.h log.h mount.h util.h user.h
config.o: common.h config.h log.h mount.h user.h util.h
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
