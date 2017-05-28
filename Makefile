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
	-Ikafel/include \
	-Iprotobuf-c-text/protobuf-c-text 

LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie -Wl,-z,noexecstack

BIN = nsjail
LIBS = kafel/libkafel.a
SRCS = nsjail.c cmdline.c config.c contain.c log.c cgroup.c mount.c net.c pid.c sandbox.c subproc.c user.c util.c uts.c
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
PROTOBUF_EXISTS := $(shell pkg-config --exists libprotobuf-c && echo yes)
ifeq ($(PROTOBUF_EXISTS), yes)
	PROTO_DEPS = config.pb-c.h config.pb-c.c
	SRCS += config.pb-c.c
	CFLAGS += -DNSJAIL_WITH_PROTOBUF $(shell pkg-config --cflags libprotobuf-c)
	LIBS += protobuf-c-text/protobuf-c-text/.libs/libprotobuf-c-text.a
	LDFLAGS += $(shell pkg-config --libs libprotobuf-c)
endif
endif


.PHONY: all clear depend indent kafel protobuf-c-text

.c.o: %.c
	$(CC) $(CFLAGS) $< -o $@

all: $(PROTO_DEPS) protobuf-c-text kafel $(BIN)
ifneq ($(PROTOBUF_EXISTS), yes)
	$(info *********************************************************)
	$(info * Code compiled without libprotobuf-c/libprotobuf-c-dev *)
	$(info *  The --config commandline option will be unavailable  *)
	$(info *********************************************************)
endif

$(BIN): $(OBJS) $(LIBS)
	$(CC) -o $(BIN) $(OBJS) $(LIBS) $(LDFLAGS)

kafel:
ifeq ("$(wildcard kafel/Makefile)","")
	git submodule update --init
endif

protobuf-c-text:
ifeq ("$(wildcard protobuf-c-text/configure)","")
	git submodule update --init
endif

kafel/libkafel.a:
	$(MAKE) -C kafel

protobuf-c-text/protobuf-c-text/.libs/libprotobuf-c-text.a:
	sh -c "cd protobuf-c-text; CFLAGS=\"$(EXTRA_CFLAGS)\" ./autogen.sh;"
	$(MAKE) -C protobuf-c-text

$(PROTO_DEPS): config.proto
	protoc-c --c_out=. config.proto

clean:
	$(RM) core Makefile.bak $(OBJS) $(BIN)
ifneq ("$(wildcard kafel/Makefile)","")
	$(MAKE) -C kafel clean
endif

depend:
	makedepend -Y -Ykafel/include -- -- $(SRCS)

indent:
	indent -linux -l100 -lc100 *.c *.h; rm -f *~

# DO NOT DELETE THIS LINE -- make depend depends on it.

nsjail.o: nsjail.h common.h cmdline.h log.h net.h subproc.h
cmdline.o: cmdline.h common.h config.h log.h mount.h util.h user.h
config.o: common.h config.h log.h mount.h user.h util.h
contain.o: contain.h common.h cgroup.h log.h mount.h net.h pid.h user.h
contain.o: util.h uts.h
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
config.pb-c.o: config.pb-c.h
