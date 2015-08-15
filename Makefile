#
#   nsjail - Makefile
#      -----------------------------------------
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

CC = gcc
CFLAGS += -O2 -g -ggdb -c -std=c11 \
	-D_GNU_SOURCE \
	-fstack-protector-all -Wformat -Wformat=2 -Wformat-security -fPIE -D_FORTIFY_SOURCE=2 -Wa,--noexecstack \
	-Wall -Wextra -Werror

LD = gcc
LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie

SRCS = nsjail.c cmdline.c contain.c log.c net.c subproc.c sandbox.c seccomp/bpf-helper.c
OBJS = $(SRCS:.c=.o)
BIN = nsjail

.c.o: %.c
	$(CC) $(CFLAGS) $< -o $@

all: $(BIN)

$(BIN): $(OBJS)
	$(LD) -o $(BIN) $(OBJS) $(LDFLAGS)

clean:
	$(RM) core Makefile.bak $(OBJS) $(BIN)

depend:
	makedepend -Y. -- $(CFLAGS) -- $(SRCS)

indent:
	indent -linux -l100 -lc100 *.c *.h seccomp/*.c seccomp/*.h; rm -f *~ seccomp/*~

# DO NOT DELETE THIS LINE -- make depend depends on it.

nsjail.o: nsjail.h cmdline.h common.h log.h net.h subproc.h
cmdline.o: cmdline.h common.h log.h
contain.o: contain.h common.h log.h
log.o: log.h common.h
net.o: net.h common.h log.h
subproc.o: subproc.h common.h contain.h log.h net.h sandbox.h
sandbox.o: sandbox.h common.h log.h seccomp/bpf-helper.h
seccomp/bpf-helper.o: seccomp/bpf-helper.h
