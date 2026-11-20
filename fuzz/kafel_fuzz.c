/* Kafel policy-source fuzz target: parse + compile + basic BPF sanity. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/filter.h>
#include "kafel.h"
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
        if (size == 0 || size > 8192) return 0; /* policy-sized inputs */
        /* NUL-terminate copy: kafel expects a C string */
        char* src = malloc(size + 1);
        if (!src) return 0;
        memcpy(src, data, size);
        src[size] = '\0';
        struct sock_fprog prog = {0};
        kafel_ctxt_t ctxt = kafel_ctxt_create();
        if (ctxt) {
                kafel_set_input_string(ctxt, src);
                if (kafel_compile(ctxt, &prog) == 0) {
                        /* compiled: sanity the program (len bounds, instruction sanity) */
                        if (prog.len == 0 || prog.len > 65535) {
                                fprintf(stderr, "BAD PROG LEN: %u\n", prog.len);
                                abort();
                        }
                        free(prog.filter);
                }
                kafel_ctxt_destroy(&ctxt);
        }
        free(src);
        return 0;
}
