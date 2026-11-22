#include <cstdint>
#include <cstddef>
namespace nstun {
struct Context;
void fuzz_feed(Context*, const uint8_t*, size_t);
Context* fuzz_ctx_new();
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
        static nstun::Context* ctx = nstun::fuzz_ctx_new();
        nstun::fuzz_feed(ctx, data, size);
        return 0;
}
