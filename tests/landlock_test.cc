#include "landlock.h"

#include <assert.h>
#include <stdint.h>

#include "config.pb.h"

namespace {

constexpr uint64_t kBitExecute = 1ULL << 0;
constexpr uint64_t kBitWriteFile = 1ULL << 1;
constexpr uint64_t kBitReadFile = 1ULL << 2;
constexpr uint64_t kBitReadDir = 1ULL << 3;
constexpr uint64_t kBitRemoveDir = 1ULL << 4;
constexpr uint64_t kBitMakeDir = 1ULL << 7;
constexpr uint64_t kBitRefer = 1ULL << 13;
constexpr uint64_t kBitTruncate = 1ULL << 14;
constexpr uint64_t kBitIoctlDev = 1ULL << 15;

void test_abi_downgrade() {
	const uint64_t abi1 = landlock::handledAccessForAbi(1);
	assert((abi1 & kBitRefer) == 0);
	assert((abi1 & kBitTruncate) == 0);
	assert((abi1 & kBitIoctlDev) == 0);
	assert((abi1 & (kBitExecute | kBitWriteFile | kBitReadFile | kBitReadDir)) ==
	       (kBitExecute | kBitWriteFile | kBitReadFile | kBitReadDir));

	const uint64_t abi2 = landlock::handledAccessForAbi(2);
	assert((abi2 & kBitRefer) != 0);
	assert((abi2 & kBitTruncate) == 0);
	assert((abi2 & kBitIoctlDev) == 0);

	const uint64_t abi3 = landlock::handledAccessForAbi(3);
	assert((abi3 & kBitRefer) != 0);
	assert((abi3 & kBitTruncate) != 0);
	assert((abi3 & kBitIoctlDev) == 0);

	const uint64_t abi4 = landlock::handledAccessForAbi(4);
	assert(abi4 == abi3);

	const uint64_t abi5 = landlock::handledAccessForAbi(5);
	assert((abi5 & kBitIoctlDev) != 0);
	assert(landlock::handledAccessForAbi(6) == abi5);
}

void test_access_for_mount() {
	const uint64_t abi1 = landlock::handledAccessForAbi(1);
	const uint64_t abi5 = landlock::handledAccessForAbi(5);

	nsjail::MountPt ro_dir;
	ro_dir.set_dst("/ro");
	ro_dir.set_rw(false);
	ro_dir.set_noexec(false);
	uint64_t m = landlock::accessForMount(ro_dir, /* is_dir= */ true, abi5);
	assert((m & kBitReadFile) != 0);
	assert((m & kBitReadDir) != 0);
	assert((m & kBitExecute) != 0);
	assert((m & kBitWriteFile) == 0);
	assert((m & kBitMakeDir) == 0);

	nsjail::MountPt ro_noexec;
	ro_noexec.set_dst("/ro_noexec");
	ro_noexec.set_rw(false);
	ro_noexec.set_noexec(true);
	m = landlock::accessForMount(ro_noexec, /* is_dir= */ true, abi5);
	assert((m & kBitReadFile) != 0);
	assert((m & kBitReadDir) != 0);
	assert((m & kBitExecute) == 0);
	assert((m & kBitWriteFile) == 0);

	nsjail::MountPt rw_dir;
	rw_dir.set_dst("/rw");
	rw_dir.set_rw(true);
	rw_dir.set_noexec(false);
	m = landlock::accessForMount(rw_dir, /* is_dir= */ true, abi1);
	assert((m & kBitWriteFile) != 0);
	assert((m & kBitRemoveDir) != 0);
	assert((m & kBitRefer) == 0);
	assert((m & kBitTruncate) == 0);
	assert((m & kBitIoctlDev) == 0);

	m = landlock::accessForMount(rw_dir, /* is_dir= */ true, abi5);
	assert((m & (kBitRefer | kBitTruncate | kBitIoctlDev)) ==
	       (kBitRefer | kBitTruncate | kBitIoctlDev));

	/* Regular file targets must not retain directory-only rights. */
	m = landlock::accessForMount(rw_dir, /* is_dir= */ false, abi5);
	assert((m & kBitReadDir) == 0);
	assert((m & kBitRemoveDir) == 0);
	assert((m & kBitMakeDir) == 0);
	assert((m & (kBitReadFile | kBitWriteFile | kBitExecute | kBitTruncate | kBitIoctlDev)) ==
	       (kBitReadFile | kBitWriteFile | kBitExecute | kBitTruncate | kBitIoctlDev));

	/* Mount options string (-m ...:ro,noexec) must override default flags. */
	nsjail::MountPt opts_mnt;
	opts_mnt.set_dst("/opts");
	opts_mnt.set_rw(true);
	opts_mnt.set_noexec(false);
	opts_mnt.set_options("bind,ro,noexec");
	m = landlock::accessForMount(opts_mnt, /* is_dir= */ true, abi5);
	assert((m & kBitReadFile) != 0);
	assert((m & kBitReadDir) != 0);
	assert((m & kBitWriteFile) == 0);
	assert((m & kBitExecute) == 0);
}

}  // namespace

int main() {
	test_abi_downgrade();
	test_access_for_mount();
	return 0;
}
