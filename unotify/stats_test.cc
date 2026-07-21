#include "unotify/stats.h"

#include <cstdio>
#include <limits>

#define CHECK(condition)                                                                           \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,    \
			    #condition);                                                           \
			return 1;                                                                  \
		}                                                                                  \
	} while (0)

int main() {
	constexpr uint64_t max_count = std::numeric_limits<uint64_t>::max();
	CHECK(unotify::internal::saturatingAdd(40, 2) == 42);
	CHECK(unotify::internal::saturatingAdd(max_count - 1, 2) == max_count);

	unotify::StatsStore store(/* max_entries= */ 2,
	    /* max_bytes= */ std::numeric_limits<size_t>::max());

	unotify::SyscallRecord first;
	first.name = "openat";
	first.args = {"/first"};

	unotify::SyscallRecord second;
	second.name = "openat";
	second.args = {"/second"};

	unotify::SyscallRecord third;
	third.name = "openat";
	third.args = {"/third"};

	CHECK(store.add(first));
	CHECK(store.add(second));
	CHECK(!store.add(third));
	CHECK(store.size() == 2);
	CHECK(store.dropped() == 1);

	/* Existing keys must continue to aggregate after the unique-key cap. */
	CHECK(store.add(first));
	CHECK(store.count(first) == 2);
	CHECK(store.size() == 2);

	/* String payloads and nested arg elements are independently bounded, even
	 * below the entry cap. An exact byte budget is accepted. */
	constexpr size_t small_bytes = 8 + sizeof(std::string);
	unotify::StatsStore byte_limited(/* max_entries= */ 10,
	    /* max_bytes= */ small_bytes);
	unotify::SyscallRecord small;
	small.name = "openat";
	small.args = {"/a"};
	unotify::SyscallRecord too_large;
	too_large.name = "openat";
	too_large.args = {"/bbbb"};

	CHECK(byte_limited.add(small));
	CHECK(byte_limited.bytes() == small_bytes);
	CHECK(!byte_limited.add(too_large));
	CHECK(byte_limited.size() == 1);
	CHECK(byte_limited.bytes() == small_bytes);
	CHECK(byte_limited.dropped() == 1);

	/* A zero byte limit rejects a record with any accounted bytes. */
	unotify::StatsStore zero_bytes(/* max_entries= */ 10, /* max_bytes= */ 0);
	unotify::SyscallRecord nonempty;
	nonempty.name = "x";
	CHECK(!zero_bytes.add(nonempty));
	CHECK(zero_bytes.bytes() == 0);
	CHECK(zero_bytes.dropped() == 1);
	CHECK(zero_bytes.hasOutput());

	/* Resource metadata is attacker-influenced and counts toward the budget. */
	unotify::StatsStore resource_limited(/* max_entries= */ 10,
	    /* max_bytes= */ 10);
	unotify::SyscallRecord with_path;
	with_path.name = "openat";
	with_path.res.has_path1 = true;
	with_path.res.path1.path = "/1234";
	CHECK(!resource_limited.add(with_path));
	CHECK(resource_limited.size() == 0);
	CHECK(resource_limited.dropped() == 1);

	/* Every owned resource string contributes to the retained-byte budget. */
	unotify::SyscallRecord all_resources;
	all_resources.name = "x";
	all_resources.res.has_path1 = true;
	all_resources.res.path1.path = "a";
	all_resources.res.path1.mode_extra = "b";
	all_resources.res.has_path2 = true;
	all_resources.res.path2.path = "c";
	all_resources.res.path2.mode_extra = "d";
	all_resources.res.has_net = true;
	all_resources.res.net_endpoint = "e";
	all_resources.res.has_net_path = true;
	all_resources.res.net_path.path = "f";
	all_resources.res.net_path.mode_extra = "g";
	unotify::StatsStore all_resources_exact(/* max_entries= */ 10,
	    /* max_bytes= */ 8);
	CHECK(all_resources_exact.add(all_resources));
	CHECK(all_resources_exact.bytes() == 8);
	unotify::StatsStore all_resources_short(/* max_entries= */ 10,
	    /* max_bytes= */ 7);
	CHECK(!all_resources_short.add(all_resources));
	CHECK(all_resources_short.dropped() == 1);

	/* A zero entry limit still records that output was dropped. */
	unotify::StatsStore zero_entries(/* max_entries= */ 0,
	    /* max_bytes= */ std::numeric_limits<size_t>::max());
	unotify::SyscallRecord empty;
	CHECK(!zero_entries.add(empty));
	CHECK(zero_entries.size() == 0);
	CHECK(zero_entries.dropped() == 1);
	CHECK(zero_entries.hasOutput());

	/* The producer can emit at most 128 argv entries, 128 envp entries, and
	 * one dirfd entry for execveat. Reject records outside that contract. */
	unotify::StatsStore arg_limited(/* max_entries= */ 10,
	    /* max_bytes= */ std::numeric_limits<size_t>::max());
	unotify::SyscallRecord maximum_args;
	maximum_args.name = "execveat";
	maximum_args.args.resize(257);
	CHECK(arg_limited.add(maximum_args));
	unotify::SyscallRecord excessive_args;
	excessive_args.name = "execveat";
	excessive_args.args.resize(258);
	CHECK(!arg_limited.add(excessive_args));
	CHECK(arg_limited.size() == 1);
	CHECK(arg_limited.dropped() == 1);

	return 0;
}
