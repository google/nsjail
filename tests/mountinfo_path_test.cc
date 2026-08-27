#include <cstdio>
#include <string>

#include "mountinfo.h"

static bool expectDecode(const char* encoded, const std::string& expected) {
	std::string decoded;
	if (!mountinfo::decodePath(encoded, &decoded)) {
		fprintf(stderr, "decodePath unexpectedly rejected '%s'\n", encoded);
		return false;
	}
	if (decoded != expected) {
		fprintf(stderr, "decodePath('%s') produced an unexpected path\n", encoded);
		return false;
	}
	return true;
}

static bool expectReject(const char* encoded) {
	std::string decoded;
	if (mountinfo::decodePath(encoded, &decoded)) {
		fprintf(stderr, "decodePath unexpectedly accepted '%s'\n", encoded);
		return false;
	}
	return true;
}

int main() {
	if (!expectDecode("/mnt/plain/sub", "/mnt/plain/sub")) return 1;
	if (!expectDecode("/mnt/has\\040space/sub", "/mnt/has space/sub")) return 1;
	if (!expectDecode("/mnt/has\\011tab", "/mnt/has\ttab")) return 1;
	if (!expectDecode("/mnt/has\\012newline", "/mnt/has\nnewline")) return 1;
	if (!expectDecode("/mnt/has\\134backslash", "/mnt/has\\backslash")) return 1;
	if (!expectDecode("/mnt/a\\040b\\134c", "/mnt/a b\\c")) return 1;

	if (!expectReject("/mnt/truncated\\04")) return 1;
	if (!expectReject("/mnt/non-octal\\xyz")) return 1;
	if (!expectReject("/mnt/nul\\000suffix")) return 1;

	return 0;
}
