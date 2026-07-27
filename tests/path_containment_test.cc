/*
 * Regression tests for mount-destination path traversal hardening.
 *
 * Standalone harness (mirrors util::isSafeContainmentPath /
 * createDirRecursively policy) so it can run without linking full nsjail.
 *
 *   g++ -std=c++20 -O1 -o path_containment_test tests/path_containment_test.cc
 *   ./path_containment_test
 */

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

std::vector<std::string> strSplit(const std::string& str, char delim) {
	std::vector<std::string> vec;
	std::string word;
	for (char c : str) {
		if (c == delim) {
			vec.push_back(word);
			word.clear();
		} else {
			word.push_back(c);
		}
	}
	vec.push_back(word);
	return vec;
}

bool isSafeContainmentPath(const std::string& path) {
	if (path.empty()) {
		return true;
	}
	if (path.find('\0') != std::string::npos) {
		return false;
	}
	for (const auto& component : strSplit(path, '/')) {
		if (component.empty()) {
			continue;
		}
		if (component == "." || component == "..") {
			return false;
		}
	}
	return true;
}

bool createDirRecursivelySafe(const char* dir) {
	if (dir[0] != '/') {
		return false;
	}
	if (!isSafeContainmentPath(dir)) {
		return false;
	}

	int prev_dir_fd = open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
	if (prev_dir_fd == -1) {
		return false;
	}

	char path[4096];
	if (snprintf(path, sizeof(path), "%s", dir) >= (int)sizeof(path)) {
		close(prev_dir_fd);
		return false;
	}
	char* curr = path;
	for (;;) {
		while (*curr == '/') {
			curr++;
		}
		char* next = strchr(curr, '/');
		if (next == nullptr) {
			close(prev_dir_fd);
			return true;
		}
		*next = '\0';
		if (mkdirat(prev_dir_fd, curr, 0755) == -1 && errno != EEXIST) {
			close(prev_dir_fd);
			return false;
		}
		int dir_fd = openat(prev_dir_fd, curr, O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (dir_fd == -1) {
			close(prev_dir_fd);
			return false;
		}
		close(prev_dir_fd);
		prev_dir_fd = dir_fd;
		curr = next + 1;
	}
}

}  // namespace

static void expect_safe(const char* p, bool want) {
	bool got = isSafeContainmentPath(p);
	if (got != want) {
		fprintf(stderr, "FAIL isSafeContainmentPath(%s) = %d want %d\n", p, got, want);
		exit(1);
	}
}

int main() {
	expect_safe("", true);
	expect_safe("/", true);
	expect_safe("/usr/lib", true);
	expect_safe("/tmp/nsjail.root/home/user", true);
	expect_safe("usr/lib", true);
	expect_safe("/usr//lib", true);

	expect_safe("..", false);
	expect_safe("/..", false);
	expect_safe("/../", false);
	expect_safe("/tmp/../etc", false);
	expect_safe("/tmp/nsjail.root/../../etc/passwd", false);
	expect_safe("/foo/./bar", false);
	expect_safe("./foo", false);
	expect_safe("foo/../../bar", false);

	std::string with_nul = std::string("/tmp/foo") + '\0' + "bar";
	if (isSafeContainmentPath(with_nul)) {
		fprintf(stderr, "FAIL NUL component accepted\n");
		return 1;
	}

	(void)system("rm -rf /tmp/nsj_path_test /tmp/nsj_path_escaped");
	mkdir("/tmp/nsj_path_test", 0755);
	const char* escape =
	    "/tmp/nsj_path_test/root/../../nsj_path_escaped/evil_dir/leaf";
	if (createDirRecursivelySafe(escape)) {
		fprintf(stderr, "FAIL createDirRecursively accepted traversal path\n");
		return 1;
	}
	if (access("/tmp/nsj_path_escaped", F_OK) == 0) {
		fprintf(stderr, "FAIL escape directory was created\n");
		return 1;
	}

	const char* ok = "/tmp/nsj_path_test/root/home/user/docs/leaf";
	if (!createDirRecursivelySafe(ok)) {
		fprintf(stderr, "FAIL createDirRecursively rejected safe path\n");
		return 1;
	}
	if (access("/tmp/nsj_path_test/root/home/user/docs", F_OK) != 0) {
		fprintf(stderr, "FAIL safe parents were not created\n");
		return 1;
	}

	printf("OK path_containment_test passed\n");
	return 0;
}
