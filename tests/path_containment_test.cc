/*
 * Regression tests for mount-destination path traversal hardening.
 *
 * Standalone harness (mirrors util::isSafeContainmentPath /
 * createDirRecursively policy) so it can run without linking full nsjail.
 *
 *   g++ -std=c++20 -O1 -o path_containment_test tests/path_containment_test.cc
 *   ./path_containment_test
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <limits.h>
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

	char temp_template[] = "/tmp/nsj_path_test.XXXXXX";
	char* temp_path = mkdtemp(temp_template);
	if (temp_path == nullptr) {
		perror("mkdtemp");
		return 1;
	}
	char resolved_path[PATH_MAX];
	if (realpath(temp_path, resolved_path) == nullptr) {
		perror("realpath");
		return 1;
	}
	const std::string test_root = resolved_path;
	struct TempDirGuard {
		const std::string& path;
		~TempDirGuard() {
			std::error_code error;
			std::filesystem::remove_all(path, error);
		}
	} temp_dir_guard{test_root};

	const std::string path_stage = test_root + "/path_stage";
	const std::string path_escape = test_root + "/path_escape";
	if (mkdir(path_stage.c_str(), 0755) != 0) {
		perror("mkdir path_stage");
		return 1;
	}
	const std::string escape = path_stage + "/root/../../path_escape/evil_dir/leaf";
	if (createDirRecursivelySafe(escape.c_str())) {
		fprintf(stderr, "FAIL createDirRecursively accepted traversal path\n");
		return 1;
	}
	if (access(path_escape.c_str(), F_OK) == 0) {
		fprintf(stderr, "FAIL escape directory was created\n");
		return 1;
	}

	const std::string ok = path_stage + "/root/home/user/docs/leaf";
	if (!createDirRecursivelySafe(ok.c_str())) {
		fprintf(stderr, "FAIL createDirRecursively rejected safe path\n");
		return 1;
	}
	if (access((path_stage + "/root/home/user/docs").c_str(), F_OK) != 0) {
		fprintf(stderr, "FAIL safe parents were not created\n");
		return 1;
	}

	/* Symlink intermediate must fail closed under O_NOFOLLOW walk policy. */
	const std::string symlink_stage = test_root + "/symlink_stage";
	const std::string symlink_escape = test_root + "/symlink_escape";
	if (mkdir(symlink_stage.c_str(), 0755) != 0 || mkdir(symlink_escape.c_str(), 0755) != 0) {
		perror("mkdir symlink test directories");
		return 1;
	}
	if (symlink(symlink_escape.c_str(), (symlink_stage + "/link").c_str()) != 0) {
		fprintf(stderr, "FAIL symlink setup\n");
		return 1;
	}
	/* Mimic new-API component walk with O_NOFOLLOW */
	{
		int root = open(symlink_stage.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (root < 0) {
			perror("open stage");
			return 1;
		}
		if (mkdirat(root, "link", 0755) == -1 && errno != EEXIST) {
			/* link exists as symlink; EEXIST expected */
		}
		int next = openat(root, "link", O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (next >= 0) {
			fprintf(stderr, "FAIL openat(O_NOFOLLOW) followed/opened symlink\n");
			close(next);
			close(root);
			return 1;
		}
		close(root);
		if (access((symlink_escape + "/pwned").c_str(), F_OK) == 0) {
			fprintf(stderr, "FAIL escape created\n");
			return 1;
		}
	}

	printf("OK path_containment_test passed\n");
	return 0;
}
