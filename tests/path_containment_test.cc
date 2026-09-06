/*
 * Regression tests for mount-destination path containment hardening.
 *
 * Standalone harness (mirrors util::isSafeContainmentPath /
 * openParentNoFollow policy) so it can run without linking full nsjail.
 *
 *   g++ -std=c++20 -O1 -o path_containment_test tests/path_containment_test.cc
 *   ./path_containment_test
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
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

/* Mirrors util::openParentNoFollow: walk the parent components of the final
 * path component with O_NOFOLLOW (creating missing parents), never touching
 * the final component itself. Returns true and the basename on success. */
bool openParentNoFollowSafe(const char* dir, std::string* basename_out) {
	if (dir[0] != '/') {
		return false;
	}
	if (!isSafeContainmentPath(dir)) {
		return false;
	}

	const std::string path_str(dir);
	const size_t last_slash = path_str.find_last_of('/');
	std::string parent =
	    (last_slash == std::string::npos) ? std::string("/") : path_str.substr(0, last_slash);
	std::string basename =
	    (last_slash == std::string::npos) ? path_str : path_str.substr(last_slash + 1);
	if (parent.empty()) {
		parent = "/";
	}
	if (basename.empty()) {
		basename = ".";
	} else if (basename == "." || basename == "..") {
		return false;
	}

	int prev_dir_fd = open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
	if (prev_dir_fd == -1) {
		return false;
	}

	char walk[4096];
	if (snprintf(walk, sizeof(walk), "%s", parent.c_str()) >= (int)sizeof(walk)) {
		close(prev_dir_fd);
		return false;
	}
	char* curr = walk;
	for (;;) {
		while (*curr == '/') {
			curr++;
		}
		if (*curr == '\0') {
			break;
		}
		char* next = strchr(curr, '/');
		if (next != nullptr) {
			*next = '\0';
		}
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
		if (next == nullptr) {
			break;
		}
		curr = next + 1;
	}
	close(prev_dir_fd);
	*basename_out = basename;
	return true;
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
	const char* escape = "/tmp/nsj_path_test/root/../../nsj_path_escaped/evil_dir/leaf";
	{
		std::string basename;
		if (openParentNoFollowSafe(escape, &basename)) {
			fprintf(stderr, "FAIL openParentNoFollow accepted traversal path\n");
			return 1;
		}
	}
	if (access("/tmp/nsj_path_escaped", F_OK) == 0) {
		fprintf(stderr, "FAIL escape directory was created\n");
		return 1;
	}

	{
		std::string basename;
		const char* ok = "/tmp/nsj_path_test/root/home/user/docs/leaf";
		if (!openParentNoFollowSafe(ok, &basename)) {
			fprintf(stderr, "FAIL openParentNoFollow rejected safe path\n");
			return 1;
		}
		if (basename != "leaf") {
			fprintf(stderr, "FAIL unexpected basename '%s'\n", basename.c_str());
			return 1;
		}
		if (access("/tmp/nsj_path_test/root/home/user/docs", F_OK) != 0) {
			fprintf(stderr, "FAIL safe parents were not created\n");
			return 1;
		}
	}

	/* Symlink intermediate must fail closed under O_NOFOLLOW walk policy. */
	(void)system("rm -rf /tmp/nsj_sym_stage /tmp/nsj_sym_escape");
	mkdir("/tmp/nsj_sym_stage", 0755);
	mkdir("/tmp/nsj_sym_escape", 0755);
	if (symlink("/tmp/nsj_sym_escape", "/tmp/nsj_sym_stage/link") != 0) {
		fprintf(stderr, "FAIL symlink setup\n");
		return 1;
	}
	{
		std::string basename;
		if (openParentNoFollowSafe("/tmp/nsj_sym_stage/link/leaf", &basename)) {
			fprintf(stderr,
			    "FAIL openParentNoFollow walked through intermediate symlink\n");
			return 1;
		}
	}
	/* Mimic new-API component walk with O_NOFOLLOW */
	{
		int root = open("/tmp/nsj_sym_stage", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
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
		if (access("/tmp/nsj_sym_escape/pwned", F_OK) == 0) {
			fprintf(stderr, "FAIL escape created\n");
			return 1;
		}
	}

	/* The final component is returned unresolved: a symlink there is the
	 * caller's (mount path's) responsibility, and must not be followed while
	 * resolving parents. */
	{
		std::string basename;
		if (!openParentNoFollowSafe("/tmp/nsj_sym_stage/link", &basename)) {
			fprintf(
			    stderr, "FAIL openParentNoFollow rejected final-component symlink\n");
			return 1;
		}
		if (basename != "link") {
			fprintf(stderr, "FAIL unexpected final basename '%s'\n", basename.c_str());
			return 1;
		}
		if (access("/tmp/nsj_sym_escape/pwned", F_OK) == 0) {
			fprintf(stderr, "FAIL escape created through final symlink\n");
			return 1;
		}
	}

	printf("OK path_containment_test passed\n");
	return 0;
}
