/*
 * Tests that a bind-mount source is anchored to the inode nsjail inspected,
 * so a rename/symlink swap between validation and mount cannot substitute a
 * different host directory.
 *
 * Sequence A (path re-resolved, behaviour before the fix):
 *     stat(path) -> swap path -> open_tree(AT_FDCWD, path)  => attacker wins
 * Sequence B (descriptor anchored, behaviour after the fix):
 *     fd = open(path, O_PATH) -> swap path ->
 *     open_tree(fd, "", AT_EMPTY_PATH)                     => validated inode
 *
 * Needs root (mount(2) in a private mount namespace); skips when not root.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC 02000000
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

struct fixture {
	char base[256];
	char root[512];
	char evil[512];
	char mnt[512];
	char file[512];
};

static int make_dir(const char* path) {
	return mkdir(path, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static int make_file(const char* path, char c) {
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) return -1;
	int ok = write(fd, &c, 1) == 1;
	close(fd);
	return ok ? 0 : -1;
}

/* root/root.txt = 'R', evil/root.txt = 'E', root/evil_admits_swap = absent */
static int prepare(struct fixture* f, const char* base) {
	snprintf(f->base, sizeof(f->base), "%s", base);
	snprintf(f->root, sizeof(f->root), "%s/root", base);
	snprintf(f->evil, sizeof(f->evil), "%s/evil", base);
	snprintf(f->mnt, sizeof(f->mnt), "%s/mnt", base);
	snprintf(f->file, sizeof(f->file), "%s/root.txt", f->mnt);
	if (make_dir(f->root) || make_dir(f->evil) || make_dir(f->mnt)) return -1;
	char p[600];
	snprintf(p, sizeof(p), "%s/root.txt", f->root);
	if (make_file(p, 'R')) return -1;
	snprintf(p, sizeof(p), "%s/root.txt", f->evil);
	return make_file(p, 'E');
}

static char mounted_first_byte(const char* file) {
	char c = '?';
	int fd = open(file, O_RDONLY);
	if (fd < 0) return '?';
	if (read(fd, &c, 1) != 1) c = '?';
	close(fd);
	return c;
}

/* Attacker replaces the configured source path with their own directory. */
static int swap(struct fixture* f, const char* savename) {
	char saved[600];
	snprintf(saved, sizeof(saved), "%s/%s", f->base, savename);
	if (rename(f->root, saved) != 0) return -1;
	if (rename(f->evil, f->root) != 0) return -1;
	return 0;
}

static int attach(int tree_fd, const char* dst) {
	int rc = syscall(__NR_move_mount, tree_fd, "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH);
	close(tree_fd);
	return rc;
}

int main(void) {
	if (geteuid() != 0) {
		printf("SKIP: needs root for mount(2)\n");
		return 0;
	}
	if (unshare(CLONE_NEWNS) != 0) {
		printf("SKIP: cannot create a mount namespace: %s\n", strerror(errno));
		return 0;
	}
	mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

	char base_a[] = "/tmp/nsjail-srcanchor-A.XXXXXX";
	char base_b[] = "/tmp/nsjail-srcanchor-B.XXXXXX";
	if (!mkdtemp(base_a) || !mkdtemp(base_b)) {
		perror("mkdtemp");
		return 1;
	}

	/* A: path is resolved again after the swap -> attacker's tree wins. */
	struct fixture a;
	if (prepare(&a, base_a) != 0) { perror("prepare A"); return 1; }
	struct stat st;
	if (stat(a.root, &st) != 0) { perror("stat"); return 1; }
	if (swap(&a, "root.saved") != 0) { perror("swap A"); return 1; }
	int tree = syscall(__NR_open_tree, AT_FDCWD, a.root, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	if (tree < 0) { perror("open_tree(path)"); return 1; }
	if (attach(tree, a.mnt) != 0) { perror("move_mount A"); return 1; }
	char path_result = mounted_first_byte(a.file);
	umount2(a.mnt, MNT_DETACH);

	/* B: the descriptor opened before the swap pins the validated inode. */
	struct fixture b;
	if (prepare(&b, base_b) != 0) { perror("prepare B"); return 1; }
	int src_fd = open(b.root, O_PATH | O_CLOEXEC);
	if (src_fd < 0) { perror("open(O_PATH)"); return 1; }
	if (fstat(src_fd, &st) != 0) { perror("fstat"); return 1; }
	if (swap(&b, "root.saved") != 0) { perror("swap B"); return 1; }
	tree = syscall(__NR_open_tree, src_fd, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
	if (tree < 0) { perror("open_tree(fd)"); return 1; }
	close(src_fd);
	if (attach(tree, b.mnt) != 0) { perror("move_mount B"); return 1; }
	char fd_result = mounted_first_byte(b.file);
	umount2(b.mnt, MNT_DETACH);

	printf("path re-resolved after swap : mounted '%c'  (attacker's directory)\n",
	    path_result);
	printf("descriptor anchored, swap   : mounted '%c'  (validated directory)\n",
	    fd_result);
	int ok = (path_result == 'E' && fd_result == 'R');
	printf("%s\n", ok ? "PASS: anchoring prevents mount-source substitution"
			  : "FAIL: unexpected mount contents");
	return ok ? 0 : 1;
}
