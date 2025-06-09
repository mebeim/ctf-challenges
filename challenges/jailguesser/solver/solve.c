/**
 * @mebeim - 2024-09-22
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <linux/aio_abi.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID)
#define N_ALTERNATIVE_SYSCALLS 10
#define UNKNOWN_ACTION -1U
#define ALLOWED(name) ((get_sys_action(__NR_##name) & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_ALLOW)

#define ERR(x, ...)                                    \
	do {                                               \
		ez_printf("solve: " __VA_ARGS__);              \
		ez_printf(": %s\n", strerror(errno)); exit(x); \
	} while (0)

#define ERRX(x, ...)                      \
	do {                                  \
		ez_printf("solve: " __VA_ARGS__); \
		ez_printf("\n");                  \
		exit(x);                          \
	} while (0)

#define SYSCHK(x) ({                   \
	typeof(x) __res = (x);             \
	if (__res == (typeof(x))-1)        \
		ERR(1, "syscall failed: " #x); \
	__res;                             \
})

extern char **environ;

static const char base_config[] =
	"name: \"jailguesser\"\n"
	"mode: ONCE\n"
	"daemon: false\n"
	"keep_env: false\n"
	"cwd: \"/jail\"\n"
	"keep_caps: false\n"
	"disable_no_new_privs: false\n"
	"forward_signals: true\n"
	"max_cpus: 1\n"
	"time_limit: 0\n";

static const char base_seccomp[] =
	"seccomp_string: \"#define rseq 334\"\n"
	"seccomp_string: \"#define close_range 436\"\n"
	"seccomp_string: \"#define CLONE_THREAD 0x10000\"\n"
	"seccomp_string: \"DEFAULT ERRNO(38)\"\n"
	"seccomp_string: \"ALLOW { open, openat, close, close_range, access, fcntl, ioctl, dup, dup2, pipe, newstat, newfstat, newfstatat, readlink, readlinkat, chdir, fchdir, getcwd, waitid, wait4, brk, mmap, mprotect, munmap, mremap, set_tid_address, set_robust_list, rt_sigaction, rt_sigreturn, rt_sigprocmask, rt_sigtimedwait, futex, getrandom, arch_prctl, rseq, newuname, execve, exit, exit_group, clone { (clone_flags & CLONE_THREAD) == CLONE_THREAD }";

static const char base_mounts[] =
	"mount_proc: false\n"
	"mount { src: \"/lib\" dst: \"/lib\" is_bind: true nosuid: true rw: false mandatory: true }\n"
	"mount { src: \"/lib64\" dst: \"/lib64\" is_bind: true nosuid: true rw: false mandatory: true }\n"
	"mount { dst: \"/jail\" fstype: \"tmpfs\" rw: true is_bind: false noexec: false nodev: true nosuid: true options: \"size=8388608\" }\n";

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
};

struct linux_dirent64 {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_type;
	char d_name[];
};

struct syscall_state {
	const char *name;
	unsigned nr;
	unsigned action;
};

#define S(sc) { #sc, __NR_##sc, UNKNOWN_ACTION }
static struct syscall_state syscalls[] = {
	// R/W alternatives:
	S(read), S(readv), S(vmsplice),
	S(write), S(writev),
	S(io_setup), S(io_destroy), S(io_submit), S(io_getevents), S(io_cancel),

/* The original version of the challenge also needed this, but it was removed to
 * shorten solve time.
 *
	// Misc alternatives:
	S(getdents), S(getdents64),
	S(statfs), S(fstatfs),
	S(getuid), S(geteuid), S(getresuid),
	S(getgid), S(getegid), S(getresgid),
 */
	// --- N_ALTERNATIVE_SYSCALLS ---
	// Optional:
	S(flock),
	S(getcpu),
	S(gettid),
	S(gettimeofday),
	S(kill),
	S(mkdir),
	S(mlock),
	S(nanosleep),
	S(rmdir),
	S(sched_yield),
	S(tgkill),
	S(truncate),
	S(unlink),
	S(unlinkat),
	{ NULL, -1U, UNKNOWN_ACTION },
};
#undef S

static struct syscall_state *opt_syscalls = syscalls + N_ALTERNATIVE_SYSCALLS;

static int ez_printf(const char *format, ...);
static void set_sys_action(unsigned nr, unsigned action);
static unsigned get_sys_action(unsigned nr);

/**
 * Handle SIGSYS happening because of a syscall trapped by the seccomp filter
 * and save the trap errno.
 */
static void sigsys_action(int signo, siginfo_t *info, void *ucontext) {
	set_sys_action(info->si_syscall, SECCOMP_RET_TRAP | info->si_errno);
}

/**
 * Polyfill for read(2)/write(2) using aio: io_setup, io_submit, io_getevents,
 * io_destroy.
 */
static ssize_t aio_rw_polyfill(int fd, void *buf, size_t count, unsigned short op) {
	aio_context_t ctx = 0;
	struct io_event ev;
	struct iocb cb = {
		.aio_fildes = fd,
		.aio_lio_opcode = op,
		.aio_buf = (unsigned long long)buf,
		.aio_nbytes = count,
	};
	struct iocb *cbs[] = { &cb };

	SYSCHK(syscall(SYS_io_setup, 1, &ctx));
	SYSCHK(syscall(SYS_io_submit, ctx, 1, cbs));
	SYSCHK(syscall(SYS_io_getevents, ctx, 1, 1, &ev, NULL));
	SYSCHK(syscall(SYS_io_destroy, ctx));

	return ev.res;
}

/**
 * read(2) polyfill using any of read, readv, vmsplice, io_xxx (aio).
 * Maintains error return value and errno.
 */
static ssize_t ez_read(int fd, char *buf, size_t count) {
	if (ALLOWED(read))
		return read(fd, buf, count);

	if (ALLOWED(readv)) {
		struct iovec iov = { .iov_base = buf, .iov_len = count };
		return readv(fd, &iov, 1);
	}

	if (ALLOWED(vmsplice)) {
		struct iovec iov = { .iov_base = buf, .iov_len = count };
		return vmsplice(fd, &iov, 1, 0);
	}

	if (ALLOWED(io_setup))
		return aio_rw_polyfill(fd, buf, count, IOCB_CMD_PREAD);

	ERRX(1, "No available read-like syscall!");
}

/**
 * write(2) polyfill using any of write, writev, vmsplice, io_xxx (aio).
 * Maintains error return value and errno.
 */
static ssize_t ez_write(int fd, const char *buf, size_t count) {
	if (ALLOWED(write))
		return write(fd, buf, count);

	if (ALLOWED(writev)) {
		struct iovec iov = { .iov_base = (char *)buf, .iov_len = count };
		return writev(fd, &iov, 1);
	}

	if (ALLOWED(io_setup))
		return aio_rw_polyfill(fd, (char *)buf, count, IOCB_CMD_PWRITE);

	// Pointless to try and write an error message
	exit(1);
}

/**
 * Call ez_read() in loop until either all count bytes are read or EOF. Return
 * the number of bytes read.
 */
static ssize_t ez_readall(int fd, char *buf, size_t count) {
	ssize_t nread = 0;
	ssize_t n;

	do {
		n = SYSCHK(ez_read(fd, buf + nread, count - nread));
		nread += n;
	} while (n != 0);

	return nread;
}

/**
 * Call ez_write() in loop until all count bytes are written.
 */
static void ez_writeall(int fd, const char *buf, size_t count) {
	for (size_t nwritten = 0; nwritten < count; )
		nwritten += SYSCHK(ez_write(STDOUT_FILENO, buf + nwritten, count - nwritten));
}

/**
 * printf() equivalent using ez_write() for dynamic syscall selection.
 * Assumes that the total number of bytes to write is less than 0x1000.
 */
__attribute__ ((format (printf, 1, 2)))
static int ez_printf(const char *format, ...) {
	static char buf[0x1000 + 1];
	va_list args;
	int len;

	va_start(args, format);
	len = vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	if (len < 0)
		ERR(1, "vsnprintf");

	ez_writeall(STDOUT_FILENO, buf, len);
	return len;
}

/**
 * Mark detected seccomp action for the given syscall.
 */
static void set_sys_action(unsigned nr, unsigned action) {
	for (size_t i = 0; syscalls[i].name; i++) {
		if (syscalls[i].nr == nr) {
			syscalls[i].action = action;
			return;
		}
	}

	ERRX(1, "set_sys_action(): invalid nr");
}

/**
 * Retrieve previously detected seccomp action for the given syscall.
 */
static unsigned get_sys_action(unsigned nr) {
	for (size_t i = 0; syscalls[i].name; i++) {
		if (syscalls[i].nr == nr)
			return syscalls[i].action;
	}

	ERRX(1, "get_sys_action(): invalid nr");
}

/**
 * Thread function used to detect the seccomp filter action for a given syscall.
 * This is needed because the action can kill the thread.
 */
static int test_one_syscall(void *arg) {
	struct syscall_state *ss = arg;

	long res = syscall(ss->nr, 0, 0, 0, 0, 0, 0);
	if (ss->action == UNKNOWN_ACTION) {
		if (res < 0 && errno > 150)
			ss->action = SECCOMP_RET_ERRNO | errno;
		else
			ss->action = SECCOMP_RET_ALLOW;
	}

	// We could also get trapped -> SIGSYS handler will handle it
	// We could also get killed -> main thread will handle it
	return 0;
}

/**
 * Detect how syscalls are filtred by the seccomp filter we have installed.
 */
static void detect_syscalls(void) {
	struct sigaction sa = {
		.sa_sigaction = &sigsys_action,
		.sa_flags = SA_SIGINFO,
	};

	SYSCHK(sigaction(SIGSYS, &sa, NULL));

	const size_t thread_stack_size = 0x10000;
	char *thread_stack = SYSCHK(mmap(NULL, thread_stack_size,
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0));
	thread_stack += thread_stack_size;

	// The first few belong to the "alternatives" set and can be detected easily
	// checking for errno == ENOSYS
	for (size_t i = 0; i < N_ALTERNATIVE_SYSCALLS; i++) {
		struct syscall_state *ss = syscalls + i;

		errno = 0;
		syscall(ss->nr, -1L, 0, 0, 0, 0, 0);
		if (errno != ENOSYS)
			ss->action = SECCOMP_RET_ALLOW;
	}

	// The rest belong to the "optional" set and can errno/trap/kill
	for (size_t i = 0; opt_syscalls[i].name; i++) {
		struct syscall_state *ss = opt_syscalls + i;
		pid_t tid_futex;

		// Spawn a thread because the syscall could get us killed
		int tid = SYSCHK(clone(&test_one_syscall, thread_stack, CLONE_FLAGS, ss,
			&tid_futex, NULL, &tid_futex));

		// Wait thread
		while (syscall(SYS_futex, &tid_futex, FUTEX_WAIT, tid, 0, 0, 0) == -1) {
			if (errno == EAGAIN)
				break;
			if (errno != EINTR)
				ERR(1, "futex");
		}

		// Was it killed by the syscall?
		if (ss->action == UNKNOWN_ACTION)
			ss->action = SECCOMP_RET_KILL;

		if (ss->action == UNKNOWN_ACTION)
			ERRX(1, "Could not determine seccomp action for %s", ss->name);
	}

	munmap(thread_stack - thread_stack_size, thread_stack_size);
}

static void echo_input(void) {
	static char buf[65537];
	ez_writeall(STDIN_FILENO, buf, ez_readall(STDIN_FILENO, buf, sizeof(buf)));
}

static void dump_hostname(void) {
	struct utsname u;
	SYSCHK(uname(&u));
	ez_printf("hostname: \"%s\"\n", u.nodename);
}

/* The original version of the challenge also needed this, but it was removed to
 * shorten solve time.
 *
static void dump_env(void) {
	for (char **env = environ; *env != 0; env++)
		ez_printf("envar: \"%s\"\n", *env);
}
 */

/* The original version of the challenge also needed this, but it was removed to
 * shorten solve time.
 *
static bool sigxfsz_received = false;

static void sigxfsz_handler(int signo) {
	sigxfsz_received = true;
}

static void dump_rlimits(void) {
	const size_t dummy_buf_size = 1 << 20;
	char *dummy_buf = malloc(dummy_buf_size);
	size_t rlimit_fsize = 0;
	size_t rlimit_nofile = 0;

	// Need to use O_APPEND in case we are using AIO or we won't append with
	// consecutive io_submit(2) PWRITE requests!
	int fd = SYSCHK(open("x", O_WRONLY|O_CREAT|O_APPEND, 0600));

	// Turns out we'll get killed by the kernel without warning if we exceed
	// RLIMIT_FSIZE
	SYSCHK(signal(SIGXFSZ, sigxfsz_handler));

	while (1) {
		ssize_t n = ez_write(fd, dummy_buf, dummy_buf_size);
		if ((n < 0 && errno == EFBIG) || sigxfsz_received)
			break;
		if (n < 0)
			ERR(1, "ez_write");

		rlimit_fsize += n;
	}

	free(dummy_buf);

	// RLIMIT_NOFILE is easy
	while (1) {
		if ((fd = dup(STDIN_FILENO)) < 0 && errno == EMFILE)
			break;

		rlimit_nofile = fd + 1;
	}

	SYSCHK(close_range(3, -1U, 0));

	ez_printf("rlimit_fsize: %zu\n", rlimit_fsize >> 20);
	ez_printf("rlimit_nofile: %zu\n", rlimit_nofile);
}
 */

static void dump_personality(void) {
	char *a = SYSCHK(mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));
	char *b = SYSCHK(mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));
	char *m = malloc(0x10);

	if (a < b) {
		ez_printf("persona_addr_compat_layout: true\n");
		if (m <= a)
			ez_printf("persona_addr_no_randomize: true\n");
	} else if (m > a) {
		ez_printf("persona_addr_no_randomize: true\n");
	}

	free(m);
	munmap(b, 0x1000);
	munmap(a, 0x1000);
}

static void dump_idmaps(void) {
	uid_t euid = getauxval(AT_EUID);
	gid_t egid = getauxval(AT_EGID);
	ez_printf("uidmap: { inside_id: \"%u\" outside_id: \"65534\" }\n", euid);
	ez_printf("gidmap: { inside_id: \"%u\" outside_id: \"65534\" }\n", egid);
}

/* The original version of the challenge also needed this, but it was removed to
 * shorten solve time.
 *
static int cmp(const void *a, const void *b) {
	return strcmp(*(const char **)a, *(const char **)b);
}
 */

static void dump_mounts(void) {
/* The original version of the challenge also needed this, but it was removed to
 * shorten solve time.
 *
	// 16 is the most we can get
	char *tmp_mounts[16];
	char buf[0x1000];
	size_t count = 0;
	long n;
 */

	ez_writeall(STDOUT_FILENO, base_mounts, sizeof(base_mounts) - 1);

/* The original version of the challenge also needed this, but it was removed to
 * shorten solve time.
 *
	int dirfd = open("/tmp", O_RDONLY|O_DIRECTORY);
	if (dirfd == -1) {
		if (errno == ENOENT)
			return;

		ERR(1, "open(\"/tmp\", O_RDONLY|O_DIRECTORY)");
	}

	// Find all dents under /tmp (non-recursive)
#define DOIT(x)                                                          \
	do {                                                                 \
		struct linux_dirent##x *d##x;                                    \
		n = SYSCHK(syscall(SYS_getdents##x, dirfd, buf, sizeof(buf)));   \
		if (n == 0)                                                      \
			break;                                                       \
		for (long pos = 0; pos < n; pos += d##x->d_reclen) {             \
			d##x = (struct linux_dirent##x *)(buf + pos);                \
			if (strcmp(d##x->d_name, ".") && strcmp(d##x->d_name, "..")) \
				tmp_mounts[count++] = strdup(d##x->d_name);              \
		}                                                                \
	} while (0)

	do {
		if (ALLOWED(getdents64))
			DOIT(64);
		else
			DOIT();
	} while (n != 0);

#undef DOIT

	qsort(tmp_mounts, count, sizeof(*tmp_mounts), cmp);
	SYSCHK(chdir("/tmp"));

	for (size_t i = 0; i < count; i++) {
		char *path = tmp_mounts[i];
		struct statfs fs;

		if (ALLOWED(statfs)) {
			SYSCHK(statfs(path, &fs));
		} else {
			int fsfd = SYSCHK(open(path, O_RDONLY|O_DIRECTORY));
			SYSCHK(fstatfs(fsfd, &fs));
			SYSCHK(close(fsfd));
		}

		// fs.f_bfree * fs.f_bsize works as long as the size specified in the
		// nsjail config is a multiple of fs.f_bsize
		ez_printf("mount { dst: \"/tmp/%s\" fstype: \"tmpfs\" rw: %s "
			"is_bind: false noexec: true nodev: true nosuid: true "
			"options: \"size=%zu\" }\n", path,
			access(path, W_OK) == 0 ? "true" : "false",
			fs.f_bfree * fs.f_bsize);

		free(path);
	}

	close(dirfd);
 */
}

static void dump_seccomp(void) {
	const char *errno_fmt = "seccomp_string: \"ERRNO(%u) { %s }";
	const char *trap_fmt = "seccomp_string: \"TRAP(%u) { %s }";
	const char *kill_fmt = "seccomp_string: \"KILL { %s";
	const char *fmt;

	ez_writeall(STDOUT_FILENO, base_seccomp, sizeof(base_seccomp) - 1);

	// Rest of initial ALLOW { ... }
	for (size_t i = 0; syscalls[i].name; i++) {
		const struct syscall_state *ss = syscalls + i;
		if ((ss->action & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_ALLOW)
			continue;

		ez_printf(", %s", ss->name);
	}

	ez_printf(" }\"\n");

	// ERRNO(x) { y }...
	fmt = errno_fmt;
	for (size_t i = 0; opt_syscalls[i].name; i++) {
		const struct syscall_state *ss = opt_syscalls + i;
		if ((ss->action & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_ERRNO)
			continue;

		ez_printf(fmt, ss->action & SECCOMP_RET_DATA, ss->name);
		fmt = " ERRNO(%u) { %s }";
	}

	if (fmt != errno_fmt)
		ez_printf("\"\n");

	// TRAP(x) { y }...
	fmt = trap_fmt;
	for (size_t i = 0; opt_syscalls[i].name; i++) {
		const struct syscall_state *ss = opt_syscalls + i;
		if ((ss->action & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_TRAP)
			continue;

		ez_printf(fmt, ss->action & SECCOMP_RET_DATA, ss->name);
		fmt = " TRAP(%u) { %s }";
	}

	if (fmt != trap_fmt)
		ez_printf("\"\n");

	// KILL { ... }
	fmt = kill_fmt;
	for (size_t i = 0; opt_syscalls[i].name; i++) {
		const struct syscall_state *ss = opt_syscalls + i;
		if ((ss->action & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_KILL)
			continue;

		ez_printf(fmt, ss->name);
		fmt = ", %s";
	}

	if (fmt != kill_fmt)
		ez_printf(" }\"\n");
}

int main(void) {
	detect_syscalls();

	echo_input();
	ez_writeall(STDOUT_FILENO, base_config, sizeof(base_config) - 1);
	dump_hostname();
	// dump_env();
	dump_idmaps();
	// dump_rlimits();
	dump_personality();
	dump_mounts();
	dump_seccomp();

	return 0;
}
