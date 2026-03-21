#include "lightbox.h"

#define SYS_fchdir 81
#define SYS_chroot 161
#if defined(__x86_64__)
#define SYS_fsync 74
#define SYS_renameat 264
#elif defined(__aarch64__)
#define SYS_fsync 82
#define SYS_renameat 38
#else
#error "Unsupported architecture"
#endif

void print_str(int32_t fd, const char *s) {
    lc_print_string(fd, s, lc_string_length(s));
}

void die(const char *msg) {
    print_str(STDERR, msg);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

void die2(const char *prefix, const char *detail) {
    print_str(STDERR, prefix);
    print_str(STDERR, detail);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

bool streq(const char *a, const char *b) {
    size_t la = lc_string_length(a);
    size_t lb = lc_string_length(b);
    if (la != lb) return false;
    return lc_string_equal(a, la, b, lb);
}

size_t str_copy(char *dst, const char *src, size_t max) {
    size_t len = lc_string_length(src);
    if (len >= max) len = max - 1;
    lc_bytes_copy(dst, src, len);
    dst[len] = '\0';
    return len;
}

size_t str_append(char *dst, size_t pos, const char *src, size_t max) {
    size_t len = lc_string_length(src);
    if (pos + len >= max) len = max - pos - 1;
    lc_bytes_copy(dst + pos, src, len);
    dst[pos + len] = '\0';
    return pos + len;
}

void path_join(char *buf, size_t bufsz, const char *a, const char *b) {
    size_t pos = str_copy(buf, a, bufsz);
    if (pos > 0 && buf[pos - 1] != '/')
        pos = str_append(buf, pos, "/", bufsz);
    if (b[0] == '/') b++;
    str_append(buf, pos, b, bufsz);
}

int parse_int(const char *s) {
    int neg = 0, val = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return neg ? -val : val;
}

int fmt_int(char *buf, int val) {
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; return 1; }
    int neg = 0, len = 0;
    char tmp[16];
    if (val < 0) { neg = 1; val = -val; }
    while (val > 0) { tmp[len++] = '0' + (val % 10); val /= 10; }
    int pos = 0;
    if (neg) buf[pos++] = '-';
    for (int i = len - 1; i >= 0; i--) buf[pos++] = tmp[i];
    buf[pos] = '\0';
    return pos;
}

int write_file(const char *path, const char *data) {
    lc_sysret fd = lc_kernel_open_file(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t len = lc_string_length(data);
    size_t off = 0;
    while (off < len) {
        lc_sysret n = lc_kernel_write_bytes((int32_t)fd, data + off, len - off);
        if (n <= 0) {
            lc_kernel_close_file((int32_t)fd);
            return -1;
        }
        off += (size_t)n;
    }
    lc_kernel_close_file((int32_t)fd);
    return 0;
}

void require_write_file(const char *path, const char *data) {
    if (write_file(path, data) < 0)
        die2("Error: write failed: ", path);
}

static lc_sysret lc_kernel_fsync(int32_t fd) {
    return lc_syscall1(SYS_fsync, fd);
}

static lc_sysret lc_kernel_renameat(int32_t olddirfd, const char *oldpath,
                                    int32_t newdirfd, const char *newpath) {
    return lc_syscall4(SYS_renameat, olddirfd, (int64_t)oldpath, newdirfd, (int64_t)newpath);
}

static int sync_parent_dir(const char *path) {
    char dirpath[MAX_PATH];
    size_t len = lc_string_length(path);

    if (len == 0 || len >= sizeof(dirpath))
        return -1;

    str_copy(dirpath, path, sizeof(dirpath));
    while (len > 0 && dirpath[len - 1] != '/')
        len--;

    if (len == 0)
        str_copy(dirpath, ".", sizeof(dirpath));
    else if (len == 1)
        dirpath[1] = '\0';
    else
        dirpath[len - 1] = '\0';

    lc_sysret dirfd = lc_kernel_open_file(dirpath, O_RDONLY, 0);
    if (dirfd < 0)
        return -1;

    lc_sysret rc = lc_kernel_fsync((int32_t)dirfd);
    lc_kernel_close_file((int32_t)dirfd);
    return (rc < 0) ? -1 : 0;
}

static const char *pick_tool_path(const char *const *candidates, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (path_exists(candidates[i]))
            return candidates[i];
    }
    return candidates[0];
}

const char *tool_path_ip(void) {
    static const char *const candidates[] = {
        "/sbin/ip",
        "/usr/sbin/ip",
        "/bin/ip",
        "/usr/bin/ip",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_iptables(void) {
    static const char *const candidates[] = {
        "/usr/sbin/iptables",
        "/sbin/iptables",
        "/usr/bin/iptables",
        "/bin/iptables",
        "/usr/sbin/iptables-nft",
        "/sbin/iptables-nft",
        "/usr/bin/iptables-nft",
        "/bin/iptables-nft",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_mount(void) {
    static const char *const candidates[] = {
        "/bin/mount",
        "/usr/bin/mount",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_umount(void) {
    static const char *const candidates[] = {
        "/bin/umount",
        "/usr/bin/umount",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_mkdir(void) {
    static const char *const candidates[] = {
        "/bin/mkdir",
        "/usr/bin/mkdir",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_cp(void) {
    static const char *const candidates[] = {
        "/bin/cp",
        "/usr/bin/cp",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_chown(void) {
    static const char *const candidates[] = {
        "/bin/chown",
        "/usr/bin/chown",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_rm(void) {
    static const char *const candidates[] = {
        "/bin/rm",
        "/usr/bin/rm",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_nsenter(void) {
    static const char *const candidates[] = {
        "/usr/bin/nsenter",
        "/bin/nsenter",
        "/usr/sbin/nsenter",
        "/sbin/nsenter",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

bool tool_available(const char *path) {
    return path && path[0] && path_exists(path);
}

void require_tool(const char *label, const char *path) {
    if (tool_available(path))
        return;
    print_str(STDERR, "Error: required host tool is missing: ");
    print_str(STDERR, label);
    print_str(STDERR, " (expected at ");
    print_str(STDERR, path ? path : "-");
    print_str(STDERR, ")\n");
    lc_kernel_exit(1);
}


int write_file_atomic(const char *path, const char *data) {
    char tmp[MAX_PATH];
    char pidbuf[16];
    int pid = lc_kernel_get_process_id();

    fmt_int(pidbuf, pid);
    size_t pos = str_copy(tmp, path, sizeof(tmp));
    pos = str_append(tmp, pos, ".tmp.", sizeof(tmp));
    str_append(tmp, pos, pidbuf, sizeof(tmp));

    lc_sysret fd = lc_kernel_open_file(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    size_t len = lc_string_length(data);
    size_t off = 0;
    while (off < len) {
        lc_sysret n = lc_kernel_write_bytes((int32_t)fd, data + off, len - off);
        if (n <= 0) {
            lc_kernel_close_file((int32_t)fd);
            lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
            return -1;
        }
        off += (size_t)n;
    }

    if (lc_kernel_fsync((int32_t)fd) < 0) {
        lc_kernel_close_file((int32_t)fd);
        lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
        return -1;
    }
    lc_kernel_close_file((int32_t)fd);

    if (lc_kernel_renameat(AT_FDCWD, tmp, AT_FDCWD, path) < 0) {
        lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
        return -1;
    }

    if (sync_parent_dir(path) < 0)
        return -1;
    return 0;
}

void require_write_file_atomic(const char *path, const char *data) {
    if (write_file_atomic(path, data) < 0)
        die2("Error: atomic write failed: ", path);
}

int read_file(const char *path, char *buf, size_t bufsz) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY, 0);
    if (fd < 0) return -1;
    lc_sysret n = lc_kernel_read_bytes((int32_t)fd, buf, bufsz - 1);
    lc_kernel_close_file((int32_t)fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

bool path_exists(const char *path) {
    return lc_kernel_faccessat2(AT_FDCWD, path, F_OK, 0) == 0;
}

lc_sysret lc_kernel_fchdir(int32_t fd) {
    return lc_syscall1(SYS_fchdir, fd);
}

lc_sysret lc_kernel_change_root(const char *path) {
    return lc_syscall1(SYS_chroot, (int64_t)path);
}

void require_rm_rf(const char *path) {
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        char *argv[] = { "rm", "-rf", (char *)path, NULL };
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute(tool_path_rm(), argv, envp);
        lc_kernel_exit(1);
    }
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    if (((status >> 8) & 0xff) != 0)
        die2("Error: rm -rf failed: ", path);
}

int run_cmd(const char *prog, char *const argv[]) {
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute(prog, argv, envp);
        lc_kernel_exit(127);
    }
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    return (status >> 8) & 0xff;
}

int run_cmd_quiet(const char *prog, char *const argv[]) {
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        lc_sysret devnull = lc_kernel_open_file("/dev/null", O_WRONLY, 0);
        if (devnull >= 0) lc_kernel_duplicate_fd((int32_t)devnull, STDERR, 0);
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute(prog, argv, envp);
        lc_kernel_exit(127);
    }
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    return (status >> 8) & 0xff;
}

int do_mount(const char *source, const char *target,
             const char *fstype, uint64_t flags, const char *data) {
    char *argv[16];
    int ai = 0;
    argv[ai++] = "mount";
    if ((flags & MS_PRIVATE) && (flags & MS_REC)) {
        argv[ai++] = "--make-rprivate";
        argv[ai++] = (char *)target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    if ((flags & MS_REMOUNT) && (flags & MS_BIND)) {
        char remount_opts[64];
        int rolen = 0;
        argv[ai++] = "-o";
        rolen = (int)str_copy(remount_opts, "remount,bind", sizeof(remount_opts));
        if (flags & MS_RDONLY) { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "ro", sizeof(remount_opts) - (size_t)rolen); }
        if (flags & MS_NOSUID) { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "nosuid", sizeof(remount_opts) - (size_t)rolen); }
        if (flags & MS_NODEV)  { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "nodev", sizeof(remount_opts) - (size_t)rolen); }
        if (flags & MS_NOEXEC) { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "noexec", sizeof(remount_opts) - (size_t)rolen); }
        argv[ai++] = remount_opts;
        argv[ai++] = (char *)target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    if ((flags & MS_BIND) && (flags & MS_REC)) {
        argv[ai++] = "--rbind";
        argv[ai++] = (char *)source;
        argv[ai++] = (char *)target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    if (flags & MS_BIND) {
        argv[ai++] = "--bind";
        argv[ai++] = (char *)source;
        argv[ai++] = (char *)target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    char opts[256];
    int olen = 0;
    if (flags & MS_RDONLY)  { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "ro", sizeof(opts) - (size_t)olen); }
    if (flags & MS_NOSUID)  { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "nosuid", sizeof(opts) - (size_t)olen); }
    if (flags & MS_NODEV)   { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "nodev", sizeof(opts) - (size_t)olen); }
    if (flags & MS_NOEXEC)  { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "noexec", sizeof(opts) - (size_t)olen); }
    if (data && data[0])    { if (olen) opts[olen++] = ','; str_copy(opts + olen, data, sizeof(opts) - (size_t)olen); olen += (int)lc_string_length(data); }
    opts[olen] = '\0';
    if (fstype && fstype[0]) { argv[ai++] = "-t"; argv[ai++] = (char *)fstype; }
    if (olen > 0)            { argv[ai++] = "-o"; argv[ai++] = opts; }
    if (source && source[0]) argv[ai++] = (char *)source;
    argv[ai++] = (char *)target;
    argv[ai] = NULL;
    return run_cmd(tool_path_mount(), argv);
}

void require_mount(const char *source, const char *target,
                   const char *fstype, uint64_t flags, const char *data) {
    if (do_mount(source, target, fstype, flags, data) != 0)
        die2("Error: mount failed: ", target);
}
