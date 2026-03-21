/*
 * lightbox — a minimal, secure Linux container runtime
 *
 * Built on lightc (freestanding C, no libc). Uses raw Linux syscalls for
 * namespace isolation, cgroups v2, pivot_root, seccomp, and capability dropping.
 *
 * Usage: lightbox <command> [args]
 *   setup                         — initialize host networking
 *   create <name> <ip> [options]  — create a container
 *   start  <name>                 — start a container
 *   stop   <name>                 — stop a container
 *   rm     <name>                 — remove a container
 *   exec   <name> [cmd...]        — run a command in a container
 *   ls                            — list containers
 */

#include <lightc/syscall.h>
#include <lightc/types.h>
#include <lightc/string.h>
#include <lightc/print.h>
#include <lightc/format.h>
#include <lightc/io.h>

/* ─── Compile-time limits ───────────────────────────────────────────────── */

#define MAX_PATH         512
#define MAX_VOLS         16
#define MAX_LINKS        8
#define NAME_MAX_LEN     12
#define CONF_BUF_SIZE    2048

/* ─── Configurable defaults ─────────────────────────────────────────────── */

#define LIGHTBOX_CONF_PATH  "/.config/lightbox/lightbox.conf"

/* All runtime-configurable values live here. Initialized to built-in defaults,
 * then overridden by lightbox.conf if present. */
static struct {
    char lightbox_dir[MAX_PATH];
    char rootfs[MAX_PATH];
    char container_dir[MAX_PATH];
    char run_dir[MAX_PATH];
    char cgroup_root[MAX_PATH];
    char cgroup_base[MAX_PATH];
    char bridge[32];
    char subnet[20];
    char gw[16];
    char default_mem[16];
    char default_pids[8];
    char default_cpu[4];
    int  default_oom;
} cfg_global;

/* cfg_global_init() and cfg_global_load() defined after utility functions */

/* prctl constants */
#define PR_SET_NO_NEW_PRIVS  38
#define PR_CAPBSET_READ      23
#define PR_CAPBSET_DROP      24
#define PR_SET_SECCOMP       22

/* seccomp constants */
#define SECCOMP_MODE_FILTER    2
#define SECCOMP_RET_ALLOW      0x7fff0000
#define SECCOMP_RET_ERRNO      0x00050000

/* BPF instruction macros */
#define BPF_LD   0x00
#define BPF_JMP  0x05
#define BPF_RET  0x06
#define BPF_W    0x00
#define BPF_ABS  0x20
#define BPF_JEQ  0x10
#define BPF_K    0x00

#define BPF_STMT(code, k) { (uint16_t)(code), 0, 0, (uint32_t)(k) }
#define BPF_JUMP(code, k, jt, jf) { (uint16_t)(code), (uint8_t)(jt), (uint8_t)(jf), (uint32_t)(k) }

/* capability numbers */
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_KILL             5
#define CAP_SETGID           6
#define CAP_SETUID           7
#define CAP_SETPCAP          8
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_RAW          13
#define CAP_SYS_CHROOT       18
#define CAP_MKNOD            27
#define CAP_AUDIT_WRITE      29
#define CAP_SETFCAP          31

/* device numbers: makedev(major, minor) */
#define MAKEDEV(ma, mi) (((uint64_t)(ma) << 8) | (mi))

/* clone flags (supplement those from syscall.h) */
#define CLONE_VM        0x00000100
#define CLONE_VFORK     0x00004000

/* ─── Structs ───────────────────────────────────────────────────────────── */

struct sock_filter {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct sock_fprog {
    uint16_t             len;
    struct sock_filter  *filter;
};

/* seccomp_data layout — offset of 'nr' is 0 */
#define SECCOMP_DATA_NR_OFFSET 0

typedef struct {
    char name[NAME_MAX_LEN + 1];
    char ip[16];
    char mem[16];
    char pids[8];
    char cpu[4];
    int  userns;
    int  uid_start;
    int  privileged;
    int  read_only;
    int  oom_score;
    int  nvols;
    char vol_src[MAX_VOLS][MAX_PATH];
    char vol_dst[MAX_VOLS][MAX_PATH];
    int  vol_ro[MAX_VOLS];
    int  nlinks;
    char links[MAX_LINKS][NAME_MAX_LEN + 1];
} container_config;

/* ─── Utility functions ─────────────────────────────────────────────────── */

/* Look up an environment variable by name. Returns value or NULL. */
static const char *env_get(char **envp, const char *name) {
    if (!envp) return NULL;
    size_t nlen = lc_string_length(name);
    for (int i = 0; envp[i]; i++) {
        if (lc_string_starts_with(envp[i], lc_string_length(envp[i]), name, nlen)
            && envp[i][nlen] == '=')
            return envp[i] + nlen + 1;
    }
    return NULL;
}

/* Print a null-terminated string (convenience wrapper) */
static void print_str(int32_t fd, const char *s) {
    lc_print_string(fd, s, lc_string_length(s));
}

static void die(const char *msg) {
    print_str(STDERR, msg);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

static void die2(const char *prefix, const char *detail) {
    print_str(STDERR, prefix);
    print_str(STDERR, detail);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

static bool streq(const char *a, const char *b) {
    size_t la = lc_string_length(a);
    size_t lb = lc_string_length(b);
    if (la != lb) return false;
    return lc_string_equal(a, la, b, lb);
}

static size_t str_copy(char *dst, const char *src, size_t max) {
    size_t len = lc_string_length(src);
    if (len >= max) len = max - 1;
    lc_bytes_copy(dst, src, len);
    dst[len] = '\0';
    return len;
}

static size_t str_append(char *dst, size_t pos, const char *src, size_t max) {
    size_t len = lc_string_length(src);
    if (pos + len >= max) len = max - pos - 1;
    lc_bytes_copy(dst + pos, src, len);
    dst[pos + len] = '\0';
    return pos + len;
}

static void path_join(char *buf, size_t bufsz, const char *a, const char *b) {
    size_t pos = str_copy(buf, a, bufsz);
    if (pos > 0 && buf[pos - 1] != '/') {
        pos = str_append(buf, pos, "/", bufsz);
    }
    /* skip leading slash on b */
    if (b[0] == '/') b++;
    str_append(buf, pos, b, bufsz);
}

/* Parse a decimal integer from a string */
static int parse_int(const char *s) {
    int neg = 0, val = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return neg ? -val : val;
}

/* Format an integer into a buffer, return length */
static int fmt_int(char *buf, int val) {
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

/* Write a string to a file, returns 0 on success */
static int write_file(const char *path, const char *data) {
    lc_sysret fd = lc_kernel_open_file(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t len = lc_string_length(data);
    lc_kernel_write_bytes((int32_t)fd, data, len);
    lc_kernel_close_file((int32_t)fd);
    return 0;
}

/* Read file contents into buf, null-terminate. Returns bytes read or -1. */
static int read_file(const char *path, char *buf, size_t bufsz) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY, 0);
    if (fd < 0) return -1;
    lc_sysret n = lc_kernel_read_bytes((int32_t)fd, buf, bufsz - 1);
    lc_kernel_close_file((int32_t)fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

/* Check if a path exists (file or directory) */
static bool path_exists(const char *path) {
    return lc_kernel_faccessat2(AT_FDCWD, path, F_OK, 0) == 0;
}

/* Recursively remove a directory tree (fork+exec rm -rf) */
static void rm_rf(const char *path) {
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        char *argv[] = { "rm", "-rf", (char *)path, NULL };
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute("/bin/rm", argv, envp);
        lc_kernel_exit(1);
    }
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
}

/* Copy directory tree (fork+exec cp -a) */
static void cp_a(const char *src, const char *dst) {
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        char *argv[] = { "cp", "-a", (char *)src, (char *)dst, NULL };
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute("/bin/cp", argv, envp);
        lc_kernel_exit(1);
    }
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
}

/* Run an external command (fork+exec), wait for completion */
static int run_cmd(const char *prog, char *const argv[]) {
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute(prog, argv, envp);
        lc_kernel_exit(127);
    }
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    return (status >> 8) & 0xff; /* exit code */
}

/* Run an external command with stderr suppressed (for expected-failure checks) */
static int run_cmd_quiet(const char *prog, char *const argv[]) {
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        /* redirect stderr to /dev/null */
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

/* Mount via fork+exec of /bin/mount.
 * Works around EFAULT from raw mount syscall in clone'd children. */
static int do_mount(const char *source, const char *target,
                    const char *fstype, uint64_t flags, const char *data) {
    char *argv[16];
    int ai = 0;
    argv[ai++] = "mount";
    if ((flags & MS_PRIVATE) && (flags & MS_REC)) {
        argv[ai++] = "--make-rprivate"; argv[ai++] = (char *)target;
        argv[ai] = NULL; return run_cmd("/bin/mount", argv);
    }
    if ((flags & MS_REMOUNT) && (flags & MS_BIND)) {
        argv[ai++] = "-o";
        argv[ai++] = (flags & MS_RDONLY) ? "remount,bind,ro" : "remount,bind";
        argv[ai++] = (char *)target; argv[ai] = NULL;
        return run_cmd("/bin/mount", argv);
    }
    if ((flags & MS_BIND) && (flags & MS_REC)) {
        argv[ai++] = "--rbind"; argv[ai++] = (char *)source;
        argv[ai++] = (char *)target; argv[ai] = NULL;
        return run_cmd("/bin/mount", argv);
    }
    if (flags & MS_BIND) {
        argv[ai++] = "--bind"; argv[ai++] = (char *)source;
        argv[ai++] = (char *)target; argv[ai] = NULL;
        return run_cmd("/bin/mount", argv);
    }
    char opts[256]; int olen = 0;
    if (flags & MS_RDONLY)  { if (olen) opts[olen++]=','; olen+=(int)str_copy(opts+olen,"ro",sizeof(opts)-olen); }
    if (flags & MS_NOSUID)  { if (olen) opts[olen++]=','; olen+=(int)str_copy(opts+olen,"nosuid",sizeof(opts)-olen); }
    if (flags & MS_NOEXEC)  { if (olen) opts[olen++]=','; olen+=(int)str_copy(opts+olen,"noexec",sizeof(opts)-olen); }
    if (data && data[0])    { if (olen) opts[olen++]=','; str_copy(opts+olen,data,sizeof(opts)-olen); olen+=(int)lc_string_length(data); }
    opts[olen] = '\0';
    if (fstype && fstype[0]) { argv[ai++] = "-t"; argv[ai++] = (char *)fstype; }
    if (olen > 0)            { argv[ai++] = "-o"; argv[ai++] = opts; }
    if (source && source[0]) argv[ai++] = (char *)source;
    argv[ai++] = (char *)target; argv[ai] = NULL;
    return run_cmd("/bin/mount", argv);
}

/* Validate container name: [a-zA-Z0-9_-], max 12 chars */
static void validate_name(const char *name) {
    if (!name || !name[0]) die("Error: container name required");
    size_t len = lc_string_length(name);
    if (len > NAME_MAX_LEN) die("Error: container name must be 12 characters or fewer");
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            die("Error: container name must only contain [a-zA-Z0-9_-]");
    }
}

/* ─── Configuration ─────────────────────────────────────────────────────── */

static void cfg_global_init(void) {
    str_copy(cfg_global.lightbox_dir, "/etc/lightbox", MAX_PATH);
    str_copy(cfg_global.rootfs, "/etc/lightbox/rootfs", MAX_PATH);
    str_copy(cfg_global.container_dir, "/etc/lightbox/containers", MAX_PATH);
    str_copy(cfg_global.run_dir, "/run", MAX_PATH);
    str_copy(cfg_global.cgroup_root, "/sys/fs/cgroup", MAX_PATH);
    str_copy(cfg_global.cgroup_base, "/sys/fs/cgroup/lightbox", MAX_PATH);
    str_copy(cfg_global.bridge, "br0", sizeof(cfg_global.bridge));
    str_copy(cfg_global.subnet, "10.0.0.0/24", sizeof(cfg_global.subnet));
    str_copy(cfg_global.gw, "10.0.0.1", sizeof(cfg_global.gw));
    str_copy(cfg_global.default_mem, "256M", sizeof(cfg_global.default_mem));
    str_copy(cfg_global.default_pids, "128", sizeof(cfg_global.default_pids));
    str_copy(cfg_global.default_cpu, "1", sizeof(cfg_global.default_cpu));
    cfg_global.default_oom = 500;
}

/* Apply a single key=value pair to the global config.
 * If lightbox_dir changes, recompute derived paths (rootfs, container_dir,
 * cgroup_base) unless they were explicitly set in the config file. */
static void cfg_set(const char *key, const char *val, bool derived[3]) {
    if (streq(key, "lightbox_dir")) {
        str_copy(cfg_global.lightbox_dir, val, MAX_PATH);
        /* recompute derived paths unless explicitly overridden */
        if (!derived[0]) path_join(cfg_global.rootfs, MAX_PATH, val, "rootfs");
        if (!derived[1]) path_join(cfg_global.container_dir, MAX_PATH, val, "containers");
    }
    else if (streq(key, "rootfs"))         { str_copy(cfg_global.rootfs, val, MAX_PATH); derived[0] = true; }
    else if (streq(key, "container_dir"))  { str_copy(cfg_global.container_dir, val, MAX_PATH); derived[1] = true; }
    else if (streq(key, "run_dir"))        str_copy(cfg_global.run_dir, val, MAX_PATH);
    else if (streq(key, "cgroup_root"))    str_copy(cfg_global.cgroup_root, val, MAX_PATH);
    else if (streq(key, "cgroup_base"))    { str_copy(cfg_global.cgroup_base, val, MAX_PATH); derived[2] = true; }
    else if (streq(key, "bridge"))         str_copy(cfg_global.bridge, val, sizeof(cfg_global.bridge));
    else if (streq(key, "subnet"))         str_copy(cfg_global.subnet, val, sizeof(cfg_global.subnet));
    else if (streq(key, "gw"))             str_copy(cfg_global.gw, val, sizeof(cfg_global.gw));
    else if (streq(key, "default_mem"))    str_copy(cfg_global.default_mem, val, sizeof(cfg_global.default_mem));
    else if (streq(key, "default_pids"))   str_copy(cfg_global.default_pids, val, sizeof(cfg_global.default_pids));
    else if (streq(key, "default_cpu"))    str_copy(cfg_global.default_cpu, val, sizeof(cfg_global.default_cpu));
    else if (streq(key, "default_oom"))    cfg_global.default_oom = parse_int(val);
}

/*
 * Load ~/.config/lightbox/lightbox.conf if it exists.
 * Format: key=value, one per line. Lines starting with # are comments.
 *
 * If lightbox_dir is set, rootfs and container_dir are derived from it
 * automatically unless they are also explicitly set.
 * Similarly, cgroup_base is derived from cgroup_root unless explicit.
 */
static void cfg_global_load(char **envp) {
    /* build config path: $HOME/.config/lightbox/lightbox.conf */
    const char *home = env_get(envp, "HOME");
    if (!home) home = "/root";

    char conf_path[MAX_PATH];
    path_join(conf_path, MAX_PATH, home, ".config/lightbox/lightbox.conf");

    char buf[CONF_BUF_SIZE];
    int n = read_file(conf_path, buf, sizeof(buf));
    if (n <= 0) return;

    /* track which derived paths were explicitly set */
    bool derived[3] = { false, false, false }; /* rootfs, container_dir, cgroup_base */

    /* first pass: parse all key=value pairs */
    char *p = buf;
    while (*p) {
        /* skip whitespace and comments */
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n') {
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
            continue;
        }

        /* find = */
        char *eq = p;
        while (*eq && *eq != '=' && *eq != '\n') eq++;
        if (*eq != '=') { while (*p && *p != '\n') p++; if (*p == '\n') p++; continue; }

        /* extract key (trim trailing spaces) */
        char key[64];
        size_t klen = (size_t)(eq - p);
        while (klen > 0 && (p[klen - 1] == ' ' || p[klen - 1] == '\t')) klen--;
        if (klen >= sizeof(key)) klen = sizeof(key) - 1;
        lc_bytes_copy(key, p, klen);
        key[klen] = '\0';

        /* extract value (trim leading spaces, ends at newline) */
        char *vs = eq + 1;
        while (*vs == ' ' || *vs == '\t') vs++;
        char *ve = vs;
        while (*ve && *ve != '\n') ve++;
        /* trim trailing spaces */
        char *vt = ve;
        while (vt > vs && (vt[-1] == ' ' || vt[-1] == '\t')) vt--;

        char val[MAX_PATH];
        size_t vlen = (size_t)(vt - vs);
        if (vlen >= sizeof(val)) vlen = sizeof(val) - 1;
        lc_bytes_copy(val, vs, vlen);
        val[vlen] = '\0';

        cfg_set(key, val, derived);

        p = ve;
        if (*p == '\n') p++;
    }

    /* recompute cgroup_base from cgroup_root if not explicitly set */
    if (!derived[2])
        path_join(cfg_global.cgroup_base, MAX_PATH, cfg_global.cgroup_root, "lightbox");

    /* LIGHTBOX_ROOTFS env var overrides config file */
    const char *env_rootfs = env_get(envp, "LIGHTBOX_ROOTFS");
    if (env_rootfs && env_rootfs[0])
        str_copy(cfg_global.rootfs, env_rootfs, MAX_PATH);
}

/* ─── Path helpers ──────────────────────────────────────────────────────── */

/*
 * Container directory layout:
 *   <container_dir>/<name>/rootfs/   — the container's root filesystem
 *   <container_dir>/<name>/.conf     — container config (key=value)
 *   <container_dir>/<name>/.ip       — assigned IP address
 *   <container_dir>/<name>/.pid      — PID of running container
 */

/* Path to container base directory: <container_dir>/<name> */
static void container_dir_path(char *buf, const char *name) {
    path_join(buf, MAX_PATH, cfg_global.container_dir, name);
}

/* Path to container rootfs: <container_dir>/<name>/rootfs */
static void container_root(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, "rootfs");
}

static void container_pid_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".pid");
}

static void container_ip_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".ip");
}

static void container_conf_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".conf");
}

/* ─── Config read/write ─────────────────────────────────────────────────── */

/* Read a key from config file, return value or default */
static int conf_get(const char *name, const char *key, char *val, size_t valsz, const char *def) {
    char path[MAX_PATH], buf[2048];
    container_conf_path(path, name);
    if (read_file(path, buf, sizeof(buf)) < 0) {
        str_copy(val, def, valsz);
        return 0;
    }

    size_t keylen = lc_string_length(key);
    char *p = buf;
    while (*p) {
        /* check if this line starts with key= */
        if (lc_string_starts_with(p, lc_string_length(p), key, keylen) && p[keylen] == '=') {
            char *v = p + keylen + 1;
            char *end = v;
            while (*end && *end != '\n') end++;
            size_t len = (size_t)(end - v);
            if (len >= valsz) len = valsz - 1;
            lc_bytes_copy(val, v, len);
            val[len] = '\0';
            return 1;
        }
        /* skip to next line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    str_copy(val, def, valsz);
    return 0;
}

static int conf_get_int(const char *name, const char *key, int def) {
    char val[32];
    if (conf_get(name, key, val, sizeof(val), "") && val[0])
        return parse_int(val);
    return def;
}

/* ─── Container state ───────────────────────────────────────────────────── */

static int get_container_pid(const char *name) {
    char path[MAX_PATH], buf[16];
    container_pid_path(path, name);
    if (read_file(path, buf, sizeof(buf)) < 0) return -1;
    return parse_int(buf);
}

static bool is_running(const char *name) {
    int pid = get_container_pid(name);
    if (pid <= 0) return false;

    /* check if PID is alive */
    if (lc_kernel_send_signal(pid, 0) < 0) {
        /* stale pidfile — clean up */
        char path[MAX_PATH];
        container_pid_path(path, name);
        lc_kernel_unlinkat(AT_FDCWD, path, 0);
        return false;
    }

    /* verify it's in a different PID namespace */
    char pid_ns[64], init_ns[64], proc_path[64];
    char intbuf[16]; fmt_int(intbuf, pid);

    size_t pos = str_copy(proc_path, "/proc/", sizeof(proc_path));
    pos = str_append(proc_path, pos, intbuf, sizeof(proc_path));
    str_append(proc_path, pos, "/ns/pid", sizeof(proc_path));

    lc_sysret n1 = lc_kernel_readlinkat(AT_FDCWD, proc_path, pid_ns, sizeof(pid_ns) - 1);
    lc_sysret n2 = lc_kernel_readlinkat(AT_FDCWD, "/proc/1/ns/pid", init_ns, sizeof(init_ns) - 1);
    if (n1 <= 0 || n2 <= 0) return false;
    pid_ns[n1] = '\0';
    init_ns[n2] = '\0';

    return !streq(pid_ns, init_ns);
}

/* ─── Cgroup management ─────────────────────────────────────────────────── */

static void cgroup_path(char *buf, const char *name) {
    path_join(buf, MAX_PATH, cfg_global.cgroup_base, name);
}

static void cgroup_create(const char *name, int pid) {
    char cg[MAX_PATH], tmp[MAX_PATH];
    cgroup_path(cg, name);

    /* ensure parent exists and has controllers */
    lc_kernel_mkdirat(AT_FDCWD, cfg_global.cgroup_base, 0755);

    path_join(tmp, MAX_PATH, cfg_global.cgroup_root, "cgroup.subtree_control");
    write_file(tmp, "+memory +pids +cpu +io");
    path_join(tmp, MAX_PATH, cfg_global.cgroup_base, "cgroup.subtree_control");
    write_file(tmp, "+memory +pids +cpu +io");

    lc_kernel_mkdirat(AT_FDCWD, cg, 0755);

    /* read limits from config */
    char mem[16], pids[8], cpu[4];
    conf_get(name, "mem", mem, sizeof(mem), cfg_global.default_mem);
    conf_get(name, "pids", pids, sizeof(pids), cfg_global.default_pids);
    conf_get(name, "cpu", cpu, sizeof(cpu), cfg_global.default_cpu);

    path_join(tmp, MAX_PATH, cg, "memory.max");
    write_file(tmp, mem);

    path_join(tmp, MAX_PATH, cg, "pids.max");
    write_file(tmp, pids);

    /* cpu: convert cores to quota */
    int cores = parse_int(cpu);
    if (cores < 1) cores = 1;
    char cpu_max[32];
    int quota = cores * 100000;
    int len = fmt_int(cpu_max, quota);
    str_append(cpu_max, (size_t)len, " 100000", sizeof(cpu_max));
    path_join(tmp, MAX_PATH, cg, "cpu.max");
    write_file(tmp, cpu_max);

    /* io limits */
    char io_spec[128];
    if (conf_get(name, "io", io_spec, sizeof(io_spec), "") && io_spec[0]) {
        path_join(tmp, MAX_PATH, cg, "io.max");
        write_file(tmp, io_spec);
    }

    /* move container process into this cgroup */
    char pidbuf[16];
    fmt_int(pidbuf, pid);
    path_join(tmp, MAX_PATH, cg, "cgroup.procs");
    write_file(tmp, pidbuf);
}

static void cgroup_destroy(const char *name) {
    char cg[MAX_PATH], tmp[MAX_PATH], buf[4096];
    cgroup_path(cg, name);

    if (!path_exists(cg)) return;

    /* kill remaining processes */
    path_join(tmp, MAX_PATH, cg, "cgroup.procs");
    if (read_file(tmp, buf, sizeof(buf)) > 0) {
        char *p = buf;
        while (*p) {
            int pid = parse_int(p);
            if (pid > 0) lc_kernel_send_signal(pid, 9);
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
        }
    }

    /* rmdir the cgroup */
    lc_kernel_unlinkat(AT_FDCWD, cg, AT_REMOVEDIR);
}

/* ─── Security: capabilities ────────────────────────────────────────────── */

/* Docker's default allowed capabilities */
static const int ALLOWED_CAPS[] = {
    CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID,
    CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP,
    CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_CHROOT,
    CAP_MKNOD, CAP_AUDIT_WRITE, CAP_SETFCAP,
};
#define N_ALLOWED_CAPS (sizeof(ALLOWED_CAPS) / sizeof(ALLOWED_CAPS[0]))

static bool cap_is_allowed(int cap) {
    for (size_t i = 0; i < N_ALLOWED_CAPS; i++)
        if (ALLOWED_CAPS[i] == cap) return true;
    return false;
}

static void drop_capabilities(void) {
    /* read cap_last_cap from kernel */
    char buf[8];
    int last_cap = 40; /* fallback */
    if (read_file("/proc/sys/kernel/cap_last_cap", buf, sizeof(buf)) > 0)
        last_cap = parse_int(buf);

    for (int cap = 0; cap <= last_cap; cap++) {
        if (!cap_is_allowed(cap))
            lc_kernel_prctl(PR_CAPBSET_DROP, (uint64_t)cap, 0, 0, 0);
    }
}

/* ─── Security: seccomp ─────────────────────────────────────────────────── */

/*
 * x86_64 syscall numbers to block (Docker's default deny list).
 * We build a BPF filter that returns EPERM for these.
 */
static const uint32_t BLOCKED_SYSCALLS[] = {
    /* x86_64 syscall numbers */
    163,  /* acct */
    248,  /* add_key */
    321,  /* bpf */
    305,  /* clock_adjtime */
    227,  /* clock_settime */
    174,  /* create_module */
    176,  /* delete_module */
    313,  /* finit_module */
    177,  /* get_kernel_syms */
    239,  /* get_mempolicy */
    175,  /* init_module */
    173,  /* ioperm */
    172,  /* iopl */
    312,  /* kcmp */
    320,  /* kexec_file_load */
    246,  /* kexec_load */
    250,  /* keyctl */
    212,  /* lookup_dcookie */
    237,  /* mbind */
    /* 40, mount — allowed for container setup, blocked by caps */
    429,  /* move_mount */
    303,  /* name_to_handle_at */
    180,  /* nfsservctl */
    304,  /* open_by_handle_at */
    428,  /* open_tree */
    298,  /* perf_event_open */
    135,  /* personality */
    /* 155, pivot_root — blocked by caps after setup */
    310,  /* process_vm_readv */
    311,  /* process_vm_writev */
    101,  /* ptrace */
    178,  /* query_module */
    179,  /* quotactl */
    169,  /* reboot */
    249,  /* request_key */
    238,  /* set_mempolicy */
    308,  /* setns */
    164,  /* settimeofday */
    /* 200, stime — doesn't exist on x86_64 */
    167,  /* swapon */
    168,  /* swapoff */
    156,  /* _sysctl */
    139,  /* sysfs */
    166,  /* umount2 */
    272,  /* unshare */
    134,  /* uselib */
    323,  /* userfaultfd */
    136,  /* ustat */
    /* vm86/vm86old don't exist on x86_64 */
    442,  /* mount_setattr */
    430,  /* fsopen */
    431,  /* fsconfig */
    432,  /* fsmount */
    433,  /* fspick */
};
#define N_BLOCKED_SYSCALLS (sizeof(BLOCKED_SYSCALLS) / sizeof(BLOCKED_SYSCALLS[0]))

static void apply_seccomp(void) {
    /*
     * Build a BPF program:
     *   load syscall nr
     *   for each blocked syscall: if equal, return ERRNO(EPERM)
     *   return ALLOW
     *
     * Total instructions: 1 (load) + 2*N (check+deny per syscall) + 1 (allow)
     */
    size_t n = N_BLOCKED_SYSCALLS;
    size_t prog_len = 1 + 2 * n + 1;
    struct sock_filter filter[256]; /* plenty of room */

    if (prog_len > sizeof(filter) / sizeof(filter[0])) return; /* safety */

    size_t idx = 0;

    /* load syscall number */
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET);

    /* for each blocked syscall: check and deny */
    for (size_t i = 0; i < n; i++) {
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BLOCKED_SYSCALLS[i], 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1 /* EPERM */);
    }

    /* default: allow */
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = {
        .len = (uint16_t)idx,
        .filter = filter,
    };

    lc_kernel_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uint64_t)&prog, 0, 0);
}

/* ─── Security: /proc masking ───────────────────────────────────────────── */

static void mask_proc_paths(void) {
    /* bind /dev/null over sensitive files */
    static const char *mask_files[] = {
        "/proc/kcore", "/proc/sysrq-trigger", "/proc/timer_list",
        "/proc/keys", "/proc/sched_debug",
    };
    for (size_t i = 0; i < sizeof(mask_files) / sizeof(mask_files[0]); i++) {
        if (path_exists(mask_files[i]))
            do_mount("/dev/null", mask_files[i], NULL, MS_BIND, NULL);
    }

    /* make sensitive subtrees read-only */
    static const char *ro_dirs[] = {
        "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
    };
    for (size_t i = 0; i < sizeof(ro_dirs) / sizeof(ro_dirs[0]); i++) {
        if (path_exists(ro_dirs[i])) {
            do_mount(ro_dirs[i], ro_dirs[i], NULL, MS_BIND, NULL);
            do_mount(NULL, ro_dirs[i], NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL);
        }
    }
}

/* ─── cmd_setup ─────────────────────────────────────────────────────────── */

/* Check if an iptables rule exists (-C), return 0 if it does */
static int iptables_check(char *const argv[]) {
    return run_cmd_quiet("/usr/sbin/iptables", argv);
}

/* Add an iptables rule only if it doesn't already exist */
static void iptables_idempotent(char **check_argv, char **add_argv) {
    if (iptables_check(check_argv) != 0)
        run_cmd("/usr/sbin/iptables", add_argv);
}

/* Detect the default outbound network interface */
static void detect_wan_interface(char *wan_if, size_t bufsz) {
    char route_buf[256];
    int pipefd[2];
    lc_kernel_create_pipe(pipefd, 0);
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        lc_kernel_close_file(pipefd[0]);
        lc_kernel_duplicate_fd(pipefd[1], STDOUT, 0);
        lc_kernel_close_file(pipefd[1]);
        char *argv[] = { "ip", "route", "show", "default", NULL };
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute("/sbin/ip", argv, envp);
        lc_kernel_exit(1);
    }
    lc_kernel_close_file(pipefd[1]);
    lc_sysret n = lc_kernel_read_bytes(pipefd[0], route_buf, sizeof(route_buf) - 1);
    lc_kernel_close_file(pipefd[0]);
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    if (n <= 0) die("Error: could not detect default network interface");
    route_buf[n] = '\0';

    /* parse "default via X.X.X.X dev IFACE ..." */
    const char *dev = NULL;
    for (char *p = route_buf; *p; p++) {
        if (p[0] == 'd' && p[1] == 'e' && p[2] == 'v' && p[3] == ' ') {
            dev = p + 4;
            break;
        }
    }
    if (!dev) die("Error: could not parse default route");
    size_t i = 0;
    while (dev[i] && dev[i] != ' ' && dev[i] != '\n' && i < bufsz - 1) {
        wan_if[i] = dev[i]; i++;
    }
    wan_if[i] = '\0';
}

static void cmd_setup(void) {
    print_str(STDOUT, "Setting up host networking...\n");

    /* create config and container directories */
    lc_kernel_mkdirat(AT_FDCWD, cfg_global.lightbox_dir, 0755);
    lc_kernel_mkdirat(AT_FDCWD, cfg_global.container_dir, 0755);

    /* create bridge if it doesn't exist */
    {
        char *show[] = { "ip", "link", "show", cfg_global.bridge, NULL };
        if (run_cmd_quiet("/sbin/ip", show) != 0) {
            print_str(STDOUT, "Creating bridge ");
            print_str(STDOUT, cfg_global.bridge);
            print_str(STDOUT, "...\n");
            char *add[] = { "ip", "link", "add", "name", cfg_global.bridge, "type", "bridge", NULL };
            run_cmd("/sbin/ip", add);
            char gw_cidr[20];
            str_copy(gw_cidr, cfg_global.gw, sizeof(gw_cidr));
            str_append(gw_cidr, lc_string_length(gw_cidr), "/24", sizeof(gw_cidr));
            char *addr[] = { "ip", "addr", "add", gw_cidr, "dev", cfg_global.bridge, NULL };
            run_cmd("/sbin/ip", addr);
            char *up[] = { "ip", "link", "set", cfg_global.bridge, "up", NULL };
            run_cmd("/sbin/ip", up);
        } else {
            print_str(STDOUT, "Bridge ");
            print_str(STDOUT, cfg_global.bridge);
            print_str(STDOUT, " already exists, skipping\n");
        }
    }

    /* mount cgroup2 if not already mounted */
    lc_kernel_mkdirat(AT_FDCWD, cfg_global.cgroup_root, 0755);
    /* mount returns -EBUSY if already mounted — that's fine */
    lc_kernel_mount("none", cfg_global.cgroup_root, "cgroup2", 0, NULL);

    /* enable IP forwarding */
    write_file("/proc/sys/net/ipv4/ip_forward", "1");

    /* detect WAN interface */
    char wan_if[32];
    detect_wan_interface(wan_if, sizeof(wan_if));
    print_str(STDOUT, "WAN interface: ");
    print_str(STDOUT, wan_if);
    lc_print_char(STDOUT, '\n');

    /* NAT masquerade (idempotent — check before adding) */
    {
        char *chk[] = { "iptables", "-t", "nat", "-C", "POSTROUTING",
                        "-s", cfg_global.subnet, "-o", wan_if, "-j", "MASQUERADE", NULL };
        char *add[] = { "iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-s", cfg_global.subnet, "-o", wan_if, "-j", "MASQUERADE", NULL };
        iptables_idempotent(chk, add);
    }

    /* FORWARD: bridge → WAN */
    {
        char *chk[] = { "iptables", "-C", "FORWARD", "-i", cfg_global.bridge,
                        "-o", wan_if, "-j", "ACCEPT", NULL };
        char *add[] = { "iptables", "-A", "FORWARD", "-i", cfg_global.bridge,
                        "-o", wan_if, "-j", "ACCEPT", NULL };
        iptables_idempotent(chk, add);
    }

    /* FORWARD: WAN → bridge (established/related) */
    {
        char *chk[] = { "iptables", "-C", "FORWARD", "-i", wan_if,
                        "-o", cfg_global.bridge, "-m", "state", "--state", "RELATED,ESTABLISHED",
                        "-j", "ACCEPT", NULL };
        char *add[] = { "iptables", "-A", "FORWARD", "-i", wan_if,
                        "-o", cfg_global.bridge, "-m", "state", "--state", "RELATED,ESTABLISHED",
                        "-j", "ACCEPT", NULL };
        iptables_idempotent(chk, add);
    }

    /* inter-container isolation: drop br0-to-br0 traffic */
    {
        char *chk[] = { "iptables", "-C", "FORWARD", "-i", cfg_global.bridge,
                        "-o", cfg_global.bridge, "-j", "DROP", NULL };
        char *add[] = { "iptables", "-A", "FORWARD", "-i", cfg_global.bridge,
                        "-o", cfg_global.bridge, "-j", "DROP", NULL };
        iptables_idempotent(chk, add);
    }

    print_str(STDOUT, "Host networking ready\n");
}

/* ─── cmd_create ────────────────────────────────────────────────────────── */

static void cmd_create(int argc, char **argv) {
    if (argc < 2) die("Usage: lightbox create <name> <ip> [options]");
    const char *name = argv[0];
    const char *ip = argv[1];
    validate_name(name);

    /* parse options */
    container_config cfg = {0};
    str_copy(cfg.name, name, sizeof(cfg.name));
    str_copy(cfg.ip, ip, sizeof(cfg.ip));
    str_copy(cfg.mem, cfg_global.default_mem, sizeof(cfg.mem));
    str_copy(cfg.pids, cfg_global.default_pids, sizeof(cfg.pids));
    str_copy(cfg.cpu, cfg_global.default_cpu, sizeof(cfg.cpu));
    cfg.oom_score = cfg_global.default_oom;

    for (int i = 2; i < argc; i++) {
        if (streq(argv[i], "--mem") && i + 1 < argc) {
            str_copy(cfg.mem, argv[++i], sizeof(cfg.mem));
        } else if (streq(argv[i], "--pids") && i + 1 < argc) {
            str_copy(cfg.pids, argv[++i], sizeof(cfg.pids));
        } else if (streq(argv[i], "--cpu") && i + 1 < argc) {
            str_copy(cfg.cpu, argv[++i], sizeof(cfg.cpu));
        } else if (streq(argv[i], "--userns")) {
            cfg.userns = 1;
        } else if (streq(argv[i], "--uid-start") && i + 1 < argc) {
            cfg.uid_start = parse_int(argv[++i]);
        } else if (streq(argv[i], "--privileged")) {
            cfg.privileged = 1;
        } else if (streq(argv[i], "--rootfs") && i + 1 < argc) {
            str_copy(cfg_global.rootfs, argv[++i], MAX_PATH);
        } else if (streq(argv[i], "--read-only")) {
            cfg.read_only = 1;
        } else if (streq(argv[i], "--oom-score") && i + 1 < argc) {
            cfg.oom_score = parse_int(argv[++i]);
        } else if (streq(argv[i], "--vol") && i + 1 < argc) {
            if (cfg.nvols >= MAX_VOLS) die("Error: too many volumes");
            /* parse src:dst[:ro] */
            const char *spec = argv[++i];
            const char *colon1 = NULL, *colon2 = NULL;
            for (const char *p = spec; *p; p++) {
                if (*p == ':') {
                    if (!colon1) colon1 = p;
                    else if (!colon2) colon2 = p;
                }
            }
            if (!colon1) die("Error: volume format is src:dst[:ro]");
            size_t slen = (size_t)(colon1 - spec);
            if (slen >= MAX_PATH) slen = MAX_PATH - 1;
            lc_bytes_copy(cfg.vol_src[cfg.nvols], spec, slen);
            cfg.vol_src[cfg.nvols][slen] = '\0';

            const char *dst_start = colon1 + 1;
            const char *dst_end = colon2 ? colon2 : spec + lc_string_length(spec);
            size_t dlen = (size_t)(dst_end - dst_start);
            if (dlen >= MAX_PATH) dlen = MAX_PATH - 1;
            lc_bytes_copy(cfg.vol_dst[cfg.nvols], dst_start, dlen);
            cfg.vol_dst[cfg.nvols][dlen] = '\0';

            if (colon2 && colon2[1] == 'r' && colon2[2] == 'o')
                cfg.vol_ro[cfg.nvols] = 1;
            cfg.nvols++;
        } else if (streq(argv[i], "--link") && i + 1 < argc) {
            if (cfg.nlinks >= MAX_LINKS) die("Error: too many links");
            str_copy(cfg.links[cfg.nlinks++], argv[++i], NAME_MAX_LEN + 1);
        } else {
            die2("Error: unknown option: ", argv[i]);
        }
    }

    /* check if container already exists */
    char cdir[MAX_PATH], root[MAX_PATH];
    container_dir_path(cdir, name);
    container_root(root, name);
    if (path_exists(cdir)) die2("Error: container already exists: ", name);

    print_str(STDOUT,"Creating container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");

    /* create container directory and copy rootfs into it */
    lc_kernel_mkdirat(AT_FDCWD, cdir, 0755);
    if (!path_exists(cfg_global.rootfs))
        die2("Error: rootfs not found: ", cfg_global.rootfs);
    cp_a(cfg_global.rootfs, root);

    /* store IP */
    char ip_path[MAX_PATH];
    container_ip_path(ip_path, name);
    write_file(ip_path, ip);

    /* write config */
    char conf_path[MAX_PATH], conf_buf[1024];
    container_conf_path(conf_path, name);
    size_t cpos = 0;
    cpos = str_append(conf_buf, cpos, "mem=", sizeof(conf_buf));
    cpos = str_append(conf_buf, cpos, cfg.mem, sizeof(conf_buf));
    cpos = str_append(conf_buf, cpos, "\npids=", sizeof(conf_buf));
    cpos = str_append(conf_buf, cpos, cfg.pids, sizeof(conf_buf));
    cpos = str_append(conf_buf, cpos, "\ncpu=", sizeof(conf_buf));
    cpos = str_append(conf_buf, cpos, cfg.cpu, sizeof(conf_buf));
    cpos = str_append(conf_buf, cpos, "\n", sizeof(conf_buf));

    if (cfg.privileged) cpos = str_append(conf_buf, cpos, "privileged=1\n", sizeof(conf_buf));
    if (cfg.read_only) cpos = str_append(conf_buf, cpos, "readonly=1\n", sizeof(conf_buf));
    if (cfg.userns) {
        cpos = str_append(conf_buf, cpos, "userns=1\n", sizeof(conf_buf));
        /* auto-allocate uid_start if not specified */
        if (cfg.uid_start == 0) {
            cfg.uid_start = 100000;
            /* TODO: scan existing configs for collisions */
        }
        char uid_buf[16]; fmt_int(uid_buf, cfg.uid_start);
        cpos = str_append(conf_buf, cpos, "uid_start=", sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, uid_buf, sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, "\n", sizeof(conf_buf));
    }
    {
        char oom_buf[16]; fmt_int(oom_buf, cfg.oom_score);
        cpos = str_append(conf_buf, cpos, "oom_score=", sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, oom_buf, sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, "\n", sizeof(conf_buf));
    }
    for (int i = 0; i < cfg.nvols; i++) {
        cpos = str_append(conf_buf, cpos, "vol=", sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, cfg.vol_src[i], sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, ":", sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, cfg.vol_dst[i], sizeof(conf_buf));
        if (cfg.vol_ro[i]) cpos = str_append(conf_buf, cpos, ":ro", sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, "\n", sizeof(conf_buf));
    }
    for (int i = 0; i < cfg.nlinks; i++) {
        cpos = str_append(conf_buf, cpos, "link=", sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, cfg.links[i], sizeof(conf_buf));
        cpos = str_append(conf_buf, cpos, "\n", sizeof(conf_buf));
    }
    write_file(conf_path, conf_buf);

    /* write resolv.conf */
    char resolv[MAX_PATH];
    path_join(resolv, MAX_PATH, root, "etc/resolv.conf");
    write_file(resolv, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");

    /* shift rootfs ownership for user namespace */
    if (cfg.userns && cfg.uid_start > 0) {
        print_str(STDOUT,"Shifting rootfs ownership...\n");
        /* use chown -R via fork+exec for simplicity */
        char uid_str[32];
        int len = fmt_int(uid_str, cfg.uid_start);
        str_append(uid_str, (size_t)len, ":", sizeof(uid_str));
        size_t pos = lc_string_length(uid_str);
        fmt_int(uid_str + pos, cfg.uid_start);

        lc_sysret pid = lc_kernel_fork();
        if (pid == 0) {
            char *argv2[] = { "chown", "-R", "-h", uid_str, root, NULL };
            char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
            lc_kernel_execute("/bin/chown", argv2, envp);
            lc_kernel_exit(1);
        }
        int32_t status;
        lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    }

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' created (ip=");
    print_str(STDOUT,ip);
    print_str(STDOUT,")\n");
}

/* ─── cmd_start: child process ──────────────────────────────────────────── */

struct child_args {
    int          sync_pipe_rd;
    int          sync_pipe_wr;
    const char  *name;
    const char  *root;
    int          userns;
    int          privileged;
    int          read_only;
};

/*
 * This function runs in the child after clone().
 * It sets up the container filesystem, applies security, and execs init.
 */
static int container_child(void *arg) {
    struct child_args *ca = (struct child_args *)arg;

    /* close the write end so we only read */
    lc_kernel_close_file(ca->sync_pipe_wr);

    /* make all mounts private — prevents host mount events (including
     * the host's /proc) from propagating into the container */
    do_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

    /* wait for parent to set up uid/gid maps */
    char sync_byte;
    lc_kernel_read_bytes(ca->sync_pipe_rd, &sync_byte, 1);
    lc_kernel_close_file(ca->sync_pipe_rd);

    /* set hostname */
    lc_kernel_sethostname(ca->name, lc_string_length(ca->name));

    /* read volume config and set up bind mounts */
    char conf_path[MAX_PATH];
    container_conf_path(conf_path, ca->name);
    char conf_buf[2048];
    if (read_file(conf_path, conf_buf, sizeof(conf_buf)) > 0) {
        char *p = conf_buf;
        while (*p) {
            if (p[0] == 'v' && p[1] == 'o' && p[2] == 'l' && p[3] == '=') {
                char vol_line[MAX_PATH * 2 + 4];
                char *end = p + 4;
                while (*end && *end != '\n') end++;
                size_t vlen = (size_t)(end - (p + 4));
                if (vlen < sizeof(vol_line)) {
                    lc_bytes_copy(vol_line, p + 4, vlen);
                    vol_line[vlen] = '\0';

                    /* parse src:dst[:ro] */
                    char *colon1 = NULL, *colon2 = NULL;
                    for (char *q = vol_line; *q; q++) {
                        if (*q == ':') { if (!colon1) colon1 = q; else if (!colon2) colon2 = q; }
                    }
                    if (colon1) {
                        *colon1 = '\0';
                        char *dst = colon1 + 1;
                        int ro = 0;
                        if (colon2) { *colon2 = '\0'; ro = (colon2[1] == 'r'); }

                        /* create mount point and bind */
                        char mount_point[MAX_PATH];
                        path_join(mount_point, MAX_PATH, ca->root, dst);
                        /* mkdir -p via fork */
                        lc_sysret mp = lc_kernel_fork();
                        if (mp == 0) {
                            char *a[] = { "mkdir", "-p", mount_point, NULL };
                            char *e[] = { NULL };
                            lc_kernel_execute("/bin/mkdir", a, e);
                            lc_kernel_exit(1);
                        }
                        int32_t st; lc_kernel_wait_for_child((int32_t)mp, &st, 0);

                        do_mount(vol_line, mount_point, NULL, MS_BIND, NULL);
                        if (ro)
                            do_mount(NULL, mount_point, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL);
                    }
                }
            }
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
        }
    }

    /* set up /dev via bind mounts (works in both userns and non-userns) */
    {
        char dev_path[MAX_PATH];
        path_join(dev_path, MAX_PATH, ca->root, "dev");
        do_mount("tmpfs", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755");

        struct { const char *name; uint64_t dev; int mode; } devs[] = {
            { "null",    MAKEDEV(1, 3), 0666 },
            { "zero",    MAKEDEV(1, 5), 0666 },
            { "full",    MAKEDEV(1, 7), 0666 },
            { "random",  MAKEDEV(1, 8), 0444 },
            { "urandom", MAKEDEV(1, 9), 0444 },
            { "tty",     MAKEDEV(5, 0), 0666 },
        };

        for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
            char host_dev[32], cont_dev[MAX_PATH];
            path_join(host_dev, sizeof(host_dev), "/dev", devs[i].name);
            path_join(cont_dev, MAX_PATH, dev_path, devs[i].name);
            /* create empty file as mount point */
            lc_sysret fd = lc_kernel_open_file(cont_dev, O_WRONLY | O_CREAT, devs[i].mode);
            if (fd >= 0) lc_kernel_close_file((int32_t)fd);
            do_mount(host_dev, cont_dev, NULL, MS_BIND, NULL);
        }

        /* pts and shm */
        char pts[MAX_PATH], shm[MAX_PATH];
        path_join(pts, MAX_PATH, dev_path, "pts");
        path_join(shm, MAX_PATH, dev_path, "shm");
        lc_kernel_mkdirat(AT_FDCWD, pts, 0755);
        lc_kernel_mkdirat(AT_FDCWD, shm, 0755);
    }

    /* pivot_root */
    if (do_mount(ca->root, ca->root, NULL, MS_BIND | MS_REC, NULL) != 0)
        die2("Error: bind mount rootfs failed: ", ca->root);
    if (lc_kernel_chdir(ca->root) < 0)
        die2("Error: chdir to rootfs failed: ", ca->root);
    lc_kernel_mkdirat(AT_FDCWD, ".old_root", 0755);
    if (lc_kernel_pivot_root(".", ".old_root") < 0)
        die("Error: pivot_root failed");
    { char *a[] = { "umount", "-l", "/.old_root", NULL }; run_cmd_quiet("/bin/umount", a); }
    lc_kernel_unlinkat(AT_FDCWD, "/.old_root", AT_REMOVEDIR);
    lc_kernel_chdir("/");

    /* mount proc, sys — use fork+exec of mount(8) rather than raw syscall,
     * because busybox mount may handle proc namespace association differently */
    {
        lc_sysret p = lc_kernel_fork();
        if (p == 0) {
            char *a[] = { "mount", "-t", "proc", "proc", "/proc", NULL };
            char *e[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
            lc_kernel_execute("/bin/mount", a, e);
            lc_kernel_exit(1);
        }
        int32_t st; lc_kernel_wait_for_child((int32_t)p, &st, 0);
    }
    {
        lc_sysret p = lc_kernel_fork();
        if (p == 0) {
            char *a[] = { "mount", "-t", "sysfs", "sysfs", "/sys", "-o", "ro", NULL };
            char *e[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
            lc_kernel_execute("/bin/mount", a, e);
            lc_kernel_exit(1);
        }
        int32_t st; lc_kernel_wait_for_child((int32_t)p, &st, 0);
    }

    /* devpts and shm inside container */
    do_mount("devpts", "/dev/pts", "devpts",
             MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666");
    do_mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NOEXEC, NULL);

    /* symlinks in /dev */
    lc_kernel_symlinkat("/proc/self/fd", AT_FDCWD, "/dev/fd");
    lc_kernel_symlinkat("/proc/self/fd/0", AT_FDCWD, "/dev/stdin");
    lc_kernel_symlinkat("/proc/self/fd/1", AT_FDCWD, "/dev/stdout");
    lc_kernel_symlinkat("/proc/self/fd/2", AT_FDCWD, "/dev/stderr");
    lc_kernel_symlinkat("pts/ptmx", AT_FDCWD, "/dev/ptmx");

    /* mask sensitive /proc paths (unless privileged) */
    if (!ca->privileged) {
        mask_proc_paths();
    }

    /* read-only rootfs */
    if (ca->read_only) {
        do_mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
    }

    /* bring up loopback */
    {
        char *a[] = { "ip", "link", "set", "lo", "up", NULL };
        char *e[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_sysret p = lc_kernel_fork();
        if (p == 0) { lc_kernel_execute("/sbin/ip", a, e); lc_kernel_exit(1); }
        int32_t st; lc_kernel_wait_for_child((int32_t)p, &st, 0);
    }

    /* run /init.sh if present */
    if (path_exists("/init.sh")) {
        lc_sysret p = lc_kernel_fork();
        if (p == 0) {
            char *a[] = { "/bin/sh", "/init.sh", NULL };
            char *e[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "TERM=xterm", NULL };
            lc_kernel_execute("/bin/sh", a, e);
            lc_kernel_exit(1);
        }
        int32_t st; lc_kernel_wait_for_child((int32_t)p, &st, 0);
    }

    /* mount tmpfs for /tmp and /run (after init.sh, before signaling ready) */
    do_mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
    do_mount("tmpfs", "/run", "tmpfs", 0, NULL);
    if (ca->read_only)
        do_mount("tmpfs", "/var/tmp", "tmpfs", 0, NULL);

    /* apply security sandbox (unless privileged) */
    if (!ca->privileged) {
        drop_capabilities();
        lc_kernel_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        apply_seccomp();
    }

    /* become the init process: exec sleep infinity */
    char *init_argv[] = { "sleep", "infinity", NULL };
    char *init_envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "TERM=xterm", NULL };
    lc_kernel_execute("/bin/sleep", init_argv, init_envp);

    /* if exec fails */
    die("Error: failed to exec container init");
    return 1;
}

/* ─── cmd_start ─────────────────────────────────────────────────────────── */

#define CHILD_STACK_SIZE (1024 * 1024) /* 1 MiB */

static void cmd_start(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox start <name>");
    const char *name = argv[0];
    validate_name(name);

    char root[MAX_PATH];
    container_root(root, name);
    if (!path_exists(root)) die2("Error: container does not exist: ", name);

    if (is_running(name)) die2("Error: container is already running: ", name);

    /* read container IP */
    char ip_path[MAX_PATH], ip[16];
    container_ip_path(ip_path, name);
    if (read_file(ip_path, ip, sizeof(ip)) < 0) die("Error: no IP file for container");
    /* strip trailing newline */
    for (int i = 0; ip[i]; i++) { if (ip[i] == '\n') { ip[i] = '\0'; break; } }

    /* read config */
    int userns = conf_get_int(name, "userns", 0);
    int uid_start = conf_get_int(name, "uid_start", 100000);
    int privileged = conf_get_int(name, "privileged", 0);
    int read_only = conf_get_int(name, "readonly", 0);
    int oom_score = conf_get_int(name, "oom_score", cfg_global.default_oom);

    print_str(STDOUT,"Starting container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");

    /* set up veth pair */
    char veth_host[16], veth_cont[16];
    {
        size_t p1 = str_copy(veth_host, "vb-", sizeof(veth_host));
        str_append(veth_host, p1, name, sizeof(veth_host));
        size_t p2 = str_copy(veth_cont, "ve-", sizeof(veth_cont));
        str_append(veth_cont, p2, name, sizeof(veth_cont));
    }

    /* clean up stale veth if it exists */
    { char *show[] = { "ip", "link", "show", veth_host, NULL };
      if (run_cmd_quiet("/sbin/ip", show) == 0) {
          char *del[] = { "ip", "link", "delete", veth_host, NULL };
          run_cmd("/sbin/ip", del);
      }
    }

    /* create veth pair */
    { char *a[] = { "ip", "link", "add", veth_cont, "type", "veth", "peer", "name", veth_host, NULL };
      run_cmd("/sbin/ip", a); }
    { char *a[] = { "ip", "link", "set", veth_host, "master", cfg_global.bridge, NULL };
      run_cmd("/sbin/ip", a); }
    { char *a[] = { "ip", "link", "set", veth_host, "up", NULL };
      run_cmd("/sbin/ip", a); }

    /* create sync pipe */
    int sync_pipe[2];
    lc_kernel_create_pipe(sync_pipe, O_CLOEXEC);

    /* set up clone flags */
    int clone_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
                      CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD;
    if (userns) clone_flags |= CLONE_NEWUSER;

    /* allocate child stack */
    void *stack = lc_kernel_map_memory(NULL, CHILD_STACK_SIZE,
                                        PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) die("Error: failed to allocate child stack");
    void *stack_top = (char *)stack + CHILD_STACK_SIZE;

    /* prepare child args */
    struct child_args ca = {
        .sync_pipe_rd = sync_pipe[0],
        .sync_pipe_wr = sync_pipe[1],
        .name = name,
        .root = root,
        .userns = userns,
        .privileged = privileged,
        .read_only = read_only,
    };

    /* clone — lc_kernel_clone places fn+arg on the child's stack before
     * the syscall, so the child never touches our stack frame */
    lc_sysret child_pid = lc_kernel_clone(clone_flags, stack_top,
                                           container_child, &ca);
    if (child_pid < 0) die("Error: clone failed");

    /* parent continues */
    lc_kernel_close_file(sync_pipe[0]);

    /* write uid/gid maps if userns */
    if (userns) {
        char proc_path[64], map_buf[32];
        char pidbuf[16]; fmt_int(pidbuf, (int)child_pid);

        /* deny setgroups */
        size_t pp = str_copy(proc_path, "/proc/", sizeof(proc_path));
        pp = str_append(proc_path, pp, pidbuf, sizeof(proc_path));
        str_append(proc_path, pp, "/setgroups", sizeof(proc_path));
        write_file(proc_path, "deny");

        /* uid_map */
        pp = str_copy(proc_path, "/proc/", sizeof(proc_path));
        pp = str_append(proc_path, pp, pidbuf, sizeof(proc_path));
        str_append(proc_path, pp, "/uid_map", sizeof(proc_path));
        {
            size_t mp = str_copy(map_buf, "0 ", sizeof(map_buf));
            char ub[16]; fmt_int(ub, uid_start);
            mp = str_append(map_buf, mp, ub, sizeof(map_buf));
            str_append(map_buf, mp, " 65536", sizeof(map_buf));
        }
        write_file(proc_path, map_buf);

        /* gid_map */
        pp = str_copy(proc_path, "/proc/", sizeof(proc_path));
        pp = str_append(proc_path, pp, pidbuf, sizeof(proc_path));
        str_append(proc_path, pp, "/gid_map", sizeof(proc_path));
        write_file(proc_path, map_buf);
    }

    /*
     * Set up cgroup, networking, and OOM score BEFORE unblocking the child.
     * While the child is blocked on the sync pipe it is guaranteed alive,
     * so all operations that reference its PID or network namespace succeed.
     */

    /* set up cgroup */
    cgroup_create(name, (int)child_pid);

    /* move veth into container network namespace */
    {
        char nsbuf[16]; fmt_int(nsbuf, (int)child_pid);
        char *a[] = { "ip", "link", "set", veth_cont, "netns", nsbuf, NULL };
        run_cmd("/sbin/ip", a);
    }

    /* configure networking inside the container */
    {
        char nsbuf[16]; fmt_int(nsbuf, (int)child_pid);
        char ip_cidr[20];
        str_copy(ip_cidr, ip, sizeof(ip_cidr));
        str_append(ip_cidr, lc_string_length(ip_cidr), "/24", sizeof(ip_cidr));

        char *a1[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "link", "set", veth_cont, "up", NULL };
        run_cmd("/usr/bin/nsenter", a1);
        char *a2[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "addr", "add", ip_cidr, "dev", veth_cont, NULL };
        run_cmd("/usr/bin/nsenter", a2);
        char *a3[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "route", "add", "default", "via", cfg_global.gw, NULL };
        run_cmd("/usr/bin/nsenter", a3);
    }

    /* set OOM score */
    {
        char oom_path[64], oom_buf[16];
        char pidb[16]; fmt_int(pidb, (int)child_pid);
        size_t pp = str_copy(oom_path, "/proc/", sizeof(oom_path));
        pp = str_append(oom_path, pp, pidb, sizeof(oom_path));
        str_append(oom_path, pp, "/oom_score_adj", sizeof(oom_path));
        fmt_int(oom_buf, oom_score);
        write_file(oom_path, oom_buf);
    }

    /* unblock the child — it can now set up mounts, pivot_root, and exec init */
    lc_kernel_write_bytes(sync_pipe[1], "x", 1);
    lc_kernel_close_file(sync_pipe[1]);

    /* wait for child to finish setup, then verify it's alive */
    lc_timespec ts = { .seconds = 0, .nanoseconds = 500000000 }; /* 500ms */
    lc_kernel_sleep(&ts);

    if (lc_kernel_send_signal((int32_t)child_pid, 0) < 0) {
        print_str(STDERR, "Error: container process died during startup\n");
        char *a[] = { "ip", "link", "delete", veth_host, NULL };
        run_cmd("/sbin/ip", a);
        cgroup_destroy(name);
        lc_kernel_exit(1);
    }

    /* write PID file only after confirming the child is alive */
    char pid_path[MAX_PATH], pidbuf[16];
    container_pid_path(pid_path, name);
    fmt_int(pidbuf, (int)child_pid);
    write_file(pid_path, pidbuf);

    /* set up --link rules: allow traffic between this container and linked ones */
    {
        char conf_buf2[2048];
        char conf_p[MAX_PATH];
        container_conf_path(conf_p, name);
        if (read_file(conf_p, conf_buf2, sizeof(conf_buf2)) > 0) {
            char *p = conf_buf2;
            while (*p) {
                if (p[0] == 'l' && p[1] == 'i' && p[2] == 'n' && p[3] == 'k' && p[4] == '=') {
                    char link_name[NAME_MAX_LEN + 1];
                    char *v = p + 5;
                    char *end = v;
                    while (*end && *end != '\n') end++;
                    size_t ln = (size_t)(end - v);
                    if (ln > NAME_MAX_LEN) ln = NAME_MAX_LEN;
                    lc_bytes_copy(link_name, v, ln);
                    link_name[ln] = '\0';

                    /* look up the linked container's IP */
                    char link_ip_path[MAX_PATH], link_ip[16];
                    container_ip_path(link_ip_path, link_name);
                    if (read_file(link_ip_path, link_ip, sizeof(link_ip)) > 0) {
                        for (int j = 0; link_ip[j]; j++)
                            if (link_ip[j] == '\n') { link_ip[j] = '\0'; break; }

                        /* insert ACCEPT rules for both directions (before the DROP) */
                        char *c1[] = { "iptables", "-C", "FORWARD",
                                       "-s", ip, "-d", link_ip,
                                       "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                       "-j", "ACCEPT", NULL };
                        char *a1[] = { "iptables", "-I", "FORWARD",
                                       "-s", ip, "-d", link_ip,
                                       "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                       "-j", "ACCEPT", NULL };
                        iptables_idempotent(c1, a1);
                        char *c2[] = { "iptables", "-C", "FORWARD",
                                       "-s", link_ip, "-d", ip,
                                       "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                       "-j", "ACCEPT", NULL };
                        char *a2[] = { "iptables", "-I", "FORWARD",
                                       "-s", link_ip, "-d", ip,
                                       "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                       "-j", "ACCEPT", NULL };
                        iptables_idempotent(c2, a2);
                    }
                }
                while (*p && *p != '\n') p++;
                if (*p == '\n') p++;
            }
        }
    }

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' started (pid=");
    lc_print_unsigned(STDOUT, (uint64_t)child_pid);
    print_str(STDOUT,", ip=");
    print_str(STDOUT,ip);
    print_str(STDOUT,")\n");
    print_str(STDOUT,"Attach with: lightbox exec ");
    print_str(STDOUT,name);
    print_str(STDOUT," /bin/sh\n");

    /* free child stack */
    lc_kernel_unmap_memory(stack, CHILD_STACK_SIZE);
}

/* ─── cmd_stop ──────────────────────────────────────────────────────────── */

static void cmd_stop(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox stop <name>");
    const char *name = argv[0];
    validate_name(name);

    if (!is_running(name)) die2("Error: container is not running: ", name);

    int pid = get_container_pid(name);

    print_str(STDOUT,"Stopping container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");

    /* PID 1 in a PID namespace only receives signals it has registered
     * handlers for.  sleep(1) doesn't handle SIGTERM, so send SIGKILL
     * directly — killing PID 1 destroys the entire PID namespace. */
    lc_kernel_send_signal(pid, SIGKILL);

    /* wait for process to exit */
    for (int i = 0; i < 10; i++) {
        lc_timespec ts = { .seconds = 0, .nanoseconds = 200000000 };
        lc_kernel_sleep(&ts);
        if (lc_kernel_send_signal(pid, 0) < 0) break;
    }

    /* wait for child to reap */
    int32_t status;
    lc_kernel_wait_for_child(pid, &status, WNOHANG);

    /* clean up cgroup */
    cgroup_destroy(name);

    /* clean up link iptables rules */
    {
        char ip_path[MAX_PATH], ip_buf[16];
        container_ip_path(ip_path, name);
        if (read_file(ip_path, ip_buf, sizeof(ip_buf)) > 0) {
            for (int j = 0; ip_buf[j]; j++)
                if (ip_buf[j] == '\n') { ip_buf[j] = '\0'; break; }
            /* delete any FORWARD rules referencing this container's IP on br0 */
            char *d1[] = { "sh", "-c",
                "iptables -S FORWARD 2>/dev/null | grep -- '-s ' | grep -- ' -i br0 ' | "
                "while IFS= read -r rule; do "
                "  case \"$rule\" in *" /* match container IP */ ") ;; *) continue;; esac; "
                "  eval iptables $(echo \"$rule\" | sed 's/^-A/-D/'); "
                "done", NULL };
            (void)d1;
            /* simpler approach: just try to delete rules with this IP */
            char conf_buf3[2048], conf_p[MAX_PATH];
            container_conf_path(conf_p, name);
            if (read_file(conf_p, conf_buf3, sizeof(conf_buf3)) > 0) {
                char *p = conf_buf3;
                while (*p) {
                    if (p[0] == 'l' && p[1] == 'i' && p[2] == 'n' && p[3] == 'k' && p[4] == '=') {
                        char link_name[NAME_MAX_LEN + 1];
                        char *v = p + 5, *end = v;
                        while (*end && *end != '\n') end++;
                        size_t ln = (size_t)(end - v);
                        if (ln > NAME_MAX_LEN) ln = NAME_MAX_LEN;
                        lc_bytes_copy(link_name, v, ln);
                        link_name[ln] = '\0';

                        char link_ip_path[MAX_PATH], link_ip[16];
                        container_ip_path(link_ip_path, link_name);
                        if (read_file(link_ip_path, link_ip, sizeof(link_ip)) > 0) {
                            for (int k = 0; link_ip[k]; k++)
                                if (link_ip[k] == '\n') { link_ip[k] = '\0'; break; }
                            char *c1[] = { "iptables", "-C", "FORWARD",
                                           "-s", ip_buf, "-d", link_ip,
                                           "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                           "-j", "ACCEPT", NULL };
                            char *r1[] = { "iptables", "-D", "FORWARD",
                                           "-s", ip_buf, "-d", link_ip,
                                           "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                           "-j", "ACCEPT", NULL };
                            if (iptables_check(c1) == 0)
                                run_cmd("/usr/sbin/iptables", r1);
                            char *c2[] = { "iptables", "-C", "FORWARD",
                                           "-s", link_ip, "-d", ip_buf,
                                           "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                           "-j", "ACCEPT", NULL };
                            char *r2[] = { "iptables", "-D", "FORWARD",
                                           "-s", link_ip, "-d", ip_buf,
                                           "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                           "-j", "ACCEPT", NULL };
                            if (iptables_check(c2) == 0)
                                run_cmd("/usr/sbin/iptables", r2);
                        }
                    }
                    while (*p && *p != '\n') p++;
                    if (*p == '\n') p++;
                }
            }
        }
    }

    /* clean up veth if it exists */
    {
        char veth_host[16];
        size_t p = str_copy(veth_host, "vb-", sizeof(veth_host));
        str_append(veth_host, p, name, sizeof(veth_host));
        char *show[] = { "ip", "link", "show", veth_host, NULL };
        if (run_cmd_quiet("/sbin/ip", show) == 0) {
            char *del[] = { "ip", "link", "delete", veth_host, NULL };
            run_cmd("/sbin/ip", del);
        }
    }

    /* remove PID file */
    char pid_path[MAX_PATH];
    container_pid_path(pid_path, name);
    lc_kernel_unlinkat(AT_FDCWD, pid_path, 0);

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' stopped\n");
}

/* ─── cmd_rm ────────────────────────────────────────────────────────────── */

static void cmd_rm(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox rm <name>");
    const char *name = argv[0];
    validate_name(name);

    if (is_running(name)) die2("Error: container is running (stop it first): ", name);

    char cdir[MAX_PATH];
    container_dir_path(cdir, name);
    if (!path_exists(cdir)) die2("Error: container does not exist: ", name);

    print_str(STDOUT,"Removing container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");

    cgroup_destroy(name);

    /* remove entire container directory (rootfs + metadata) */
    rm_rf(cdir);

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' removed\n");
}

/* ─── cmd_exec ──────────────────────────────────────────────────────────── */

static void cmd_exec(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox exec <name> [cmd...]");
    const char *name = argv[0];
    validate_name(name);

    if (!is_running(name)) die2("Error: container is not running: ", name);

    int pid = get_container_pid(name);
    int userns = conf_get_int(name, "userns", 0);
    int privileged = conf_get_int(name, "privileged", 0);

    /* build nsenter command */
    char pidbuf[16]; fmt_int(pidbuf, pid);

    (void)privileged; /* TODO: apply sandbox to exec'd processes */

    /* build argv for nsenter:
     * nsenter -t PID [-U] -m -u -i -n -p -- cmd [args...]
     */
    char *ns_argv[32];
    int ai = 0;
    ns_argv[ai++] = "nsenter";
    ns_argv[ai++] = "-t";
    ns_argv[ai++] = pidbuf;
    if (userns) ns_argv[ai++] = "-U";
    ns_argv[ai++] = "-m";
    ns_argv[ai++] = "-u";
    ns_argv[ai++] = "-i";
    ns_argv[ai++] = "-n";
    ns_argv[ai++] = "-p";
    ns_argv[ai++] = "-r";
    ns_argv[ai++] = "-w";
    ns_argv[ai++] = "--";

    if (argc > 1) {
        for (int i = 1; i < argc && ai < 30; i++)
            ns_argv[ai++] = argv[i];
    } else {
        ns_argv[ai++] = "/bin/sh";
    }
    ns_argv[ai] = NULL;

    char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "TERM=xterm", NULL };
    lc_kernel_execute("/usr/bin/nsenter", ns_argv, envp);
    die("Error: failed to exec nsenter");
}

/* ─── cmd_ls ────────────────────────────────────────────────────────────── */

static void print_padded(const char *s, int width) {
    print_str(STDOUT,s);
    int len = (int)lc_string_length(s);
    for (int i = len; i < width; i++) lc_print_char(STDOUT, ' ');
}

static void cmd_ls(void) {
    print_padded("NAME", 20);
    print_padded("IP", 16);
    print_padded("STATUS", 10);
    print_str(STDOUT,"PID\n");
    print_padded("----", 20);
    print_padded("--", 16);
    print_padded("------", 10);
    print_str(STDOUT,"---\n");

    /* scan container directory */
    lc_sysret dirfd = lc_kernel_open_file(cfg_global.container_dir, O_RDONLY, 0);
    if (dirfd < 0) return;

    char dirbuf[4096];
    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)dirfd, dirbuf, sizeof(dirbuf));
        if (n <= 0) break;

        int64_t pos = 0;
        while (pos < n) {
            /* struct linux_dirent64 */
            uint64_t ino = *(uint64_t *)(dirbuf + pos);
            (void)ino;
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            uint8_t dtype = *(uint8_t *)(dirbuf + pos + 18);
            char *dname = dirbuf + pos + 19;

            if (dtype == 4 /* DT_DIR */ && dname[0] != '.') {
                /* this is a container */
                char ip_buf[16] = "-";
                char ip_path[MAX_PATH];
                container_ip_path(ip_path, dname);
                read_file(ip_path, ip_buf, sizeof(ip_buf));
                /* strip newline */
                for (int i = 0; ip_buf[i]; i++) { if (ip_buf[i] == '\n') { ip_buf[i] = '\0'; break; } }

                const char *status = "stopped";
                char pid_str[16] = "-";
                if (is_running(dname)) {
                    status = "running";
                    fmt_int(pid_str, get_container_pid(dname));
                }

                print_padded(dname, 20);
                print_padded(ip_buf, 16);
                print_padded(status, 10);
                print_str(STDOUT,pid_str);
                lc_print_char(STDOUT, '\n');
            }
            pos += reclen;
        }
    }
    lc_kernel_close_file((int32_t)dirfd);
}

/* ─── Usage ─────────────────────────────────────────────────────────────── */

static void usage(void) {
    print_str(STDERR,
        "Usage: lightbox <command> [args]\n"
        "\n"
        "Commands:\n"
        "  create <name> <ip> [options]  Create a new container\n"
        "         --mem  <limit>         Memory limit (default: 256M)\n"
        "         --pids <limit>         Max processes (default: 128)\n"
        "         --cpu  <num>           CPU cores (default: 1)\n"
        "         --vol  <src:dst[:ro]>  Bind mount (repeatable)\n"
        "         --rootfs <path>         Base rootfs to copy (default: $LIGHTBOX_ROOTFS or lightbox.conf)\n"
        "         --userns               Enable user namespace isolation\n"
        "         --uid-start <n>        Host UID offset (default: auto)\n"
        "         --read-only            Read-only root filesystem\n"
        "         --privileged           Disable security sandbox\n"
        "         --oom-score <n>        OOM score adjustment (default: 500)\n"
        "         --link <name>          Allow network to another container\n"
        "  start  <name>                 Start a stopped container\n"
        "  stop   <name>                 Stop a running container\n"
        "  rm     <name>                 Remove a container (must be stopped)\n"
        "  exec   <name> [cmd...]        Execute a command in a running container\n"
        "  ls                            List all containers\n"
        "  setup                         Setup host networking\n"
    );
    lc_kernel_exit(1);
}

/* ─── main ──────────────────────────────────────────────────────────────── */

int main(int argc, char **argv, char **envp) {
    if (argc < 2) usage();

    /* load configuration: built-in defaults → lightbox.conf → env vars */
    cfg_global_init();
    cfg_global_load(envp);

    const char *cmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (streq(cmd, "setup"))       cmd_setup();
    else if (streq(cmd, "create")) cmd_create(sub_argc, sub_argv);
    else if (streq(cmd, "start"))  cmd_start(sub_argc, sub_argv);
    else if (streq(cmd, "stop"))   cmd_stop(sub_argc, sub_argv);
    else if (streq(cmd, "rm"))     cmd_rm(sub_argc, sub_argv);
    else if (streq(cmd, "exec"))   cmd_exec(sub_argc, sub_argv);
    else if (streq(cmd, "ls"))     cmd_ls();
    else                           usage();

    return 0;
}
