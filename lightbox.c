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

#include "lightbox.h"

/* ─── Compile-time limits ───────────────────────────────────────────────── */

#define MAX_PATH         512
#define MAX_VOLS         16
#define MAX_LINKS        8
#define NAME_MAX_LEN     12
#define CONF_BUF_SIZE    2048
#define USERNS_RANGE_SIZE 65536
#define USERNS_MIN_START 100000
#define CHILD_STACK_SIZE (1024 * 1024) /* 1 MiB */

/* ─── Configurable defaults ─────────────────────────────────────────────── */

#define LIGHTBOX_CONF_PATH  "/.config/lightbox/lightbox.conf"

/* All runtime-configurable values live here. Initialized to built-in defaults,
 * then overridden by lightbox.conf if present. */
global_config cfg_global;

/* cfg_global_init() and cfg_global_load() defined after utility functions */

/* prctl constants */
#define PR_SET_NO_NEW_PRIVS  38
#define PR_SET_KEEPCAPS      8
#define PR_CAPBSET_READ      23
#define PR_CAPBSET_DROP      24
#define PR_SET_SECCOMP       22

/* seccomp constants */
#define SECCOMP_MODE_FILTER    2
#define SECCOMP_RET_ALLOW      0x7fff0000
#define SECCOMP_RET_ERRNO      0x00050000
#define SECCOMP_RET_KILL_PROCESS 0x80000000U

/* seccomp/audit constants */
#define AUDIT_ARCH_X86_64      0xc000003eU

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

/* raw syscall numbers used by lightbox directly */
#define SYS_fchdir      81
#define SYS_chroot      161
#if defined(__x86_64__)
#define SYS_capget      125
#define SYS_capset      126
#elif defined(__aarch64__)
#define SYS_capget      90
#define SYS_capset      91
#else
#error "Unsupported architecture"
#endif

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

struct user_cap_header {
    uint32_t version;
    int32_t pid;
};

struct user_cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

/* seccomp_data layout — offset of 'nr' is 0 */
#define SECCOMP_DATA_NR_OFFSET 0
#define SECCOMP_DATA_ARCH_OFFSET 4

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

static bool parse_u32_strict(const char *s, uint32_t *out) {
    uint32_t val = 0;
    if (!s || !s[0]) return false;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c < '0' || c > '9') return false;
        val = val * 10u + (uint32_t)(c - '0');
    }
    *out = val;
    return true;
}

static bool parse_ipv4(const char *s, uint8_t out[4]) {
    uint32_t cur = 0;
    int octet = 0;
    bool have_digit = false;
    if (!s || !s[0]) return false;

    for (size_t i = 0;; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            have_digit = true;
            cur = cur * 10u + (uint32_t)(c - '0');
            if (cur > 255u) return false;
        } else if (c == '.' || c == '\0') {
            if (!have_digit || octet >= 4) return false;
            out[octet++] = (uint8_t)cur;
            cur = 0;
            have_digit = false;
            if (c == '\0') break;
        } else {
            return false;
        }
    }

    return octet == 4;
}

static uint32_t ipv4_to_u32(const uint8_t ip[4]) {
    return ((uint32_t)ip[0] << 24) |
           ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8) |
           (uint32_t)ip[3];
}

static bool parse_cidr_ipv4(const char *cidr, uint8_t net[4], uint32_t *prefix) {
    const char *slash = NULL;
    for (const char *p = cidr; *p; p++) {
        if (*p == '/') { slash = p; break; }
    }
    if (!slash) return false;

    char ip_part[20];
    size_t ip_len = (size_t)(slash - cidr);
    if (ip_len == 0 || ip_len >= sizeof(ip_part)) return false;
    lc_bytes_copy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    if (!parse_ipv4(ip_part, net)) return false;
    if (!parse_u32_strict(slash + 1, prefix)) return false;
    return *prefix <= 32u;
}

static void validate_ipv4_address(const char *ip) {
    uint8_t tmp[4];
    if (!parse_ipv4(ip, tmp))
        die2("Error: invalid IPv4 address: ", ip);
}

static void validate_ip_in_subnet(const char *ip, const char *cidr) {
    uint8_t ip_octets[4], net_octets[4];
    uint32_t prefix = 0;
    if (!parse_ipv4(ip, ip_octets))
        die2("Error: invalid IPv4 address: ", ip);
    if (!parse_cidr_ipv4(cidr, net_octets, &prefix))
        die2("Error: invalid subnet in config: ", cidr);

    uint32_t mask = (prefix == 0) ? 0u : (0xffffffffu << (32u - prefix));
    if ((ipv4_to_u32(ip_octets) & mask) != (ipv4_to_u32(net_octets) & mask))
        die2("Error: IP is outside configured subnet: ", ip);
}

static void validate_positive_integer_option(const char *label, const char *value) {
    uint32_t parsed;
    if (!parse_u32_strict(value, &parsed) || parsed == 0)
        die2(label, value);
}

static void validate_oom_score(int oom_score) {
    if (oom_score < -1000 || oom_score > 1000)
        die("Error: oom-score must be between -1000 and 1000");
}

static void validate_volume_paths(const char *src, const char *dst) {
    if (!src[0]) die("Error: volume source must not be empty");
    if (src[0] != '/') die2("Error: volume source must be an absolute path: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/proc", 5) &&
        (src[5] == '\0' || src[5] == '/'))
        die2("Error: volume source under /proc is not allowed: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/sys", 4) &&
        (src[4] == '\0' || src[4] == '/'))
        die2("Error: volume source under /sys is not allowed: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/dev", 4) &&
        (src[4] == '\0' || src[4] == '/'))
        die2("Error: volume source under /dev is not allowed: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/.old_root", 10))
        die2("Error: reserved volume source: ", src);
    if (!dst[0]) die("Error: volume destination must not be empty");
    if (dst[0] != '/') die2("Error: volume destination must be an absolute container path: ", dst);
    if (streq(dst, "/")) die("Error: mounting over / is not allowed");
    if (lc_string_starts_with(dst, lc_string_length(dst), "/proc", 5) &&
        (dst[5] == '\0' || dst[5] == '/'))
        die2("Error: volume destination under /proc is not allowed: ", dst);
    if (lc_string_starts_with(dst, lc_string_length(dst), "/sys", 4) &&
        (dst[4] == '\0' || dst[4] == '/'))
        die2("Error: volume destination under /sys is not allowed: ", dst);
    if (lc_string_starts_with(dst, lc_string_length(dst), "/dev", 4) &&
        (dst[4] == '\0' || dst[4] == '/'))
        die2("Error: volume destination under /dev is not allowed: ", dst);
    if (lc_string_starts_with(dst, lc_string_length(dst), "/.old_root", 10))
        die2("Error: reserved volume destination: ", dst);
}

/* Validate container name: [a-zA-Z0-9_-], max 12 chars */
void validate_name(const char *name) {
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

static bool uid_ranges_overlap(int start_a, int start_b) {
    int end_a = start_a + USERNS_RANGE_SIZE;
    int end_b = start_b + USERNS_RANGE_SIZE;
    return !(end_a <= start_b || end_b <= start_a);
}

static bool userns_range_in_use(const char *exclude_name, int uid_start) {
    lc_sysret dirfd = lc_kernel_open_file(cfg_global.container_dir, O_RDONLY, 0);
    if (dirfd < 0) return false;

    char dirbuf[4096];
    bool in_use = false;

    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)dirfd, dirbuf, sizeof(dirbuf));
        if (n <= 0) break;

        int64_t pos = 0;
        while (pos < n) {
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            uint8_t dtype = *(uint8_t *)(dirbuf + pos + 18);
            char *dname = dirbuf + pos + 19;

            if (dtype == 4 /* DT_DIR */ && dname[0] != '.') {
                if (exclude_name && streq(dname, exclude_name)) {
                    pos += reclen;
                    continue;
                }

                if (conf_get_int(dname, "userns", 0)) {
                    int existing = conf_get_int(dname, "uid_start", 0);
                    if (existing > 0 && uid_ranges_overlap(existing, uid_start)) {
                        in_use = true;
                        break;
                    }
                }
            }
            pos += reclen;
        }
        if (in_use) break;
    }

    lc_kernel_close_file((int32_t)dirfd);
    return in_use;
}

static int allocate_uid_start(const char *exclude_name) {
    int candidate = USERNS_MIN_START;
    for (int i = 0; i < 4096; i++, candidate += USERNS_RANGE_SIZE) {
        if (!userns_range_in_use(exclude_name, candidate))
            return candidate;
    }
    return -1;
}

/* ─── Cgroup management ─────────────────────────────────────────────────── */

static void cgroup_path(char *buf, const char *name) {
    path_join(buf, MAX_PATH, cfg_global.cgroup_base, name);
}

static int cgroup_create(const char *name, int pid) {
    char cg[MAX_PATH], tmp[MAX_PATH];
    cgroup_path(cg, name);

    /* ensure parent exists and has controllers */
    lc_kernel_mkdirat(AT_FDCWD, cfg_global.cgroup_base, 0755);

    path_join(tmp, MAX_PATH, cfg_global.cgroup_root, "cgroup.subtree_control");
    if (write_file(tmp, "+memory +pids +cpu +io") < 0) return -1;
    path_join(tmp, MAX_PATH, cfg_global.cgroup_base, "cgroup.subtree_control");
    if (write_file(tmp, "+memory +pids +cpu +io") < 0) return -1;

    lc_kernel_mkdirat(AT_FDCWD, cg, 0755);

    /* read limits from config */
    char mem[16], pids[8], cpu[4];
    conf_get(name, "mem", mem, sizeof(mem), cfg_global.default_mem);
    conf_get(name, "pids", pids, sizeof(pids), cfg_global.default_pids);
    conf_get(name, "cpu", cpu, sizeof(cpu), cfg_global.default_cpu);

    path_join(tmp, MAX_PATH, cg, "memory.max");
    if (write_file(tmp, mem) < 0) return -1;

    path_join(tmp, MAX_PATH, cg, "pids.max");
    if (write_file(tmp, pids) < 0) return -1;

    /* cpu: convert cores to quota */
    int cores = parse_int(cpu);
    if (cores < 1) cores = 1;
    char cpu_max[32];
    int quota = cores * 100000;
    int len = fmt_int(cpu_max, quota);
    str_append(cpu_max, (size_t)len, " 100000", sizeof(cpu_max));
    path_join(tmp, MAX_PATH, cg, "cpu.max");
    if (write_file(tmp, cpu_max) < 0) return -1;

    /* io limits */
    char io_spec[128];
    if (conf_get(name, "io", io_spec, sizeof(io_spec), "") && io_spec[0]) {
        path_join(tmp, MAX_PATH, cg, "io.max");
        if (write_file(tmp, io_spec) < 0) return -1;
    }

    /* move container process into this cgroup */
    char pidbuf[16];
    fmt_int(pidbuf, pid);
    path_join(tmp, MAX_PATH, cg, "cgroup.procs");
    if (write_file(tmp, pidbuf) < 0) return -1;
    return 0;
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

static void cgroup_join_self(const char *name) {
    char cg[MAX_PATH], procs_path[MAX_PATH], pidbuf[16];
    cgroup_path(cg, name);
    path_join(procs_path, MAX_PATH, cg, "cgroup.procs");
    fmt_int(pidbuf, lc_kernel_get_process_id());
    require_write_file(procs_path, pidbuf);
}

/* ─── Security: capabilities ────────────────────────────────────────────── */

/* Default non-privileged container capabilities.
 * Deliberately stricter than Docker's historical default:
 * - no CAP_NET_RAW: avoid raw sockets/packet capture by default
 * - no CAP_MKNOD: device node creation is unnecessary with our fixed /dev setup
 */
static const int ALLOWED_CAPS[] = {
    CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID,
    CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP,
    CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT,
    CAP_AUDIT_WRITE, CAP_SETFCAP,
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
    425,  /* io_uring_setup */
    426,  /* io_uring_enter */
    427,  /* io_uring_register */
    175,  /* init_module */
    173,  /* ioperm */
    172,  /* iopl */
    312,  /* kcmp */
    320,  /* kexec_file_load */
    246,  /* kexec_load */
    250,  /* keyctl */
    212,  /* lookup_dcookie */
    237,  /* mbind */
    256,  /* migrate_pages */
    /* 40, mount — allowed for container setup, blocked by caps */
    429,  /* move_mount */
    279,  /* move_pages */
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
    435,  /* clone3 */
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
     * Total instructions:
     *   1 arch load + 1 arch check + 1 kill +
     *   1 nr load + 2*N (check+deny per syscall) + 1 allow
     */
    size_t n = N_BLOCKED_SYSCALLS;
    size_t prog_len = 4 + 2 * n + 1;
    struct sock_filter filter[256]; /* plenty of room */

    if (prog_len > sizeof(filter) / sizeof(filter[0]))
        die("Error: seccomp program too large");

    size_t idx = 0;

    /* kill mismatched syscall ABIs */
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET);
    filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

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

    if (lc_kernel_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uint64_t)&prog, 0, 0) < 0)
        die("Error: failed to install seccomp filter");
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

/* ─── cmd_create ────────────────────────────────────────────────────────── */

static void cmd_create(int argc, char **argv) {
    require_tool("cp", tool_path_cp());
    if (argc < 2) die("Usage: lightbox create <name> <ip> [options]");
    const char *name = argv[0];
    const char *ip = argv[1];
    validate_name(name);
    validate_ipv4_address(ip);
    validate_ip_in_subnet(ip, cfg_global.subnet);

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
            validate_positive_integer_option("Error: pids must be a positive integer: ", cfg.pids);
        } else if (streq(argv[i], "--cpu") && i + 1 < argc) {
            str_copy(cfg.cpu, argv[++i], sizeof(cfg.cpu));
            validate_positive_integer_option("Error: cpu must be a positive integer: ", cfg.cpu);
        } else if (streq(argv[i], "--userns")) {
            die("Error: --userns is not supported yet");
        } else if (streq(argv[i], "--uid-start") && i + 1 < argc) {
            (void)argv[++i];
            die("Error: --uid-start is not supported yet");
        } else if (streq(argv[i], "--privileged")) {
            cfg.privileged = 1;
        } else if (streq(argv[i], "--rootfs") && i + 1 < argc) {
            str_copy(cfg_global.rootfs, argv[++i], MAX_PATH);
        } else if (streq(argv[i], "--read-only")) {
            cfg.read_only = 1;
        } else if (streq(argv[i], "--oom-score") && i + 1 < argc) {
            cfg.oom_score = parse_int(argv[++i]);
            validate_oom_score(cfg.oom_score);
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
            validate_volume_paths(cfg.vol_src[cfg.nvols], cfg.vol_dst[cfg.nvols]);

            if (colon2 && colon2[1] == 'r' && colon2[2] == 'o' && colon2[3] == '\0')
                cfg.vol_ro[cfg.nvols] = 1;
            else if (colon2)
                die2("Error: invalid volume mode in spec: ", spec);
            cfg.nvols++;
        } else if (streq(argv[i], "--link") && i + 1 < argc) {
            if (cfg.nlinks >= MAX_LINKS) die("Error: too many links");
            validate_name(argv[i + 1]);
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

    const char *create_err = NULL;
    bool created_dir = false;

    /* create container directory and copy rootfs into it */
    if (lc_kernel_mkdirat(AT_FDCWD, cdir, 0755) < 0) {
        create_err = "failed to create container dir";
        goto fail_create;
    }
    created_dir = true;
    set_container_state(name, "creating\n");
    if (!path_exists(cfg_global.rootfs)) {
        create_err = "rootfs not found";
        goto fail_create;
    }
    {
        lc_sysret pid = lc_kernel_fork();
        if (pid == 0) {
            char *argv2[] = { "cp", "-a", (char *)cfg_global.rootfs, root, NULL };
            char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
            lc_kernel_execute(tool_path_cp(), argv2, envp);
            lc_kernel_exit(1);
        }
        int32_t status;
        lc_kernel_wait_for_child((int32_t)pid, &status, 0);
        if (((status >> 8) & 0xff) != 0) {
            create_err = "failed to copy rootfs";
            goto fail_create;
        }
    }

    /* store IP */
    char ip_path[MAX_PATH];
    container_ip_path(ip_path, name);
    if (write_file_atomic(ip_path, ip) < 0) {
        create_err = "failed to write IP metadata";
        goto fail_create;
    }

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
        if (cfg.uid_start == 0) {
            cfg.uid_start = allocate_uid_start(name);
            if (cfg.uid_start <= 0) {
                create_err = "failed to allocate uid_start";
                goto fail_create;
            }
        }
        if (cfg.uid_start < USERNS_MIN_START) {
            create_err = "uid_start is below the managed userns range";
            goto fail_create;
        }
        if (userns_range_in_use(name, cfg.uid_start)) {
            create_err = "uid_start overlaps an existing container userns range";
            goto fail_create;
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
    if (write_file_atomic(conf_path, conf_buf) < 0) {
        create_err = "failed to write container config";
        goto fail_create;
    }

    /* write resolv.conf */
    char resolv[MAX_PATH];
    path_join(resolv, MAX_PATH, root, "etc/resolv.conf");
    if (write_file_atomic(resolv, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n") < 0) {
        create_err = "failed to write resolv.conf";
        goto fail_create;
    }

    /* shift rootfs ownership for user namespace */
    if (cfg.userns && cfg.uid_start > 0) {
        require_tool("chown", tool_path_chown());
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
            lc_kernel_execute(tool_path_chown(), argv2, envp);
            lc_kernel_exit(1);
        }
        int32_t status;
        lc_kernel_wait_for_child((int32_t)pid, &status, 0);
        if (((status >> 8) & 0xff) != 0) {
            create_err = "failed to shift rootfs ownership";
            goto fail_create;
        }
    }

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' created (ip=");
    print_str(STDOUT,ip);
    print_str(STDOUT,")\n");
    set_container_state(name, "stopped\n");
    return;

fail_create:
    if (create_err) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, create_err);
        if (streq(create_err, "rootfs not found")) {
            print_str(STDERR, ": ");
            print_str(STDERR, cfg_global.rootfs);
        }
        lc_print_char(STDERR, '\n');
    }
    if (created_dir)
        require_rm_rf(cdir);
    lc_kernel_exit(1);
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

static uint64_t sigmask_from_signal(int signum) {
    return (signum > 0 && signum <= 64) ? (1ULL << (uint64_t)(signum - 1)) : 0;
}

static uint64_t supervisor_signal_mask(void) {
    return sigmask_from_signal(SIGHUP) |
           sigmask_from_signal(SIGINT) |
           sigmask_from_signal(SIGQUIT) |
           sigmask_from_signal(SIGTERM) |
           sigmask_from_signal(SIGCHLD);
}

static void reap_children_nonblock(void) {
    for (;;) {
        int32_t status;
        lc_sysret pid = lc_kernel_wait_for_child(-1, &status, WNOHANG);
        if (pid <= 0) break;
    }
}

static void run_init_hook_if_present(void) {
    if (!path_exists("/init.sh")) return;

    lc_sysret p = lc_kernel_fork();
    if (p == 0) {
        uint64_t empty_mask = 0;
        lc_kernel_set_signal_mask(LC_SIG_SETMASK, &empty_mask, NULL);
        char *a[] = { "/bin/sh", "/init.sh", NULL };
        char *e[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "TERM=xterm", NULL };
        lc_kernel_execute("/bin/sh", a, e);
        lc_kernel_exit(1);
    }

    int32_t st;
    lc_kernel_wait_for_child((int32_t)p, &st, 0);
    if (((st >> 8) & 0xff) != 0)
        die("Error: /init.sh failed");
}

static int supervisor_loop(void) {
    uint64_t mask = supervisor_signal_mask();
    if (lc_kernel_set_signal_mask(LC_SIG_BLOCK, &mask, NULL) < 0)
        die("Error: failed to block supervisor signals");

    lc_sysret sfd = lc_kernel_create_signal_fd(-1, &mask, SFD_CLOEXEC);
    if (sfd < 0)
        die("Error: failed to create signalfd");

    for (;;) {
        lc_signal_info si;
        lc_sysret n = lc_kernel_read_bytes((int32_t)sfd, &si, sizeof(si));
        if (n != (lc_sysret)sizeof(si))
            die("Error: failed to read signalfd");

        switch (si.signal) {
            case SIGCHLD:
                reap_children_nonblock();
                break;
            case SIGHUP:
            case SIGINT:
            case SIGQUIT:
            case SIGTERM:
                reap_children_nonblock();
                lc_kernel_close_file((int32_t)sfd);
                return 0;
            default:
                break;
        }
    }
}

static void build_proc_pid_path(char *buf, size_t bufsz, int pid, const char *suffix) {
    char pidbuf[16];
    fmt_int(pidbuf, pid);
    size_t pos = str_copy(buf, "/proc/", bufsz);
    pos = str_append(buf, pos, pidbuf, bufsz);
    if (suffix && suffix[0])
        str_append(buf, pos, suffix, bufsz);
}

static int open_target_path(int target_pid, const char *suffix) {
    char path[64];
    build_proc_pid_path(path, sizeof(path), target_pid, suffix);
    return (int)lc_kernel_open_file(path, O_RDONLY | O_CLOEXEC, 0);
}

static void require_setns_fd(int fd, int nstype, const char *name) {
    if (lc_kernel_setns(fd, nstype) < 0)
        die2("Error: failed to join namespace: ", name);
}

static int exec_inside_container(const char *name, int target_pid, int userns,
                                 int privileged, char *const cmd_argv[]) {
    int rootfd = open_target_path(target_pid, "/root");
    if (rootfd < 0)
        die("Error: failed to open target root");

    int userfd = -1;
    if (userns) {
        userfd = open_target_path(target_pid, "/ns/user");
        if (userfd < 0)
            die("Error: failed to open target user namespace");
    }

    int mntfd = open_target_path(target_pid, "/ns/mnt");
    int utsfd = open_target_path(target_pid, "/ns/uts");
    int ipcfd = open_target_path(target_pid, "/ns/ipc");
    int netfd = open_target_path(target_pid, "/ns/net");
    int pidfd = open_target_path(target_pid, "/ns/pid");
    if (mntfd < 0 || utsfd < 0 || ipcfd < 0 || netfd < 0 || pidfd < 0)
        die("Error: failed to open target namespace fd");

    if (userns)
        require_setns_fd(userfd, CLONE_NEWUSER, "user");

    /* Join the host-side container cgroup before switching mount namespaces. */
    cgroup_join_self(name);

    require_setns_fd(mntfd, CLONE_NEWNS, "mount");
    require_setns_fd(utsfd, CLONE_NEWUTS, "uts");
    require_setns_fd(ipcfd, CLONE_NEWIPC, "ipc");
    require_setns_fd(netfd, CLONE_NEWNET, "net");

    if (lc_kernel_fchdir(rootfd) < 0)
        die("Error: failed to chdir to target root");
    if (lc_kernel_change_root(".") < 0)
        die("Error: failed to chroot into target root");
    if (lc_kernel_chdir("/") < 0)
        die("Error: failed to chdir to container root");

    require_setns_fd(pidfd, CLONE_NEWPID, "pid");

    lc_sysret child = lc_kernel_fork();
    if (child < 0)
        die("Error: exec helper fork failed");

    if (child == 0) {
        uint64_t empty_mask = 0;
        lc_kernel_set_signal_mask(LC_SIG_SETMASK, &empty_mask, NULL);

        if (!privileged) {
            drop_capabilities();
            if (lc_kernel_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                die("Error: failed to enable no_new_privs");
            apply_seccomp();
        }

        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "TERM=xterm", NULL };
        lc_kernel_execute(cmd_argv[0], cmd_argv, envp);
        die2("Error: failed to exec command: ", cmd_argv[0]);
    }

    int32_t status;
    lc_kernel_wait_for_child((int32_t)child, &status, 0);
    return status;
}

static void cleanup_start_failure(const char *name, const char *ip, const char *veth_host,
                                  int child_pid, void *stack) {
    if (child_pid > 0)
        lc_kernel_send_signal(child_pid, SIGKILL);

    if (veth_host && veth_host[0]) {
        char *show[] = { "ip", "link", "show", (char *)veth_host, NULL };
        if (run_cmd_quiet(tool_path_ip(), show) == 0) {
            char *del[] = { "ip", "link", "delete", (char *)veth_host, NULL };
            run_cmd(tool_path_ip(), del);
        }
    }

    cgroup_destroy(name);
    if (ip && ip[0])
        (void)update_link_rules(name, ip, false);

    {
        char pid_path[MAX_PATH];
        container_pid_path(pid_path, name);
        lc_kernel_unlinkat(AT_FDCWD, pid_path, 0);
        container_pid_start_path(pid_path, name);
        lc_kernel_unlinkat(AT_FDCWD, pid_path, 0);
    }

    set_container_state(name, "failed\n");

    if (stack && stack != MAP_FAILED)
        lc_kernel_unmap_memory(stack, CHILD_STACK_SIZE);
}

static int delete_veth_if_present(const char *ifname) {
    char *show[] = { "ip", "link", "show", (char *)ifname, NULL };
    if (run_cmd_quiet(tool_path_ip(), show) != 0)
        return 0;

    char *del[] = { "ip", "link", "delete", (char *)ifname, NULL };
    return run_cmd(tool_path_ip(), del);
}

static void require_mount_syscall(const char *source, const char *target,
                                  const char *fstype, uint64_t flags, const char *data) {
    if (lc_kernel_mount(source, target, fstype, flags, data) < 0)
        die2("Error: mount failed: ", target);
}

static void enter_user_namespace_root(void) {
    struct user_cap_header hdr = { 0x20080522, 0 };
    struct user_cap_data data[2];

    if (lc_kernel_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
        die("Error: failed to enable keepcaps for userns");
    if (lc_kernel_setgid(0) < 0)
        die("Error: failed to setgid(0) in userns");
    if (lc_kernel_setuid(0) < 0)
        die("Error: failed to setuid(0) in userns");

    if (lc_syscall2(SYS_capget, (int64_t)&hdr, (int64_t)data) < 0)
        die("Error: capget failed in userns");

    data[0].effective = data[0].permitted;
    data[1].effective = data[1].permitted;

    if (lc_syscall2(SYS_capset, (int64_t)&hdr, (int64_t)data) < 0)
        die("Error: capset failed in userns");
}

/*
 * This function runs in the child after clone().
 * It sets up the container filesystem, applies security, and execs init.
 */
static int container_child(void *arg) {
    struct child_args *ca = (struct child_args *)arg;

    /* close the write end so we only read */
    lc_kernel_close_file(ca->sync_pipe_wr);

    /* wait for parent to set up uid/gid maps */
    char sync_byte;
    lc_kernel_read_bytes(ca->sync_pipe_rd, &sync_byte, 1);
    lc_kernel_close_file(ca->sync_pipe_rd);

    if (ca->userns)
        enter_user_namespace_root();

    /* make all mounts private — prevents host mount events (including
     * the host's /proc) from propagating into the container */
    require_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

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
                            lc_kernel_execute(tool_path_mkdir(), a, e);
                            lc_kernel_exit(1);
                        }
                        int32_t st; lc_kernel_wait_for_child((int32_t)mp, &st, 0);

                        require_mount(vol_line, mount_point, NULL, MS_BIND, NULL);
                        {
                            uint64_t remount_flags = MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV;
                            if (ro) remount_flags |= MS_RDONLY;
                            require_mount(NULL, mount_point, NULL, remount_flags, NULL);
                        }
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
        require_mount("tmpfs", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755");

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
            require_mount(host_dev, cont_dev, NULL, MS_BIND, NULL);
            if (!ca->privileged) {
                uint64_t dev_flags = MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NOEXEC;
                if (streq(devs[i].name, "random") || streq(devs[i].name, "urandom"))
                    dev_flags |= MS_RDONLY;
                require_mount(NULL, cont_dev, NULL, dev_flags, NULL);
            }
        }

        /* pts and shm */
        char pts[MAX_PATH], shm[MAX_PATH];
        path_join(pts, MAX_PATH, dev_path, "pts");
        path_join(shm, MAX_PATH, dev_path, "shm");
        lc_kernel_mkdirat(AT_FDCWD, pts, 0755);
        lc_kernel_mkdirat(AT_FDCWD, shm, 0755);
    }

    /* pivot_root */
    require_mount(ca->root, ca->root, NULL, MS_BIND | MS_REC, NULL);
    if (lc_kernel_chdir(ca->root) < 0)
        die2("Error: chdir to rootfs failed: ", ca->root);
    lc_kernel_mkdirat(AT_FDCWD, ".old_root", 0755);
    if (lc_kernel_pivot_root(".", ".old_root") < 0)
        die("Error: pivot_root failed");
    { char *a[] = { "umount", "-l", "/.old_root", NULL }; run_cmd_quiet(tool_path_umount(), a); }
    lc_kernel_unlinkat(AT_FDCWD, "/.old_root", AT_REMOVEDIR);
    lc_kernel_chdir("/");

    /* Ensure standard mountpoints exist inside the container rootfs. */
    lc_kernel_mkdirat(AT_FDCWD, "/proc", 0555);
    lc_kernel_mkdirat(AT_FDCWD, "/sys", 0555);
    lc_kernel_mkdirat(AT_FDCWD, "/tmp", 01777);
    lc_kernel_mkdirat(AT_FDCWD, "/run", 0755);
    lc_kernel_mkdirat(AT_FDCWD, "/var", 0755);
    lc_kernel_mkdirat(AT_FDCWD, "/var/tmp", 01777);

    /* mount proc with the raw syscall; busybox mount is not reliable here */
    require_mount_syscall("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

    /*
     * sysfs mounting is typically not permitted inside an unprivileged user
     * namespace. Leave /sys as the rootfs directory in that mode.
     */
    if (!ca->userns)
        require_mount_syscall("sysfs", "/sys", "sysfs", MS_RDONLY, NULL);

    /* devpts and shm inside container */
    require_mount("devpts", "/dev/pts", "devpts",
                  MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666");
    require_mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

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
        require_mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
    }

    /* bring up loopback */
    {
        char *a[] = { "ip", "link", "set", "lo", "up", NULL };
        char *e[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_sysret p = lc_kernel_fork();
        if (p == 0) { lc_kernel_execute(tool_path_ip(), a, e); lc_kernel_exit(1); }
        int32_t st; lc_kernel_wait_for_child((int32_t)p, &st, 0);
        if (((st >> 8) & 0xff) != 0) die("Error: failed to bring up loopback");
    }

    /* run /init.sh if present */
    run_init_hook_if_present();

    /* mount tmpfs for /tmp and /run (after init.sh, before signaling ready) */
    require_mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL);
    require_mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, NULL);
    if (ca->read_only)
        require_mount("tmpfs", "/var/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL);

    /* apply security sandbox (unless privileged) */
    if (!ca->privileged) {
        drop_capabilities();
        if (lc_kernel_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
            die("Error: failed to enable no_new_privs");
        apply_seccomp();
    }

    /* remain as PID 1 and reap adopted children until shutdown */
    return supervisor_loop();
}

/* ─── cmd_start ─────────────────────────────────────────────────────────── */

static void cmd_start(int argc, char **argv) {
    require_tool("ip", tool_path_ip());
    require_tool("nsenter", tool_path_nsenter());
    require_tool("mount", tool_path_mount());
    require_tool("umount", tool_path_umount());
    require_tool("mkdir", tool_path_mkdir());
    if (argc < 1) die("Usage: lightbox start <name>");
    const char *name = argv[0];
    validate_name(name);

    char root[MAX_PATH];
    container_root(root, name);
    if (!path_exists(root)) die2("Error: container does not exist: ", name);

    if (is_running(name)) die2("Error: container is already running: ", name);

    /* read container IP */
    char ip[16];
    if (read_container_ip(name, ip, sizeof(ip)) < 0) die("Error: no IP file for container");

    /* read config */
    int userns = conf_get_int(name, "userns", 0);
    int uid_start = conf_get_int(name, "uid_start", 100000);
    int privileged = conf_get_int(name, "privileged", 0);
    int read_only = conf_get_int(name, "readonly", 0);
    int oom_score = conf_get_int(name, "oom_score", cfg_global.default_oom);

    if (userns)
        die("Error: containers configured with user namespaces are not supported yet");

    print_str(STDOUT,"Starting container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");
    set_container_state(name, "starting\n");

    const char *start_err = NULL;
    int32_t child_pid = -1;
    void *stack = MAP_FAILED;
    int sync_pipe[2] = { -1, -1 };

    /* set up veth pair */
    char veth_host[16], veth_cont[16];
    {
        size_t p1 = str_copy(veth_host, "vb-", sizeof(veth_host));
        str_append(veth_host, p1, name, sizeof(veth_host));
        size_t p2 = str_copy(veth_cont, "ve-", sizeof(veth_cont));
        str_append(veth_cont, p2, name, sizeof(veth_cont));
    }

    /* clean up stale veth endpoints if either name is left behind */
    if (delete_veth_if_present(veth_host) != 0 ||
        delete_veth_if_present(veth_cont) != 0) {
        start_err = "failed to delete stale veth";
        goto fail_start;
    }

    /* create veth pair */
    { char *a[] = { "ip", "link", "add", veth_cont, "type", "veth", "peer", "name", veth_host, NULL };
      if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to create veth pair"; goto fail_start; } }
    { char *a[] = { "ip", "link", "set", veth_host, "master", cfg_global.bridge, NULL };
      if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to attach veth to bridge"; goto fail_start; } }
    { char *a[] = { "ip", "link", "set", veth_host, "up", NULL };
      if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to bring host veth up"; goto fail_start; } }

    /* create sync pipe */
    if (lc_kernel_create_pipe(sync_pipe, O_CLOEXEC) < 0) {
        start_err = "failed to create sync pipe";
        goto fail_start;
    }

    /* set up clone flags */
    int clone_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
                      CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD;
    if (userns) clone_flags |= CLONE_NEWUSER;

    /* allocate child stack */
    stack = lc_kernel_map_memory(NULL, CHILD_STACK_SIZE,
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
    child_pid = (int32_t)lc_kernel_clone(clone_flags, stack_top,
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
        if (write_file(proc_path, "deny") < 0) { start_err = "failed to write setgroups"; goto fail_start; }

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
        if (write_file(proc_path, map_buf) < 0) { start_err = "failed to write uid_map"; goto fail_start; }

        /* gid_map */
        pp = str_copy(proc_path, "/proc/", sizeof(proc_path));
        pp = str_append(proc_path, pp, pidbuf, sizeof(proc_path));
        str_append(proc_path, pp, "/gid_map", sizeof(proc_path));
        if (write_file(proc_path, map_buf) < 0) { start_err = "failed to write gid_map"; goto fail_start; }
    }

    /*
     * Set up cgroup, networking, and OOM score BEFORE unblocking the child.
     * While the child is blocked on the sync pipe it is guaranteed alive,
     * so all operations that reference its PID or network namespace succeed.
     */

    /* set up cgroup */
    if (cgroup_create(name, (int)child_pid) != 0) {
        start_err = "failed to create cgroup";
        goto fail_start;
    }

    /* move veth into container network namespace */
    {
        char nsbuf[16]; fmt_int(nsbuf, (int)child_pid);
        char *a[] = { "ip", "link", "set", veth_cont, "netns", nsbuf, NULL };
        if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to move veth into netns"; goto fail_start; }
    }

    /* configure networking inside the container */
    {
        char nsbuf[16]; fmt_int(nsbuf, (int)child_pid);
        char ip_cidr[20];
        str_copy(ip_cidr, ip, sizeof(ip_cidr));
        str_append(ip_cidr, lc_string_length(ip_cidr), "/24", sizeof(ip_cidr));

        char *a1[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "link", "set", veth_cont, "up", NULL };
        if (run_cmd(tool_path_nsenter(), a1) != 0) { start_err = "failed to bring container veth up"; goto fail_start; }
        char *a2[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "addr", "add", ip_cidr, "dev", veth_cont, NULL };
        if (run_cmd(tool_path_nsenter(), a2) != 0) { start_err = "failed to assign container IP"; goto fail_start; }
        char *a3[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "route", "add", "default", "via", cfg_global.gw, NULL };
        if (run_cmd(tool_path_nsenter(), a3) != 0) { start_err = "failed to install default route"; goto fail_start; }
    }

    /* set OOM score */
    {
        char oom_path[64], oom_buf[16];
        char pidb[16]; fmt_int(pidb, (int)child_pid);
        size_t pp = str_copy(oom_path, "/proc/", sizeof(oom_path));
        pp = str_append(oom_path, pp, pidb, sizeof(oom_path));
        str_append(oom_path, pp, "/oom_score_adj", sizeof(oom_path));
        fmt_int(oom_buf, oom_score);
        if (write_file(oom_path, oom_buf) < 0) { start_err = "failed to set oom_score_adj"; goto fail_start; }
    }

    /* unblock the child — it can now set up mounts, pivot_root, and exec init */
    if (lc_kernel_write_bytes(sync_pipe[1], "x", 1) != 1) {
        start_err = "failed to signal container child";
        goto fail_start;
    }
    lc_kernel_close_file(sync_pipe[1]);
    sync_pipe[1] = -1;

    /* wait for child to finish setup, then verify it's alive */
    lc_timespec ts = { .seconds = 0, .nanoseconds = 500000000 }; /* 500ms */
    lc_kernel_sleep(&ts);

    {
        int32_t child_status;
        lc_sysret waited = lc_kernel_wait_for_child((int32_t)child_pid, &child_status, WNOHANG);
        if (waited == (lc_sysret)child_pid) {
            start_err = "container process died during startup";
            goto fail_start;
        }
    }

    if (lc_kernel_send_signal((int32_t)child_pid, 0) < 0) {
        start_err = "container process died during startup";
        goto fail_start;
    }

    /* Persist both PID and its /proc starttime to guard against PID reuse. */
    char pid_path[MAX_PATH], pidbuf[16], pid_start_path[MAX_PATH], pid_start[32];
    container_pid_path(pid_path, name);
    container_pid_start_path(pid_start_path, name);
    fmt_int(pidbuf, (int)child_pid);
    if (get_container_pid_starttime(name, pid_start, sizeof(pid_start)) == 0) {
        start_err = "unexpected stale pid starttime metadata";
        goto fail_start;
    }
    {
        char proc_stat[64], statbuf[512];
        size_t pos = str_copy(proc_stat, "/proc/", sizeof(proc_stat));
        pos = str_append(proc_stat, pos, pidbuf, sizeof(proc_stat));
        str_append(proc_stat, pos, "/stat", sizeof(proc_stat));
        if (read_file(proc_stat, statbuf, sizeof(statbuf)) <= 0) {
            start_err = "failed to read container proc stat";
            goto fail_start;
        }
        char *p = statbuf;
        char *last_paren = NULL;
        while (*p) {
            if (*p == ')') last_paren = p;
            p++;
        }
        if (!last_paren) {
            start_err = "failed to parse container proc stat";
            goto fail_start;
        }
        p = last_paren + 1;
        while (*p == ' ') p++;
        for (int field = 3; field < 22; field++) {
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
        }
        size_t len = 0;
        while (p[len] && p[len] != ' ' && p[len] != '\n' && len < sizeof(pid_start) - 1)
            len++;
        if (len == 0 || len >= sizeof(pid_start) - 1) {
            start_err = "failed to capture container starttime";
            goto fail_start;
        }
        lc_bytes_copy(pid_start, p, len);
        pid_start[len] = '\0';
    }
    if (write_file_atomic(pid_start_path, pid_start) < 0) {
        start_err = "failed to write pid starttime file";
        goto fail_start;
    }
    if (write_file_atomic(pid_path, pidbuf) < 0) {
        start_err = "failed to write pid file";
        goto fail_start;
    }
    if (update_link_rules(name, ip, true) != 0) {
        start_err = "failed to install link iptables rules";
        goto fail_start;
    }
    set_container_state(name, "running\n");

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
    return;

fail_start:
    if (sync_pipe[0] >= 0) lc_kernel_close_file(sync_pipe[0]);
    if (sync_pipe[1] >= 0) lc_kernel_close_file(sync_pipe[1]);
    if (start_err) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, start_err);
        lc_print_char(STDERR, '\n');
    }
    cleanup_start_failure(name, ip, veth_host, child_pid, stack);
    lc_kernel_exit(1);
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
    set_container_state(name, "stopping\n");

    /* Ask the in-container supervisor to exit cleanly before forcing SIGKILL. */
    lc_kernel_send_signal(pid, SIGTERM);

    /* wait for process to exit */
    for (int i = 0; i < 10; i++) {
        lc_timespec ts = { .seconds = 0, .nanoseconds = 200000000 };
        lc_kernel_sleep(&ts);
        if (lc_kernel_send_signal(pid, 0) < 0) break;
    }

    if (lc_kernel_send_signal(pid, 0) == 0)
        lc_kernel_send_signal(pid, SIGKILL);

    /* wait for child to reap */
    int32_t status;
    lc_kernel_wait_for_child(pid, &status, WNOHANG);

    /* clean up cgroup */
    cgroup_destroy(name);

    /* clean up link iptables rules */
    {
        char ip_buf[16];
        if (read_container_ip(name, ip_buf, sizeof(ip_buf)) == 0 &&
            update_link_rules(name, ip_buf, false) != 0) {
            print_str(STDERR, "Error: failed to remove link iptables rules\n");
        }
    }

    /* clean up veth if it exists */
    {
        char veth_host[16];
        size_t p = str_copy(veth_host, "vb-", sizeof(veth_host));
        str_append(veth_host, p, name, sizeof(veth_host));
        char *show[] = { "ip", "link", "show", veth_host, NULL };
        if (run_cmd_quiet(tool_path_ip(), show) == 0) {
            char *del[] = { "ip", "link", "delete", veth_host, NULL };
            run_cmd(tool_path_ip(), del);
        }
    }

    /* remove PID file */
    char pid_path[MAX_PATH];
    container_pid_path(pid_path, name);
    lc_kernel_unlinkat(AT_FDCWD, pid_path, 0);
    container_pid_start_path(pid_path, name);
    lc_kernel_unlinkat(AT_FDCWD, pid_path, 0);
    set_container_state(name, "stopped\n");

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' stopped\n");
}

/* ─── cmd_rm ────────────────────────────────────────────────────────────── */

static void cmd_rm(int argc, char **argv) {
    require_tool("rm", tool_path_rm());
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
    require_rm_rf(cdir);

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

    if (userns)
        die("Error: exec into userns containers is not supported yet");

    char *cmd_argv[32];
    int ai = 0;
    if (argc > 1) {
        for (int i = 1; i < argc && ai < 31; i++)
            cmd_argv[ai++] = argv[i];
    } else {
        cmd_argv[ai++] = "/bin/sh";
    }
    cmd_argv[ai] = NULL;

    lc_sysret worker = lc_kernel_fork();
    if (worker < 0)
        die("Error: failed to fork exec worker");

    if (worker == 0) {
        int status = exec_inside_container(name, pid, userns, privileged, cmd_argv);
        int exit_code = (status & 0x7f) ? (128 + (status & 0x7f)) : ((status >> 8) & 0xff);
        lc_kernel_exit(exit_code);
    }

    int32_t status;
    lc_kernel_wait_for_child((int32_t)worker, &status, 0);
    lc_kernel_exit((status & 0x7f) ? (128 + (status & 0x7f)) : ((status >> 8) & 0xff));
}

/* ─── cmd_ls ────────────────────────────────────────────────────────────── */

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
        "         --userns               Future improvement; not supported yet\n"
        "         --uid-start <n>        Future improvement; not supported yet\n"
        "         --read-only            Read-only root filesystem\n"
        "         --privileged           Disable security sandbox\n"
        "         --oom-score <n>        OOM score adjustment (default: 500)\n"
        "         --link <name>          Allow network to another container\n"
        "  start  <name>                 Start a stopped container\n"
        "  stop   <name>                 Stop a running container\n"
        "  rm     <name>                 Remove a container (must be stopped)\n"
        "  exec   <name> [cmd...]        Execute a command in a running container\n"
        "  inspect <name>                Show container metadata and runtime state\n"
        "  doctor                        Show host/runtime dependency status\n"
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
    else if (streq(cmd, "inspect")) cmd_inspect(sub_argc, sub_argv);
    else if (streq(cmd, "doctor")) cmd_doctor();
    else if (streq(cmd, "ls"))     cmd_ls();
    else                           usage();

    return 0;
}
