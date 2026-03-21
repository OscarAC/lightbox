#include "lightbox.h"

#define USERNS_RANGE_SIZE 65536

void container_dir_path(char *buf, const char *name) {
    path_join(buf, MAX_PATH, cfg_global.container_dir, name);
}

void container_root(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, "rootfs");
}

void container_pid_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".pid");
}

void container_pid_start_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".pid_start");
}

void container_ip_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".ip");
}

void container_conf_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".conf");
}

void container_state_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".state");
}

void set_container_state(const char *name, const char *state) {
    char path[MAX_PATH];
    container_state_path(path, name);
    require_write_file_atomic(path, state);
}

void get_container_state(const char *name, char *buf, size_t bufsz) {
    char path[MAX_PATH];
    container_state_path(path, name);
    if (read_file(path, buf, bufsz) <= 0) {
        str_copy(buf, "unknown", bufsz);
        return;
    }
    for (size_t i = 0; buf[i]; i++) {
        if (buf[i] == '\n') { buf[i] = '\0'; break; }
    }
    if (!buf[0]) str_copy(buf, "unknown", bufsz);
}

int conf_get(const char *name, const char *key, char *val, size_t valsz, const char *def) {
    char path[MAX_PATH], buf[2048];
    container_conf_path(path, name);
    if (read_file(path, buf, sizeof(buf)) < 0) {
        str_copy(val, def, valsz);
        return 0;
    }

    size_t keylen = lc_string_length(key);
    char *p = buf;
    while (*p) {
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
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    str_copy(val, def, valsz);
    return 0;
}

int conf_get_int(const char *name, const char *key, int def) {
    char val[32];
    if (conf_get(name, key, val, sizeof(val), "") && val[0])
        return parse_int(val);
    return def;
}

int get_container_pid(const char *name) {
    char path[MAX_PATH], buf[16];
    container_pid_path(path, name);
    if (read_file(path, buf, sizeof(buf)) < 0) return -1;
    return parse_int(buf);
}

static void clear_runtime_identity(const char *name, bool mark_failed) {
    char path[MAX_PATH];
    container_pid_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    container_pid_start_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    if (mark_failed)
        set_container_state(name, "failed\n");
}

static int read_proc_starttime(int pid, char *buf, size_t bufsz) {
    char path[64], statbuf[512], pidbuf[16];
    fmt_int(pidbuf, pid);
    size_t pos = str_copy(path, "/proc/", sizeof(path));
    pos = str_append(path, pos, pidbuf, sizeof(path));
    str_append(path, pos, "/stat", sizeof(path));

    if (read_file(path, statbuf, sizeof(statbuf)) <= 0)
        return -1;

    char *p = statbuf;
    char *last_paren = NULL;
    while (*p) {
        if (*p == ')') last_paren = p;
        p++;
    }
    if (!last_paren) return -1;

    p = last_paren + 1;
    while (*p == ' ') p++;

    for (int field = 3; field < 22; field++) {
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
    }

    if (!*p) return -1;

    size_t len = 0;
    while (p[len] && p[len] != ' ' && p[len] != '\n')
        len++;
    if (len == 0 || len >= bufsz)
        return -1;

    lc_bytes_copy(buf, p, len);
    buf[len] = '\0';
    return 0;
}

int get_container_pid_starttime(const char *name, char *buf, size_t bufsz) {
    char path[MAX_PATH];
    container_pid_start_path(path, name);
    if (read_file(path, buf, bufsz) <= 0)
        return -1;
    for (size_t i = 0; buf[i]; i++) {
        if (buf[i] == '\n') { buf[i] = '\0'; break; }
    }
    return buf[0] ? 0 : -1;
}

bool is_running(const char *name) {
    int pid = get_container_pid(name);
    if (pid <= 0) return false;

    if (lc_kernel_send_signal(pid, 0) < 0) {
        clear_runtime_identity(name, true);
        return false;
    }

    char expected_start[32], actual_start[32];
    if (get_container_pid_starttime(name, expected_start, sizeof(expected_start)) < 0 ||
        read_proc_starttime(pid, actual_start, sizeof(actual_start)) < 0 ||
        !streq(expected_start, actual_start)) {
        clear_runtime_identity(name, true);
        return false;
    }

    char pid_ns[64], init_ns[64], proc_path[64];
    char intbuf[16];
    char *pid_ptr = intbuf;
    int pid_val = pid;

    if (pid_val == 0) {
        intbuf[0] = '0';
        intbuf[1] = '\0';
    } else {
        char rev[16];
        int len = 0;
        while (pid_val > 0 && len < (int)sizeof(rev)) {
            rev[len++] = (char)('0' + (pid_val % 10));
            pid_val /= 10;
        }
        for (int i = 0; i < len; i++)
            intbuf[i] = rev[len - 1 - i];
        intbuf[len] = '\0';
    }

    size_t pos = str_copy(proc_path, "/proc/", sizeof(proc_path));
    pos = str_append(proc_path, pos, pid_ptr, sizeof(proc_path));
    str_append(proc_path, pos, "/ns/pid", sizeof(proc_path));

    lc_sysret n1 = lc_kernel_readlinkat(AT_FDCWD, proc_path, pid_ns, sizeof(pid_ns) - 1);
    lc_sysret n2 = lc_kernel_readlinkat(AT_FDCWD, "/proc/1/ns/pid", init_ns, sizeof(init_ns) - 1);
    if (n1 <= 0 || n2 <= 0) {
        clear_runtime_identity(name, true);
        return false;
    }
    pid_ns[n1] = '\0';
    init_ns[n2] = '\0';

    return !streq(pid_ns, init_ns);
}
