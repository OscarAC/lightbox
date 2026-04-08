#include "lightbox.h"

#define CONF_BUF_SIZE 2048

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

void cfg_global_init(void) {
    str_copy(cfg_global.lightbox_dir, "/var/lib/lightbox", MAX_PATH);
    str_copy(cfg_global.rootfs, "/var/lib/lightbox/rootfs", MAX_PATH);
    str_copy(cfg_global.container_dir, "/var/lib/lightbox/containers", MAX_PATH);
    str_copy(cfg_global.run_dir, "/run/lightbox", MAX_PATH);
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

static void cfg_set(const char *key, const char *val, bool derived[3]) {
    if (streq(key, "lightbox_dir")) {
        str_copy(cfg_global.lightbox_dir, val, MAX_PATH);
        if (!derived[0]) path_join(cfg_global.rootfs, MAX_PATH, val, "rootfs");
        if (!derived[1]) path_join(cfg_global.container_dir, MAX_PATH, val, "containers");
    } else if (streq(key, "rootfs")) {
        str_copy(cfg_global.rootfs, val, MAX_PATH);
        derived[0] = true;
    } else if (streq(key, "container_dir")) {
        str_copy(cfg_global.container_dir, val, MAX_PATH);
        derived[1] = true;
    } else if (streq(key, "run_dir")) {
        str_copy(cfg_global.run_dir, val, MAX_PATH);
    } else if (streq(key, "cgroup_root")) {
        str_copy(cfg_global.cgroup_root, val, MAX_PATH);
    } else if (streq(key, "cgroup_base")) {
        str_copy(cfg_global.cgroup_base, val, MAX_PATH);
        derived[2] = true;
    } else if (streq(key, "bridge")) {
        str_copy(cfg_global.bridge, val, sizeof(cfg_global.bridge));
    } else if (streq(key, "subnet")) {
        str_copy(cfg_global.subnet, val, sizeof(cfg_global.subnet));
    } else if (streq(key, "gw")) {
        str_copy(cfg_global.gw, val, sizeof(cfg_global.gw));
    } else if (streq(key, "default_mem")) {
        str_copy(cfg_global.default_mem, val, sizeof(cfg_global.default_mem));
    } else if (streq(key, "default_pids")) {
        str_copy(cfg_global.default_pids, val, sizeof(cfg_global.default_pids));
    } else if (streq(key, "default_cpu")) {
        str_copy(cfg_global.default_cpu, val, sizeof(cfg_global.default_cpu));
    } else if (streq(key, "default_oom")) {
        cfg_global.default_oom = parse_int(val);
    }
}

void cfg_global_load(char **envp) {
    const char *home = env_get(envp, "HOME");
    if (!home) home = "/root";

    char conf_path[MAX_PATH];
    path_join(conf_path, MAX_PATH, home, ".config/lightbox/lightbox.conf");

    char buf[CONF_BUF_SIZE];
    int n = read_file(conf_path, buf, sizeof(buf));
    if (n <= 0) return;

    bool derived[3] = { false, false, false };

    char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n') {
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
            continue;
        }

        char *eq = p;
        while (*eq && *eq != '=' && *eq != '\n') eq++;
        if (*eq != '=') {
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
            continue;
        }

        char key[64];
        size_t klen = (size_t)(eq - p);
        while (klen > 0 && (p[klen - 1] == ' ' || p[klen - 1] == '\t')) klen--;
        if (klen >= sizeof(key)) klen = sizeof(key) - 1;
        lc_bytes_copy(key, p, klen);
        key[klen] = '\0';

        char *vs = eq + 1;
        while (*vs == ' ' || *vs == '\t') vs++;
        char *ve = vs;
        while (*ve && *ve != '\n') ve++;
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

    if (!derived[2])
        path_join(cfg_global.cgroup_base, MAX_PATH, cfg_global.cgroup_root, "lightbox");

    const char *env_rootfs = env_get(envp, "LIGHTBOX_ROOTFS");
    if (env_rootfs && env_rootfs[0])
        str_copy(cfg_global.rootfs, env_rootfs, MAX_PATH);
}
