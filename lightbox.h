#ifndef LIGHTBOX_H
#define LIGHTBOX_H

#include <lightc/syscall.h>
#include <lightc/types.h>
#include <lightc/string.h>
#include <lightc/print.h>
#include <lightc/format.h>
#include <lightc/io.h>

#define MAX_PATH         512
#define NAME_MAX_LEN     12

typedef struct {
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
} global_config;

extern global_config cfg_global;

void print_str(int32_t fd, const char *s);
void die(const char *msg);
void die2(const char *prefix, const char *detail);
bool streq(const char *a, const char *b);
size_t str_copy(char *dst, const char *src, size_t max);
size_t str_append(char *dst, size_t pos, const char *src, size_t max);
void path_join(char *buf, size_t bufsz, const char *a, const char *b);
int parse_int(const char *s);
int fmt_int(char *buf, int val);
int write_file(const char *path, const char *data);
void require_write_file(const char *path, const char *data);
int write_file_atomic(const char *path, const char *data);
void require_write_file_atomic(const char *path, const char *data);
void cfg_global_init(void);
void cfg_global_load(char **envp);

int read_file(const char *path, char *buf, size_t bufsz);
bool path_exists(const char *path);
lc_sysret lc_kernel_fchdir(int32_t fd);
lc_sysret lc_kernel_change_root(const char *path);
void require_rm_rf(const char *path);
int run_cmd(const char *prog, char *const argv[]);
int run_cmd_quiet(const char *prog, char *const argv[]);
int do_mount(const char *source, const char *target,
             const char *fstype, uint64_t flags, const char *data);
void require_mount(const char *source, const char *target,
                   const char *fstype, uint64_t flags, const char *data);
const char *tool_path_ip(void);
const char *tool_path_iptables(void);
const char *tool_path_mount(void);
const char *tool_path_umount(void);
const char *tool_path_mkdir(void);
const char *tool_path_cp(void);
const char *tool_path_chown(void);
const char *tool_path_rm(void);
const char *tool_path_nsenter(void);
bool tool_available(const char *path);
void require_tool(const char *label, const char *path);
void validate_name(const char *name);

void container_dir_path(char *buf, const char *name);
void container_root(char *buf, const char *name);
void container_pid_path(char *buf, const char *name);
void container_pid_start_path(char *buf, const char *name);
void container_ip_path(char *buf, const char *name);
void container_conf_path(char *buf, const char *name);
void container_state_path(char *buf, const char *name);

void set_container_state(const char *name, const char *state);
void get_container_state(const char *name, char *buf, size_t bufsz);
int conf_get(const char *name, const char *key, char *val, size_t valsz, const char *def);
int conf_get_int(const char *name, const char *key, int def);
int get_container_pid(const char *name);
int get_container_pid_starttime(const char *name, char *buf, size_t bufsz);
bool is_running(const char *name);
int read_container_ip(const char *name, char *ip, size_t ipsz);
int update_link_rules(const char *name, const char *ip, bool add_rules);

void cmd_setup(void);
void cmd_doctor(void);
void cmd_ls(int argc, char **argv);
void cmd_inspect(int argc, char **argv);

#endif
