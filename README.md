# lightbox

A minimal, secure Linux container runtime. Single static binary, ~33KB, no libc — built on [lightc](https://github.com/OscarAC/lightc) using raw Linux syscalls.

## Prerequisites

- Linux with namespace and cgroup v2 support
- GCC and ninja (build time)
- `iproute2`, `iptables`, `util-linux` (`nsenter`) at runtime
- BusyBox `ip` is not sufficient; `lightbox start` requires the full `iproute2` `ip` binary for veth creation and bridge attachment
- Root privileges

## Building

Depends on [lightc](https://github.com/OscarAC/lightc), a freestanding C runtime.

```sh
# Option 1: git submodule (preferred)
git clone --recursive <lightbox-repo-url>
cd lightbox && make

# Option 2: sibling directory
git clone https://github.com/OscarAC/lightc ../lightc
make

# Option 3: explicit path
make LIGHTC=/path/to/lightc
```

The Makefile auto-detects lightc as a submodule (`lightc/`) or sibling (`../lightc/`). It builds the lightc static library if needed, then produces a single statically linked `lightbox` binary.

## Quick start

### 1. Get a rootfs

lightbox needs a Linux root filesystem to use as a base image. Any distro works — Alpine minirootfs is a good starting point (~3MB):

```sh
mkdir -p /opt/rootfs/alpine
wget https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.21.3-x86_64.tar.gz -C /opt/rootfs/alpine
```

Tell lightbox where to find it — either export the environment variable or pass `--rootfs` on each create:

```sh
export LIGHTBOX_ROOTFS=/opt/rootfs/alpine
```

### 2. Set up host networking

Run once to create the bridge, enable NAT, and mount cgroups. Safe to re-run (idempotent).

```sh
./lightbox setup
```

This creates:
- A `br0` bridge on `10.0.0.1/24`
- iptables NAT masquerade for outbound traffic
- FORWARD rules for container-to-WAN communication
- A DROP rule for inter-container traffic (isolation by default)
- cgroup v2 mount at `/sys/fs/cgroup`

### 3. Create, start, and use containers

```sh
# Create a container with IP 10.0.0.2
./lightbox create mybox 10.0.0.2

# Start it
./lightbox start mybox

# Get a shell inside
./lightbox exec mybox /bin/sh

# Run a single command
./lightbox exec mybox cat /etc/os-release

# List all containers
./lightbox ls

# Stop and remove
./lightbox stop mybox
./lightbox rm mybox
```

### 4. Customize containers

```sh
# Custom resource limits
./lightbox create app 10.0.0.2 --mem 512M --cpu 2 --pids 256

# User namespaces are planned but not supported yet
# ./lightbox create sandbox 10.0.0.3 --userns

# Read-only rootfs with a data volume
./lightbox create web 10.0.0.4 --read-only --vol /data/www:/var/www:ro

# Mount a host file into the container
./lightbox create app 10.0.0.6 --vol /srv/config/app.conf:/etc/app.conf:ro

# Use a different rootfs image
./lightbox create deb 10.0.0.5 --rootfs /opt/rootfs/debian

# Disable the security sandbox
./lightbox create dev 10.0.0.6 --privileged

# Allow two containers to talk to each other
./lightbox create api 10.0.0.10 --link db
./lightbox create db  10.0.0.11

# Add a volume to an existing container configuration
./lightbox add-vol app /srv/config/app.conf:/etc/app.conf:ro
# Restart if the container is already running
```

## Configuration

lightbox reads `~/.config/lightbox/lightbox.conf` at startup. All values have built-in defaults — the config file is optional.

```ini
# ~/.config/lightbox/lightbox.conf

# Base directory for lightbox data (base rootfs and container directories)
lightbox_dir = /var/lib/lightbox

# Default rootfs to copy when creating containers
# Also overridable with LIGHTBOX_ROOTFS env var or --rootfs flag
rootfs = /var/lib/lightbox/rootfs

# Where containers are stored (each gets a subdirectory)
container_dir = /var/lib/lightbox/containers

# PID file directory
run_dir = /run/lightbox

# cgroup v2 mount point
cgroup_root = /sys/fs/cgroup

# Bridge interface and network
bridge = br0
subnet = 10.0.0.0/24
gw = 10.0.0.1

# Default container resource limits
default_mem = 256M
default_pids = 128
default_cpu = 1
default_oom = 500
```

If `lightbox_dir` is set, `rootfs` and `container_dir` are automatically derived from it (e.g., `rootfs = <lightbox_dir>/rootfs`) unless explicitly overridden.

### Rootfs resolution order

1. `--rootfs <path>` flag on create (highest priority)
2. `LIGHTBOX_ROOTFS` environment variable
3. `rootfs` in `lightbox.conf`
4. `/var/lib/lightbox/rootfs` (built-in default)

## Command reference

```
lightbox <command> [args]

  setup                         Initialize host networking
  create <name> <ip> [options]  Create a new container
  start  <name>                 Start a stopped container
  stop   <name>                 Stop a running container
  add-vol <name> <src>:<dst>[:ro]  Add a volume to an existing container
  rm     <name>                 Remove a container
  exec   <name> [cmd...]        Run a command in a container
  ls                            List all containers
```

### Create options

| Flag | Default | Description |
|------|---------|-------------|
| `--rootfs <path>` | `$LIGHTBOX_ROOTFS` | Base rootfs to copy |
| `--mem <limit>` | `256M` | Memory limit |
| `--pids <limit>` | `128` | Max processes |
| `--cpu <num>` | `1` | CPU cores |
| `--vol <src>:<dst>[:ro]` | — | Bind mount (repeatable) |
| `--userns` | — | Future improvement; not supported yet |
| `--uid-start <n>` | — | Future improvement; not supported yet |
| `--read-only` | off | Read-only root filesystem |
| `--privileged` | off | Disable security sandbox |
| `--oom-score <n>` | `500` | OOM score adjustment |
| `--link <name>` | — | Allow network to another container (repeatable) |

## Security

All security features are on by default. Pass `--privileged` to disable.

| Feature | Implementation |
|---------|---------------|
| Capability dropping | `prctl(PR_CAPBSET_DROP)` — keeps Docker's 14 default caps |
| Seccomp | BPF filter blocking ~50 dangerous syscalls |
| no_new_privs | Prevents SUID escalation |
| /proc masking | Bind-mounts `/dev/null` over kcore, sysrq-trigger, etc. |
| /proc read-only | Remounts /proc/sys, /proc/bus, /proc/fs, /proc/irq read-only |
| Container isolation | iptables drops br0-to-br0 traffic by default |
| User namespaces | Planned future improvement |
| OOM priority | Containers scored higher for OOM killer |

## How it works

- **Namespaces**: `clone()` with PID, mount, UTS, IPC, net (and optionally user) namespace flags
- **Filesystem**: each container lives under `<container_dir>/<name>/` with `rootfs/` for the filesystem and `.conf`, `.ip`, `.pid` for metadata. `pivot_root` into the rootfs copy
- **Devices**: bind-mounted from host (`/dev/null`, `/dev/zero`, `/dev/random`, etc.)
- **Networking**: veth pair per container connected to a host bridge with NAT
- **Resource limits**: cgroups v2 (memory, PIDs, CPU, I/O)
- **Init**: lightbox remains PID 1 inside the container; if `/init.sh` exists in the rootfs it is run after `/tmp` and `/run` are mounted, then lightbox stays alive to reap children and handle shutdown
- **External tools**: `ip` and `iptables` for networking (fork+exec); everything else is direct syscalls
- **Configuration**: optional `~/.config/lightbox/lightbox.conf` for all paths and defaults

## Volume Notes

- `--vol` now supports both directory and single-file bind mounts.
- `lightbox add-vol <name> <src>:<dst>[:ro]` appends a volume to an existing container's config.
- If the container is already running, added volumes take effect after a restart.
