/*
 * eBPF loader. Loads programs, pins to bpffs, drops privileges.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/limits.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Classic object loading; bpftool skeleton can be added later */
#define JVL_PIN_DIR "/sys/fs/bpf/javelin"
#define JVL_PROG_PIN  JVL_PIN_DIR "/programs"
#define JVL_MAP_PIN   JVL_PIN_DIR "/maps"

static volatile sig_atomic_t g_stop = 0;

static void sigint_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* Pin helpers */
static int pin_map(int map_fd, const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", JVL_MAP_PIN, name);
    return bpf_obj_pin(map_fd, path);
}

static int pin_prog(int prog_fd, const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", JVL_PROG_PIN, name);
    return bpf_obj_pin(prog_fd, path);
}

/* Main */
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <javelin_monitor.bpf.o> [target_pid]\n", argv[0]);
        return 1;
    }

    const char *obj_path = argv[1];
    __u32 target_pid = (argc >= 3) ? (__u32)atoi(argv[2]) : 0;

    /* Bump RLIMIT_MEMLOCK for libbpf */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    /* Create bpffs directories */
    mkdir("/sys/fs/bpf", 0755);
    mkdir(JVL_PIN_DIR, 0755);
    mkdir(JVL_PROG_PIN, 0755);
    mkdir(JVL_MAP_PIN, 0755);

    /* Open and load object */
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    /* Pin maps so that even if this loader exits, the eBPF programs persist */
    struct bpf_map *map = NULL;
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        int fd = bpf_map__fd(map);
        if (pin_map(fd, name) != 0 && errno != EEXIST) {
            fprintf(stderr, "Warning: failed to pin map %s: %s\n", name, strerror(errno));
        }
    }

    /* Attach LSM programs */
    struct bpf_program *prog = NULL;
    bpf_object__for_each_program(prog, obj) {
        const char *name = bpf_program__name(prog);
        int fd = bpf_program__fd(prog);

        if (pin_prog(fd, name) != 0 && errno != EEXIST) {
            fprintf(stderr, "Warning: failed to pin prog %s: %s\n", name, strerror(errno));
        }

        /* LSM programs are auto-attached by bpf_object__load if kernel supports it */
        fprintf(stderr, "[loader] Program '%s' loaded (fd=%d)\n", name, fd);
    }

    /* Populate target PID filter if provided */
    if (target_pid != 0) {
        struct bpf_map *pid_map = bpf_object__find_map_by_name(obj, "jvl_target_pids");
        if (pid_map) {
            __u8 dummy = 1;
            bpf_map_update_elem(bpf_map__fd(pid_map), &target_pid, &dummy, BPF_ANY);
            fprintf(stderr, "[loader] Added PID %u to target filter\n", target_pid);
        }
    }

    /* Drop privileges if running as root */
    if (getuid() == 0) {
        const char *drop_user = getenv("SUDO_UID");
        if (drop_user) {
            uid_t uid = (uid_t)atoi(drop_user);
            gid_t gid = (gid_t)atoi(getenv("SUDO_GID") ?: "0");
            if (setgid(gid) != 0 || setuid(uid) != 0) {
                fprintf(stderr, "[loader] Failed to drop privileges; aborting\n");
                return 1;
            }
            fprintf(stderr, "[loader] Dropped privileges to uid=%d gid=%d\n", uid, gid);
        } else {
            fprintf(stderr, "[loader] Refusing to run as root without SUDO_UID\n");
            return 1;
        }
    }

    /* Expose ring buffer via UNIX socket for the shim to consume */
    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "jvl_rb");
    if (!rb_map) {
        fprintf(stderr, "[loader] Ring buffer map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    int rb_fd = bpf_map__fd(rb_map);
    struct ring_buffer *rb = ring_buffer__new(rb_fd, NULL, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[loader] Failed to create ring buffer\n");
        bpf_object__close(obj);
        return 1;
    }

    /* UNIX domain socket for local shim communication */
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock >= 0) {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        snprintf(addr.sun_path, sizeof(addr.sun_path), "/run/javelin/ebpf.sock");
        unlink(addr.sun_path);
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
            listen(sock, 4) == 0) {
            fprintf(stderr, "[loader] Listening on %s\n", addr.sun_path);
        } else {
            close(sock);
            sock = -1;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    fprintf(stderr, "[loader] Running. Press Ctrl-C to unload.\n");
    while (!g_stop) {
        /* Poll ring buffer; callback would forward to connected shim sockets */
        ring_buffer__poll(rb, 100 /* ms */);
    }

    fprintf(stderr, "[loader] Shutting down...\n");
    ring_buffer__free(rb);
    close(sock);
    unlink("/run/javelin/ebpf.sock");
    bpf_object__close(obj);
    return 0;
}
