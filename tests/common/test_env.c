#define _GNU_SOURCE
#include "test_env.h"
#include <sched.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}

// Run a shell command, printf-style. 0 = success
static int sh(const char *fmt, ...)
{
    char cmd[256];
    va_list ap; va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    int rc = system(cmd);
    if (rc != 0) fprintf(stderr, "env: '%s' failed (%d)\n", cmd, rc);
    return rc;
}

/* Create a new network namespace. If we are not root, we first create a user
 * namespace in which we are root. */
static int enter_ns(void)
{
    uid_t uid = getuid(); gid_t gid = getgid();
    char map[64];
    //root ?
    if (uid == 0)
        return unshare(CLONE_NEWNET);

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) return -1;
    write_file("/proc/self/setgroups", "deny");
    snprintf(map, sizeof map, "0 %u 1", uid);
    if (write_file("/proc/self/uid_map", map) < 0) return -1;
    snprintf(map, sizeof map, "0 %u 1", gid);
    return write_file("/proc/self/gid_map", map);
}

int wk_env_init(void)
{
    if (enter_ns() < 0) { perror("unshare"); return -1; }

    return sh("ip link set lo up")
        || sh("ip link add %s type veth peer name %s", WK_VETH_A, WK_VETH_B)
        || sh("ip link set %s address 02:11:22:33:c4:d4", WK_VETH_A)
        || sh("ip link set %s address d4:c4:33:22:11:02", WK_VETH_B)
        || sh("ip link set %s up", WK_VETH_A)
        || sh("ip link set %s up", WK_VETH_B);
}