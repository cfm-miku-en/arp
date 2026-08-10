/* SPDX-FileCopyrightText: 2026 cfm-miku-en */
/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARP_EXPORT __attribute__((visibility("default")))

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

#ifndef F_OK
#define F_OK 0
#endif

/* returns 1 exists, 0 absent */
ARP_EXPORT int arp_path_exists(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    long result = syscall(__NR_faccessat, AT_FDCWD, path, F_OK, 0);
    if (result == 0) {
        return 1;
    }

    if (result == -1 && errno == EACCES) {
        return 1;
    }

    return 0;
}

/* returns 1 enforcing, 0 permissive, -1 unknown */
ARP_EXPORT int arp_selinux_enforcing(void)
{
    static const char *kEnforcePath = "/sys/fs/selinux/enforce";

    long fd = syscall(__NR_openat, AT_FDCWD, kEnforcePath, O_RDONLY, 0);
    if (fd < 0) {
        return -1;
    }

    char buffer[8];
    memset(buffer, 0, sizeof(buffer));

    long bytesRead = syscall(__NR_read, fd, buffer, sizeof(buffer) - 1);
    syscall(__NR_close, fd);

    if (bytesRead <= 0) {
        return -1;
    }

    if (buffer[0] == '1') {
        return 1;
    }
    if (buffer[0] == '0') {
        return 0;
    }

    return -1;
}
