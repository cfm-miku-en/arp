/* SPDX-FileCopyrightText: 2026 cfm-miku-en */
/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
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

/* ---- line reader over a proc file, raw syscalls only ---- */

typedef struct {
    long fd;
    char buf[8192];
    int len;
    int pos;
} arp_reader;

static int arp_reader_open(arp_reader *r, const char *path)
{
    r->fd = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0);
    r->len = 0;
    r->pos = 0;
    return r->fd < 0 ? -1 : 0;
}

static void arp_reader_close(arp_reader *r)
{
    if (r->fd >= 0) syscall(__NR_close, r->fd);
    r->fd = -1;
}

static int arp_read_line(arp_reader *r, char *out, int out_size)
{
    int written = 0;

    for (;;) {
        if (r->pos >= r->len) {
            long got = syscall(__NR_read, r->fd, r->buf, (long)sizeof(r->buf));
            if (got <= 0) break;
            r->len = (int)got;
            r->pos = 0;
        }

        char c = r->buf[r->pos++];
        if (c == '\n') {
            out[written] = '\0';
            return 1;
        }
        if (written < out_size - 1) out[written++] = c;
    }

    out[written] = '\0';
    return written > 0 ? 1 : 0;
}

static int arp_ends_with(const char *text, const char *suffix)
{
    size_t tl = strlen(text);
    size_t sl = strlen(suffix);
    if (sl == 0 || sl > tl) return 0;
    return strcmp(text + (tl - sl), suffix) == 0;
}

static int arp_is_map_header(const char *line)
{
    char c = line[0];
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static unsigned long arp_parse_hex(const char *s, int *consumed)
{
    unsigned long value = 0;
    int i = 0;

    for (; s[i]; i++) {
        char c = s[i];
        unsigned digit;

        if (c >= '0' && c <= '9') digit = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (unsigned)(c - 'A' + 10);
        else break;

        value = (value << 4) | digit;
    }

    if (consumed) *consumed = i;
    return value;
}

static long arp_parse_dec(const char *s)
{
    long value = 0;
    while (*s == ' ') s++;
    while (*s >= '0' && *s <= '9') {
        value = value * 10 + (*s - '0');
        s++;
    }
    return value;
}

/*
 * Locate the first executable mapping backed by a library whose path ends with
 * soname. Fills start, end and the file offset. Returns 0 on success, -1 if not found.
 */
static int arp_find_exec_map(const char *soname, unsigned long *start,
                             unsigned long *end, unsigned long *file_off,
                             char *path_out, int path_size)
{
    arp_reader r;
    char line[512];

    if (arp_reader_open(&r, "/proc/self/maps") < 0) return -1;

    while (arp_read_line(&r, line, (int)sizeof(line))) {
        int used = 0;
        unsigned long a = arp_parse_hex(line, &used);
        if (line[used] != '-') continue;

        int cursor = used + 1;
        unsigned long b = arp_parse_hex(line + cursor, &used);
        cursor += used;

        while (line[cursor] == ' ') cursor++;
        if (line[cursor + 2] != 'x') continue;

        int perms = cursor;
        cursor += 4;
        while (line[cursor] == ' ') cursor++;

        unsigned long off = arp_parse_hex(line + cursor, &used);
        cursor += used;

        const char *slash = strchr(line + cursor, '/');
        if (slash == NULL) continue;
        if (!arp_ends_with(slash, soname)) continue;

        (void)perms;
        *start = a;
        *end = b;
        *file_off = off;

        int i = 0;
        for (; slash[i] && i < path_size - 1; i++) path_out[i] = slash[i];
        path_out[i] = '\0';

        arp_reader_close(&r);
        return 0;
    }

    arp_reader_close(&r);
    return -1;
}

/*
 * Private_Dirty across executable mappings of soname, in kB. -1 if unreadable.
 *
 * Writing to a code page forces copy-on-write, and restoring the original page
 * protection afterwards does not undo that accounting. So a process whose code has
 * been patched in memory carries dirty executable pages even after the attacker
 * tidies up. A clean process should read ~0.
 */
ARP_EXPORT long arp_code_dirty_kb(const char *soname)
{
    arp_reader r;
    char line[512];
    long total = 0;
    int in_target = 0;
    int found_any = 0;

    if (soname == NULL || soname[0] == '\0') return -1;
    if (arp_reader_open(&r, "/proc/self/smaps") < 0) return -1;

    while (arp_read_line(&r, line, (int)sizeof(line))) {
        if (arp_is_map_header(line)) {
            const char *slash = strchr(line, '/');
            int executable = 0;

            int cursor = 0;
            while (line[cursor] && line[cursor] != ' ') cursor++;
            while (line[cursor] == ' ') cursor++;
            if (line[cursor] && line[cursor + 2] == 'x') executable = 1;

            in_target = executable && slash != NULL && arp_ends_with(slash, soname);
            if (in_target) found_any = 1;
            continue;
        }

        if (in_target && strncmp(line, "Private_Dirty:", 14) == 0) {
            total += arp_parse_dec(line + 14);
        }
    }

    arp_reader_close(&r);
    return found_any ? total : -1;
}

/* Size in bytes of the first executable mapping of soname. -1 if not found. */
ARP_EXPORT long arp_code_exec_size(const char *soname)
{
    unsigned long start, end, off;
    char path[512];

    if (soname == NULL || soname[0] == '\0') return -1;
    if (arp_find_exec_map(soname, &start, &end, &off, path, (int)sizeof(path)) < 0) return -1;

    return (long)(end - start);
}

/*
 * Compare a window of executing memory against the file it was loaded from.
 * Returns 1 if they differ, 0 if identical, -1 if the check could not run.
 *
 * The on-disk file is the reference rather than a hash captured at startup: a
 * baseline taken in-process can already be of patched memory, and there is no way
 * to tell from inside. The file cannot be altered without breaking the content
 * hash and the signing certificate, so it is the one trustworthy reference here.
 */
ARP_EXPORT int arp_code_compare(const char *soname, long window_start, long window_length)
{
    unsigned long start, end, file_off;
    char path[512];
    char file_chunk[4096];

    if (soname == NULL || soname[0] == '\0') return -1;
    if (window_start < 0 || window_length <= 0) return -1;
    if (arp_find_exec_map(soname, &start, &end, &file_off, path, (int)sizeof(path)) < 0) return -1;

    unsigned long span = end - start;
    if ((unsigned long)window_start >= span) return -1;

    unsigned long remaining = span - (unsigned long)window_start;
    if ((unsigned long)window_length < remaining) remaining = (unsigned long)window_length;

    long fd = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return -1;

    unsigned long done = 0;
    int result = 0;

    while (done < remaining) {
        unsigned long chunk = remaining - done;
        if (chunk > sizeof(file_chunk)) chunk = sizeof(file_chunk);

        long got = syscall(__NR_pread64, fd, file_chunk, (long)chunk,
                           (long)(file_off + (unsigned long)window_start + done));
        if (got <= 0) {
            result = (done == 0) ? -1 : 0;
            break;
        }

        const char *live = (const char *)(start + (unsigned long)window_start + done);
        if (memcmp(live, file_chunk, (size_t)got) != 0) {
            result = 1;
            break;
        }

        done += (unsigned long)got;
    }

    syscall(__NR_close, fd);
    return result;
}

static const char *arp_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/*
 * Basenames of every .so executing from app-private storage, NUL-separated in out.
 * Returns how many, or -1.
 *
 * The caller compares this against the libraries actually present in the APK. Anything
 * running that the APK does not ship was injected - which catches a loader dropped in
 * at runtime under a name no hardcoded artifact list would ever contain.
 *
 * Only /data paths are considered. System libraries live under /system, /vendor and
 * /apex and are legitimately absent from our APK.
 */
ARP_EXPORT int arp_list_app_libraries(char *out, int out_size)
{
    arp_reader r;
    char line[512];
    int written = 0;
    int count = 0;

    if (out == NULL || out_size <= 0) return -1;
    if (arp_reader_open(&r, "/proc/self/maps") < 0) return -1;

    while (arp_read_line(&r, line, (int)sizeof(line))) {
        int cursor = 0;
        while (line[cursor] && line[cursor] != ' ') cursor++;
        while (line[cursor] == ' ') cursor++;
        if (line[cursor] == '\0' || line[cursor + 2] != 'x') continue;

        const char *path = strchr(line + cursor, '/');
        if (path == NULL) continue;
        if (strncmp(path, "/data/", 6) != 0) continue;
        if (!arp_ends_with(path, ".so")) continue;

        const char *name = arp_basename(path);
        size_t len = strlen(name);
        if (written + (int)len + 1 >= out_size) break;

        /* One library owns several mappings, so de-duplicate as we go. */
        int seen = 0;
        int scan = 0;
        while (scan < written) {
            if (strcmp(out + scan, name) == 0) { seen = 1; break; }
            scan += (int)strlen(out + scan) + 1;
        }
        if (seen) continue;

        memcpy(out + written, name, len + 1);
        written += (int)len + 1;
        count++;
    }

    arp_reader_close(&r);
    return count;
}

/* ---- runtime instrumentation ---- */

#define ARP_INSTR_TRACER      0x01
#define ARP_INSTR_ANON_EXEC   0x02
#define ARP_INSTR_FRIDA_PORT  0x04

static long arp_parse_dec_after(const char *line, const char *label)
{
    const char *p = strstr(line, label);
    if (p == NULL) return -1;
    return arp_parse_dec(p + strlen(label));
}

/*
 * Someone is attached with ptrace. Frida's attach mode sets this, as does any
 * debugger. One file read and no side effects, which is why this is preferred over
 * the fork-and-ptrace trick: the version of that which actually works has to stop
 * the process to find out, and stopping a VR app to check for debuggers is a worse
 * outcome than the debugger.
 */
static int arp_tracer_present(void)
{
    arp_reader r;
    char line[256];
    int found = 0;

    if (arp_reader_open(&r, "/proc/self/status") < 0) return 0;

    while (arp_read_line(&r, line, (int)sizeof(line))) {
        long pid = arp_parse_dec_after(line, "TracerPid:");
        if (pid >= 0) {
            found = pid != 0;
            break;
        }
    }

    arp_reader_close(&r);
    return found ? ARP_INSTR_TRACER : 0;
}

/*
 * A large writable-and-executable mapping that no file backs.
 *
 * Injected code has to live somewhere it can be both written and run, and a file
 * cannot back it because it was never on disk. That makes this behavioural rather
 * than a signature: it does not care what the tool is called or which one it is.
 *
 * Labelled anonymous regions are skipped - the runtime's own JIT cache appears as
 * [anon:dalvik-jit-code-cache] and is legitimate. Needs baselining on a stock
 * headset before it is allowed to enforce.
 */
static int arp_anonymous_exec_memory(void)
{
    arp_reader r;
    char line[512];
    int found = 0;

    if (arp_reader_open(&r, "/proc/self/maps") < 0) return 0;

    while (arp_read_line(&r, line, (int)sizeof(line))) {
        int used = 0;
        unsigned long start = arp_parse_hex(line, &used);
        if (line[used] != '-') continue;

        int cursor = used + 1;
        unsigned long end = arp_parse_hex(line + cursor, &used);
        cursor += used;

        while (line[cursor] == ' ') cursor++;
        if (line[cursor] != 'r' || line[cursor + 1] != 'w' || line[cursor + 2] != 'x') continue;

        /* File-backed or labelled means it has an explanation. */
        if (strchr(line, '/') != NULL) continue;
        if (strchr(line, '[') != NULL) continue;

        if (end > start && (end - start) > (512UL * 1024UL)) {
            found = 1;
            break;
        }
    }

    arp_reader_close(&r);
    return found ? ARP_INSTR_ANON_EXEC : 0;
}

/*
 * frida-server listening on its default port.
 *
 * Port-open alone would only say something is bound there, so this completes the
 * D-Bus handshake frida-server speaks: it answers AUTH with REJECT, and nothing
 * else will. That is the difference between "a port is open" and "frida-server is
 * on the other end", which matters when the answer can end in a ban.
 *
 * A closed port on loopback refuses immediately, so the timeout below is a bound
 * for the odd case rather than the usual cost.
 */
static int arp_frida_port(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(0x7f000001);

    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
        close(s);
        return 0;
    }

    static const char auth[] = "\x00" "AUTH\r\n";
    if (send(s, auth, sizeof(auth) - 1, 0) <= 0) {
        close(s);
        return 0;
    }

    char reply[64];
    memset(reply, 0, sizeof reply);
    ssize_t got = recv(s, reply, sizeof(reply) - 1, 0);
    close(s);

    if (got <= 0) return 0;
    return strstr(reply, "REJECT") != NULL ? 1 : 0;
}

/*
 * Bit flags: 1 tracer attached, 2 anonymous executable memory, 4 frida-server.
 *
 * probe_ports is separate because it opens sockets. Nothing on a stock Quest binds
 * 27042, so a hit there is close to conclusive - but it is still the only check here
 * that touches the network, so the caller decides.
 */
ARP_EXPORT int arp_instrumentation_scan(int probe_ports)
{
    int flags = 0;

    flags |= arp_tracer_present();
    flags |= arp_anonymous_exec_memory();

    if (probe_ports) {
        if (arp_frida_port(27042) || arp_frida_port(27043)) flags |= ARP_INSTR_FRIDA_PORT;
    }

    return flags;
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
