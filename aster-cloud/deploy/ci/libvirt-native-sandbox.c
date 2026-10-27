/* CI-only Linux amd64 launcher. Not shipped in controller/node bundles.
 *
 * libslirp 4.7 invokes setsid() in its guestfwd child before exec. QEMU 6.2/8.2
 * groups that session operation with credential changes. Keep QEMU's default,
 * obsolete and resource-control filters, replacing only its PRIVILEGED group
 * here: all nine other calls remain fatal; setgroups/capset are also denied.
 * Sources: qemu/qemu v6.2.0 softmmu/qemu-seccomp.c, v8.2.0 system/qemu-seccomp.c;
 * qemu/libslirp v4.7.0 src/misc.c, fork_exec_child_setup().
 */
#define _GNU_SOURCE
#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error "This CI helper supports Linux x86-64 LP64 only"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define QEMU "/usr/bin/qemu-system-x86_64"
#define X32_BIT UINT32_C(0x40000000)
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define NET_SIZE (2 * PATH_MAX + 512)

struct denied_call { const char *name; int number; };
static const struct denied_call denied[] = {
    {"setuid", SYS_setuid}, {"setgid", SYS_setgid},
    {"setpgid", SYS_setpgid}, {"setreuid", SYS_setreuid},
    {"setregid", SYS_setregid}, {"setresuid", SYS_setresuid},
    {"setresgid", SYS_setresgid}, {"setfsuid", SYS_setfsuid},
    {"setfsgid", SYS_setfsgid}, {"setgroups", SYS_setgroups},
    {"capset", SYS_capset},
};

static void refuse(void)
{
    fputs("NATIVE_SANDBOX_REJECTED\n", stderr);
    exit(1);
}

/* Kernel-generated fields only. Do not export IDs, paths, or /proc content. */
static bool security_status(bool filtered)
{
    FILE *stream = fopen("/proc/self/status", "re");
    char line[4096], extra;
    unsigned seen = 0;
    const uid_t uid = getuid();
    const gid_t gid = getgid();
    bool valid = stream != NULL && uid != 0 && gid != 0;
    if (stream == NULL) return false;
    while (fgets(line, sizeof(line), stream) != NULL) {
        unsigned bit = 0;
        if (strchr(line, '\n') == NULL) { valid = false; break; }
        if (strncmp(line, "Uid:", 4) == 0 || strncmp(line, "Gid:", 4) == 0) {
            unsigned long a, b, c, d;
            bool user = line[0] == 'U';
            unsigned long expected = user ? (unsigned long)uid : (unsigned long)gid;
            bit = user ? 1U : 2U;
            if (sscanf(line + 4, "%lu %lu %lu %lu %c", &a, &b, &c, &d, &extra) != 4 ||
                a != expected || b != expected || c != expected || d != expected)
                valid = false;
        } else {
            static const char *const caps[] = {"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"};
            for (size_t i = 0; i < ARRAY_LEN(caps); ++i) {
                if (strncmp(line, caps[i], 7) == 0) {
                    unsigned long long value;
                    bit = 4U << i;
                    if (sscanf(line + 7, "%llx %c", &value, &extra) != 1 || value != 0)
                        valid = false;
                }
            }
            if (strncmp(line, "NoNewPrivs:", 11) == 0) {
                unsigned value;
                bit = 64U;
                if (sscanf(line + 11, "%u %c", &value, &extra) != 1 ||
                    (filtered && value != 1)) valid = false;
            } else if (strncmp(line, "Seccomp:", 8) == 0) {
                unsigned value;
                bit = 128U;
                if (sscanf(line + 8, "%u %c", &value, &extra) != 1 ||
                    (filtered && value != 2)) valid = false;
            }
        }
        if (bit != 0 && (seen & bit) != 0) valid = false;
        seen |= bit;
    }
    if (ferror(stream)) valid = false;
    if (fclose(stream) != 0) valid = false;
    /* CapBnd is not required zero: a non-root process cannot generally drop it.
     * NNP and zero permitted/inheritable/ambient capabilities prevent exec gain. */
    return valid && seen == 255U;
}

static void install_filter(void)
{
    const struct rlimit no_core = {0, 0};
    if (!security_status(false) || setrlimit(RLIMIT_CORE, &no_core) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1) refuse();

    struct sock_filter filter[6 + 2 * ARRAY_LEN(denied) + 1];
    size_t n = 0;
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                              offsetof(struct seccomp_data, arch));
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              AUDIT_ARCH_X86_64, 1, 0);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                              offsetof(struct seccomp_data, nr));
    /* x32 shares AUDIT_ARCH_X86_64: reject its ABI bit before comparing numbers. */
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, X32_BIT, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    for (size_t i = 0; i < ARRAY_LEN(denied); ++i) {
        filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  (uint32_t)denied[i].number, 0, 1);
        filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    }
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    if (n != ARRAY_LEN(filter)) refuse();
    struct sock_fprog program = {.len = (unsigned short)n, .filter = filter};
    /* The helper is single-threaded; all later fork/exec descendants inherit. */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0L, 0L) != 0 ||
        !security_status(true)) refuse();
}

static int child_status(pid_t child)
{
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result == -1 && errno == EINTR);
    if (result != child) refuse();
    return status;
}

static void test_denied(long number, bool compat)
{
    pid_t child = fork();
    if (child < 0) refuse();
    if (child == 0) {
        alarm(3);
        if (compat) {
            /* A harmless i386 getpid through int80 must die on the arch check. */
            long result = 20;
            __asm__ volatile("int $0x80" : "+a"(result) : : "memory", "cc");
        } else {
            (void)syscall(number, 0L, 0L, 0L, 0L, 0L, 0L);
        }
        _exit(7); /* EPERM/ENOSYS is not evidence of this filter's enforcement. */
    }
    int status = child_status(child);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS) refuse();
}

static void self_test(void)
{
    alarm(30);
    install_filter();
    for (size_t i = 0; i < ARRAY_LEN(denied); ++i) test_denied(denied[i].number, false);
    test_denied((long)((uint32_t)SYS_getpid | X32_BIT), false);
    test_denied(0, true);
    pid_t child = fork();
    if (child < 0) refuse();
    if (child == 0) {
        alarm(3);
        pid_t session = setsid();
        _exit(session == getpid() && session > 0 && getsid(0) == session &&
              security_status(true) ? 0 : 8);
    }
    int status = child_status(child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || !security_status(true)) refuse();
    alarm(0);
    fputs("{\"schema\":1,\"passed\":true,\"setsid_allowed\":true,\"denied_syscalls\":[", stdout);
    for (size_t i = 0; i < ARRAY_LEN(denied); ++i)
        printf("%s\"%s\"", i == 0 ? "" : ",", denied[i].name);
    fputs("],\"x32_denied\":true,\"i386_denied\":true,\"no_new_privs\":1,\"seccomp\":2,\"capabilities_zero\":true}\n", stdout);
    if (fflush(stdout) != 0) refuse();
}

static void work_directory(char work[PATH_MAX])
{
    struct stat info;
    if (getcwd(work, PATH_MAX) == NULL || work[0] != '/' || lstat(work, &info) != 0 ||
        !S_ISDIR(info.st_mode) || info.st_uid != getuid() ||
        (info.st_mode & 07777) != 0700) refuse();
    for (const char *p = work; *p != '\0'; ++p)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || strchr("/_-.", *p) != NULL)) refuse();
}

static void owned_file(const char *path, uint64_t maximum)
{
    struct stat info;
    if (lstat(path, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != getuid() ||
        info.st_nlink != 1 || (info.st_mode & 06022) != 0 || info.st_size <= 0 ||
        (uint64_t)info.st_size > maximum) refuse();
}

static void fixed_path(char path[PATH_MAX], const char *work, const char *base)
{
    int n = snprintf(path, PATH_MAX, "%s/%s", work, base);
    if (n < 0 || n >= PATH_MAX) refuse();
}

static void drive(char *output, size_t capacity, const char *path, const char *suffix)
{
    int n = snprintf(output, capacity, "file=%s,%s", path, suffix);
    if (n < 0 || (size_t)n >= capacity) refuse();
}

static int validate_qemu(int argc, char **argv, const char *work)
{
    if (argc != 35) refuse();
    char overlay_path[PATH_MAX], image_path[PATH_MAX], seed_path[PATH_MAX], relay_path[PATH_MAX];
    char overlay[PATH_MAX + 128], image[PATH_MAX + 128], seed[PATH_MAX + 128], net[NET_SIZE];
    fixed_path(overlay_path, work, "root.qcow2");
    fixed_path(seed_path, work, "seed.img");
    fixed_path(relay_path, work, "relay.py");
    owned_file(overlay_path, UINT64_C(17179869184));
    owned_file(seed_path, UINT64_C(134217728));
    owned_file(relay_path, UINT64_C(1048576));
    drive(overlay, sizeof(overlay), overlay_path, "if=none,id=root,format=qcow2");
    drive(seed, sizeof(seed), seed_path, "if=none,id=seed,format=raw,readonly=on");
    static const char *const images[] = {
        "ubuntu-22.04-server-cloudimg-amd64.img", "ubuntu-24.04-server-cloudimg-amd64.img"
    };
    bool image_found = false;
    for (size_t i = 0; i < ARRAY_LEN(images); ++i) {
        fixed_path(image_path, work, images[i]);
        drive(image, sizeof(image), image_path, "if=none,id=approved,format=raw,readonly=on");
        if (strcmp(argv[24], image) == 0) { image_found = true; break; }
    }
    if (!image_found) refuse();
    owned_file(image_path, UINT64_C(2147483648));
    size_t length = strnlen(argv[32], sizeof(net));
    if (length < 32 || length >= sizeof(net)) refuse();
    char nonce[33];
    memcpy(nonce, argv[32] + length - 32, 32); nonce[32] = '\0';
    for (size_t i = 0; i < 32; ++i)
        if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) refuse();
    int n = snprintf(net, sizeof(net),
        "user,id=apt,restrict=on,ipv6=off,guestfwd=tcp:10.0.2.100:443-cmd:/usr/bin/python3 -I %s archive.ubuntu.com %s"
        ",guestfwd=tcp:10.0.2.101:443-cmd:/usr/bin/python3 -I %s security.ubuntu.com %s",
        relay_path, nonce, relay_path, nonce);
    if (n < 0 || (size_t)n >= sizeof(net)) refuse();
    const char *const expected[] = {
        QEMU, "-machine", "pc,accel=tcg", "-cpu", "max,vmx=off,svm=off", "-smp", "2", "-m", "3072",
        "-nodefaults", "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
        "-sandbox", "on,obsolete=deny,elevateprivileges=allow,spawn=allow,resourcecontrol=deny",
        "-drive", overlay, "-device", "virtio-blk-pci,drive=root,bootindex=0",
        "-drive", image, "-device", "virtio-blk-pci,drive=approved",
        "-drive", seed, "-device", "virtio-blk-pci,drive=seed",
        "-netdev", net, "-device", "virtio-net-pci,netdev=apt"
    };
    if ((size_t)argc != ARRAY_LEN(expected)) refuse();
    for (size_t i = 0; i < ARRAY_LEN(expected); ++i)
        if (strcmp(argv[i], expected[i]) != 0) refuse();
    /* Validate and execute the same opened root-owned binary; no PATH lookup. */
    int fd = open(QEMU, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    unsigned char magic[5];
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
        (info.st_mode & 06022) != 0 || (info.st_mode & 0111) == 0 ||
        pread(fd, magic, sizeof(magic), 0) != (ssize_t)sizeof(magic) ||
        memcmp(magic, "\177ELF\002", sizeof(magic)) != 0) refuse();
    return fd;
}

int main(int argc, char **argv)
{
    char work[PATH_MAX];
    work_directory(work);
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        self_test();
        return 0;
    }
    int executable = validate_qemu(argc - 1, argv + 1, work);
    install_filter();
    char home[PATH_MAX + 6];
    int n = snprintf(home, sizeof(home), "HOME=%s", work);
    if (n < 0 || (size_t)n >= sizeof(home)) refuse();
    char *const environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", home, NULL};
    fexecve(executable, argv + 1, environment);
    refuse();
    return 1;
}
