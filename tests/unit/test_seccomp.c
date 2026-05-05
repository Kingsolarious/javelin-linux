/* seccomp filter test */

#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Declared in seccomp_shim.c */
extern int jv_seccomp_install(void);

int main(void) {
    printf("Testing seccomp filter...\n");

    if (jv_seccomp_install() != 0) {
        printf("  [SKIP] seccomp install failed (may need CAP_SYS_ADMIN)\n");
        return 0;
    }

    /* read should work */
    char buf[1];
    if (read(STDIN_FILENO, buf, 0) < 0) {
        printf("  [FAIL] read() blocked by seccomp\n");
        return 1;
    }

    /* getpid should fail with ENOSYS */
    long rc = syscall(SYS_getpid);
    if (rc >= 0 || errno != ENOSYS) {
        printf("  [FAIL] getpid() not blocked (rc=%ld, errno=%d)\n", rc, errno);
        return 1;
    }

    printf("  [PASS] seccomp filter: allowed syscalls work, blocked return ENOSYS\n");
    return 0;
}
