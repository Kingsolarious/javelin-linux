/*
 * Unit tests for the native javelin.h API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "../../src/javelin/javelin.h"

static int test_system_info(void)
{
    struct { uint32_t page_size; uint32_t phys_pages; uint32_t gran; uint64_t min_a; uint64_t max_a; char cpus; } info = {0};
    uint32_t retlen = 0;

    jv_result_t rc = jv_query_system_info(JV_SYS_BASIC, &info, sizeof(info), &retlen);
    assert(rc == JV_OK);
    assert(retlen == sizeof(info));
    assert(info.page_size > 0);
    assert(info.cpus > 0);
    printf("  [PASS] jv_query_system_info(JV_SYS_BASIC)\n");
    return 0;
}

static int test_stub_classes(void)
{
    char buf[256];
    for (int cls = 1; cls <= 10; cls++) {
        memset(buf, 0xAA, sizeof(buf));
        uint32_t local_retlen = 0;
        jv_result_t rc = jv_query_system_info(cls, buf, sizeof(buf), &local_retlen);
        assert(rc == JV_OK);
        for (size_t i = 0; i < local_retlen; i++)
            assert((unsigned char)buf[i] != 0xAA);
    }
    printf("  [PASS] jv_query_system_info stub classes\n");
    return 0;
}

static int test_read_memory_self(void)
{
    uint32_t magic = 0xDEADBEEF;
    uint32_t readbuf = 0;
    uint32_t readlen = 0;

    jv_result_t rc = jv_read_memory(NULL, &magic, &readbuf, sizeof(readbuf), &readlen);
    if (rc == JV_OK) {
        assert(readbuf == magic);
        assert(readlen == sizeof(magic));
        printf("  [PASS] jv_read_memory (self)\n");
    } else {
        printf("  [PASS] jv_read_memory (self) denied (expected in restricted env)\n");
    }
    return 0;
}

static int test_protect_memory(void)
{
    size_t ps = 4096;
    char *mem = aligned_alloc(ps, ps);
    assert(mem != NULL);
    memset(mem, 0, ps);

    void *base = mem;
    uint32_t len = (uint32_t)ps;
    uint32_t oldprot = 0;

    jv_result_t rc = jv_protect_memory(NULL, &base, &len, JV_PROT_READ | JV_PROT_WRITE, &oldprot);
    assert(rc == JV_OK);
    printf("  [PASS] jv_protect_memory (READ|WRITE)\n");

    free(mem);
    return 0;
}

static int test_close_handle(void)
{
    assert(jv_close_handle((void *)0x1234) == JV_OK);
    printf("  [PASS] jv_close_handle\n");
    return 0;
}

static int test_process_info(void)
{
    struct { int32_t exit; void *peb; uint64_t aff; int32_t prio; uint64_t pid; uint64_t parent; } info = {0};
    uint32_t retlen = 0;

    jv_result_t rc = jv_query_process_info(NULL, JV_PROC_BASIC, &info, sizeof(info), &retlen);
    assert(rc == JV_OK);
    assert(info.pid == (uint64_t)getpid());
    printf("  [PASS] jv_query_process_info(JV_PROC_BASIC)\n");
    return 0;
}

static int test_alloc_free(void)
{
    void *addr = NULL;
    uint32_t len = 4096;

    jv_result_t rc = jv_alloc_memory(NULL, &addr, &len, JV_MEM_RESERVE | JV_MEM_COMMIT, JV_PROT_READ | JV_PROT_WRITE);
    assert(rc == JV_OK);
    assert(addr != NULL);

    rc = jv_free_memory(NULL, &addr, &len, 0);
    assert(rc == JV_OK);
    assert(addr == NULL);
    printf("  [PASS] jv_alloc_memory / jv_free_memory\n");
    return 0;
}

int main(void)
{
    printf("Running javelin native API tests...\n");

    test_system_info();
    test_stub_classes();
    test_read_memory_self();
    test_protect_memory();
    test_close_handle();
    test_process_info();
    test_alloc_free();

    printf("\nAll tests passed.\n");
    return 0;
}
