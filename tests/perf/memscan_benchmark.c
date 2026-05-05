/*
 * memscan benchmark
 * quick throughput test for process_vm_readv and mprotect
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define TARGET_THROUGHPUT_MB_S 500
#define WARMUP_ITERATIONS 10
#define BENCHMARK_ITERATIONS 100

/* timing */
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static double mb_per_sec(size_t bytes, uint64_t ns) {
    return (double)bytes / ((double)ns / 1e9) / (1024.0 * 1024.0);
}

/* benchmark 1: self-read throughput */
static int bench_self_read(size_t region_size) {
    char *src = mmap(NULL, region_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* fill so the kernel does not zero-page dedup */
    for (size_t i = 0; i < region_size; i++)
        src[i] = (char)(i & 0xFF);

    char *dst = aligned_alloc(4096, region_size);
    if (!dst) {
        perror("aligned_alloc");
        return 1;
    }

    struct iovec local = {.iov_base = dst, .iov_len = region_size};
    struct iovec remote = {.iov_base = src, .iov_len = region_size};

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        ssize_t rc = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (rc < 0) {
            perror("process_vm_readv (warmup)");
            return 1;
        }
    }

    /* Benchmark */
    uint64_t start = now_ns();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        ssize_t rc = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (rc < 0) {
            perror("process_vm_readv");
            return 1;
        }
    }
    uint64_t elapsed = now_ns() - start;

    size_t total_bytes = region_size * BENCHMARK_ITERATIONS;
    double throughput = mb_per_sec(total_bytes, elapsed);
    double latency_us = (double)elapsed / BENCHMARK_ITERATIONS / 1000.0;

    printf("Self-read (%zu MB):  %.1f MB/s  |  latency %.2f us/call\n", region_size / (1024 * 1024),
           throughput, latency_us);

    if (throughput < TARGET_THROUGHPUT_MB_S) {
        printf("  WARNING: Below target of %d MB/s\n", TARGET_THROUGHPUT_MB_S);
    }

    munmap(src, region_size);
    free(dst);
    return 0;
}

/* benchmark 2: chunked vector read */
static int bench_chunked_read(size_t total_size, size_t chunk_size) {
    char *src = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(src, 0xAB, total_size);

    size_t num_chunks = total_size / chunk_size;
    struct iovec *local = calloc(num_chunks, sizeof(struct iovec));
    struct iovec *remote = calloc(num_chunks, sizeof(struct iovec));
    char *dst = aligned_alloc(4096, total_size);
    if (!local || !remote || !dst) {
        perror("allocation failed");
        return 1;
    }

    for (size_t i = 0; i < num_chunks; i++) {
        local[i].iov_base = dst + i * chunk_size;
        local[i].iov_len = chunk_size;
        remote[i].iov_base = src + i * chunk_size;
        remote[i].iov_len = chunk_size;
    }

    const int max_iov = 1024;
    uint64_t start = now_ns();
    for (size_t offset = 0; offset < num_chunks; offset += max_iov) {
        int iovcnt = (num_chunks - offset < (size_t)max_iov) ? (int)(num_chunks - offset) : max_iov;
        ssize_t rc = process_vm_readv(getpid(), local + offset, iovcnt, remote + offset, iovcnt, 0);
        if (rc < 0) {
            perror("process_vm_readv (chunked)");
            return 1;
        }
        (void)rc;
    }
    uint64_t elapsed = now_ns() - start;

    double throughput = mb_per_sec(total_size, elapsed);
    printf("Chunked read (%zu chunks of %zu KB):  %.1f MB/s\n", num_chunks, chunk_size / 1024,
           throughput);

    free(local);
    free(remote);
    free(dst);
    munmap(src, total_size);
    return 0;
}

/* benchmark 3: mprotect w->x latency */
static int bench_mprotect(size_t region_size) {
    char *mem = mmap(NULL, region_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        mprotect(mem, region_size, PROT_READ | PROT_EXEC);
        mprotect(mem, region_size, PROT_READ | PROT_WRITE);
    }

    uint64_t start = now_ns();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        mprotect(mem, region_size, PROT_READ | PROT_EXEC);
        mprotect(mem, region_size, PROT_READ | PROT_WRITE);
    }
    uint64_t elapsed = now_ns() - start;

    double latency_us = (double)elapsed / BENCHMARK_ITERATIONS / 2 / 1000.0;
    printf("mprotect toggle (%zu MB):  %.2f us/call\n", region_size / (1024 * 1024), latency_us);

    munmap(mem, region_size);
    return 0;
}

/* main */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("memscan benchmark\n");
    printf("target: >= %d MB/s\n\n", TARGET_THROUGHPUT_MB_S);

    int rc = 0;

    printf("continuous read:\n");
    rc |= bench_self_read(4 * 1024 * 1024);  /* 4 MB */
    rc |= bench_self_read(16 * 1024 * 1024); /* 16 MB */
    rc |= bench_self_read(64 * 1024 * 1024); /* 64 MB */
    printf("\n");

    printf("chunked read:\n");
    rc |= bench_chunked_read(64 * 1024 * 1024, 4 * 1024);  /* 4 KB chunks */
    rc |= bench_chunked_read(64 * 1024 * 1024, 64 * 1024); /* 64 KB chunks */
    printf("\n");

    printf("mprotect toggle:\n");
    rc |= bench_mprotect(4 * 1024 * 1024);
    rc |= bench_mprotect(64 * 1024 * 1024);
    printf("\n");

    if (rc == 0)
        printf("Benchmark completed successfully.\n");
    else
        printf("Benchmark completed with errors.\n");

    return rc;
}
