/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * javelin linux native interface
 * public API for libjavelin.so
 *
 * this header defines the ABI. changes require corresponding
 * windows-side updates.
 */

#ifndef JAVELIN_H
#define JAVELIN_H

#include <stddef.h>
#include <stdint.h>

typedef int32_t jv_result_t;

#define JV_OK 0
#define JV_ERR_DENIED -1
#define JV_ERR_INVALID -2
#define JV_ERR_NOMEM -3
#define JV_ERR_NOTIMPL -4

typedef void *jv_handle_t;
#define JV_INVALID_HANDLE ((void *)-1)

/* windows NT info class values. renumbering will break compatibility. */
enum jv_proc_info {
    JV_PROC_BASIC = 0,
    JV_PROC_DEBUG_PORT = 7,
    JV_PROC_IMAGE_NAME = 27,
};

enum jv_sys_info {
    JV_SYS_BASIC = 0,
    JV_SYS_PROCESSOR = 1,
    JV_SYS_PERFORMANCE = 2,
    JV_SYS_PROCESS = 5,
};

/* windows page protection flags. same values as winnt.h */
enum jv_mem_prot {
    JV_PROT_NONE = 0x01,
    JV_PROT_READ = 0x02,
    JV_PROT_WRITE = 0x04,
    JV_PROT_EXEC = 0x10,
};

/* windows memory allocation flags. same values as winnt.h */
enum jv_mem_flags {
    JV_MEM_COMMIT = 0x00001000,
    JV_MEM_RESERVE = 0x00002000,
    JV_MEM_TOPDOWN = 0x00100000,
};

/* process */
jv_result_t jv_query_system_info(int info_class, void *buf, uint32_t len, uint32_t *out_len);
jv_result_t jv_query_process_info(jv_handle_t proc, int info_class, void *buf, uint32_t len,
                                  uint32_t *out_len);
jv_result_t jv_open_process(jv_handle_t *out, uint32_t access, void *client_id);
jv_result_t jv_close_handle(jv_handle_t h);

/* memory */
jv_result_t jv_read_memory(jv_handle_t proc, void *addr, void *buf, uint32_t len,
                           uint32_t *out_len);
jv_result_t jv_write_memory(jv_handle_t proc, void *addr, const void *buf, uint32_t len,
                            uint32_t *out_len);
jv_result_t jv_protect_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t prot,
                              uint32_t *old_prot);
jv_result_t jv_alloc_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t flags,
                            uint32_t prot);
jv_result_t jv_free_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t free_type);
jv_result_t jv_flush_icache(jv_handle_t proc, void *addr, uint32_t len);

/* threads */
jv_result_t jv_create_thread(jv_handle_t *out, void *start, void *arg);

/* debug */
jv_result_t jv_debug_attach(jv_handle_t proc);
jv_result_t jv_debug_detach(jv_handle_t proc);

/* registry (stub) */
jv_result_t jv_query_value(void *key, void *name, uint32_t class, void *buf, uint32_t len,
                           uint32_t *out_len);

/* files (stub) */
jv_result_t jv_create_file(jv_handle_t *out, const char *path, uint32_t access,
                           uint32_t disposition);

/* callbacks (stub) */
jv_result_t jv_register_callbacks(void *reg, void **out);
void jv_unregister_callbacks(void *cb);

/* lifecycle */
int jv_init(void);
void jv_fini(void);

#endif
