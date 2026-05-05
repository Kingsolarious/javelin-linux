/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * architecture-specific constants.
 *
 * windows NT hardcodes these per architecture. the linux shim
 * must match exactly or games miscompute address space layout.
 */

#ifndef JVL_ARCH_H
#define JVL_ARCH_H

#include <stdint.h>

#if defined(__x86_64__)

/* x86_64 canonical address space. bit 47 sign-extends.
 * 48-bit virtual, 57-bit with 5-level paging (la57).
 * games compiled for windows x64 assume 48-bit. */
#define JV_ARCH_MIN_ADDR 0x0000000000010000ULL
#define JV_ARCH_MAX_ADDR 0x00007FFFFFFFFFFFULL
#define JV_ARCH_PAGE_SHIFT 12
#define JV_ARCH_NAME "x86_64"

#elif defined(__aarch64__)

/* arm64 virtual address space. TCR_EL1.T1SZ determines the
 * effective size. typical linux distros use 39-bit (T1SZ=25)
 * or 48-bit (T1SZ=16). windows on arm64 uses 48-bit.
 * match the windows assumption. */
#define JV_ARCH_MIN_ADDR 0x0000000000010000ULL
#define JV_ARCH_MAX_ADDR 0x0000FFFFFFFFFFFFULL
#define JV_ARCH_PAGE_SHIFT 12
#define JV_ARCH_NAME "aarch64"

#else

#error "unsupported architecture"

#endif

#endif
