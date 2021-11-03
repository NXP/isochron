/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2019-2021 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - libnfnetlink.h
 */
#ifndef _ISOCHRON_ENDIAN_H /* _ENDIAN_H name is taken :-/ */
#define _ISOCHRON_ENDIAN_H

/* Copied from libnfnetlink.h */

/* Pablo: What is the equivalence of be64_to_cpu in userspace?
 *
 * Harald: Good question.  I don't think there's a standard way [yet?],
 * so I'd suggest manually implementing it by "#if little endian" bitshift
 * operations in C (at least for now).
 *
 * All the payload of any nfattr will always be in network byte order.
 * This would allow easy transport over a real network in the future
 * (e.g. jamal's netlink2).
 *
 * Pablo: I've called it __be64_to_cpu instead of be64_to_cpu, since maybe
 * there will one in the userspace headers someday. We don't want to
 * pollute POSIX space naming,
 */
#include <byteswap.h>

#ifdef __CHECKER__
#define __force		__attribute__((force))
#else
# define __force
#endif /* __CHECKER__ */

#if __BYTE_ORDER == __BIG_ENDIAN
#  ifndef __be16_to_cpu
#  define __be16_to_cpu(x)	((__force __u16)(__be16)(x))
#  endif
#  ifndef __cpu_to_be16
#  define __cpu_to_be16(x)	((__force __be16)(__u16)(x))
#  endif
#  ifndef __be32_to_cpu
#  define __be32_to_cpu(x)	((__force __u32)(__be32)(x))
#  endif
#  ifndef __cpu_to_be32
#  define __cpu_to_be32(x)	((__force __be32)(__u32)(x))
#  endif
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	((__force __u64)(__be64)(x))
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	((__force __be64)(__u64)(x))
#  endif
# else
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  ifndef __be16_to_cpu
#  define __be16_to_cpu(x)	__bswap_16((__force __u16)(__be16)(x))
#  endif
#  ifndef __cpu_to_be16
#  define __cpu_to_be16(x)	((__force __be16)__bswap_16((x)))
#  endif
#  ifndef __be32_to_cpu
#  define __be32_to_cpu(x)	__bswap_32((__force __u32)(__be32)(x))
#  endif
#  ifndef __cpu_to_be32
#  define __cpu_to_be32(x)	((__force __be32)__bswap_32((x)))
#  endif
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	__bswap_64((__force __u64)(__be64)(x))
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	((__force __be64)__bswap_64((x)))
#  endif
# endif
#endif

#endif
