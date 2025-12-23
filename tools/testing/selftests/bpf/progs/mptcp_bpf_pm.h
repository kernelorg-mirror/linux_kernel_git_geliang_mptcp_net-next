/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __MPTCP_BPF_PM_H__
#define __MPTCP_BPF_PM_H__

#include "bpf_tracing_net.h"

/* mptcp helpers from include/net/mptcp.h */
#define U8_MAX		((u8)~0U)

/* max value of mptcp_addr_info.id */
#define MPTCP_PM_MAX_ADDR_ID		U8_MAX

/* mptcp macros from include/uapi/linux/mptcp.h */
#define MPTCP_PM_ADDR_FLAG_SIGNAL			(1 << 0)
#define MPTCP_PM_ADDR_FLAG_SUBFLOW			(1 << 1)
#define MPTCP_PM_ADDR_FLAG_BACKUP			(1 << 2)
#define MPTCP_PM_ADDR_FLAG_FULLMESH			(1 << 3)
#define MPTCP_PM_ADDR_FLAG_IMPLICIT			(1 << 4)

/* address families macros from include/linux/socket.h */
#define AF_UNSPEC	0
#define AF_INET		2
#define AF_INET6	10

#define inet_sk(ptr) container_of(ptr, struct inet_sock, sk)

#define ipv6_addr_equal(a, b)	((a).s6_addr32[0] == (b).s6_addr32[0] &&	\
				 (a).s6_addr32[1] == (b).s6_addr32[1] &&	\
				 (a).s6_addr32[2] == (b).s6_addr32[2] &&	\
				 (a).s6_addr32[3] == (b).s6_addr32[3])

static __always_inline bool
mptcp_addresses_equal(const struct mptcp_addr_info *a,
		      const struct mptcp_addr_info *b, bool use_port)
{
	bool addr_equals = false;

	if (a->family == b->family) {
		if (a->family == AF_INET)
			addr_equals = a->addr.s_addr == b->addr.s_addr;
		else
			addr_equals = ipv6_addr_equal(a->addr6, b->addr6);
	}

	if (!addr_equals)
		return false;
	if (!use_port)
		return true;

	return a->port == b->port;
}

static __always_inline void mptcp_pm_copy_addr(struct mptcp_addr_info *dst,
					       const struct mptcp_addr_info *src)
{
	dst->id = src->id;
	dst->family = src->family;
	dst->port = src->port;

	if (src->family == AF_INET) {
		dst->addr.s_addr = src->addr.s_addr;
	} else if (src->family == AF_INET6) {
		dst->addr6.s6_addr32[0] = src->addr6.s6_addr32[0];
		dst->addr6.s6_addr32[1] = src->addr6.s6_addr32[1];
		dst->addr6.s6_addr32[2] = src->addr6.s6_addr32[2];
		dst->addr6.s6_addr32[3] = src->addr6.s6_addr32[3];
	}
}

static __always_inline void mptcp_pm_copy_entry(struct mptcp_pm_addr_entry *dst,
						struct mptcp_pm_addr_entry *src)
{
	mptcp_pm_copy_addr(&dst->addr, &src->addr);

	dst->flags = src->flags;
	dst->ifindex = src->ifindex;
}

#define BITS_PER_LONG (sizeof(unsigned long) * 8)

static __always_inline void bpf_set_bit(unsigned long nr, unsigned long *addr)
{
	addr[nr / BITS_PER_LONG] |= (1UL << (nr % BITS_PER_LONG));
}

static __always_inline bool bpf_test_bit(unsigned long nr, const unsigned long *addr)
{
	return (addr[nr / BITS_PER_LONG] & (1UL << (nr % BITS_PER_LONG))) != 0;
}

static __always_inline uint8_t bpf_find_next_zero_bit(const unsigned long *addr,
						      unsigned long size,
						      unsigned long offset)
{
	unsigned long index = offset / BITS_PER_LONG;
	unsigned long bit_offset = offset % BITS_PER_LONG;

	for (; index * BITS_PER_LONG < size; index++) {
		unsigned long word = ~addr[index];

		if (bit_offset > 0) {
			word &= (~0UL << bit_offset);
		}

		if (index == (size - 1) / BITS_PER_LONG) {
			unsigned long excess_bits = (index + 1) * BITS_PER_LONG - size;
			if (excess_bits < BITS_PER_LONG) {
				word &= (~0UL >> excess_bits);
			}
		}

		if (word != 0) {
			unsigned long bit = __builtin_ffsl(word) - 1;
			unsigned long result = index * BITS_PER_LONG + bit;
			return (result < size) ? (uint8_t)result : (uint8_t)size;
		}

		bit_offset = 0;
	}

	return (uint8_t)size;
}
#endif
