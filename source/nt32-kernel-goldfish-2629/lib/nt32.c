/*
 * @Name: Notrace32 (=NT32): Kernel GDB tracepoint based service framework.
 * @Test: This module is tested successfully on Android emulator based on
 *        ICS SDK 4.0.4. 
 * @Compatibility: You can normally compile/run this kernel module because
 * all the Android SDK by Google is using Android kernel based same Linux 
 * version 2.6.29
 *
 * ---------------------------------------------------
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright(C) Notrace32 (https://code.google.com/p/notrace32/), 2012
 *
 */

/* Management of release version. */
#define NT32_VERSION			(20120425)

/* Support for REDHAT Linux */
#include <linux/version.h>
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b)	(((a) << 8) + (b))
#define RHEL_RELEASE_CODE		0
#endif

/* Special configuration */
#include "nt32-special.h"

/* Existing Kernel module */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/poll.h>
#include <linux/kprobes.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <asm/atomic.h>

/* Reutilize the existing Ring buffer for FTRACE */
#ifdef NT32_FTRACE_RING_BUFFER
#ifndef NT32_SELF_RING_BUFFER
#include <linux/ring_buffer.h>
#endif
#endif

/* setting performance events for system using PMU */
#ifdef CONFIG_PERF_EVENTS
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)) \
    && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,1))
#warning "Current Kernel is too old.  Function of performance counters is not available."
#else
#include <linux/perf_event.h>
#define NT32_PERF_EVENTS
#endif
#else
#warning "Current Kernel doesn't open CONFIG_PERF_EVENTS.  Function of performance counters is not available."
#endif

#ifndef __percpu
#define __percpu
#endif

#ifndef this_cpu_ptr
#define this_cpu_ptr(v)	per_cpu_ptr(v, smp_processor_id())
#endif

#define KERN_NULL

/* Verification of existing features: KPROBE , PROCFS , DEBUGFS */
#include "nt32-kprobe.h"

/* Main header file for various CPU architecture */
#include "nt32-arch.h"

/* Define MUTEX facility instead of Semaphore by default */
#ifndef DEFINE_SEMAPHORE
#define DEFINE_SEMAPHORE(name)	DECLARE_MUTEX(name)
#endif

/* Debugging of NT32 source code */ 
//#define NT32DEBUG		1
#ifdef NT32DEBUG
#define NT32_DEBUG		KERN_WARNING
#endif

/* #define NT32_DEBUG_V */

#define NT32_RW_MAX		16384
#define NT32_RW_BUFP_MAX	(NT32_RW_MAX - 4 - nt32_rw_size)

#define FID_TYPE			unsigned int
#define FID_SIZE			sizeof(FID_TYPE)
#define FID(x)			(*((FID_TYPE *)x))
#define FID_HEAD			0
#define FID_REG			1
#define FID_MEM			2
#define FID_VAR			3
#define FID_END			4
#define FID_PAGE_BEGIN		5
#define FID_PAGE_END		6

/* NT32_framework_SIZE must align with framework_ALIGN_SIZE 
 * if use NT32_framework_SIMPLE. 
 */
#include "nt32-framework.h"

// opeartion code and data structures 
#include "nt32-structure.h"

/* Ring buffer for kernel-level GDB tracepoint module. */
#ifdef NT32_RB
#include "nt32_rb.c"
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)) \
    || (RHEL_RELEASE_CODE != 0 && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5,6))

#ifndef __HAVE_ARCH_STRCASECMP
/* Compare strings */
int strcasecmp(const char *s1, const char *s2)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while (c1 == c2 && c1 != 0);
	return c1 - c2;
}
#endif

#ifndef __HAVE_ARCH_STRNCASECMP
/* Compare strings according to length */
int strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}
#endif
#endif

/* Allocate CPU cycle depends on a specific core */ 
#define NT32_LOCAL_CLOCK	nt32_local_clock()
#ifdef NT32_CLOCK_CYCLE
static unsigned long long
nt32_local_clock(void)
{
#ifdef CONFIG_X86
	unsigned long long a;
	rdtscll(a);
	return a;
#else
#error "This ARCH cannot get cycle."
#endif
}
#else
static unsigned long long
nt32_local_clock(void)
{
#ifdef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
	unsigned long flags;
	unsigned int cpu;

	local_irq_save(flags);
	cpu = smp_processor_id();
	local_irq_restore(flags);

	return cpu_clock(cpu);
#else
	return cpu_clock(0);
#endif	/* CONFIG_HAVE_UNSTABLE_SCHED_CLOCK */
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
static long
probe_kernel_read(void *dst, const void *src, size_t size)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);

	/* pagefault_disable();*/
	inc_preempt_count();
	barrier();

	ret = __copy_from_user_inatomic(dst,
			(__force const void __user *)src, size);

	/* pagefault_enable(); */
	barrier();
	dec_preempt_count();
	barrier();
	preempt_check_resched();

	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif

struct nt32_realloc_s {
	char		*buf;
	size_t	size;
	size_t	real_size;
};


/* Reallocate aloocation */ 
static int
nt32_realloc_alloc(struct nt32_realloc_s *grs, size_t size)
{
	if (size) {
		grs->buf = vmalloc(size);
		if (!grs->buf)
			return -ENOMEM;
	} else
		grs->buf = NULL;

	grs->size = 0;
	grs->real_size = size;

	return 0;
}

/* Reallocate */ 
static char *
nt32_realloc(struct nt32_realloc_s *grs, size_t size, int is_end)
{
	char	*tmp;

	if (unlikely((grs->real_size < grs->size + size)
		     || (is_end && grs->real_size != grs->size + size))) {
		grs->real_size = grs->size + size;
		if (!is_end)
			grs->real_size += 100;

		tmp = vmalloc(grs->real_size);
		if (!tmp) {
			vfree(grs->buf);
			memset(grs, 0, sizeof(struct nt32_realloc_s));
			return NULL;
		}

		memcpy(tmp, grs->buf, grs->size);
		if (grs->buf)
			vfree(grs->buf);
		grs->buf = tmp;
	}

	grs->size += size;
	return grs->buf + grs->size - size;
}

/* Reallocate strings */
static int
nt32_realloc_str(struct nt32_realloc_s *grs, char *str, int is_end)
{
	char	*wbuf;
	int	str_len = strlen(str);

	wbuf = nt32_realloc(grs, str_len, is_end);
	if (wbuf == NULL)
		return -ENOMEM;

	memcpy(wbuf, str, str_len);

	return 0;
}

static inline void
nt32_realloc_reset(struct nt32_realloc_s *grs)
{
	grs->size = 0;
}

static inline int
nt32_realloc_is_alloced(struct nt32_realloc_s *grs)
{
	return (grs->buf != NULL);
}

static inline int
nt32_realloc_is_empty(struct nt32_realloc_s *grs)
{
	return (grs->size == 0);
}

static inline void
nt32_realloc_sub_size(struct nt32_realloc_s *grs, size_t size)
{
	grs->size -= size;
}

/* Translation of x86 registers ( Reading registers ) */
#ifdef CONFIG_X86
static ULONGEST
nt32_action_reg_read(struct pt_regs *regs, struct nt32_entry *tpe, int num)
{
	ULONGEST	ret;

	switch (num) {
#ifdef CONFIG_X86_32
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	case 0:
		ret = regs->ax;
		break;
	case 1:
		ret = regs->cx;
		break;
	case 2:
		ret = regs->dx;
		break;
	case 3:
		ret = regs->bx;
		break;
	case 4:
		ret = (ULONGEST)(CORE_ADDR)&regs->sp;
		break;
	case 5:
		ret = regs->bp;
		break;
	case 6:
		ret = regs->si;
		break;
	case 7:
		ret = regs->di;
		break;
	case 8:
		if (tpe->step)
			ret = regs->ip;
		else
			ret = regs->ip - 1;
		break;
	case 9:
		ret = regs->flags;
		break;
	case 10:
		ret = regs->cs;
		break;
	case 11:
		ret = regs->ss;
		break;
	case 12:
		ret = regs->ds;
		break;
	case 13:
		ret = regs->es;
		break;
	case 14:
		ret = regs->fs;
		break;
	case 15:
		ret = regs->gs;
		break;
#else
	case 0:
		ret = regs->eax;
		break;
	case 1:
		ret = regs->ecx;
		break;
	case 2:
		ret = regs->edx;
		break;
	case 3:
		ret = regs->ebx;
		break;
	case 4:
		ret = (ULONGEST)(CORE_ADDR)&regs->esp;
		break;
	case 5:
		ret = regs->ebp;
		break;
	case 6:
		ret = regs->esi;
		break;
	case 7:
		ret = regs->edi;
		break;
	case 8:
		ret = regs->eip - 1;
		break;
	case 9:
		ret = regs->eflags;
		break;
	case 10:
		ret = regs->xcs;
		break;
	case 11:
		ret = regs->xss;
		break;
	case 12:
		ret = regs->xds;
		break;
	case 13:
		ret = regs->xes;
		break;
	case 14:
		/* ret = regs->xfs; */
		ret = 0;
		break;
	case 15:
		/* ret = regs->xgs; */
		ret = 0;
		break;
#endif
#else
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	case 0:
		ret = regs->ax;
		break;
	case 1:
		ret = regs->bx;
		break;
	case 2:
		ret = regs->cx;
		break;
	case 3:
		ret = regs->dx;
		break;
	case 4:
		ret = regs->si;
		break;
	case 5:
		ret = regs->di;
		break;
	case 6:
		ret = regs->bp;
		break;
	case 7:
		ret = regs->sp;
		break;
	case 16:
		if (tpe->step)
			ret = regs->ip;
		else
			ret = regs->ip - 1;
		break;
	case 17:
		ret = regs->flags;
		break;
#else
	case 0:
		ret = regs->rax;
		break;
	case 1:
		ret = regs->rbx;
		break;
	case 2:
		ret = regs->rcx;
		break;
	case 3:
		ret = regs->rdx;
		break;
	case 4:
		ret = regs->rsi;
		break;
	case 5:
		ret = regs->rdi;
		break;
	case 6:
		ret = regs->rbp;
		break;
	case 7:
		ret = regs->rsp;
		break;
	case 16:
		if (tpe->step)
			ret = regs->rip;
		else
			ret = regs->rip - 1;
		break;
	case 17:
		ret = regs->eflags;
		break;
#endif
	case 8:
		ret = regs->r8;
		break;
	case 9:
		ret = regs->r9;
		break;
	case 10:
		ret = regs->r10;
		break;
	case 11:
		ret = regs->r11;
		break;
	case 12:
		ret = regs->r12;
		break;
	case 13:
		ret = regs->r13;
		break;
	case 14:
		ret = regs->r14;
		break;
	case 15:
		ret = regs->r15;
		break;
	case 18:
		ret = regs->cs;
		break;
	case 19:
		ret = regs->ss;
		break;
#endif
	default:
		ret = 0;
		tpe->reason = nt32_stop_access_wrong_reg;
		break;
	}

	return ret;
}

/* Convert  registers to ascii */
static void
nt32_regs2ascii(struct pt_regs *regs, char *buf)
{
/* for ./arch/x86/innclude/asm/swab.h */ 
#ifdef CONFIG_X86_32
#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_regs2ascii: ax = 0x%x\n",
		(unsigned int) regs->ax);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cx = 0x%x\n",
		(unsigned int) regs->cx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: dx = 0x%x\n",
		(unsigned int) regs->dx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bx = 0x%x\n",
		(unsigned int) regs->bx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: sp = 0x%x\n",
		(unsigned int) regs->sp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bp = 0x%x\n",
		(unsigned int) regs->bp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: si = 0x%x\n",
		(unsigned int) regs->si);
	printk(NT32_DEBUG_V "nt32_regs2ascii: di = 0x%x\n",
		(unsigned int) regs->di);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ip = 0x%x\n",
		(unsigned int) regs->ip);
	printk(NT32_DEBUG_V "nt32_regs2ascii: flags = 0x%x\n",
		(unsigned int) regs->flags);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cs = 0x%x\n",
		(unsigned int) regs->cs);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ss = 0x%x\n",
		(unsigned int) regs->ss);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ds = 0x%x\n",
		(unsigned int) regs->ds);
	printk(NT32_DEBUG_V "nt32_regs2ascii: es = 0x%x\n",
		(unsigned int) regs->es);
	printk(NT32_DEBUG_V "nt32_regs2ascii: fs = 0x%x\n",
		(unsigned int) regs->fs);
	printk(NT32_DEBUG_V "nt32_regs2ascii: gs = 0x%x\n",
		(unsigned int) regs->gs);
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	sprintf(buf, "%08x", (unsigned int) swab32(regs->ax));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->cx));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->dx));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->bx));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->sp));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->bp));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->si));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->di));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->ip));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->flags));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->cs));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->ss));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->ds));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->es));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->fs));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->gs));
	buf += 8;
#else
	sprintf(buf, "%08x", (unsigned int) swab32(regs->eax));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->ecx));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->edx));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->ebx));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->esp));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->ebp));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->esi));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->edi));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->eip));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->eflags));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->xcs));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->xss));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->xds));
	buf += 8;
	sprintf(buf, "%08x", (unsigned int) swab32(regs->xes));
	buf += 8;
	/* sprintf(buf, "%08x", (unsigned int) swab32(regs->xfs)); */
	sprintf(buf, "00000000");
	buf += 8;
	/* sprintf(buf, "%08x", (unsigned int) swab32(regs->xgs)); */
	sprintf(buf, "00000000");
	buf += 8;
#endif
#else
#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_regs2ascii: ax = 0x%lx\n", regs->ax);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bx = 0x%lx\n", regs->bx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cx = 0x%lx\n", regs->cx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: dx = 0x%lx\n", regs->dx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: si = 0x%lx\n", regs->si);
	printk(NT32_DEBUG_V "nt32_regs2ascii: di = 0x%lx\n", regs->di);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bp = 0x%lx\n", regs->bp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: sp = 0x%lx\n", regs->sp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r8 = 0x%lx\n", regs->r8);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r9 = 0x%lx\n", regs->r9);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r10 = 0x%lx\n", regs->r10);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r11 = 0x%lx\n", regs->r11);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r12 = 0x%lx\n", regs->r12);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r13 = 0x%lx\n", regs->r13);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r14 = 0x%lx\n", regs->r14);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r15 = 0x%lx\n", regs->r15);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ip = 0x%lx\n", regs->ip);
	printk(NT32_DEBUG_V "nt32_regs2ascii: flags = 0x%lx\n", regs->flags);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cs = 0x%lx\n", regs->cs);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ss = 0x%lx\n", regs->ss);
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->ax));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->bx));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->cx));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->dx));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->si));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->di));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->bp));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->sp));
	buf += 16;
#else
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rax));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rbx));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rcx));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rdx));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rsi));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rdi));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rbp));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rsp));
	buf += 16;
#endif
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r8));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r9));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r10));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r11));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r12));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r13));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r14));
	buf += 16;
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->r15));
	buf += 16;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->ip));
	buf += 16;
	sprintf(buf, "%08x",
		(unsigned int) swab32((unsigned int)regs->flags));
	buf += 8;
#else
	sprintf(buf, "%016lx", (unsigned long) swab64(regs->rip));
	buf += 16;
	sprintf(buf, "%08x",
		(unsigned int) swab32((unsigned int)regs->eflags));
	buf += 8;
#endif
	sprintf(buf, "%08x",
		(unsigned int) swab32((unsigned int)regs->cs));
	buf += 8;
	sprintf(buf, "%08x",
		(unsigned int) swab32((unsigned int)regs->ss));
	buf += 8;
#endif
}

static void
nt32_regs2bin(struct pt_regs *regs, char *buf)
{
#ifdef CONFIG_X86_32
#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_regs2ascii: ax = 0x%x\n",
		(unsigned int) regs->ax);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cx = 0x%x\n",
		(unsigned int) regs->cx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: dx = 0x%x\n",
		(unsigned int) regs->dx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bx = 0x%x\n",
		(unsigned int) regs->bx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: sp = 0x%x\n",
		(unsigned int) regs->sp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bp = 0x%x\n",
		(unsigned int) regs->bp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: si = 0x%x\n",
		(unsigned int) regs->si);
	printk(NT32_DEBUG_V "nt32_regs2ascii: di = 0x%x\n",
		(unsigned int) regs->di);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ip = 0x%x\n",
		(unsigned int) regs->ip);
	printk(NT32_DEBUG_V "nt32_regs2ascii: flags = 0x%x\n",
		(unsigned int) regs->flags);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cs = 0x%x\n",
		(unsigned int) regs->cs);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ss = 0x%x\n",
		(unsigned int) regs->ss);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ds = 0x%x\n",
		(unsigned int) regs->ds);
	printk(NT32_DEBUG_V "nt32_regs2ascii: es = 0x%x\n",
		(unsigned int) regs->es);
	printk(NT32_DEBUG_V "nt32_regs2ascii: fs = 0x%x\n",
		(unsigned int) regs->fs);
	printk(NT32_DEBUG_V "nt32_regs2ascii: gs = 0x%x\n",
		(unsigned int) regs->gs);
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	memcpy(buf, &regs->ax, 4);
	buf += 4;
	memcpy(buf, &regs->cx, 4);
	buf += 4;
	memcpy(buf, &regs->dx, 4);
	buf += 4;
	memcpy(buf, &regs->bx, 4);
	buf += 4;
	memcpy(buf, &regs->sp, 4);
	buf += 4;
	memcpy(buf, &regs->bp, 4);
	buf += 4;
	memcpy(buf, &regs->si, 4);
	buf += 4;
	memcpy(buf, &regs->di, 4);
	buf += 4;
	memcpy(buf, &regs->ip, 4);
	buf += 4;
	memcpy(buf, &regs->flags, 4);
	buf += 4;
	memcpy(buf, &regs->cs, 4);
	buf += 4;
	memcpy(buf, &regs->ss, 4);
	buf += 4;
	memcpy(buf, &regs->ds, 4);
	buf += 4;
	memcpy(buf, &regs->es, 4);
	buf += 4;
	memcpy(buf, &regs->fs, 4);
	buf += 4;
	memcpy(buf, &regs->gs, 4);
	buf += 4;
#else
	memcpy(buf, &regs->eax, 4);
	buf += 4;
	memcpy(buf, &regs->ecx, 4);
	buf += 4;
	memcpy(buf, &regs->edx, 4);
	buf += 4;
	memcpy(buf, &regs->ebx, 4);
	buf += 4;
	memcpy(buf, &regs->esp, 4);
	buf += 4;
	memcpy(buf, &regs->ebp, 4);
	buf += 4;
	memcpy(buf, &regs->esi, 4);
	buf += 4;
	memcpy(buf, &regs->edi, 4);
	buf += 4;
	memcpy(buf, &regs->eip, 4);
	buf += 4;
	memcpy(buf, &regs->eflags, 4);
	buf += 4;
	memcpy(buf, &regs->xcs, 4);
	buf += 4;
	memcpy(buf, &regs->xss, 4);
	buf += 4;
	memcpy(buf, &regs->xds, 4);
	buf += 4;
	memcpy(buf, &regs->xes, 4);
	buf += 4;
	/* memcpy(buf, &regs->xfs, 4); */
	memset(buf, '\0', 4);
	buf += 4;
	/* memcpy(buf, &regs->xgs, 4); */
	memset(buf, '\0', 4);
	buf += 4;
#endif
#else
#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_regs2ascii: ax = 0x%lx\n", regs->ax);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bx = 0x%lx\n", regs->bx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cx = 0x%lx\n", regs->cx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: dx = 0x%lx\n", regs->dx);
	printk(NT32_DEBUG_V "nt32_regs2ascii: si = 0x%lx\n", regs->si);
	printk(NT32_DEBUG_V "nt32_regs2ascii: di = 0x%lx\n", regs->di);
	printk(NT32_DEBUG_V "nt32_regs2ascii: bp = 0x%lx\n", regs->bp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: sp = 0x%lx\n", regs->sp);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r8 = 0x%lx\n", regs->r8);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r9 = 0x%lx\n", regs->r9);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r10 = 0x%lx\n", regs->r10);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r11 = 0x%lx\n", regs->r11);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r12 = 0x%lx\n", regs->r12);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r13 = 0x%lx\n", regs->r13);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r14 = 0x%lx\n", regs->r14);
	printk(NT32_DEBUG_V "nt32_regs2ascii: r15 = 0x%lx\n", regs->r15);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ip = 0x%lx\n", regs->ip);
	printk(NT32_DEBUG_V "nt32_regs2ascii: flags = 0x%lx\n", regs->flags);
	printk(NT32_DEBUG_V "nt32_regs2ascii: cs = 0x%lx\n", regs->cs);
	printk(NT32_DEBUG_V "nt32_regs2ascii: ss = 0x%lx\n", regs->ss);
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	memcpy(buf, &regs->ax, 8);
	buf += 8;
	memcpy(buf, &regs->bx, 8);
	buf += 8;
	memcpy(buf, &regs->cx, 8);
	buf += 8;
	memcpy(buf, &regs->dx, 8);
	buf += 8;
	memcpy(buf, &regs->si, 8);
	buf += 8;
	memcpy(buf, &regs->di, 8);
	buf += 8;
	memcpy(buf, &regs->bp, 8);
	buf += 8;
	memcpy(buf, &regs->sp, 8);
	buf += 8;
#else
	memcpy(buf, &regs->rax, 8);
	buf += 8;
	memcpy(buf, &regs->rbx, 8);
	buf += 8;
	memcpy(buf, &regs->rcx, 8);
	buf += 8;
	memcpy(buf, &regs->rdx, 8);
	buf += 8;
	memcpy(buf, &regs->rsi, 8);
	buf += 8;
	memcpy(buf, &regs->rdi, 8);
	buf += 8;
	memcpy(buf, &regs->rbp, 8);
	buf += 8;
	memcpy(buf, &regs->rsp, 8);
	buf += 8;
#endif
	memcpy(buf, &regs->r8, 8);
	buf += 8;
	memcpy(buf, &regs->r9, 8);
	buf += 8;
	memcpy(buf, &regs->r10, 8);
	buf += 8;
	memcpy(buf, &regs->r11, 8);
	buf += 8;
	memcpy(buf, &regs->r12, 8);
	buf += 8;
	memcpy(buf, &regs->r13, 8);
	buf += 8;
	memcpy(buf, &regs->r14, 8);
	buf += 8;
	memcpy(buf, &regs->r15, 8);
	buf += 8;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	memcpy(buf, &regs->ip, 8);
	buf += 8;
	memcpy(buf, &regs->flags, 4);
	buf += 4;
#else
	memcpy(buf, &regs->rip, 8);
	buf += 8;
	memcpy(buf, &regs->eflags, 4);
	buf += 4;
#endif
	memcpy(buf, &regs->cs, 4);
	buf += 4;
	memcpy(buf, &regs->ss, 4);
	buf += 4;
#endif
}
#endif

/* Translation of  MIPS architecture using DWARF 2 spec 
 * http://gcc.gnu.org/ml/gcc-patches/2003-03/msg02596.html 
 * http://comments.gmane.org/gmane.comp.gdb.patches/8277 
 */
#ifdef CONFIG_MIPS
static ULONGEST
nt32_action_reg_read(struct pt_regs *regs, struct nt32_entry *tpe, int num)
{
	ULONGEST	ret;

	if (num > 90) {
		/* GDB convert the reg number to a GDB
		   (1 * gdbarch_num_regs .. 2 * gdbarch_num_regs) REGNUM
		   in function mips_dwarf_dwarf2_ecoff_reg_to_regnum.  */
		num -= 90;
	}

	if (num >= 0 && num <= 31) {
		ret = regs->regs[num];
	} else {
		switch (num) {
		case 32:
			ret = regs->cp0_status;
			break;
		case 33:
			ret = regs->lo;
			break;
		case 34:
			ret = regs->hi;
			break;
		case 35:
			ret = regs->cp0_badvaddr;
			break;
		case 36:
			ret = regs->cp0_cause;
			break;
		case 37:
			ret = regs->cp0_epc;
			break;
		default:
			ret = 0;
			tpe->reason = nt32_stop_access_wrong_reg;
			break;
		}
	}

	return ret;
};

/* Display the debug information of CP0 register using GDB debug spec */
static void
nt32_regs2ascii(struct pt_regs *regs, char *buf)
{
#ifdef NT32_DEBUG_V
	{
		int	i;

		for (i = 0; i < 32; i++)
			printk(NT32_DEBUG_V "nt32_gdbrsp_g: r%d = 0x%lx\n", i,
			       regs->regs[i]);
	}
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: status = 0x%lx\n",
	       regs->cp0_status);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: lo = 0x%lx\n", regs->lo);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: hi = 0x%lx\n", regs->hi);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: badvaddr = 0x%lx\n",
	       regs->cp0_badvaddr);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: cause = 0x%lx\n", regs->cp0_cause);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: pc = 0x%lx\n", regs->cp0_epc);
#endif

#ifdef CONFIG_32BIT
#define OUTFORMAT	"%08lx"
#define REGSIZE		8
#ifdef __LITTLE_ENDIAN
#define SWAB(a)		swab32(a)
#else
#define SWAB(a)		(a)
#endif
#else
#define OUTFORMAT	"%016lx"
#define REGSIZE		16
#ifdef __LITTLE_ENDIAN
#define SWAB(a)		swab64(a)
#else
#define SWAB(a)		(a)
#endif
#endif
	{
		int	i;

		for (i = 0; i < 32; i++) {
			sprintf(buf, OUTFORMAT,
				 (unsigned long) SWAB(regs->regs[i]));
			buf += REGSIZE;
		}
	}

	sprintf(buf, OUTFORMAT,
		 (unsigned long) SWAB(regs->cp0_status));
	buf += REGSIZE;
	sprintf(buf, OUTFORMAT,
		 (unsigned long) SWAB(regs->lo));
	buf += REGSIZE;
	sprintf(buf, OUTFORMAT,
		 (unsigned long) SWAB(regs->hi));
	buf += REGSIZE;
	sprintf(buf, OUTFORMAT,
		 (unsigned long) SWAB(regs->cp0_badvaddr));
	buf += REGSIZE;
	sprintf(buf, OUTFORMAT,
		 (unsigned long) SWAB(regs->cp0_cause));
	buf += REGSIZE;
	sprintf(buf, OUTFORMAT,
		 (unsigned long) SWAB(regs->cp0_epc));
	buf += REGSIZE;
#undef OUTFORMAT
#undef REGSIZE
#undef SWAB
}


/* Convert registers to binary */
static void
nt32_regs2bin(struct pt_regs *regs, char *buf)
{
#ifdef NT32_DEBUG_V
	{
		int	i;

		for (i = 0; i < 32; i++)
			printk(NT32_DEBUG_V "nt32_gdbrsp_g: r%d = 0x%lx\n", i,
			       regs->regs[i]);
	}
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: status = 0x%lx\n",
	       regs->cp0_status);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: lo = 0x%lx\n", regs->lo);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: hi = 0x%lx\n", regs->hi);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: badvaddr = 0x%lx\n",
	       regs->cp0_badvaddr);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: cause = 0x%lx\n", regs->cp0_cause);
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: pc = 0x%lx\n", regs->cp0_epc);
#endif

#ifdef CONFIG_32BIT
#define REGSIZE		4
#else
#define REGSIZE		8
#endif
	{
		int	i;

		for (i = 0; i < 32; i++) {
			memcpy(buf, &regs->regs[i], REGSIZE);
			buf += REGSIZE;
		}
	}
	memcpy(buf, &regs->cp0_status, REGSIZE);
	buf += REGSIZE;
	memcpy(buf, &regs->lo, REGSIZE);
	buf += REGSIZE;
	memcpy(buf, &regs->hi, REGSIZE);
	buf += REGSIZE;
	memcpy(buf, &regs->cp0_badvaddr, REGSIZE);
	buf += REGSIZE;
	memcpy(buf, &regs->cp0_cause, REGSIZE);
	buf += REGSIZE;
	memcpy(buf, &regs->cp0_epc, REGSIZE);
	buf += REGSIZE;
#undef REGSIZE
}
#endif

/* Read action info of registers on ARM architecutre */
#ifdef CONFIG_ARM
static ULONGEST
nt32_action_reg_read(struct pt_regs *regs, struct nt32_entry *tpe, int num)
{
	if (num >= 0 && num < 16)
		return regs->uregs[num];
	else if (num == 25)
		return regs->uregs[16];

	tpe->reason = nt32_stop_access_wrong_reg;
	return 0;
}

/* From register to Ascii */
static void
nt32_regs2ascii(struct pt_regs *regs, char *buf)
{
#ifdef __LITTLE_ENDIAN
#define SWAB(a)		swab32(a)
#else
#define SWAB(a)		(a)
#endif
	int	i;

	for (i = 0; i < 16; i++) {
#ifdef NT32_DEBUG_V
		printk(NT32_DEBUG_V "nt32_gdbrsp_g: r%d = 0x%lx\n",
		       i, regs->uregs[i]);
#endif
		sprintf(buf, "%08lx", (unsigned long) SWAB(regs->uregs[i]));
		buf += 8;
	}

	/* f0-f7 fps */
	memset(buf, '0', 200);
	buf += 200;

#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: cpsr = 0x%lx\n", regs->uregs[16]);
#endif
	sprintf(buf, "%08lx",
		 (unsigned long) SWAB(regs->uregs[16]));
	buf += 8;
#undef SWAB
}

/* From register to binary */
static void
nt32_regs2bin(struct pt_regs *regs, char *buf)
{
	int	i;

	for (i = 0; i < 16; i++) {
#ifdef NT32_DEBUG_V
		printk(NT32_DEBUG_V "nt32_gdbrsp_g: r%d = 0x%lx\n",
		       i, regs->uregs[i]);
#endif
		memcpy(buf, &regs->uregs[i], 4);
		buf += 4;
	}

	/* f0-f7 fps */
	memset(buf, '\0', 100);
	buf += 100;

#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_gdbrsp_g: cpsr = 0x%lx\n", regs->uregs[16]);
#endif
	memcpy(buf, &regs->uregs[16], 4);
	buf += 4;
}
#endif

/* If CPU architecture support PMU(Performant Monitoring Unit), 
 * Define performance event per-CPU 
 */
#ifdef NT32_PERF_EVENTS
static DEFINE_PER_CPU(int, pc_pe_list_all_disabled);
static DEFINE_PER_CPU(struct pe_tv_s *, pc_pe_list);

static void
pc_pe_list_disable(void)
{
	struct pe_tv_s *ppl;

	if (__get_cpu_var(pc_pe_list_all_disabled))
		return;

	for (ppl = __get_cpu_var(pc_pe_list); ppl; ppl = ppl->pc_next) {
		if (ppl->en)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
			__perf_event_disable(ppl->event);
#else
			perf_event_disable(ppl->event);
#endif
	}
}

/* Read cpu information from performance event */
static void
pc_pe_list_enable(void)
{
	struct pe_tv_s *ppl;

	if (__get_cpu_var(pc_pe_list_all_disabled))
		return;

	for (ppl = __get_cpu_var(pc_pe_list); ppl; ppl = ppl->pc_next) {
		if (ppl->en)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
			__perf_event_enable(ppl->event);
#else
			perf_event_enable(ppl->event);
#endif
	}
}

/* Enable cpu variable with performance event */
static void
nt32_pc_pe_en(int enable)
{
	struct pe_tv_s *ppl = __get_cpu_var(pc_pe_list);

	for (ppl = __get_cpu_var(pc_pe_list); ppl; ppl = ppl->pc_next)
		ppl->en = enable;

	__get_cpu_var(pc_pe_list_all_disabled) = !enable;
}

static void
nt32_pe_set_en(struct pe_tv_s *pts, int enable)
{
	if (pts->event->cpu != smp_processor_id()) {
		if (enable)
			perf_event_enable(pts->event);
		else
			perf_event_disable(pts->event);
	}
	pts->en = enable;
}
#else
static void
nt32_pc_pe_en(int enable)
{
}
#endif	/* End of NT32_PERF_EVENTS */

#ifdef NT32_framework_SIMPLE
static char *
nt32_framework_next(char *framework)
{
	switch (FID(framework)) {
	case FID_HEAD:
		framework += framework_ALIGN(NT32_framework_HEAD_SIZE);
		break;
	case FID_REG:
		framework += framework_ALIGN(NT32_framework_REG_SIZE);
		break;
	case FID_MEM: {
			struct nt32_framework_mem	*gfm;

			gfm = (struct nt32_framework_mem *) (framework + FID_SIZE
							+ sizeof(char *));
			framework += framework_ALIGN(NT32_framework_MEM_SIZE + gfm->size);
		}
		break;
	case FID_VAR:
		framework += framework_ALIGN(NT32_framework_VAR_SIZE);
		break;
	case FID_END:
		framework = nt32_framework_end;
		break;
	default:
		return NULL;
		break;
	}

	return framework;
}
#endif

#ifdef NT32_framework_SIMPLE
#ifdef framework_ALLOC_RECORD
ULONGEST	framework_alloc_size;
ULONGEST	framework_alloc_size_hole;
#endif

static char *
nt32_framework_alloc(size_t size)
{
	char	*ret = NULL;

#ifdef framework_ALLOC_RECORD
	framework_alloc_size += size;
	framework_alloc_size_hole += (framework_ALIGN(size) - size);
#endif

	size = framework_ALIGN(size);

	if (size > NT32_framework_SIZE)
		return NULL;

	spin_lock(&nt32_framework_lock);

	if (nt32_framework_w_start + size > nt32_framework_end) {
		if (nt32_circular) {
			nt32_framework_is_circular = 1;
#ifdef framework_ALLOC_RECORD
			if (nt32_framework_w_start != nt32_framework_end
			    && nt32_framework_end - nt32_framework_w_start < FID_SIZE) {
				printk(KERN_WARNING "framework align wrong."
						    "start = %p end = %p\n",
				       nt32_framework_w_start, nt32_framework_end);
				goto out;
			}
#endif
			if (nt32_framework_w_start != nt32_framework_end)
				FID(nt32_framework_w_start) = FID_END;
			nt32_framework_w_start = nt32_framework;
			nt32_framework_r_start = nt32_framework;
		} else
			goto out;
	}

	if (nt32_framework_is_circular) {
		while (nt32_framework_w_start <= nt32_framework_r_start
		       && nt32_framework_w_start + size > nt32_framework_r_start) {
			char *tmp = nt32_framework_next(nt32_framework_r_start);
			if (tmp == NULL)
				goto out;
			if (tmp == nt32_framework_end)
				nt32_framework_r_start = nt32_framework;
			else
				nt32_framework_r_start = tmp;
		}
	}

	ret = nt32_framework_w_start;
	nt32_framework_w_start += size;

out:
	spin_unlock(&nt32_framework_lock);
	return ret;
}
#endif

struct nt32_trace_s {
	struct nt32_entry		*tpe;
	struct pt_regs			*regs;
#ifdef NT32_framework_SIMPLE
	/* Next part set it to prev part.  */
	char				**next;
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	/* NULL means doesn't have head.  */
	char				*next;
#endif
#ifdef NT32_RB
	/* rb of current cpu.  */
	struct nt32_rb_s			*next;
	u64				id;
#endif
	int				step;
	struct kretprobe_instance	*ri;
	int				*run;
	struct timespec			xtime;
	ULONGEST			printk_tmp;
	unsigned int			printk_level;
	unsigned int			printk_format;
	struct nt32src			*printk_str;
};

#define NT32_PRINTK_FORMAT_A	0
#define NT32_PRINTK_FORMAT_D	1
#define NT32_PRINTK_FORMAT_U	2
#define NT32_PRINTK_FORMAT_X	3
#define NT32_PRINTK_FORMAT_S	4
#define NT32_PRINTK_FORMAT_B	5

#ifdef NT32_FTRACE_RING_BUFFER
#define NT32_framework_RINGBUFFER_ALLOC(size)				\
	do {								\
		rbe = ring_buffer_lock_reserve(nt32_framework, size);	\
		if (rbe == NULL) {					\
			gts->tpe->reason = nt32_stop_framework_full;		\
			return -1;					\
		}							\
		tmp = ring_buffer_event_data(rbe);			\
	} while (0)
#endif

static struct nt32_var	*nt32_nt32_var_array_find(unsigned int num);
static int		nt32_collect_var(struct nt32_trace_s *gts,
					struct nt32_var *tve);

static int
nt32_action_head(struct nt32_trace_s *gts)
{
	char				*tmp;
	ULONGEST			*trace_nump;
#ifdef NT32_FTRACE_RING_BUFFER
	struct ring_buffer_event	*rbe;
#endif

#ifdef NT32_RB
	gts->next = (struct nt32_rb_s *)this_cpu_ptr(nt32_rb);
#endif

	/* Get the head.  */
#ifdef NT32_FTRACE_RING_BUFFER
	NT32_framework_RINGBUFFER_ALLOC(NT32_framework_HEAD_SIZE);
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_RB)
#ifdef NT32_RB
	NT32_RB_LOCK(gts->next);
	tmp = nt32_rb_alloc(gts->next, NT32_framework_HEAD_SIZE, 0);
#endif
#ifdef NT32_framework_SIMPLE
	tmp = nt32_framework_alloc(NT32_framework_HEAD_SIZE);
#endif
	if (!tmp) {
		gts->tpe->reason = nt32_stop_framework_full;
		return -1;
	}
#endif

	FID(tmp) = FID_HEAD;
	tmp += FID_SIZE;

#ifdef NT32_RB
	gts->id = nt32_rb_clock();
	*(u64 *)tmp = gts->id;
	tmp += sizeof(u64);
#endif

#ifdef NT32_framework_SIMPLE
	gts->next = (char **)tmp;
	*(gts->next) = NULL;
	tmp += sizeof(char *);
#endif

	trace_nump = (ULONGEST *)tmp;
	*trace_nump = gts->tpe->num;

#ifdef NT32_FTRACE_RING_BUFFER
	ring_buffer_unlock_commit(nt32_framework, rbe);
	gts->next = (char *)1;
#endif

#ifdef NT32_framework_SIMPLE
	/* Trace $cpu_id and $clock.  */
	{
		struct nt32_var	*tve;

		tve = nt32_nt32_var_array_find(NT32_VAR_CLOCK_ID);
		if (!tve) {
			gts->tpe->reason = nt32_stop_agent_expr_code_error;
			return -1;
		}
		if (nt32_collect_var(gts, tve))
			return -1;
		tve = nt32_nt32_var_array_find(NT32_VAR_CPU_ID);
		if (!tve) {
			gts->tpe->reason = nt32_stop_agent_expr_code_error;
			return -1;
		}
		if (nt32_collect_var(gts, tve))
			return -1;
	}
#endif

	atomic_inc(&nt32_framework_create);

	return 0;
}

static int
nt32_action_printk(struct nt32_trace_s *gts, ULONGEST addr, size_t size)
{
	unsigned int	printk_format = gts->printk_format;
	char		*pbuf = __get_cpu_var(nt32_printf);

	if (gts->printk_str == NULL) {
		gts->tpe->reason = nt32_stop_agent_expr_code_error;
		printk(KERN_WARNING "nt32_action_printk: id:%d addr:%p "
				    "printk doesn't have var name.  Please "
				    "check actions of it.\n",
			(int)gts->tpe->num, (void *)(CORE_ADDR)gts->tpe->addr);
		return -1;
	}

	if (size) {
		if (size > NT32_PRINTF_MAX - 1)
			size = NT32_PRINTF_MAX - 1;
		if (gts->printk_format != NT32_PRINTK_FORMAT_S
		    && gts->printk_format != NT32_PRINTK_FORMAT_B
		    && size > 8)
			size = 8;
		if (probe_kernel_read(pbuf, (void *)(CORE_ADDR)addr, size)) {
			gts->tpe->reason = nt32_stop_efault;
			printk(KERN_WARNING "nt32_action_printk: id:%d addr:%p "
					    "read %p %u get error.\n",
			       (int)gts->tpe->num,
			       (void *)(CORE_ADDR)gts->tpe->addr,
			       (void *)(CORE_ADDR)addr,
			       (unsigned int)size);
			return -1;
		}
	} else {
		size = sizeof(ULONGEST);
		memcpy(pbuf, &addr, sizeof(ULONGEST));
	}

	if (printk_format == NT32_PRINTK_FORMAT_A) {
		if (size == 1 || size == 2 || size == 4 || size == 8)
			printk_format = NT32_PRINTK_FORMAT_U;
		else
			printk_format = NT32_PRINTK_FORMAT_B;
	}

	switch (printk_format) {
	case NT32_PRINTK_FORMAT_D:
		switch (size) {
		case 1:
			printk(KERN_NULL "<%d>%s%d\n", gts->printk_level,
			       gts->printk_str->src, pbuf[0]);
			break;
		case 2:
			printk(KERN_NULL "<%d>%s%d\n", gts->printk_level,
			       gts->printk_str->src, (int)(*(short *)pbuf));
			break;
		case 4:
			printk(KERN_NULL "<%d>%s%d\n", gts->printk_level,
			       gts->printk_str->src, *(int *)pbuf);
			break;
		case 8:
			printk(KERN_NULL "<%d>%s%lld\n", gts->printk_level,
			       gts->printk_str->src, *(long long *)pbuf);
			break;
		default:
			printk(KERN_WARNING "nt32_action_printk: id:%d addr:%p "
					    "size %d cannot printk.\n",
			       (int)gts->tpe->num,
			       (void *)(CORE_ADDR)gts->tpe->addr,
			       (unsigned int)size);
			gts->tpe->reason = nt32_stop_agent_expr_code_error;
			return -1;
			break;
		}
		break;
	case NT32_PRINTK_FORMAT_U:
		switch (size) {
		case 1:
			printk(KERN_NULL "<%d>%s%u\n", gts->printk_level,
			       gts->printk_str->src, pbuf[0]);
			break;
		case 2:
			printk(KERN_NULL "<%d>%s%u\n", gts->printk_level,
			       gts->printk_str->src, (int)(*(short *)pbuf));
			break;
		case 4:
			printk(KERN_NULL "<%d>%s%u\n", gts->printk_level,
			       gts->printk_str->src, *(int *)pbuf);
			break;
		case 8:
			printk(KERN_NULL "<%d>%s%llu\n", gts->printk_level,
			       gts->printk_str->src, *(long long *)pbuf);
			break;
		default:
			printk(KERN_WARNING "nt32_action_printk: id:%d addr:%p"
					    "size %d cannot printk.\n",
			       (int)gts->tpe->num,
			       (void *)(CORE_ADDR)gts->tpe->addr,
			       (unsigned int)size);
			gts->tpe->reason = nt32_stop_agent_expr_code_error;
			return -1;
			break;
		}
		break;
	case NT32_PRINTK_FORMAT_X:
		switch (size) {
		case 1:
			printk(KERN_NULL "<%d>%s0x%x\n", gts->printk_level,
			       gts->printk_str->src, pbuf[0]);
			break;
		case 2:
			printk(KERN_NULL "<%d>%s0x%x\n", gts->printk_level,
			       gts->printk_str->src, (int)(*(short *)pbuf));
			break;
		case 4:
			printk(KERN_NULL "<%d>%s0x%x\n", gts->printk_level,
			       gts->printk_str->src, *(int *)pbuf);
			break;
		case 8:
			printk(KERN_NULL "<%d>%s0x%llx\n", gts->printk_level,
			       gts->printk_str->src, *(long long *)pbuf);
			break;
		default:
			printk(KERN_WARNING "nt32_action_printk: id:%d addr:%p "
					    "size %d cannot printk.\n",
			       (int)gts->tpe->num,
			       (void *)(CORE_ADDR)gts->tpe->addr,
			       (unsigned int)size);
			gts->tpe->reason = nt32_stop_agent_expr_code_error;
			return -1;
			break;
		}
		break;
	case NT32_PRINTK_FORMAT_S:
		pbuf[NT32_PRINTF_MAX - 1] = '\0';
		printk("<%d>%s%s\n", gts->printk_level, gts->printk_str->src,
		       pbuf);
		break;
	case NT32_PRINTK_FORMAT_B: {
			size_t	i;

			printk(KERN_NULL "<%d>%s", gts->printk_level,
			       gts->printk_str->src);
			for (i = 0; i < size; i++)
				printk("%02x", (unsigned int)pbuf[i]);
			printk("\n");
		}
		break;
	default:
		printk(KERN_WARNING "nt32_action_printk: id:%d addr:%p "
				    "printk format %u is not support.\n",
		       (int)gts->tpe->num, (void *)(CORE_ADDR)gts->tpe->addr,
		       gts->printk_format);
		gts->tpe->reason = nt32_stop_agent_expr_code_error;
		return -1;
		break;
	}

	gts->printk_str = gts->printk_str->next;

	return 0;
}

static int
nt32_action_memory_read(struct nt32_trace_s *gts, int reg, CORE_ADDR addr,
		       size_t size)
{
	char				*tmp;
	struct nt32_framework_mem		*fm;
#ifdef NT32_FTRACE_RING_BUFFER
	struct ring_buffer_event	*rbe;
#endif

	if (reg >= 0)
		addr += (CORE_ADDR) nt32_action_reg_read(gts->regs,
							gts->tpe, reg);
	if (gts->tpe->reason != nt32_stop_normal)
		return -1;

	if (gts->next == NULL) {
		if (nt32_action_head(gts))
			return -1;
	}

#ifdef NT32_FTRACE_RING_BUFFER
	NT32_framework_RINGBUFFER_ALLOC(NT32_framework_MEM_SIZE + size);
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_RB)
#ifdef NT32_RB
	tmp = nt32_rb_alloc(gts->next, NT32_framework_MEM_SIZE + size, gts->id);
#endif
#ifdef NT32_framework_SIMPLE
	tmp = nt32_framework_alloc(NT32_framework_MEM_SIZE + size);
#endif
	if (!tmp) {
		gts->tpe->reason = nt32_stop_framework_full;
		return -1;
	}
#ifdef NT32_framework_SIMPLE
	*gts->next = tmp;
#endif
#endif

	FID(tmp) = FID_MEM;
	tmp += FID_SIZE;

#ifdef NT32_framework_SIMPLE
	gts->next = (char **)tmp;
	*gts->next = NULL;
	tmp += sizeof(char *);
#endif

	fm = (struct nt32_framework_mem *)tmp;
	fm->addr = addr;
	fm->size = size;
	tmp += sizeof(struct nt32_framework_mem);

#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_action_memory_read: id:%d addr:%p %p %u\n",
	       (int)gts->tpe->num, (void *)(CORE_ADDR)gts->tpe->addr,
	       (void *)addr, (unsigned int)size);
#endif

	if (probe_kernel_read(tmp, (void *)addr, size)) {
		gts->tpe->reason = nt32_stop_efault;
#ifdef NT32_framework_SIMPLE
		memset(tmp, 0, size);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		ring_buffer_discard_commit(nt32_framework, rbe);
#endif
#ifdef NT32_RB
		NT32_RB_RELEASE(gts->next);
#endif
		printk(KERN_WARNING "nt32_action_memory_read: id:%d addr:%p "
				    "read %p %u get error.\n",
		       (int)gts->tpe->num, (void *)(CORE_ADDR)gts->tpe->addr,
		       (void *)addr, (unsigned int)size);
		return -1;
	}

#ifdef NT32_FTRACE_RING_BUFFER
	ring_buffer_unlock_commit(nt32_framework, rbe);
#endif

	return 0;
}

static int
nt32_action_r(struct nt32_trace_s *gts, struct action *ae)
{
	struct pt_regs			*regs;
	char				*tmp;
#ifdef NT32_FTRACE_RING_BUFFER
	struct ring_buffer_event	*rbe;
#endif

	if (gts->next == NULL) {
		if (nt32_action_head(gts))
			return -1;
	}

#ifdef NT32_FTRACE_RING_BUFFER
	NT32_framework_RINGBUFFER_ALLOC(NT32_framework_REG_SIZE);
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_RB)
#ifdef NT32_RB
	tmp = nt32_rb_alloc(gts->next, NT32_framework_REG_SIZE, gts->id);
#endif
#ifdef NT32_framework_SIMPLE
	tmp = nt32_framework_alloc(NT32_framework_REG_SIZE);
#endif
	if (!tmp) {
		gts->tpe->reason = nt32_stop_framework_full;
		return -1;
	}
#ifdef NT32_framework_SIMPLE
	*gts->next = tmp;
#endif
#endif

	FID(tmp) = FID_REG;
	tmp += FID_SIZE;

#ifdef NT32_framework_SIMPLE
	gts->next = (char **)tmp;
	*gts->next = NULL;
	tmp += sizeof(char *);
#endif

	regs = (struct pt_regs *)tmp;

	memcpy(regs, gts->regs, sizeof(struct pt_regs));
#ifdef CONFIG_X86_32
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
	regs->sp = (unsigned long)&regs->sp;
#else
	regs->esp = (unsigned long)&regs->esp;
#endif
#endif	/* CONFIG_X86_32 */

	if (gts->ri)
		NT32_REGS_PC(regs) = (CORE_ADDR)gts->ri->ret_addr;
#ifdef CONFIG_X86
	else if (!gts->step)
		NT32_REGS_PC(regs) -= 1;
#endif	/* CONFIG_X86 */

#ifdef NT32_FTRACE_RING_BUFFER
	ring_buffer_unlock_commit(nt32_framework, rbe);
#endif

	return 0;
}

static struct nt32_var *
nt32_nt32_var_array_find(unsigned int num)
{
	struct nt32_var	*ret;

#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_nt32_var_array_find: num:%u %u %u\n",
	       nt32_var_head, nt32_var_tail, num);
#endif

	if (num < nt32_var_head || num > nt32_var_tail)
		return NULL;

	ret = nt32_var_array[num - nt32_var_head];
	if (ret->per_cpu)
		ret = ret->per_cpu[smp_processor_id()];

	return ret;
}

static uint64_t
nt32_get_var_special(struct nt32_trace_s *gts, unsigned int num)
{
	uint64_t	ret;

	switch (num) {
	case NT32_VAR_CURRENT_TASK_ID:
		if (gts->ri)
			ret = (uint64_t)(CORE_ADDR)gts->ri->task;
		else
			ret = (uint64_t)(CORE_ADDR)get_current();
		break;
	case NT32_VAR_CURRENT_TASK_PID_ID:
		if (gts->ri)
			ret = (uint64_t)(CORE_ADDR)gts->ri->task->pid;
		else
			ret = (uint64_t)(CORE_ADDR)get_current()->pid;
		break;
	case NT32_VAR_CURRENT_THREAD_INFO_ID:
		ret = (uint64_t)(CORE_ADDR)current_thread_info();
		break;
	case NT32_VAR_CLOCK_ID:
		ret = (uint64_t)NT32_LOCAL_CLOCK;
		break;
	case NT32_VAR_COOKED_CLOCK_ID:
		ret = (uint64_t)(__get_cpu_var(local_clock_current)
					- __get_cpu_var(local_clock_offset));
		break;
#ifdef CONFIG_X86
	case NT32_VAR_RDTSC_ID:
		{
			unsigned long long a;
			rdtscll(a);
			ret = (uint64_t)a;
		}
		break;
	case NT32_VAR_COOKED_RDTSC_ID:
		ret = (uint64_t)(__get_cpu_var(rdtsc_current)
					- __get_cpu_var(rdtsc_offset));
		break;
#endif
	case NT32_VAR_CPU_ID:
		ret = (uint64_t)(CORE_ADDR)smp_processor_id();
		break;
	case NT32_VAR_CPU_NUMBER_ID:
		ret = (uint64_t)nt32_cpu_number;
		break;
	case NT32_VAR_PRINTK_TMP_ID:
		ret = gts->printk_tmp;
		break;
	case NT32_VAR_DUMP_STACK_ID:
		printk(KERN_NULL "nt32 %d %p:", (int)gts->tpe->num,
		       (void *)(CORE_ADDR)gts->tpe->addr);
		dump_stack();
		ret = 0;
		break;
	case NT32_VAR_XTIME_SEC_ID:
		if (gts->xtime.tv_sec == 0 && gts->xtime.tv_nsec == 0)
			getnstimeofday(&gts->xtime);
		ret = (uint64_t)gts->xtime.tv_sec;
		break;
	case NT32_VAR_XTIME_NSEC_ID:
		if (gts->xtime.tv_sec == 0 && gts->xtime.tv_nsec == 0)
			getnstimeofday(&gts->xtime);
		ret = (uint64_t)gts->xtime.tv_nsec;
		break;
	case NT32_VAR_HARDIRQ_COUNT_ID:
		ret = (uint64_t)hardirq_count();
		break;
	case NT32_VAR_SOFTIRQ_COUNT_ID:
		ret = (uint64_t)softirq_count();
		break;
	case NT32_VAR_IRQ_COUNT_ID:
		ret = (uint64_t)irq_count();
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

static void
nt32_set_var_special(struct nt32_trace_s *gts, unsigned int num, ULONGEST val)
{
	switch (num) {
	case NT32_VAR_PRINTK_TMP_ID:
		gts->printk_tmp = val;
		break;
	case NT32_VAR_PRINTK_LEVEL_ID:
		gts->printk_level = (unsigned int)val;
		break;
	case NT32_VAR_PRINTK_FORMAT_ID:
		gts->printk_format = (unsigned int)val;
		break;
	case NT32_VAR_PC_PE_EN_ID:
		nt32_pc_pe_en((int)val);
		break;
	}
}

static int
nt32_collect_var_special(struct nt32_trace_s *gts, unsigned int num)
{
	struct nt32_framework_var		*fvar;
	char				*tmp;
#ifdef NT32_FTRACE_RING_BUFFER
	struct ring_buffer_event	*rbe;
#endif

	if (gts->next == NULL) {
		if (nt32_action_head(gts))
			return -1;
	}

	if (NT32_VAR_AUTO_TRACEV(num))
		return 0;

#ifdef NT32_FTRACE_RING_BUFFER
	NT32_framework_RINGBUFFER_ALLOC(NT32_framework_VAR_SIZE);
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_RB)
#ifdef NT32_RB
	tmp = nt32_rb_alloc(gts->next, NT32_framework_VAR_SIZE, gts->id);
#endif
#ifdef NT32_framework_SIMPLE
	tmp = nt32_framework_alloc(NT32_framework_VAR_SIZE);
#endif
	if (!tmp) {
		gts->tpe->reason = nt32_stop_framework_full;
		return -1;
	}
#ifdef NT32_framework_SIMPLE
	*gts->next = tmp;
#endif
#endif

	FID(tmp) = FID_VAR;
	tmp += FID_SIZE;

#ifdef NT32_framework_SIMPLE
	gts->next = (char **)tmp;
	*gts->next = NULL;
	tmp += sizeof(char *);
#endif

	fvar = (struct nt32_framework_var *) tmp;
	fvar->num = num;
	fvar->val = nt32_get_var_special(gts, num);

#ifdef NT32_FTRACE_RING_BUFFER
	ring_buffer_unlock_commit(nt32_framework, rbe);
#endif

	return 0;
}

uint64_t
nt32_get_var(struct nt32_trace_s *gts, struct nt32_var *tve)
{
#ifdef NT32_PERF_EVENTS
	if (tve->ptid == pe_tv_val || tve->ptid == pe_tv_enabled
	    || tve->ptid == pe_tv_running) {
		tve->pts->val = perf_event_read_value(tve->pts->event,
						      &(tve->pts->enabled),
						      &(tve->pts->running));
		switch (tve->ptid) {
		case pe_tv_val:
			return (uint64_t)(tve->pts->val);
			break;
		case pe_tv_enabled:
			return (uint64_t)(tve->pts->enabled);
			break;
		case pe_tv_running:
			return (uint64_t)(tve->pts->running);
			break;
		default:
			return 0;
			break;
		}
	}
#endif

	return tve->val;
}

static int
nt32_collect_var(struct nt32_trace_s *gts, struct nt32_var *tve)
{
	struct nt32_framework_var		*fvar;
	char				*tmp;
#ifdef NT32_FTRACE_RING_BUFFER
	struct ring_buffer_event	*rbe;
#endif

	if (gts->next == NULL) {
		if (nt32_action_head(gts))
			return -1;
	}

#ifdef NT32_FTRACE_RING_BUFFER
	NT32_framework_RINGBUFFER_ALLOC(NT32_framework_VAR_SIZE);
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_RB)
#ifdef NT32_RB
	tmp = nt32_rb_alloc(gts->next, NT32_framework_VAR_SIZE, gts->id);
#endif
#ifdef NT32_framework_SIMPLE
	tmp = nt32_framework_alloc(NT32_framework_VAR_SIZE);
#endif
	if (!tmp) {
		gts->tpe->reason = nt32_stop_framework_full;
		return -1;
	}
#ifdef NT32_framework_SIMPLE
	*gts->next = tmp;
#endif
#endif

	FID(tmp) = FID_VAR;
	tmp += FID_SIZE;

#ifdef NT32_framework_SIMPLE
	gts->next = (char **)tmp;
	*gts->next = NULL;
	tmp += sizeof(char *);
#endif

	fvar = (struct nt32_framework_var *) tmp;
	fvar->num = tve->num;
	fvar->val = nt32_get_var(gts, tve);

#ifdef NT32_FTRACE_RING_BUFFER
	ring_buffer_unlock_commit(nt32_framework, rbe);
#endif

	return 0;
}

#define STACK_MAX	32
static DEFINE_PER_CPU(ULONGEST[STACK_MAX], action_x_stack);

static int
nt32_action_x(struct nt32_trace_s *gts, struct action *ae)
{
	int		ret = 0;
	unsigned int	pc = 0, sp = 0;
	ULONGEST	top = 0;
	int		arg;
	union {
		union {
			uint8_t	bytes[1];
			uint8_t	val;
		} u8;
		union {
			uint8_t	bytes[2];
			uint16_t val;
		} u16;
		union {
			uint8_t bytes[4];
			uint32_t val;
		} u32;
		union {
			uint8_t bytes[8];
			ULONGEST val;
		} u64;
	} cnv;
	uint8_t		*ebuf = ae->u.exp.buf;
	int		psize = NT32_PRINTF_MAX;
	char		*pbuf = __get_cpu_var(nt32_printf);
	ULONGEST	*stack = __get_cpu_var(action_x_stack);

	if (unlikely(ae->u.exp.need_var_lock))
		spin_lock(&nt32_var_lock);

	while (1) {
#ifdef NT32_DEBUG_V
		printk(NT32_DEBUG_V "nt32_parse_x: cmd %x\n", ebuf[pc]);
#endif

		switch (ebuf[pc++]) {
		/* add */
		case 0x02:
			top += stack[--sp];
			break;

		case op_check_add:
			if (sp)
				top += stack[--sp];
			else
				goto code_error_out;
			break;

		/* sub */
		case 0x03:
			top = stack[--sp] - top;
			break;

		case op_check_sub:
			if (sp)
				top = stack[--sp] - top;
			else
				goto code_error_out;
			break;

		/* mul */
		case 0x04:
			top *= stack[--sp];
			break;

		case op_check_mul:
			if (sp)
				top *= stack[--sp];
			else
				goto code_error_out;
			break;

#ifndef CONFIG_MIPS
		/* div_signed */
		case 0x05:
			if (top) {
				LONGEST l = (LONGEST) stack[--sp];
				do_div(l, (LONGEST) top);
				top = l;
			} else
				goto code_error_out;
			break;

		case op_check_div_signed:
			if (top && sp) {
				LONGEST l = (LONGEST) stack[--sp];
				do_div(l, (LONGEST) top);
				top = l;
			} else
				goto code_error_out;
			break;

		/* div_unsigned */
		case 0x06:
			if (top) {
				ULONGEST ul = stack[--sp];
				do_div(ul, top);
				top = ul;
			} else
				goto code_error_out;
			break;

		case op_check_div_unsigned:
			if (top && sp) {
				ULONGEST ul = stack[--sp];
				do_div(ul, top);
				top = ul;
			} else
				goto code_error_out;
			break;

		/* rem_signed */
		case 0x07:
			if (top) {
				LONGEST l1 = (LONGEST) stack[--sp];
				LONGEST l2 = (LONGEST) top;
				top = do_div(l1, l2);
			} else
				goto code_error_out;
			break;

		case op_check_rem_signed:
			if (top && sp) {
				LONGEST l1 = (LONGEST) stack[--sp];
				LONGEST l2 = (LONGEST) top;
				top = do_div(l1, l2);
			} else
				goto code_error_out;
			break;

		/* rem_unsigned */
		case 0x08:
			if (top) {
				ULONGEST ul1 = stack[--sp];
				ULONGEST ul2 = top;
				top = do_div(ul1, ul2);
			} else
				goto code_error_out;
			break;

		case op_check_rem_unsigned:
			if (top && sp) {
				ULONGEST ul1 = stack[--sp];
				ULONGEST ul2 = top;
				top = do_div(ul1, ul2);
			} else
				goto code_error_out;
			break;
#endif

		/* lsh */
		case 0x09:
			top = stack[--sp] << top;
			break;

		case op_check_lsh:
			if (sp)
				top = stack[--sp] << top;
			else
				goto code_error_out;
			break;

		/* rsh_signed */
		case 0x0a:
			top = ((LONGEST) stack[--sp]) >> top;
			break;

		case op_check_rsh_signed:
			if (sp)
				top = ((LONGEST) stack[--sp]) >> top;
			else
				goto code_error_out;
			break;

		/* rsh_unsigned */
		case 0x0b:
			top = stack[--sp] >> top;
			break;

		case op_check_rsh_unsigned:
			if (sp)
				top = stack[--sp] >> top;
			else
				goto code_error_out;
			break;

		/* trace */
		case 0x0c:
			--sp;
			if (!gts->tpe->have_printk) {
				if (nt32_action_memory_read
					(gts, -1,
						(CORE_ADDR) stack[sp],
						(size_t) top))
					goto out;
			}
			top = stack[--sp];
			break;

		case op_check_trace:
			if (sp > 1) {
				if (nt32_action_memory_read
					(gts, -1, (CORE_ADDR) stack[--sp],
					(size_t) top)) {
					/* nt32_action_memory_read will
						set error status with itself
						if it got error. */
					goto out;
				}
				top = stack[--sp];
			} else
				goto code_error_out;
			break;

		/* trace_printk */
		case op_trace_printk:
			if (nt32_action_printk(gts,
						(ULONGEST)stack[--sp],
						(size_t) top))
				goto out;
			top = stack[--sp];
			break;

		/* trace_quick */
		case 0x0d:
			if (!gts->tpe->have_printk) {
				if (nt32_action_memory_read
					(gts, -1, (CORE_ADDR) top,
						(size_t) ebuf[pc]))
					goto out;
			}
			pc++;
			break;

		/* trace_quick_printk */
		case op_trace_quick_printk:
			if (nt32_action_printk(gts, (ULONGEST) top,
						(size_t) ebuf[pc++]))
				goto out;
			break;

		/* log_not */
		case 0x0e:
			top = !top;
			break;

		/* bit_and */
		case 0x0f:
			top &= stack[--sp];
			break;

		case op_check_bit_and:
			if (sp)
				top &= stack[--sp];
			else
				goto code_error_out;
			break;

		/* bit_or */
		case 0x10:
			top |= stack[--sp];
			break;

		case op_check_bit_or:
			if (sp)
				top |= stack[--sp];
			else
				goto code_error_out;
			break;

		/* bit_xor */
		case 0x11:
			top ^= stack[--sp];
			break;

		case op_check_bit_xor:
			if (sp)
				top ^= stack[--sp];
			else
				goto code_error_out;
			break;

		/* bit_not */
		case 0x12:
			top = ~top;
			break;

		/* equal */
		case 0x13:
			top = (stack[--sp] == top);
			break;

		case op_check_equal:
			if (sp)
				top = (stack[--sp] == top);
			else
				goto code_error_out;
			break;

		/* less_signed */
		case 0x14:
			top = (((LONGEST) stack[--sp])
				< ((LONGEST) top));
			break;

		case op_check_less_signed:
			if (sp)
				top = (((LONGEST) stack[--sp])
					< ((LONGEST) top));
			else
				goto code_error_out;
			break;

		/* less_unsigned */
		case 0x15:
			top = (stack[--sp] < top);
			break;

		case op_check_less_unsigned:
			if (sp)
				top = (stack[--sp] < top);
			else
				goto code_error_out;
			break;

		/* ext */
		case 0x16:
			arg = ebuf[pc++];
			if (arg < (sizeof(LONGEST)*8)) {
				LONGEST mask = 1 << (arg - 1);
				top &= ((LONGEST) 1 << arg) - 1;
				top = (top ^ mask) - mask;
			}
			break;

		/* ref8 */
		case 0x17:
			if (probe_kernel_read
				(cnv.u8.bytes,
				(void *)(CORE_ADDR)top, 1))
				goto code_error_out;
			top = (ULONGEST) cnv.u8.val;
			break;

		/* ref16 */
		case 0x18:
			if (probe_kernel_read
				(cnv.u16.bytes,
				(void *)(CORE_ADDR)top, 2))
				goto code_error_out;
			top = (ULONGEST) cnv.u16.val;
			break;

		/* ref32 */
		case 0x19:
			if (probe_kernel_read
				(cnv.u32.bytes,
				(void *)(CORE_ADDR)top, 4))
				goto code_error_out;
			top = (ULONGEST) cnv.u32.val;
			break;

		/* ref64 */
		case 0x1a:
			if (probe_kernel_read
				(cnv.u64.bytes,
				(void *)(CORE_ADDR)top, 8))
				goto code_error_out;
			top = (ULONGEST) cnv.u64.val;
			break;

		/* if_goto */
		case 0x20:
			if (top)
				pc = (ebuf[pc] << 8)
					+ (ebuf[pc + 1]);
			else
				pc += 2;
			/* pop */
			top = stack[--sp];
			break;

		case op_check_if_goto:
			if (top)
				pc = (ebuf[pc] << 8)
					+ (ebuf[pc + 1]);
			else
				pc += 2;
			/* pop */
			if (sp)
				top = stack[--sp];
			else
				goto code_error_out;
			break;

		/* goto */
		case 0x21:
			pc = (ebuf[pc] << 8) + (ebuf[pc + 1]);
			break;

		/* const8 */
		case 0x22:
			stack[sp++] = top;
			top = ebuf[pc++];
			break;

		/* const16 */
		case 0x23:
			stack[sp++] = top;
			top = ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			break;

		/* const32 */
		case 0x24:
			stack[sp++] = top;
			top = ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			break;

		/* const64 */
		case 0x25:
			stack[sp++] = top;
			top = ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			top = (top << 8) + ebuf[pc++];
			break;

		/* reg */
		case 0x26:
			stack[sp++] = top;
			arg = ebuf[pc++];
			arg = (arg << 8) + ebuf[pc++];
			top = nt32_action_reg_read(gts->regs, gts->tpe,
							arg);
			if (gts->tpe->reason != nt32_stop_normal)
				goto error_out;
			break;

		/* end */
		case 0x27:
			if (gts->run)
				*(gts->run) = (int)top;
			goto out;
			break;

		/* dup */
		case 0x28:
			stack[sp++] = top;
			break;

		/* pop */
		case 0x29:
			top = stack[--sp];
			break;

		case op_check_pop:
			if (sp)
				top = stack[--sp];
			else
				goto code_error_out;
			break;

		/* zero_ext */
		case 0x2a:
			arg = ebuf[pc++];
			if (arg < (sizeof(LONGEST)*8))
				top &= ((LONGEST) 1 << arg) - 1;
			break;

		/* swap */
		case 0x2b:
			stack[sp] = top;
			top = stack[sp - 1];
			stack[sp - 1] = stack[sp];
			break;

		case op_check_swap:
			if (sp) {
				stack[sp] = top;
				top = stack[sp - 1];
				stack[sp - 1] = stack[sp];
			} else
				goto code_error_out;
			break;

		/* getv */
		case 0x2c:
			arg = ebuf[pc++];
			arg = (arg << 8) + ebuf[pc++];

			stack[sp++] = top;

			top = nt32_get_var(gts, nt32_nt32_var_array_find(arg));
			break;

		/* getv_sepecial */
		case op_special_getv:
			arg = ebuf[pc++];
			arg = (arg << 8) + ebuf[pc++];
			stack[sp++] = top;
			top = nt32_get_var_special(gts, arg);
			break;

		/* setv */
		case 0x2d: {
				struct nt32_var	*tve;

				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				tve = nt32_nt32_var_array_find(arg);
#ifdef NT32_PERF_EVENTS
				if (tve->ptid == pe_tv_en)
					nt32_pe_set_en(tve->pts, (int)top);
				else if (tve->ptid == pe_tv_val)
					perf_event_set(tve->pts->event,
							   (u64)top);
#endif
				tve->val = (uint64_t)top;
			}
			break;

		/* setv_sepecial */
		case op_special_setv:
			arg = ebuf[pc++];
			arg = (arg << 8) + ebuf[pc++];
			nt32_set_var_special(gts, arg, top);
			break;

		/* tracev */
		case 0x2e:
			arg = ebuf[pc++];
			arg = (arg << 8) + ebuf[pc++];

			if (nt32_collect_var(gts, nt32_nt32_var_array_find(arg))) {
				/* nt32_collect_var will set error
				   status with itself if it got error. */
				goto out;
			}
			break;

		/* tracev_special */
		case op_special_tracev:
			arg = ebuf[pc++];
			arg = (arg << 8) + ebuf[pc++];
			nt32_collect_var_special(gts, arg);
			break;

		/* tracev_printk */
		case op_tracev_printk: {
				uint64_t	u64;
				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				if (!NT32_VAR_IS_SPECIAL(arg))
					u64 = nt32_get_var(gts,
							  nt32_nt32_var_array_find
								(arg));
				else
					u64 = nt32_get_var_special(gts, arg);
				if (nt32_action_printk(gts, u64, 0)) {
					/* nt32_collect_var will set error status
					   with itself if it got error. */
					goto out;
				}
			}
			break;
		}

		if (ae->type != 'X' && unlikely(sp > STACK_MAX - 5)) {
			printk(KERN_WARNING "nt32_action_x: stack overflow.\n");
			gts->tpe->reason
				= nt32_stop_agent_expr_stack_overflow;
			goto error_out;
		}
	}
code_error_out:
	gts->tpe->reason = nt32_stop_agent_expr_code_error;
error_out:
	ret = -1;
	printk(KERN_WARNING "nt32_action_x: tracepoint %d addr:%p"
			    "action X get error in pc %u.\n",
		(int)gts->tpe->num, (void *)(CORE_ADDR)gts->tpe->addr, pc);
out:
	if (unlikely(psize != NT32_PRINTF_MAX)) {
		unsigned long	flags;

		local_irq_save(flags);
		printk("%s", pbuf - (NT32_PRINTF_MAX - psize));
		local_irq_restore(flags);
	}
	if (unlikely(ae->u.exp.need_var_lock))
		spin_unlock(&nt32_var_lock);
	return ret;
}

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
static void
nt32_handler_wakeup(void)
{
#ifdef NT32_FTRACE_RING_BUFFER
	FID_TYPE	eid = FID_END;
	ring_buffer_write(nt32_framework, FID_SIZE, &eid);
#endif

	if (atomic_read(&nt32framework_pipe_wq_v) > 0) {
		atomic_dec(&nt32framework_pipe_wq_v);
		add_preempt_count(HARDIRQ_OFFSET);
		tasklet_schedule(&nt32framework_pipe_wq_tasklet);
		sub_preempt_count(HARDIRQ_OFFSET);
	}
}
#endif

static void
nt32_handler(struct nt32_trace_s *gts)
{
	struct action		*ae;

#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_handler: tracepoint %d %p\n",
	       (int)gts->tpe->num, (void *)(CORE_ADDR)gts->tpe->addr);
#endif

	if (gts->tpe->kpreg == 0)
		return;

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (!nt32_pipe_trace && get_current()->pid == nt32_nt32framework_pipe_pid)
		return;
#endif

	if (gts->tpe->no_self_trace
	    && (get_current()->pid == nt32_nt32_pid
		|| get_current()->pid == nt32_nt32framework_pid)) {
			return;
	}

	if (gts->tpe->have_printk) {
		gts->printk_level = 8;
		gts->printk_str = gts->tpe->printk_str;
	}

	/* Condition.  */
	if (gts->tpe->cond) {
		int	run;

		gts->run = &run;
		if (nt32_action_x(gts, gts->tpe->cond))
			goto tpe_stop;
		if (!run)
			return;
	}

	gts->run = NULL;

	/* Pass.  */
	if (!gts->tpe->nopass) {
		if (atomic_dec_return(&gts->tpe->current_pass) < 0)
			goto tpe_stop;
	}

	/* Handle actions.  */
	if (gts->step)
		ae = gts->tpe->step_action_list;
	else
		ae = gts->tpe->action_list;
	for (; ae; ae = ae->next) {
		switch (ae->type) {
		case 'R':
			if (nt32_action_r(gts, ae))
				goto tpe_stop;
			break;
		case 'X':
		case 0xff:
			if (nt32_action_x(gts, ae))
				goto tpe_stop;
			break;
		case 'M':
			if (nt32_action_memory_read(gts, ae->u.m.regnum,
						   ae->u.m.offset,
						   ae->u.m.size))
				goto tpe_stop;
			break;
		}
	}

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (gts->next) {
#ifdef NT32_RB
		NT32_RB_UNLOCK(gts->next);
#endif
		nt32_handler_wakeup();
	}
#endif

	return;

tpe_stop:
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (gts->next) {
#ifdef NT32_RB
		NT32_RB_UNLOCK(gts->next);
#endif
		nt32_handler_wakeup();
	}
#endif
	gts->tpe->kpreg = 0;
	add_preempt_count(HARDIRQ_OFFSET);
	tasklet_schedule(&gts->tpe->tasklet);
	sub_preempt_count(HARDIRQ_OFFSET);
#ifdef NT32_DEBUG_V
	printk(NT32_DEBUG_V "nt32_handler: tracepoint %d %p stop.\n",
		(int)gts->tpe->num, (void *)(CORE_ADDR)gts->tpe->addr);
#endif
	return;
}

static DEFINE_PER_CPU(int, nt32_handler_began);

#ifdef CONFIG_X86
static int	nt32_access_cooked_rdtsc;
#endif
static int	nt32_access_cooked_clock;
#ifdef NT32_PERF_EVENTS
static int	nt32_have_pc_pe;
#endif

static void
nt32_handler_begin(void)
{
	if (!__get_cpu_var(nt32_handler_began)) {
#ifdef CONFIG_X86
		if (nt32_access_cooked_rdtsc) {
			u64	a;

			rdtscll(a);
			__get_cpu_var(rdtsc_current) = a;
		}
#endif

		if (nt32_access_cooked_clock)
			__get_cpu_var(local_clock_current) = NT32_LOCAL_CLOCK;

#ifdef NT32_PERF_EVENTS
		if (nt32_have_pc_pe)
			pc_pe_list_disable();
#endif

		__get_cpu_var(nt32_handler_began) = 1;
	}
}

static void
nt32_handler_end(void)
{
	if (__get_cpu_var(nt32_handler_began)) {
#ifdef NT32_PERF_EVENTS
		if (nt32_have_pc_pe)
			pc_pe_list_enable();
#endif

		if (nt32_access_cooked_clock) {
			__get_cpu_var(local_clock_offset) += NT32_LOCAL_CLOCK
					- __get_cpu_var(local_clock_current);
			__get_cpu_var(local_clock_current) = 0;
		}

#ifdef CONFIG_X86
		if (nt32_access_cooked_rdtsc) {
			u64	a;

			rdtscll(a);
			__get_cpu_var(rdtsc_offset) += a
					- __get_cpu_var(rdtsc_current);
			__get_cpu_var(rdtsc_current) = 0;
		}
#endif

		__get_cpu_var(nt32_handler_began) = 0;
	}
}

static inline void
nt32_kp_pre_handler_1(struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe	*kp;
	struct nt32_trace_s	gts;

	memset(&gts, 0, sizeof(struct nt32_trace_s));
	kp = container_of(p, struct kretprobe, kp);
	gts.tpe = container_of(kp, struct nt32_entry, kp);
	gts.regs = regs;

	nt32_handler(&gts);
}

static inline void
nt32_kp_post_handler_1(struct kprobe *p, struct pt_regs *regs,
		      unsigned long flags)
{
	struct kretprobe	*kp;
	struct nt32_entry	*tpe;
	struct nt32_trace_s	gts;

	kp = container_of(p, struct kretprobe, kp);
	tpe = container_of(kp, struct nt32_entry, kp);

	memset(&gts, 0, sizeof(struct nt32_trace_s));
	gts.tpe = tpe;
	gts.regs = regs;
	gts.step = 1;

	nt32_handler(&gts);
}

static inline void
nt32_kp_ret_handler_1(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nt32_trace_s	gts;

	memset(&gts, 0, sizeof(struct nt32_trace_s));
	gts.tpe = container_of(ri->rp, struct nt32_entry, kp);
	gts.regs = regs;
	gts.ri = ri;

	nt32_handler(&gts);
}

static int
nt32_kp_pre_handler_plus_step(struct kprobe *p, struct pt_regs *regs)
{
	nt32_handler_begin();

	nt32_kp_pre_handler_1(p, regs);

	return 0;
}

static int
nt32_kp_pre_handler_plus(struct kprobe *p, struct pt_regs *regs)
{
	nt32_handler_begin();

	nt32_kp_pre_handler_1(p, regs);

	nt32_handler_end();

	return 0;
}

static int
nt32_kp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	nt32_kp_pre_handler_1(p, regs);

	return 0;
}

/* Only available when tpe->step is true.  */

static void
nt32_kp_post_handler_plus(struct kprobe *p, struct pt_regs *regs,
			 unsigned long flags)
{
	nt32_kp_post_handler_1(p, regs, flags);

	nt32_handler_end();
}

/* Only available when tpe->step is true.  */

static void
nt32_kp_post_handler(struct kprobe *p, struct pt_regs *regs,
			 unsigned long flags)
{
	nt32_kp_post_handler_1(p, regs, flags);
}

static int
nt32_kp_ret_handler_plus(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	nt32_handler_begin();

	nt32_kp_ret_handler_1(ri, regs);

	nt32_handler_end();

	return 0;
}

static int
nt32_kp_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	nt32_kp_ret_handler_1(ri, regs);

	return 0;
}

static struct action *
nt32_action_alloc(char *pkg)
{
	struct action	*ret;

	ret = kmalloc(sizeof(struct action), GFP_KERNEL);
	if (!ret)
		goto out;

	memset(ret, '\0', sizeof(struct action));
	ret->type = pkg[0];
	ret->src = pkg;

out:
	return ret;
}

static void
nt32_action_release(struct action *ae)
{
	struct action	*ae2;

	while (ae) {
		ae2 = ae;
		ae = ae->next;
		/* Release ae2.  */
		switch (ae2->type) {
		case 'X':
		case 0xff:
			kfree(ae2->u.exp.buf);
			break;
		}
		kfree(ae2->src);
		kfree(ae2);
	}
}

static void
nt32_src_release(struct nt32src *src)
{
	struct nt32src	*src2;

	while (src) {
		src2 = src;
		src = src->next;
		kfree(src2->src);
		kfree(src2);
	}
}

static void
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19))
nt32_stop(struct work_struct *work)
{
	struct nt32_entry	*tpe = container_of(work,
						    struct nt32_entry, work);
#else
nt32_stop(void *p)
{
	struct nt32_entry	*tpe = p;
#endif

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_stop: tracepoint %d %p\n", (int)tpe->num,
	       (void *)(CORE_ADDR)tpe->addr);
#endif

	if (tpe->is_kretprobe)
		unregister_kretprobe(&tpe->kp);
	else
		unregister_kprobe(&tpe->kp.kp);
}

static struct nt32_entry *
nt32_list_add(ULONGEST num, ULONGEST addr)
{
	struct nt32_entry	*ret = kcalloc(1, sizeof(struct nt32_entry),
					       GFP_KERNEL);

	if (!ret)
		goto out;
	memset(ret, '\0', sizeof(struct nt32_entry));
	ret->num = num;
	ret->addr = addr;
	ret->kp.kp.addr = (kprobe_opcode_t *) (CORE_ADDR)addr;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19))
	INIT_WORK(&ret->work, nt32_stop);
#else
	INIT_WORK(&ret->work, nt32_stop, ret);
#endif
	ret->have_printk = 0;

	/* Add to nt32_list.  */
	ret->next = nt32_list;
	nt32_list = ret;

out:
	return ret;
}

static struct nt32_entry *
nt32_list_find(ULONGEST num, ULONGEST addr)
{
	struct nt32_entry	*tpe;

	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		if (tpe->num == num && tpe->addr == addr)
			return tpe;
	}

	return NULL;
}

/* If more than one nt32 entry have same num, return NULL.  */

static struct nt32_entry *
nt32_list_find_without_addr(ULONGEST num)
{
	struct nt32_entry	*tpe, *ret = NULL;

	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		if (tpe->num == num) {
			if (ret)
				return NULL;
			else
				ret = tpe;
		}
	}

	return ret;
}

static void
nt32_list_release(void)
{
	struct nt32_entry	*tpe;

	while (nt32_list) {
		tpe = nt32_list;
		nt32_list = nt32_list->next;
		nt32_action_release(tpe->cond);
		nt32_action_release(tpe->action_list);
		nt32_src_release(tpe->src);
		kfree(tpe);
	}

	current_nt32 = NULL;
	current_nt32_action = NULL;
	current_nt32_src = NULL;
}

#ifdef NT32_FTRACE_RING_BUFFER
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34)) || defined(NT32_SELF_RING_BUFFER)
static void
nt32_framework_iter_open(void)
{
	int	cpu;


	for_each_online_cpu(cpu)
		nt32_framework_iter[cpu] = ring_buffer_read_prepare(nt32_framework, cpu);
	ring_buffer_read_prepare_sync();
	for_each_online_cpu(cpu) {
		ring_buffer_read_start(nt32_framework_iter[cpu]);
	}
}
#else
static void
nt32_framework_iter_open(void)
{
	int	cpu;

	for_each_online_cpu(cpu) {
		nt32_framework_iter[cpu] = ring_buffer_read_start(nt32_framework, cpu);
		ring_buffer_iter_reset(nt32_framework_iter[cpu]);
	}
}
#endif

static void
nt32_framework_iter_reset(void)
{
	int	cpu;

	for_each_online_cpu(cpu)
		ring_buffer_iter_reset(nt32_framework_iter[cpu]);
	nt32_framework_current_num = -1;
}

static int
nt32_framework_iter_peek_head(void)
{
	int	cpu;
	int	ret = -1;
	u64	min = 0;

	for_each_online_cpu(cpu) {
		struct ring_buffer_event	*rbe;
		char				*tmp;
		u64				ts;

		while (1) {
			rbe = ring_buffer_iter_peek(nt32_framework_iter[cpu], &ts);
			if (rbe == NULL)
				break;
			tmp = ring_buffer_event_data(rbe);
			if (FID(tmp) == FID_HEAD)
				break;
			ring_buffer_read(nt32_framework_iter[cpu], NULL);
		}

		if (rbe) {
			if ((min && ts < min) || !min) {
				min = ts;
				ret = cpu;
			}
		}
	}

	if (ret < 0)
		nt32_framework_current_num = -1;
	else
		nt32_framework_current_num++;
	return ret;
}

static void
nt32_framework_iter_close(void)
{
	int	cpu;

	for_each_online_cpu(cpu) {
		if (nt32_framework_iter[cpu]) {
			ring_buffer_read_finish(nt32_framework_iter[cpu]);
			nt32_framework_iter[cpu] = NULL;
		}
	}
}
#endif

static void
nt32_framework_reset(void)
{
	nt32_framework_current_num = -1;
#ifdef NT32_framework_SIMPLE
	nt32_framework_r_start = nt32_framework;
	nt32_framework_w_start = nt32_framework;
	nt32_framework_end = nt32_framework + NT32_framework_SIZE;
	nt32_framework_is_circular = 0;
	nt32_framework_current = NULL;
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	nt32_framework_iter_close();
	if (nt32_framework)
		ring_buffer_reset(nt32_framework);
#endif
#ifdef NT32_RB
	nt32_rb_reset();
#endif
	atomic_set(&nt32_framework_create, 0);
	if (nt32_framework_file) {
		vfree(nt32_framework_file);
		nt32_framework_file = NULL;
		nt32_framework_file_size = 0;
	}
}

static int
hex2int(char hex, int *i)
{
	if ((hex >= '0') && (hex <= '9')) {
		*i = hex - '0';
		return 1;
	}
	if ((hex >= 'a') && (hex <= 'f')) {
		*i = hex - 'a' + 10;
		return 1;
	}
	if ((hex >= 'A') && (hex <= 'F')) {
		*i = hex - 'A' + 10;
		return 1;
	}

	return 0;
}

static char *
hex2ulongest(char *pkg, ULONGEST *u64)
{
	int	i;

	if (u64)
		*u64 = 0;
	while (hex2int(pkg[0], &i)) {
		pkg++;
		if (u64) {
			*u64 = (*u64) << 4;
			*u64 |= i & 0xf;
		}
	}

	return pkg;
}

static char *
string2hex(char *pkg, char *out)
{
	char	*ret = out;

	while (pkg[0]) {
		sprintf(out, "%x", pkg[0]);
		pkg++;
		out += 2;
	}

	return ret;
}

static char *
hex2string(char *pkg, char *out)
{
	char	*ret = out;
	int	i, j;

	while (hex2int(pkg[0], &i) && hex2int(pkg[1], &j)) {
		out[0] = i * 16 + j;
		pkg += 2;
		out += 1;
	}
	out[0] = '\0';

	return ret;
}

static char *
nt32_strdup(char *begin, char *end)
{
	int	len;
	char	*ret;

	if (end)
		len = end - begin;
	else
		len = strlen(begin);

	ret = kmalloc(len + 1, GFP_KERNEL);
	if (ret == NULL)
		return NULL;

	strncpy(ret, begin, len);
	ret[len] = '\0';

	return ret;
}

static void
nt32ro_list_clear(void)
{
	struct nt32ro_entry	*e;

	while (nt32ro_list) {
		e = nt32ro_list;
		nt32ro_list = nt32ro_list->next;
		kfree(e);
	}
}

static struct nt32ro_entry *
nt32ro_list_add(CORE_ADDR start, CORE_ADDR end)
{
	struct nt32ro_entry	*e;

	e = kmalloc(sizeof(struct nt32ro_entry), GFP_KERNEL);
	if (e == NULL)
		goto out;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32ro_list_add: %p %p\n", (void *)start, (void *)end);
#endif

	e->start = start;
	e->end = end;

	e->next = nt32ro_list;
	nt32ro_list = e;

out:
	return e;
}

#ifdef NT32_PERF_EVENTS
static struct nt32_var *
nt32_var_add(unsigned int num, uint64_t val, char *src,
	    struct nt32_var **per_cpu, int per_cpu_id,
	    enum pe_tv_id ptid, struct pe_tv_s *pts)
#else
static struct nt32_var *
nt32_var_add(unsigned int num, uint64_t val, char *src,
	    struct nt32_var **per_cpu, int per_cpu_id)
#endif
{
	struct nt32_var *var = kcalloc(1, sizeof(struct nt32_var), GFP_KERNEL);
	if (!var)
		goto out;

	var->num = num;
	var->val = val;

	var->src = nt32_strdup(src, NULL);
	if (var->src == NULL) {
		kfree(var);
		var = NULL;
		goto out;
	}

	var->per_cpu = per_cpu;
	if (per_cpu)
		var->per_cpu[per_cpu_id] = var;

#ifdef NT32_PERF_EVENTS
	var->ptid = ptid;
	var->pts = pts;
#endif

	var->next = nt32_var_list;
	nt32_var_list = var;
	nt32_var_head = min(var->num, nt32_var_head);
	nt32_var_tail = max(var->num, nt32_var_tail);

out:
	return var;
}

static struct nt32_var *
nt32_var_find(unsigned int num)
{
	struct nt32_var	*ret = NULL;

	if (num >= nt32_var_head && num <= nt32_var_tail) {
		for (ret = nt32_var_list; ret; ret = ret->next) {
			if (ret->num == num)
				break;
		}
	}

	return ret;
}

static void
nt32_var_release(void)
{
	struct nt32_var	*tve;

	nt32_var_head = NT32_VAR_SPECIAL_MIN;
	nt32_var_tail = NT32_VAR_SPECIAL_MAX;
	current_nt32_var = NULL;

	while (nt32_var_list != NT32_VAR_LIST_FIRST) {
		tve = nt32_var_list;
		nt32_var_list = nt32_var_list->next;

		if (tve->per_cpu) {
			struct nt32_var	*tve1;

			for (tve1 = nt32_var_list; tve1; tve1 = tve1->next) {
				if (tve1->per_cpu == tve->per_cpu)
					tve1->per_cpu = NULL;
			}

			kfree(tve->per_cpu);
		}

#ifdef NT32_PERF_EVENTS
		if (tve->pts) {
			struct nt32_var	*tve1;

			for (tve1 = nt32_var_list; tve1; tve1 = tve1->next) {
				if (tve1->pts == tve->pts) {
					tve1->pts = NULL;
					tve1->ptid = pe_tv_unknown;
				}
			}

			if (tve->pts->event)
				perf_event_release_kernel(tve->pts->event);
			kfree(tve->pts);
		}
#endif

		kfree(tve->src);
		kfree(tve);
	}

	nt32_start_ignore_error = 0;
}

static int
nt32_gdbrsp_qtstop(void)
{
	struct nt32_entry	*tpe;
#ifdef NT32_PERF_EVENTS
	struct nt32_var		*tve;
#endif

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_qtstop\n");
#endif

#ifdef framework_ALLOC_RECORD
	printk(KERN_WARNING "framework_alloc_size = %llu, "
			    "framework_alloc_size_hole = %llu\n",
	       framework_alloc_size, framework_alloc_size_hole);
	framework_alloc_size = 0;
	framework_alloc_size_hole = 0;
#endif

	if (!nt32_start)
		return -EBUSY;

	flush_workqueue(nt32_wq);

	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		if (tpe->kpreg) {
			if (tpe->is_kretprobe)
				unregister_kretprobe(&tpe->kp);
			else
				unregister_kprobe(&tpe->kp.kp);
			tpe->kpreg = 0;
		}
		tasklet_kill(&tpe->tasklet);
	}

#ifdef NT32_PERF_EVENTS
	for (tve = nt32_var_list; tve; tve = tve->next) {
		if (tve->pts == NULL)
			continue;
		if (tve->pts->event == NULL)
			continue;

		tve->pts->val = perf_event_read_value(tve->pts->event,
						      &(tve->pts->enabled),
						      &(tve->pts->running));
		perf_event_release_kernel(tve->pts->event);
		tve->pts->event = NULL;
	}
#endif

	kfree(nt32_var_array);
	nt32_var_array = NULL;

#ifdef NT32_FTRACE_RING_BUFFER
	if (nt32_framework) {
		nt32_framework_iter_open();
		nt32_framework_iter_reset();
	}
#endif

	nt32_start = 0;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (atomic_read(&nt32framework_pipe_wq_v) > 0) {
		atomic_dec(&nt32framework_pipe_wq_v);
		tasklet_schedule(&nt32framework_pipe_wq_tasklet);
	}
	tasklet_kill(&nt32framework_pipe_wq_tasklet);
#endif
	wake_up_interruptible_nr(&nt32framework_wq, 1);

	return 0;
}

static int
nt32_gdbrsp_qtinit(void)
{
#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_qtinit\n");
#endif

	if (nt32_start)
		nt32_gdbrsp_qtstop();

	nt32_list_release();

#ifdef NT32_RB
	if (!NT32_RB_PAGE_IS_EMPTY)
#elif defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
	if (nt32_framework)
#endif
		nt32_framework_reset();

	nt32ro_list_clear();

	nt32_var_release();

#ifdef CONFIG_X86
	nt32_access_cooked_rdtsc = 0;
#endif
	nt32_access_cooked_clock = 0;
#ifdef NT32_PERF_EVENTS
	nt32_have_pc_pe = 0;
#endif

	return 0;
}

struct nt32_x_loop {
	struct nt32_x_loop	*next;
	unsigned int		addr;
	int			non_goto_done;
};

static struct nt32_x_loop *
nt32_x_loop_find(struct nt32_x_loop *list, unsigned int pc)
{
	struct nt32_x_loop	*ret = NULL;

	for (ret = list; ret; ret = ret->next) {
		if (ret->addr == pc)
			break;
	}

	return ret;
}

static struct nt32_x_loop *
nt32_x_loop_add(struct nt32_x_loop **list, unsigned int pc, int non_goto_done)
{
	struct nt32_x_loop	*ret;

	ret = kmalloc(sizeof(struct nt32_x_loop), GFP_KERNEL);
	if (!ret)
		goto out;

	ret->addr = pc;
	ret->non_goto_done = non_goto_done;

	ret->next = *list;
	*list = ret;

out:
	return ret;
}

struct nt32_x_if_goto {
	struct nt32_x_if_goto	*next;
	unsigned int		ip;
	unsigned int		sp;
};

static struct nt32_x_if_goto *
nt32_x_if_goto_add(struct nt32_x_if_goto **list, unsigned int pc, unsigned int sp)
{
	struct nt32_x_if_goto	*ret;

	ret = kmalloc(sizeof(struct nt32_x_loop), GFP_KERNEL);
	if (!ret)
		goto out;

	ret->ip = pc;
	ret->sp = sp;

	ret->next = *list;
	*list = ret;

out:
	return ret;
}

struct nt32_x_var {
	struct nt32_x_var	*next;
	unsigned int		num;
	unsigned int		flags;
};

static int
nt32_x_var_add(struct nt32_x_var **list, unsigned int num, unsigned int flag)
{
	struct nt32_x_var	*curv;

	for (curv = *list; curv; curv = curv->next) {
		if (curv->num == num)
			break;
	}

	if (!curv) {
		curv = kmalloc(sizeof(struct nt32_x_var), GFP_KERNEL);
		if (!curv)
			return -ENOMEM;
		curv->num = num;
		curv->flags = 0;
		if (*list) {
			curv->next = *list;
			*list = curv;
		} else {
			curv->next = NULL;
			*list = curv;
		}
	}

	curv->flags |= flag;

	return 0;
}

static int
nt32_check_x_simple(struct nt32_entry *tpe, struct action *ae)
{
	int			ret = -EINVAL;
	unsigned int		pc = 0, sp = 0;
	struct nt32_x_if_goto	*glist = NULL, *gtmp;
	struct nt32_x_var	*vlist = NULL, *vtmp;
	uint8_t			*ebuf = ae->u.exp.buf;
	int			last_trace_pc = -1;
	unsigned int		sp_max = 0;

reswitch:
	while (pc < ae->u.exp.size) {
#ifdef NT32_DEBUG_V
		printk(NT32_DEBUG_V "nt32_check_x_simple: cmd %x\n", ebuf[pc]);
#endif
		switch (ebuf[pc++]) {
		/* add */
		case 0x02:
		/* sub */
		case 0x03:
		/* mul */
		case 0x04:
		/* lsh */
		case 0x09:
		/* rsh_signed */
		case 0x0a:
		/* rsh_unsigned */
		case 0x0b:
		/* bit_and */
		case 0x0f:
		/* bit_or */
		case 0x10:
		/* bit_xor */
		case 0x11:
		/* equal */
		case 0x13:
		/* less_signed */
		case 0x14:
		/* less_unsigned */
		case 0x15:
		/* pop */
		case 0x29:
		/* swap */
		case 0x2b:
			if (sp < 1) {
				printk(KERN_WARNING "nt32_check_x_simple: stack "
						    "overflow in %d.\n",
				       pc - 1);
				goto release_out;
			} else {
				if (ebuf[pc - 1] != 0x2b)
					sp--;
			}
			break;

		/* trace */
		case 0x0c:
			if (tpe->have_printk)
				last_trace_pc = pc - 1;

			if (sp < 2) {
				printk(KERN_WARNING "nt32_check_x_simple: stack "
						    "overflow in %d.\n",
				       pc - 1);
				goto release_out;
			} else
				sp -= 2;
			break;

		/* log_not */
		case 0x0e:
		/* bit_not */
		case 0x12:
		/* ref8 */
		case 0x17:
		/* ref16 */
		case 0x18:
		/* ref32 */
		case 0x19:
		/* ref64 */
		case 0x1a:
			break;

		/* dup */
		case 0x28:
			sp++;
			if (sp_max < sp)
				sp_max = sp;
			break;

		/* const8 */
		case 0x22:
			sp++;
			if (sp_max < sp)
				sp_max = sp;
		/* ext */
		case 0x16:
		/* zero_ext */
		case 0x2a:
			if (pc >= ae->u.exp.size)
				goto release_out;
			pc++;
			break;

		/* trace_quick */
		case 0x0d:
			if (tpe->have_printk)
				last_trace_pc = pc - 1;

			if (pc >= ae->u.exp.size)
				goto release_out;
			pc++;
			break;

		/* const16 */
		case 0x23:
		/* reg */
		case 0x26:
			if (pc + 1 >= ae->u.exp.size)
				goto release_out;
			pc += 2;

			sp++;
			if (sp_max < sp)
				sp_max = sp;
			break;

		/* const32 */
		case 0x24:
			if (pc + 3 >= ae->u.exp.size)
				goto release_out;
			pc += 4;

			sp++;
			if (sp_max < sp)
				sp_max = sp;
			break;

		/* const64 */
		case 0x25:
			if (pc + 7 >= ae->u.exp.size)
				goto release_out;
			pc += 8;

			sp++;
			if (sp_max < sp)
				sp_max = sp;
			break;

		/* if_goto */
		case 0x20:
			if (tpe->have_printk) {
				printk(KERN_WARNING "If_goto action doesn't"
				       "support printk.\n");
				goto release_out;
			}
			if (pc + 1 >= ae->u.exp.size)
				goto release_out;

			{
				unsigned int	dpc = (ebuf[pc] << 8)
						      + ebuf[pc + 1];

				if (dpc < pc) {
					/* This action X include loop. */
					ae->type = 0xff;
					ret = 0;
					goto release_out;
				}

				if (!nt32_x_if_goto_add(&glist, dpc, sp)) {
					ret = -ENOMEM;
					goto release_out;
				}
			}

			pc += 2;
			break;

		/* goto */
		case 0x21:
			if (pc + 1 >= ae->u.exp.size)
				goto release_out;

			{
				unsigned int	dpc = (ebuf[pc] << 8)
						      + ebuf[pc + 1];

				if (dpc < pc) {
					/* This action X include loop. */
					ae->type = 0xff;
					ret = 0;
					goto release_out;
				}

				pc = dpc;
			}
			break;

		/* end */
		case 0x27:
			goto out;
			break;

		/* getv */
		case 0x2c: {
				int	arg;

				if (pc + 1 >= ae->u.exp.size)
					goto release_out;
				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				if (!NT32_VAR_IS_SPECIAL(arg)) {
					if (nt32_x_var_add(&vlist, arg, 1)) {
						ret = -ENOMEM;
						goto release_out;
					}
				} else {
					if (arg == NT32_VAR_NO_SELF_TRACE_ID) {
						tpe->no_self_trace = 1;
						ret = 1;
						goto release_out;
					}

					if (arg == NT32_VAR_COOKED_CLOCK_ID)
						nt32_access_cooked_clock = 1;
#ifdef CONFIG_X86
					else if (arg == NT32_VAR_COOKED_RDTSC_ID)
						nt32_access_cooked_rdtsc = 1;
#endif
					ebuf[pc - 3] = op_special_getv;
				}
			}
			sp++;
			if (sp_max < sp)
				sp_max = sp;
			break;

		/* setv */
		case 0x2d: {
				int	arg;

				if (pc + 1 >= ae->u.exp.size)
					goto release_out;
				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				if (!NT32_VAR_IS_SPECIAL(arg)) {
					if (nt32_x_var_add(&vlist, arg, 2)) {
						ret = -ENOMEM;
						goto release_out;
					}
				} else {
					if (arg == NT32_VAR_NO_SELF_TRACE_ID) {
						tpe->no_self_trace = 1;
						ret = 1;
						goto release_out;
					} else if (arg == NT32_VAR_KRET_ID) {
						/* XXX: still not set it
						value to maxactive.  */
						tpe->is_kretprobe = 1;
						ret = 1;
						goto release_out;
					}

					if (arg == NT32_VAR_PRINTK_LEVEL_ID)
						tpe->have_printk = 1;

					ebuf[pc - 3] = op_special_setv;
				}
			}
			break;

		/* tracev */
		case 0x2e: {
				int	arg;

				if (tpe->have_printk)
					last_trace_pc = pc - 1;

				if (pc + 1 >= ae->u.exp.size)
					goto release_out;
				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				if (!NT32_VAR_IS_SPECIAL(arg)) {
					if (nt32_x_var_add(&vlist, arg, 4)) {
						ret = -ENOMEM;
						goto release_out;
					}
				} else {
					if (arg == NT32_VAR_NO_SELF_TRACE_ID) {
						tpe->no_self_trace = 1;
						ret = 1;
						goto release_out;
					}
					if (arg == NT32_VAR_COOKED_CLOCK_ID)
						nt32_access_cooked_clock = 1;
#ifdef CONFIG_X86
					else if (arg == NT32_VAR_COOKED_RDTSC_ID)
						nt32_access_cooked_rdtsc = 1;
#endif
					ebuf[pc - 3] = op_special_tracev;
				}
			}
			break;

		/* div_signed */
		case 0x05:
		/* div_unsigned */
		case 0x06:
		/* rem_signed */
		case 0x07:
		/* rem_unsigned */
		case 0x08:
#ifdef CONFIG_MIPS
			/* XXX, mips don't have 64 bit div.  */
			goto release_out;
#endif
			if (sp < 1) {
				printk(KERN_WARNING "nt32_check_x_simple: stack "
						    "overflow in %d.\n",
				       pc - 1);
				goto release_out;
			} else
				sp--;
			break;

		/* float */
		case 0x01:
		/* ref_float */
		case 0x1b:
		/* ref_double */
		case 0x1c:
		/* ref_long_double */
		case 0x1d:
		/* l_to_d */
		case 0x1e:
		/* d_to_l */
		case 0x1f:
		/* trace16 */
		case 0x30:
		default:
			goto release_out;
			break;
		}
	}
	goto release_out;

out:
#ifdef NT32_DEBUG
	printk(NT32_DEBUG "sp_max = %d\n", sp_max);
#endif
	if (sp_max >= STACK_MAX) {
		printk(KERN_WARNING "nt32_check_x_simple: stack overflow, "
				    "current %d, max %d.\n",
		       sp_max, STACK_MAX);
		goto release_out;
	}
	if (glist) {
		pc = glist->ip;
		sp = glist->sp;
		gtmp = glist;
		glist = glist->next;
		kfree(gtmp);
		goto reswitch;
	}
	ret = 0;
#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_check_x_simple: Code is OK. sp_max is %d.\n",
	       sp_max);
#endif

release_out:
	while (glist) {
		gtmp = glist;
		glist = glist->next;
		kfree(gtmp);
	}
	while (vlist) {
		struct nt32_var *var;

		vtmp = vlist;
		vlist = vlist->next;

		/* Get the var of vtmp.  */
		var = nt32_var_find(vtmp->num);
		if (var == NULL) {
			printk(KERN_WARNING "nt32_check_x_simple: cannot find "
					    "tvar %d.\n", vtmp->num);
			ret = -EINVAL;
		} else {
			if (var->per_cpu == NULL) {
				if ((vtmp->flags & 2)
				    && ((vtmp->flags & 1) || (vtmp->flags & 4)))
					ae->u.exp.need_var_lock = 1;
			}
		}
		kfree(vtmp);
	}

	if (tpe->have_printk && last_trace_pc > -1) {
		/* Set the last trace code to printk code.  */
		switch (ebuf[last_trace_pc]) {
		/* trace */
		case 0x0c:
			ebuf[last_trace_pc] = op_trace_printk;
			break;
		/* trace_quick */
		case 0x0d:
			ebuf[last_trace_pc] = op_trace_quick_printk;
			break;
		/* tracev */
		case 0x2e:
			ebuf[last_trace_pc] = op_tracev_printk;
			break;
		case op_special_tracev:
			ebuf[last_trace_pc] = op_tracev_printk;
			break;
		}
	}

	return ret;
}

static int
nt32_check_x_loop(struct nt32_entry *tpe, struct action *ae)
{
	int			ret = -EINVAL;
	unsigned int		pc = 0;
	struct nt32_x_loop	*glist = NULL, *gtmp;
	struct nt32_x_var	*vlist = NULL, *vtmp;
	uint8_t			*ebuf = ae->u.exp.buf;

	printk(KERN_WARNING "Action of tracepoint %d have loop.\n",
	       (int)tpe->num);

	tpe->have_printk = 0;

reswitch:
	while (pc < ae->u.exp.size) {
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32_check_x_loop: cmd %x\n", ebuf[pc]);
#endif
		switch (ebuf[pc++]) {
		/* add */
		case 0x02:
			ebuf[pc - 1] = op_check_add;
			break;
		/* sub */
		case 0x03:
			ebuf[pc - 1] = op_check_sub;
			break;
		/* mul */
		case 0x04:
			ebuf[pc - 1] = op_check_mul;
			break;
		/* lsh */
		case 0x09:
			ebuf[pc - 1] = op_check_lsh;
			break;
		/* rsh_signed */
		case 0x0a:
			ebuf[pc - 1] = op_check_rsh_signed;
			break;
		/* rsh_unsigned */
		case 0x0b:
			ebuf[pc - 1] = op_check_rsh_unsigned;
			break;
		/* bit_and */
		case 0x0f:
			ebuf[pc - 1] = op_check_bit_and;
			break;
		/* bit_or */
		case 0x10:
			ebuf[pc - 1] = op_check_bit_or;
			break;
		/* bit_xor */
		case 0x11:
			ebuf[pc - 1] = op_check_bit_xor;
			break;
		/* equal */
		case 0x13:
			ebuf[pc - 1] = op_check_equal;
			break;
		/* less_signed */
		case 0x14:
			ebuf[pc - 1] = op_check_less_signed;
			break;
		/* less_unsigned */
		case 0x15:
			ebuf[pc - 1] = op_check_less_unsigned;
			break;
		/* pop */
		case 0x29:
			ebuf[pc - 1] = op_check_pop;
			break;
		/* swap */
		case 0x2b:
			ebuf[pc - 1] = op_check_swap;
			break;

		/* trace */
		case 0x0c:
			ebuf[pc - 1] = op_check_trace;
			break;

		/* log_not */
		case 0x0e:
		/* bit_not */
		case 0x12:
		/* ref8 */
		case 0x17:
		/* ref16 */
		case 0x18:
		/* ref32 */
		case 0x19:
		/* ref64 */
		case 0x1a:
		/* dup */
		case 0x28:
			break;

		/* const8 */
		case 0x22:
		/* ext */
		case 0x16:
		/* zero_ext */
		case 0x2a:
		/* trace_quick */
		case 0x0d:
			if (pc >= ae->u.exp.size)
				goto release_out;
			pc++;
			break;

		/* const16 */
		case 0x23:
		/* reg */
		case 0x26:
			if (pc + 1 >= ae->u.exp.size)
				goto release_out;
			pc += 2;
			break;

		/* const32 */
		case 0x24:
			if (pc + 3 >= ae->u.exp.size)
				goto release_out;
			pc += 4;
			break;

		/* const64 */
		case 0x25:
			if (pc + 7 >= ae->u.exp.size)
				goto release_out;
			pc += 8;
			break;

		/* if_goto */
		case 0x20:
		case op_check_if_goto:
			ebuf[pc - 1] = op_check_if_goto;

			if (pc + 1 >= ae->u.exp.size)
				goto release_out;

			gtmp = nt32_x_loop_find(glist, pc);
			if (gtmp) {
				if (gtmp->non_goto_done)
					goto out;
				else {
					gtmp->non_goto_done = 1;
					pc += 2;
				}
			} else {
				if (!nt32_x_loop_add(&glist, pc, 0)) {
					ret = -ENOMEM;
					goto release_out;
				}
				pc = (ebuf[pc] << 8) + ebuf[pc + 1];
			}
			break;

		/* goto */
		case 0x21:
			if (pc + 1 >= ae->u.exp.size)
				goto release_out;

			gtmp = nt32_x_loop_find(glist, pc);
			if (gtmp)
				goto out;
			else {
				if (!nt32_x_loop_add(&glist, pc, 1)) {
					ret = -ENOMEM;
					goto release_out;
				}
			}

			pc = (ebuf[pc] << 8) + (ebuf[pc + 1]);
			break;

		/* end */
		case 0x27:
			goto out;
			break;

		/* getv */
		case 0x2c: {
				int	arg;

				if (pc + 1 >= ae->u.exp.size)
					goto release_out;
				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				if (!NT32_VAR_IS_SPECIAL(arg)) {
					if (nt32_x_var_add(&vlist, arg, 1)) {
						ret = -ENOMEM;
						goto release_out;
					}
				} else {
					if (arg == NT32_VAR_NO_SELF_TRACE_ID) {
						tpe->no_self_trace = 1;
						ret = 1;
						goto release_out;
					}

					if (arg == NT32_VAR_COOKED_CLOCK_ID)
						nt32_access_cooked_clock = 1;
#ifdef CONFIG_X86
					else if (arg == NT32_VAR_COOKED_RDTSC_ID)
						nt32_access_cooked_rdtsc = 1;
#endif
					ebuf[pc - 3] = op_special_getv;
				}
			}
			break;

		/* setv */
		case 0x2d: {
				int	arg;

				if (pc + 1 >= ae->u.exp.size)
					goto release_out;
				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				if (!NT32_VAR_IS_SPECIAL(arg)) {
					if (nt32_x_var_add(&vlist, arg, 2)) {
						ret = -ENOMEM;
						goto release_out;
					}
				} else {
					if (arg == NT32_VAR_NO_SELF_TRACE_ID) {
						tpe->no_self_trace = 1;
						ret = 1;
						goto release_out;
					} else if (arg == NT32_VAR_KRET_ID) {
						/* XXX: still not set it
						value to maxactive.  */
						tpe->is_kretprobe = 1;
						ret = 1;
						goto release_out;
					}

					if (arg == NT32_VAR_PRINTK_LEVEL_ID) {
						printk(KERN_WARNING "Loop "
						       "action doesn't"
						       "support printk.\n");
						goto release_out;
					}

					ebuf[pc - 3] = op_special_setv;
				}
			}
			break;

		/* tracev */
		case 0x2e: {
				int	arg;

				if (pc + 1 >= ae->u.exp.size)
					goto release_out;
				arg = ebuf[pc++];
				arg = (arg << 8) + ebuf[pc++];

				if (!NT32_VAR_IS_SPECIAL(arg)) {
					if (nt32_x_var_add(&vlist, arg, 4)) {
						ret = -ENOMEM;
						goto release_out;
					}
				} else {
					if (arg == NT32_VAR_NO_SELF_TRACE_ID) {
						tpe->no_self_trace = 1;
						ret = 1;
						goto release_out;
					}
					if (arg == NT32_VAR_COOKED_CLOCK_ID)
						nt32_access_cooked_clock = 1;
#ifdef CONFIG_X86
					else if (arg == NT32_VAR_COOKED_RDTSC_ID)
						nt32_access_cooked_rdtsc = 1;
#endif
					ebuf[pc - 3] = op_special_tracev;
				}
			}
			break;

		/* div_signed */
		case 0x05:
#ifdef CONFIG_MIPS
			/* XXX, mips don't have 64 bit div.  */
			printk(KERN_WARNING "MIPS don't have 64 bit div.\n");
			goto release_out;
#endif
			ebuf[pc - 1] = op_check_div_signed;
			break;
		/* div_unsigned */
		case 0x06:
#ifdef CONFIG_MIPS
			/* XXX, mips don't have 64 bit div.  */
			printk(KERN_WARNING "MIPS don't have 64 bit div.\n");
			goto release_out;
#endif
			ebuf[pc - 1] = op_check_div_unsigned;
			break;
		/* rem_signed */
		case 0x07:
#ifdef CONFIG_MIPS
			/* XXX, mips don't have 64 bit div.  */
			printk(KERN_WARNING "MIPS don't have 64 bit div.\n");
			goto release_out;
#endif
			ebuf[pc - 1] = op_check_rem_signed;
			break;
		/* rem_unsigned */
		case 0x08:
#ifdef CONFIG_MIPS
			/* XXX, mips don't have 64 bit div.  */
			printk(KERN_WARNING "MIPS don't have 64 bit div.\n");
			goto release_out;
#endif
			ebuf[pc - 1] = op_check_rem_unsigned;
			break;

		/* float */
		case 0x01:
		/* ref_float */
		case 0x1b:
		/* ref_double */
		case 0x1c:
		/* ref_long_double */
		case 0x1d:
		/* l_to_d */
		case 0x1e:
		/* d_to_l */
		case 0x1f:
		/* trace16 */
		case 0x30:
		default:
			goto release_out;
			break;
		}
	}
	goto release_out;

out:
	for (gtmp = glist; gtmp; gtmp = gtmp->next) {
		if (!gtmp->non_goto_done)
			break;
	}
	if (gtmp) {
		pc = gtmp->addr + 2;
		gtmp->non_goto_done = 1;
		goto reswitch;
	}
	ret = 0;

release_out:
	while (glist) {
		gtmp = glist;
		glist = glist->next;
		kfree(gtmp);
	}
	while (vlist) {
		struct nt32_var *var;

		vtmp = vlist;
		vlist = vlist->next;

		/* Get the var of vtmp.  */
		var = nt32_var_find(vtmp->num);
		if (var == NULL) {
			printk(KERN_WARNING "nt32_check_x_loop: cannot find "
					    "tvar %d.\n", vtmp->num);
			ret = -EINVAL;
		} else {
			if (var->per_cpu == NULL) {
				if ((vtmp->flags & 2)
				    && ((vtmp->flags & 1) || (vtmp->flags & 4)))
					ae->u.exp.need_var_lock = 1;
			}
		}
		kfree(vtmp);
	}

	return ret;
}

static int
nt32_check_x(struct nt32_entry *tpe, struct action *ae)
{
	int	ret = nt32_check_x_simple(tpe, ae);

	if (ret != 0 || ae->type == 'X')
		return ret;

	return nt32_check_x_loop(tpe, ae);
}

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
static void
nt32framework_pipe_wq_wake_up(unsigned long data)
{
	wake_up_interruptible_nr(&nt32framework_pipe_wq, 1);
}
#endif

static void
nt32_wq_add_work(unsigned long data)
{
	queue_work(nt32_wq, (struct work_struct *)data);
}

static int
nt32_gdbrsp_qtstart(void)
{
	int			cpu;
	struct nt32_entry	*tpe;
	struct nt32_var		*tve;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_qtstart\n");
#endif

	if (nt32_start)
		return -EBUSY;

#ifdef NT32_FTRACE_RING_BUFFER
	if (!tracing_is_on()) {
		printk(KERN_WARNING "qtstart: Ring buffer is off.  Please use "
		       "command "
		       "\"echo 1 > /sys/kernel/debug/tracing/tracing_on\" "
		       "open it.\n");
		return -EIO;
	}
#endif

	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		int		ret;
		struct action	*ae, *prev_ae = NULL;

		/* Check cond.  */
		if (tpe->cond) {
			ret = nt32_check_x(tpe, tpe->cond);
			if (ret > 0) {
				kfree(tpe->cond->u.exp.buf);
				kfree(tpe->cond);
				tpe->cond = NULL;
			} else if (ret < 0)
				return ret;
		}

		/* Check X.  */
		for (ae = tpe->action_list; ae; ae = ae->next) {
re_check:
			if (ae->type == 'X' || ae->type == 0xff) {
				ret = nt32_check_x(tpe, ae);
				if (ret > 0) {
					struct action	*old_ae = ae;

					/* Remove ae from action_list.  */
					ae = ae->next;
					if (prev_ae)
						prev_ae->next = ae;
					else
						tpe->action_list = ae;

					kfree(old_ae->u.exp.buf);
					kfree(old_ae);

					if (ae)
						goto re_check;
					else
						break;
				} else if (ret < 0)
					return ret;
			}

			prev_ae = ae;
		}

		/* Check the tracepoint that have printk.  */
		if (tpe->have_printk) {
			struct action	*ae, *prev_ae = NULL;
			struct nt32src	*src, *srctail = NULL;

restart:
			for (ae = tpe->action_list; ae;
			     prev_ae = ae, ae = ae->next) {
				switch (ae->type) {
				case 'R':
					/* Remove it. */
					if (prev_ae)
						prev_ae->next = ae->next;
					else
						tpe->action_list = ae->next;
					kfree(ae->src);
					kfree(ae);
					if (prev_ae)
						ae = prev_ae;
					else
						goto restart;
					break;
				case 'M':
					printk(KERN_WARNING "qtstart: action "
					       "of tp %d %p is not right.  "
					       "Please put global variable to "
					       "trace state variable "
					       "$printk_tmp before print it.\n",
					       (int)tpe->num,
					       (void *)(CORE_ADDR)tpe->addr);
					return -EINVAL;
					break;
				}
			}

			for (src = tpe->src; src; src = src->next) {
				int		i;
				char		str[strlen(src->src) >> 1];
				char		*var = NULL;
				ULONGEST	num;
				char		tmp[30];
				struct nt32src	*ksrc;

#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_qtstart: action "
						 "%s\n", src->src);
#endif
				/* Get the action in str.  */
				if (strncmp("cmd:0:", src->src,
					    strlen("cmd:0:")))
					continue;
				var = hex2ulongest(src->src + 6, &num);
				if (var[0] == '\0')
					return -EINVAL;
				var++;
				hex2string(var, str);
				if (strlen(str) != num)
					return -EINVAL;
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_qtstart: action "
						 "command %s\n", str);
#endif

				if (strncmp("collect ", str,
					    strlen("collect ")))
					continue;
				for (i = strlen("collect "); ; i++) {
					if (str[i] != ' ') {
						var = str + i;
						break;
					}
					if (str[i] == '\0')
						break;
				}
				if (!var) {
					printk(KERN_WARNING "qtstart: cannot "
							    "get the var name "
							    "from tp %d %p"
							    "command %s.\n",
					       (int)tpe->num,
					       (void *)(CORE_ADDR)tpe->addr,
					       str);
					return -EINVAL;
				}
				if (strcmp(var, "$args") == 0
				    || strcmp(var, "$local") == 0) {
					printk(KERN_WARNING "qtstart: cannot "
							    "print $args and "
							    "$local.\n");
					return -EINVAL;
				}
				if (strcmp(var, "$reg") == 0)
					continue;

				ksrc = kmalloc(sizeof(struct nt32src),
					       GFP_KERNEL);
				if (ksrc == NULL)
					return -ENOMEM;
				ksrc->next = NULL;

				snprintf(tmp, 30, "nt32 %d %p:", (int)tpe->num,
					 (void *)(CORE_ADDR)tpe->addr);
				ksrc->src = kmalloc(strlen(tmp)
						   + strlen(var) + 2,
						   GFP_KERNEL);
				if (ksrc->src == NULL) {
					kfree(ksrc);
					return -ENOMEM;
				}
				sprintf(ksrc->src, "%s%s=", tmp, var);

#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_qtstart: new "
						 "printk var %s\n", ksrc->src);
#endif

				if (tpe->printk_str)
					srctail->next = ksrc;
				else
					tpe->printk_str = ksrc;
				srctail = ksrc;
			}
		}
	}

#if defined(NT32_FTRACE_RING_BUFFER)			\
    && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))	\
    && !defined(NT32_SELF_RING_BUFFER)
	if (nt32_framework && nt32_circular_is_changed) {
		ring_buffer_free(nt32_framework);
		nt32_framework = NULL;
	}
	nt32_circular_is_changed = 0;
#endif

#ifdef NT32_RB
	if (NT32_RB_PAGE_IS_EMPTY) {
		if (nt32_rb_page_alloc(NT32_framework_SIZE) != 0) {
			nt32_rb_page_free();
			return -ENOMEM;
		}
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
	if (!nt32_framework) {
#ifdef NT32_framework_SIMPLE
		nt32_framework = vmalloc(NT32_framework_SIZE);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		nt32_framework = ring_buffer_alloc(NT32_framework_SIZE,
					      nt32_circular ? RB_FL_OVERWRITE
							     : 0);
#endif
		if (!nt32_framework)
			return -ENOMEM;
#endif

		nt32_framework_reset();
	}

	for_each_online_cpu(cpu) {
#ifdef CONFIG_X86
		per_cpu(rdtsc_current, cpu) = 0;
		per_cpu(rdtsc_offset, cpu) = 0;
#endif
		per_cpu(local_clock_current, cpu) = 0;
		per_cpu(local_clock_offset, cpu) = 0;
		per_cpu(nt32_handler_began, cpu) = 0;
	}

	nt32_start = 1;

	nt32_var_array = kmalloc(sizeof(struct nt32_var *)
				* (nt32_var_tail - nt32_var_head + 1),
				GFP_KERNEL);
	if (!nt32_var_array) {
		nt32_gdbrsp_qtstop();
		return -ENOMEM;
	}
	memset(nt32_var_array, '\0', sizeof(struct nt32_var *)
				    *(nt32_var_tail - nt32_var_head + 1));
	for (tve = nt32_var_list; tve; tve = tve->next)
		nt32_var_array[tve->num - nt32_var_head] = tve;

#ifdef NT32_PERF_EVENTS
	/* Clear pc_pe_list.  */
	for_each_online_cpu(cpu) {
		per_cpu(pc_pe_list, cpu) = NULL;
		per_cpu(pc_pe_list_all_disabled, cpu) = 1;
	}
	for (tve = nt32_var_list; tve; tve = tve->next) {
		if (tve->ptid == pe_tv_unknown)
			continue;
		if (tve->pts->event)
			continue;

		/* Get event.  */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0))
		tve->pts->event =
			perf_event_create_kernel_counter(&(tve->pts->attr),
							 tve->pts->cpu,
							 NULL, NULL, NULL);
#elif (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,36)) \
       || (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,1))
		tve->pts->event =
			perf_event_create_kernel_counter(&(tve->pts->attr),
							 tve->pts->cpu,
							 NULL, NULL);
#else
		tve->pts->event =
			perf_event_create_kernel_counter(&(tve->pts->attr),
							 tve->pts->cpu,
							 -1, NULL);
#endif
		if (IS_ERR(tve->pts->event)) {
			int	ret = PTR_ERR(tve->pts->event);

			printk(KERN_WARNING "nt32_gdbrsp_qtstart:"
			       "create perf_event CPU%d %d %d got error.\n",
			       (int)tve->pts->cpu, (int)tve->pts->attr.type,
			       (int)tve->pts->attr.config);
			tve->pts->event = NULL;
			nt32_gdbrsp_qtstop();
			return ret;
		}

		/* Add event to pc_pe_list.  */
		if (tve->pts->cpu >= 0) {
			struct pe_tv_s *ppl = per_cpu(pc_pe_list,
						      tve->pts->cpu);
			if (ppl == NULL) {
				per_cpu(pc_pe_list, tve->pts->cpu) = tve->pts;
				tve->pts->pc_next = NULL;
			} else {
				tve->pts->pc_next = ppl;
				per_cpu(pc_pe_list,
					tve->pts->cpu) = tve->pts;
			}
			if (tve->pts->en)
				per_cpu(pc_pe_list_all_disabled, tve->pts->cpu)
					= 0;
		}
	}
#endif

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	tasklet_init(&nt32framework_pipe_wq_tasklet, nt32framework_pipe_wq_wake_up, 0);
#endif

	nt32_start_last_errno = 0;

	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		tpe->reason = nt32_stop_normal;
		if (!tpe->disable && tpe->addr != 0) {
			int	ret;

			if (!tpe->nopass)
				atomic_set(&tpe->current_pass, tpe->pass);

			tasklet_init(&tpe->tasklet, nt32_wq_add_work,
				     (unsigned long)&tpe->work);

			if (tpe->is_kretprobe) {
				if (nt32_access_cooked_clock
#ifdef CONFIG_X86
				    || nt32_access_cooked_rdtsc
#endif
#ifdef NT32_PERF_EVENTS
				    || nt32_have_pc_pe
#endif
				)
					tpe->kp.handler =
						nt32_kp_ret_handler_plus;
				else
					tpe->kp.handler = nt32_kp_ret_handler;
				ret = register_kretprobe(&tpe->kp);
			} else {
				if (nt32_access_cooked_clock
#ifdef CONFIG_X86
				    || nt32_access_cooked_rdtsc
#endif
#ifdef NT32_PERF_EVENTS
				    || nt32_have_pc_pe
#endif
				) {
					if (tpe->step) {
						tpe->kp.kp.pre_handler =
						  nt32_kp_pre_handler_plus_step;
						tpe->kp.kp.post_handler =
						    nt32_kp_post_handler_plus;
					} else
						tpe->kp.kp.pre_handler =
							nt32_kp_pre_handler_plus;
					ret = register_kprobe(&tpe->kp.kp);
				} else {
					tpe->kp.kp.pre_handler =
						nt32_kp_pre_handler;
					if (tpe->step)
						tpe->kp.kp.post_handler =
							nt32_kp_post_handler;
					ret = register_kprobe(&tpe->kp.kp);
				}
			}
			if (ret < 0) {
				printk(KERN_WARNING "nt32_gdbrsp_qtstart:"
				"register tracepoint %d %p got error.\n",
				(int)tpe->num, (void *)(CORE_ADDR)tpe->addr);
				if (nt32_start_ignore_error) {
					nt32_start_last_errno = (uint64_t)ret;
					continue;
				} else {
					nt32_gdbrsp_qtstop();
					return ret;
				}
			}
			tpe->kpreg = 1;
		}
	}

	return 0;
}

static int
nt32_parse_x(struct nt32_entry *tpe, struct action *ae, char **pkgp)
{
	ULONGEST	size;
	int		ret = 0, i, h, l;
	char		*pkg = *pkgp;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_parse_x: %s\n", pkg);
#endif

	if (pkg[0] == '\0') {
		ret = -EINVAL;
		goto out;
	}
	pkg = hex2ulongest(pkg, &size);
	if (pkg[0] != ',') {
		ret = -EINVAL;
		goto out;
	}
	ae->u.exp.size = (unsigned int)size;
	pkg++;

	ae->u.exp.buf = kmalloc(ae->u.exp.size, GFP_KERNEL);
	if (!ae->u.exp.buf)
		return -ENOMEM;

	for (i = 0; i < ae->u.exp.size
		    && hex2int(pkg[0], &h) && hex2int(pkg[1], &l);
	     i++) {
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32_parse_x: %s %d %d\n", pkg, h, l);
#endif
		ae->u.exp.buf[i] = (h << 4) | l;
		pkg += 2;
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32_parse_x: %x\n", ae->u.exp.buf[i]);
#endif
	}
	if (i != ae->u.exp.size) {
		kfree(ae->u.exp.buf);
		ret = -EINVAL;
		goto out;
	}

	ae->u.exp.need_var_lock = 0;

out:
	*pkgp = pkg;
	return ret;
}

static int
nt32_gdbrsp_qtdp(char *pkg)
{
	int			addnew = 1;
	ULONGEST		num, addr;
	struct nt32_entry	*tpe;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_qtdp: %s\n", pkg);
#endif

	if (nt32_start)
		return -EBUSY;

	if (pkg[0] == '-') {
		pkg++;
		addnew = 0;
	}

	/* Get num and addr.  */
	if (pkg[0] == '\0')
		return -EINVAL;
	pkg = hex2ulongest(pkg, &num);
	if (pkg[0] == '\0')
		return -EINVAL;
	pkg++;
	pkg = hex2ulongest(pkg, &addr);
	if (pkg[0] == '\0')
		return -EINVAL;
	pkg++;

	tpe = nt32_list_find(num, addr);
	if (addnew) {
		ULONGEST	ulongtmp;

		if (tpe)
			return -EINVAL;

		tpe = nt32_list_add(num, addr);
		if (tpe == NULL)
			return -ENOMEM;

		if (pkg[0] == '\0')
			return -EINVAL;
		if (pkg[0] == 'D')
			tpe->disable = 1;
		pkg++;

		/* Get step.  */
		if (pkg[0] == '\0')
			return -EINVAL;
		pkg++;
		pkg = hex2ulongest(pkg, &ulongtmp);
		if (pkg[0] == '\0')
			return -EINVAL;
		if (ulongtmp > 1) {
			printk(KERN_WARNING "NT32 only support one step.\n");
			return -EINVAL;
		}
		tpe->step = (int)ulongtmp;

		/* Get pass.  */
		if (pkg[0] == '\0')
			return -EINVAL;
		pkg++;
		pkg = hex2ulongest(pkg, &tpe->pass);
		if (tpe->pass == 0)
			tpe->nopass = 1;
	}

	if (tpe) {
		/* Add action to tpe.  */
		int	step_action = 0;

		if (pkg[0] == 'S') {
			if (tpe->step == 0)
				return -EINVAL;
			pkg++;
			step_action = 1;
		} else if (tpe->step_action_list)
			step_action = 1;
		while (pkg[0]) {
			struct action	*ae = NULL, *atail = NULL;

#ifdef NT32_DEBUG
			printk(NT32_DEBUG "nt32_gdbrsp_qtdp: %s\n", pkg);
#endif
			switch (pkg[0]) {
			case ':':
				pkg++;
				break;
			case 'M': {
					int		is_neg = 0;
					ULONGEST	ulongtmp;

					ae = nt32_action_alloc(pkg);
					if (!ae)
						return -ENOMEM;
					pkg++;
					if (pkg[0] == '-') {
						is_neg = 1;
						pkg++;
					}
					pkg = hex2ulongest(pkg, &ulongtmp);
					ae->u.m.regnum = (int)ulongtmp;
					if (is_neg)
						ae->u.m.regnum
						  = -ae->u.m.regnum;
					if (pkg[0] == '\0') {
						kfree(ae);
						return -EINVAL;
					}
					pkg++;
					pkg = hex2ulongest(pkg, &ulongtmp);
					ae->u.m.offset = (CORE_ADDR)ulongtmp;
					if (pkg[0] == '\0') {
						kfree(ae);
						return -EINVAL;
					}
					pkg++;
					pkg = hex2ulongest(pkg, &ulongtmp);
					ae->u.m.size = (size_t)ulongtmp;
				}
				break;
			case 'R':
				/* XXX: reg_mask is ignore.  */
				ae = nt32_action_alloc(pkg);
				if (!ae)
					return -ENOMEM;
				pkg++;
				pkg = hex2ulongest(pkg,
						   &ae->u.reg_mask);
				break;
			case 'X': {
					int	ret;

					ae = nt32_action_alloc(pkg);
					if (!ae)
						return -ENOMEM;
					pkg++;
					ret = nt32_parse_x(tpe, ae, &pkg);
					if (ret) {
						kfree(ae);
						ae = NULL;

						if (ret < 0)
							return ret;
					}
				}
				break;
			case '-':
				pkg++;
				break;
			default:
				/* XXX: Not support.  */
				return 1;
			}

			if (ae) {
				/* Save the src.  */
				ae->src = nt32_strdup(ae->src, pkg);
				if (ae->src == NULL) {
					kfree(ae);
					return -ENOMEM;
				}
				/* Add ae to tpe.  */
				if ((ae->type == 'X' || ae->type == 0xff)
				    && addnew && !tpe->cond) {
					tpe->cond = ae;
					tpe->cond->next = NULL;
				} else if (!step_action && !tpe->action_list) {
					tpe->action_list = ae;
					atail = ae;
				} else if (step_action
					   && !tpe->step_action_list) {
					tpe->step_action_list = ae;
					atail = ae;
				} else {
					if (atail == NULL) {
						if (step_action)
							atail =
							  tpe->step_action_list;
						else
							atail =
							  tpe->action_list;
						for (; atail->next;
						     atail = atail->next)
							;
					}
					atail->next = ae;
					atail = ae;
				}
			}
		}
	} else
		return -EINVAL;

	return 0;
}

static int
nt32_gdbrsp_qtdpsrc(char *pkg)
{
	ULONGEST		num, addr;
	struct nt32src		*src, *srctail;
	struct nt32_entry	*tpe;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_qtdpsrc: %s\n", pkg);
#endif

	if (nt32_start)
		return -EBUSY;

	/* Get num and addr.  */
	if (pkg[0] == '\0')
		return -EINVAL;
	pkg = hex2ulongest(pkg, &num);
	if (pkg[0] == '\0')
		return -EINVAL;
	pkg++;
	pkg = hex2ulongest(pkg, &addr);
	if (pkg[0] == '\0')
		return -EINVAL;
	pkg++;
	tpe = nt32_list_find(num, addr);
	if (tpe == NULL)
		return -EINVAL;

	src = kmalloc(sizeof(struct nt32src), GFP_KERNEL);
	if (src == NULL)
		return -ENOMEM;
	src->next = NULL;
	src->src = nt32_strdup(pkg, NULL);
	if (src->src == NULL) {
		kfree(src);
		return -ENOMEM;
	}

	if (tpe->src) {
		for (srctail = tpe->src; srctail->next;
		     srctail = srctail->next)
			;
		srctail->next = src;
	} else
		tpe->src = src;

	return 0;
}

static int
nt32_gdbrsp_qtdisconnected(char *pkg)
{
	ULONGEST setting;

	if (pkg[0] == '\0')
		return -EINVAL;

	hex2ulongest(pkg, &setting);
	nt32_disconnected_tracing = (int)setting;

	return 0;
}

static int
nt32_gdbrsp_qtbuffer(char *pkg)
{
	if (strncmp("circular:", pkg, 9) == 0) {
		ULONGEST setting;

		pkg += 9;
		if (pkg[0] == '\0')
			return -EINVAL;
		hex2ulongest(pkg, &setting);

#ifdef NT32_FTRACE_RING_BUFFER
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)) \
    || defined(NT32_SELF_RING_BUFFER)
		nt32_circular = (int)setting;
		if (nt32_framework)
			ring_buffer_change_overwrite(nt32_framework, (int)setting);
#else
		if (nt32_circular != (int)setting)
			nt32_circular_is_changed = 1;
#endif
#endif
		nt32_circular = (int)setting;

		return 0;
	}

	return 1;
}

static int
nt32_framework_head_find_num(int num)
{
#ifdef NT32_framework_SIMPLE
	int	tfnum = 0;
	char	*tmp = nt32_framework_r_start;

	do {
		if (tmp == nt32_framework_end)
			tmp = nt32_framework;

		if (FID(tmp) == FID_HEAD) {
			if (tfnum == num) {
				nt32_framework_current_num = num;
				nt32_framework_current = tmp;
				return 0;
			}
			tfnum++;
		}

		tmp = nt32_framework_next(tmp);
		if (!tmp)
			break;
	} while (tmp != nt32_framework_w_start);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	if (nt32_framework_current_num >= num)
		nt32_framework_iter_reset();

	while (1) {
		int	cpu;

		cpu = nt32_framework_iter_peek_head();
		if (cpu < 0)
			break;

		if (num == nt32_framework_current_num)
			return cpu;

		ring_buffer_read(nt32_framework_iter[cpu], NULL);
	}
#endif
#ifdef NT32_RB
	if (num < nt32_framework_current_num)
		nt32_rb_read_reset();

	while (1) {
		if (nt32_framework_current_num == num)
			return 0;

		if (nt32_rb_read() != 0)
			break;
	}
#endif

	return -1;
}

static int
nt32_framework_head_find_addr(int inside, unsigned long lo,
			 unsigned long hi)
{
#ifdef NT32_framework_SIMPLE
	int	tfnum = nt32_framework_current_num;
	char	*tmp;

	if (nt32_framework_current)
		tmp = nt32_framework_current;
	else
		tmp = nt32_framework_r_start;

	do {
		if (tmp == nt32_framework_end)
			tmp = nt32_framework;

		if (FID(tmp) == FID_HEAD) {
			if (tfnum != nt32_framework_current_num) {
				char		*next;
				struct pt_regs	*regs = NULL;

				for (next = *(char **)(tmp + FID_SIZE); next;
				     next = *(char **)(next + FID_SIZE)) {
					if (FID(next) == FID_REG) {
						regs = (struct pt_regs *)
						       (next + FID_SIZE
							+ sizeof(char *));
						break;
					}
				}
				if (regs
				    && ((inside
					 && NT32_REGS_PC(regs) >= lo
					 && NT32_REGS_PC(regs) <= hi)
					|| (!inside
					    && (NT32_REGS_PC(regs) < lo
						|| NT32_REGS_PC(regs) > hi)))) {
					nt32_framework_current_num = tfnum;
					nt32_framework_current = tmp;
					return 0;
				}
			}
			tfnum++;
		}

		tmp = nt32_framework_next(tmp);
		if (!tmp)
			break;
	} while (tmp != nt32_framework_w_start);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	while (1) {
		int				cpu;
		struct ring_buffer_event	*rbe;
		char				*tmp;
		struct pt_regs			*regs = NULL;

		cpu = nt32_framework_iter_peek_head();
		if (cpu < 0)
			break;

		while (1) {
			ring_buffer_read(nt32_framework_iter[cpu], NULL);
			rbe = ring_buffer_iter_peek(nt32_framework_iter[cpu], NULL);
			if (rbe == NULL)
				break;

			tmp = ring_buffer_event_data(rbe);
			if (FID(tmp) == FID_HEAD)
				break;
			if (FID(tmp) == FID_REG) {
				regs = (struct pt_regs *)(tmp + FID_SIZE);
				break;
			}
		}

		if (regs
		    && ((inside
			  && NT32_REGS_PC(regs) >= lo
			  && NT32_REGS_PC(regs) <= hi)
			|| (!inside
			    && (NT32_REGS_PC(regs) < lo
				|| NT32_REGS_PC(regs) > hi))))
			return nt32_framework_head_find_num(nt32_framework_current_num);
	}
#endif
#ifdef NT32_RB
	struct nt32_rb_walk_s	rbws;

	if (nt32_framework_current_num < 0) {
		if (nt32_rb_read() != 0)
			return -1;
	}

	rbws.flags = NT32_RB_WALK_PASS_PAGE | NT32_RB_WALK_CHECK_END
		     | NT32_RB_WALK_CHECK_ID | NT32_RB_WALK_CHECK_TYPE;
	rbws.type = FID_REG;

	while (1) {
		char	*tmp;

		rbws.end = nt32_framework_current_rb->w;
		rbws.id = nt32_framework_current_id;
		tmp = nt32_rb_walk(&rbws, nt32_framework_current_rb->rp);
		if (rbws.reason == nt32_rb_walk_type) {
			struct pt_regs	*regs
				= (struct pt_regs *)(tmp + FID_SIZE);

			if ((inside && NT32_REGS_PC(regs) >= lo
			     && NT32_REGS_PC(regs) <= hi)
			    || (!inside && (NT32_REGS_PC(regs) < lo
					    || NT32_REGS_PC(regs) > hi))) {
				return 0;
			}
		}

		if (nt32_rb_read() != 0)
			break;
	}
#endif

	return -1;
}

static int
nt32_framework_head_find_trace(ULONGEST trace)
{
#ifdef NT32_framework_SIMPLE
	int	tfnum = nt32_framework_current_num;
	char	*tmp;

	if (nt32_framework_current)
		tmp = nt32_framework_current;
	else
		tmp = nt32_framework_r_start;

	do {
		if (tmp == nt32_framework_end)
			tmp = nt32_framework;

		if (FID(tmp) == FID_HEAD) {
			if (tfnum != nt32_framework_current_num) {
				if (trace == *(ULONGEST *) (tmp + FID_SIZE
							    + sizeof(char *))) {
					nt32_framework_current_num = tfnum;
					nt32_framework_current = tmp;
					return 0;
				}
			}
			tfnum++;
		}

		tmp = nt32_framework_next(tmp);
		if (!tmp)
			break;
	} while (tmp != nt32_framework_w_start);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	while (1) {
		int				cpu;
		struct ring_buffer_event	*rbe;
		char				*tmp;

		cpu = nt32_framework_iter_peek_head();
		if (cpu < 0)
			break;

		rbe = ring_buffer_iter_peek(nt32_framework_iter[cpu], NULL);
		if (rbe == NULL) {
			/* It will not happen, just for safe.  */
			return -1;
		}
		tmp = ring_buffer_event_data(rbe);
		if (trace == *(ULONGEST *) (tmp + FID_SIZE))
			return cpu;

		ring_buffer_read(nt32_framework_iter[cpu], NULL);
	}
#endif
#ifdef NT32_RB
	if (nt32_framework_current_num < 0) {
		if (nt32_rb_read() != 0)
			return -1;
	}

	while (1) {
		if (nt32_framework_current_tpe == trace)
			return 0;

		if (nt32_rb_read() != 0)
			break;
	}
#endif

	return -1;
}

static int
nt32_gdbrsp_qtframework(char *pkg)
{
	int	ret = -1;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	int	old_num = nt32_framework_current_num;
#endif

	if (nt32_start)
		return -EBUSY;

	if (nt32_nt32framework_pipe_pid >= 0)
		return -EBUSY;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_qtframework: %s\n", pkg);
#endif

	if (atomic_read(&nt32_framework_create) == 0)
		goto out;

	if (strncmp(pkg, "pc:", 3) == 0) {
		ULONGEST	addr;

		pkg += 3;

		if (pkg[0] == '\0')
			return -EINVAL;
		hex2ulongest(pkg, &addr);

		ret = nt32_framework_head_find_addr(1, (unsigned long)addr,
					       (unsigned long)addr);
	} else if (strncmp(pkg, "tdp:", 4) == 0) {
		ULONGEST	trace;

		pkg += 4;

		if (pkg[0] == '\0')
			return -EINVAL;
		hex2ulongest(pkg, &trace);

		ret = nt32_framework_head_find_trace(trace);
	} else if (strncmp(pkg, "range:", 6) == 0) {
		ULONGEST	start, end;

		pkg += 6;

		if (pkg[0] == '\0')
			return -EINVAL;
		pkg = hex2ulongest(pkg, &start);
		if (pkg[0] == '\0')
			return -EINVAL;
		pkg++;
		hex2ulongest(pkg, &end);

		ret = nt32_framework_head_find_addr(1, (unsigned long)start,
					       (unsigned long)end);
	} else if (strncmp(pkg, "outside:", 8) == 0) {
		ULONGEST	start, end;

		pkg += 8;

		if (pkg[0] == '\0')
			return -EINVAL;
		pkg = hex2ulongest(pkg, &start);
		if (pkg[0] == '\0')
			return -EINVAL;
		pkg++;
		hex2ulongest(pkg, &end);

		ret = nt32_framework_head_find_addr(0, (unsigned long)start,
					       (unsigned long)end);
	} else {
		ULONGEST	num;

		if (pkg[0] == '\0')
			return -EINVAL;
		hex2ulongest(pkg, &num);

		if (((int) num) < 0) {
			/* Return to current.  */
#ifdef NT32_framework_SIMPLE
			nt32_framework_current = NULL;
			nt32_framework_current_num = -1;
#endif
#ifdef NT32_FTRACE_RING_BUFFER
			nt32_framework_iter_reset();
#endif
#ifdef NT32_RB
			nt32_rb_read_reset();
#endif

			return 0;
		}
		ret = nt32_framework_head_find_num((int) num);
	}

out:
	if (ret < 0) {
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
		/* Set framework back to old_num.  */
		if (old_num < 0)
#ifdef NT32_FTRACE_RING_BUFFER
			nt32_framework_iter_reset();
#endif
#ifdef NT32_RB
			nt32_rb_read_reset();
#endif
		else
			nt32_framework_head_find_num(old_num);
#endif
		snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "F-1");
		nt32_rw_bufp += 3;
		nt32_rw_size += 3;
	} else {
#ifdef NT32_framework_SIMPLE
		nt32_framework_current_tpe = *(ULONGEST *)(nt32_framework_current
						      + FID_SIZE
						      + sizeof(char *));
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		struct ring_buffer_event	*rbe;
		char				*tmp;

		rbe = ring_buffer_read(nt32_framework_iter[ret],
				       &nt32_framework_current_clock);
		if (rbe == NULL) {
			/* It will not happen, just for safe.  */
			ret = -1;
			goto out;
		}
		nt32_framework_current_cpu = ret;
		tmp = ring_buffer_event_data(rbe);
		nt32_framework_current_tpe = *(ULONGEST *)(tmp + FID_SIZE);
#endif
		snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "F%xT%x",
			 nt32_framework_current_num,
			 (unsigned int) nt32_framework_current_tpe);
		nt32_rw_size += strlen(nt32_rw_bufp);
		nt32_rw_bufp += strlen(nt32_rw_bufp);
	}
	return 1;
}

static int
nt32_gdbrsp_qtro(char *pkg)
{
	ULONGEST	start, end;

	nt32ro_list_clear();

	while (pkg[0]) {
		pkg = hex2ulongest(pkg, &start);
		if (pkg[0] != ',')
			return -EINVAL;
		pkg++;
		pkg = hex2ulongest(pkg, &end);
		if (pkg[0])
			pkg++;

		if (nt32ro_list_add((CORE_ADDR)start, (CORE_ADDR)end) == NULL)
			return -ENOMEM;
	}

	return 0;
}

static int
nt32_gdbrsp_qtdv(char *pkg)
{
	ULONGEST	num, val;
	struct nt32_var	*var;
	char		*src;
	char		*src_no_val;
	int		src_no_val_size;
	int		per_cpu_id = 0;
	struct nt32_var	**per_cpu = NULL;
	int		per_cpu_alloced = 0;
	int		ret = -EINVAL;
#ifdef NT32_PERF_EVENTS
	enum pe_tv_id	ptid = pe_tv_unknown;
	struct pe_tv_s	*pts = NULL;
	int		pts_alloced = 0;
#endif

	pkg = hex2ulongest(pkg, &num);
	if (pkg[0] != ':')
		goto error_out;
	pkg++;
	src = pkg;
	pkg = hex2ulongest(pkg, &val);
	if (pkg[0] != ':')
		goto error_out;

	if (NT32_VAR_IS_SPECIAL(num)) {
		/* Change the value of special tv.  */
		var = nt32_var_find(num);
		if (var)
			var->val = val;
		if (num == NT32_VAR_IGNORE_ERROR_ID)
			nt32_start_ignore_error = (int)val;
		else if (num == NT32_VAR_PIPE_TRACE_ID)
			nt32_pipe_trace = (int)val;

		return 0;
	}

	/* src_no_val is not include the val but the ':' after it. */
	src_no_val = pkg;
	src_no_val_size = strlen(src_no_val);

	pkg++;

	var = nt32_var_find(num);
	if (var)
		goto error_out;

	/* Check if this is a "pc_" or "per_cpu_" trace state variable.  */
	if (strncasecmp(pkg, "0:70635f", 8) == 0
	    || strncasecmp(pkg, "0:7065725f6370755f", 18) == 0) {
		int		name_size;
		char		*id_s;
		int		mul = 1;
		struct nt32_var	*tve;

		if (strncasecmp(pkg, "0:70635f", 8) == 0)
			pkg += 8;
		else
			pkg += 18;
		name_size = strlen(pkg);

		/* Get the cpu id of this variable.  */
		if (name_size % 2 != 0)
			goto error_out;
		for (id_s = pkg + name_size - 2; id_s > pkg; id_s -= 2) {
			int	i, j;

			if (!hex2int(id_s[0], &i))
				goto error_out;
			if (!hex2int(id_s[1], &j))
				goto error_out;
			j |= (i << 4);
			if (j < 0x30 || j > 0x39)
				break;
			j -= 0x30;
			per_cpu_id += mul * j;
			mul *= 10;
			/* src_no_val_size will not include the cpu id.  */
			src_no_val_size -= 2;
		}
		if (mul == 1)
			goto error_out;
		if (per_cpu_id >= nt32_cpu_number) {
			printk(KERN_WARNING "nt32_gdbrsp_qtdv: id %d is bigger "
					    "than cpu number %d.\n",
			       per_cpu_id, nt32_cpu_number);
			goto error_out;
		}

		/* Find the per cpu array per_cpu.  */
		for (tve = nt32_var_list; tve; tve = tve->next) {
			if (tve->per_cpu) {
				char	*nt32_var_src;
				/* Let nt32_var_src point after the value.  */
				nt32_var_src = hex2ulongest(tve->src, NULL);

				if (strncmp(nt32_var_src, src_no_val,
					    src_no_val_size) == 0) {
					per_cpu = tve->per_cpu;
					break;
				}
			}
		}
		if (per_cpu == NULL) {
			per_cpu = kcalloc(nt32_cpu_number,
					  sizeof(struct nt32_var *),
					  GFP_KERNEL);
			if (per_cpu == NULL) {
				ret = -ENOMEM;
				goto error_out;
			}
			per_cpu_alloced = 1;
#ifdef NT32_DEBUG
			printk(NT32_DEBUG "nt32_gdbrsp_qtdv: Create a "
					 "new per_cpu list for %s and set var "
					 "to cpu %d.\n",
			       src_no_val, per_cpu_id);
#endif
		} else {
#ifdef NT32_DEBUG
			printk(NT32_DEBUG "nt32_gdbrsp_qtdv: Find a "
					 "per_cpu list for %s and set var "
					 "to cpu %d.\n",
			       src_no_val, per_cpu_id);
#endif
		}
	} else {
		/* Remove first "0:" for following code.  */
		if (strlen(pkg) <= 2)
			goto error_out;
		pkg += 2;
	}

	/* Check if this is a "pe_" OR "perf_event_" trace state variable.  */
	if (strncasecmp(pkg, "70655f", 6) == 0
	    || strncasecmp(pkg, "706572665f6576656e745f", 22) == 0) {
#ifdef NT32_PERF_EVENTS
		struct nt32_var	*tve;

		if (strncasecmp(pkg, "70655f", 6) == 0)
			pkg += 6;
		else
			pkg += 22;

		if (strncasecmp(pkg, "6370755f", 8) == 0) {
			/* "cpu_" */
			pkg += 8;
			ptid = pe_tv_cpu;
		} else if (strncasecmp(pkg, "747970655f", 10) == 0) {
			/* "type_" */
			pkg += 10;
			ptid = pe_tv_type;
		} else if (strncasecmp(pkg, "636f6e6669675f", 14) == 0) {
			/* "config_" */
			pkg += 14;
			ptid = pe_tv_config;
		} else if (strncasecmp(pkg, "656e5f", 6) == 0) {
			/* "en_" */
			pkg += 6;
			ptid = pe_tv_en;
		} else if (strncasecmp(pkg, "76616c5f", 8) == 0) {
			/* "val_" */
			pkg += 8;
			ptid = pe_tv_val;
		} else if (strncasecmp(pkg, "656e61626c65645f", 16) == 0) {
			/* "enabled_" */
			pkg += 16;
			ptid = pe_tv_enabled;
		} else if (strncasecmp(pkg, "72756e6e696e675f", 16) == 0) {
			/* "running_" */
			pkg += 16;
			ptid = pe_tv_running;
		} else
			goto pe_format_error;

		if (strlen(pkg) <= 0)
			goto pe_format_error;

		/* Find the pe_tv that name is pkg.  */
		for (tve = nt32_var_list; tve; tve = tve->next) {
			if (tve->ptid != pe_tv_unknown) {
				if (strcmp(tve->pts->name, pkg) == 0)
					break;
			}
		}

		if (tve)
			pts = tve->pts;
		else {
			pts = kcalloc(1, sizeof(struct pe_tv_s), GFP_KERNEL);
			if (pts == NULL) {
				ret = -ENOMEM;
				goto error_out;
			}
			pts_alloced = 1;
			/* Init the value in pts to default value.  */
			pts->name = nt32_strdup(pkg, NULL);
			if (per_cpu)
				pts->cpu = per_cpu_id;
			else
				pts->cpu = -1;
			pts->en = 0;
			pts->attr.type = PERF_TYPE_HARDWARE;
			pts->attr.config = PERF_COUNT_HW_CPU_CYCLES;
			pts->attr.disabled = 1;
			pts->attr.pinned = 1;
			pts->attr.size = sizeof(struct perf_event_attr);
		}

		/* Set current val to pts.  */
		switch (ptid) {
		case pe_tv_cpu:
			pts->cpu = (int)(LONGEST)val;
			break;
		case pe_tv_type:
			pts->attr.type = val;
			break;
		case pe_tv_config:
			pts->attr.config = val;
			break;
		case pe_tv_en:
			if (val) {
				pts->attr.disabled = 0;
				pts->en = 1;
			} else {
				pts->attr.disabled = 1;
				pts->en = 0;
			}
			break;
		case pe_tv_val:
		case pe_tv_enabled:
		case pe_tv_running:
			break;
		default:
			goto pe_format_error;
			break;
		}

		nt32_have_pc_pe = 1;
#else
		printk(KERN_WARNING "Current Kernel doesn't open "
				    "NT32_PERF_EVENTS\n");
		ret = -ENXIO;
		goto error_out;
#endif
	}

#ifdef NT32_PERF_EVENTS
	if (!nt32_var_add((unsigned int)num, (uint64_t)val, src,
			 per_cpu, per_cpu_id, ptid, pts)) {
#else
	if (!nt32_var_add((unsigned int)num, (uint64_t)val, src,
			 per_cpu, per_cpu_id)) {
#endif
		ret = -ENOMEM;
		goto error_out;
	}

	return 0;

#ifdef NT32_PERF_EVENTS
pe_format_error:
	printk(KERN_WARNING "The format of this perf event "
			    "trace state variables is not right.\n");
#endif

error_out:
#ifdef NT32_PERF_EVENTS
	if (pts_alloced)
		kfree(pts);
#endif
	if (per_cpu_alloced)
		kfree(per_cpu);
	return ret;
}

static int
nt32_gdbrsp_QT(char *pkg)
{
	int	ret = 1;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_QT: %s\n", pkg);
#endif

	if (strcmp("init", pkg) == 0)
		ret = nt32_gdbrsp_qtinit();
	else if (strcmp("Stop", pkg) == 0)
		ret = nt32_gdbrsp_qtstop();
	else if (strcmp("Start", pkg) == 0)
		ret = nt32_gdbrsp_qtstart();
	else if (strncmp("DP:", pkg, 3) == 0)
		ret = nt32_gdbrsp_qtdp(pkg + 3);
	else if (strncmp("DPsrc:", pkg, 6) == 0)
		ret = nt32_gdbrsp_qtdpsrc(pkg + 6);
	else if (strncmp("Disconnected:", pkg, 13) == 0)
		ret = nt32_gdbrsp_qtdisconnected(pkg + 13);
	else if (strncmp("Buffer:", pkg, 7) == 0)
		ret = nt32_gdbrsp_qtbuffer(pkg + 7);
	else if (strncmp("framework:", pkg, 6) == 0)
		ret = nt32_gdbrsp_qtframework(pkg + 6);
	else if (strncmp("ro:", pkg, 3) == 0)
		ret = nt32_gdbrsp_qtro(pkg + 3);
	else if (strncmp("DV:", pkg, 3) == 0)
		ret = nt32_gdbrsp_qtdv(pkg + 3);

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_QT: return %d\n", ret);
#endif

	return ret;
}

static int
nt32_get_status(struct nt32_entry *tpe, char *buf, int bufmax)
{
	int			size = 0;
	int			tfnum = 0;
	CORE_ADDR		tmpaddr;

#ifdef NT32_RB
	if (NT32_RB_PAGE_IS_EMPTY) {
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
	if (!nt32_framework) {
#endif
		snprintf(buf, bufmax, "tnotrun:0;");
		buf += 10;
		size += 10;
		bufmax -= 10;
	} else if (!tpe || (tpe && tpe->reason == nt32_stop_normal)) {
		snprintf(buf, bufmax, "tstop:0;");
		buf += 8;
		size += 8;
		bufmax -= 8;
	} else {
		char	outtmp[100];

		switch (tpe->reason) {
		case nt32_stop_framework_full:
			snprintf(buf, bufmax, "tfull:%lx;",
				 (unsigned long)tpe->num);
			break;
		case nt32_stop_efault:
			snprintf(buf, bufmax, "terror:%s:%lx;",
				 string2hex("read memory false", outtmp),
				 (unsigned long)tpe->num);
			break;
		case nt32_stop_access_wrong_reg:
			snprintf(buf, bufmax, "terror:%s:%lx;",
				 string2hex("access wrong register", outtmp),
				 (unsigned long)tpe->num);
			break;
		case nt32_stop_agent_expr_code_error:
			snprintf(buf, bufmax, "terror:%s:%lx;",
				 string2hex("agent expression code error",
					    outtmp),
				 (unsigned long)tpe->num);
			break;
		case nt32_stop_agent_expr_stack_overflow:
			snprintf(buf, bufmax, "terror:%s:%lx;",
				string2hex("agent expression stack overflow",
					   outtmp),
				(unsigned long)tpe->num);
			break;
		default:
			buf[0] = '\0';
			break;
		}

		size += strlen(buf);
		bufmax -= strlen(buf);
		buf += strlen(buf);
	}

	if (atomic_read(&nt32_framework_create)) {
#ifdef NT32_framework_SIMPLE
		char	*tmp = nt32_framework_r_start;

		do {
			if (tmp == nt32_framework_end)
				tmp = nt32_framework;

			if (FID(tmp) == FID_HEAD)
				tfnum++;

			tmp = nt32_framework_next(tmp);
			if (!tmp)
				break;
		} while (tmp != nt32_framework_w_start);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		if (nt32_start) {
			/* XXX: It is just the number of entries.  */
			tfnum = (int)ring_buffer_entries(nt32_framework);
		} else {
			int	old_num = nt32_framework_current_num;
			int	cpu;

			nt32_framework_iter_reset();

			for_each_online_cpu(cpu) {
				char				*tmp;
				struct ring_buffer_event	*rbe;

				while (1) {
					rbe = ring_buffer_read
						(nt32_framework_iter[cpu], NULL);
					if (rbe == NULL)
						break;
					tmp = ring_buffer_event_data(rbe);
					if (FID(tmp) == FID_HEAD)
						tfnum++;
				}
			}

			if (old_num == -1)
				nt32_framework_iter_reset();
			else if (old_num >= 0) {
				nt32_framework_head_find_num(old_num);
				ring_buffer_read
					(nt32_framework_iter[nt32_framework_current_cpu],
					 NULL);
			}
		}
#endif
#ifdef NT32_RB
		int			cpu;
		struct nt32_rb_walk_s	rbws;

		rbws.flags = NT32_RB_WALK_PASS_PAGE | NT32_RB_WALK_CHECK_END;

		for_each_online_cpu(cpu) {
			struct nt32_rb_s	*rb
				= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
			void		*tmp;
			unsigned long	flags;

			NT32_RB_LOCK_IRQ(rb, flags);
			rbws.end = rb->w;
			tmp = rb->r;
			while (1) {
				tmp = nt32_rb_walk(&rbws, tmp);
				if (rbws.reason != nt32_rb_walk_new_entry)
					break;
				tfnum++;
				tmp += framework_ALIGN(NT32_framework_HEAD_SIZE);
			}
			NT32_RB_UNLOCK_IRQ(rb, flags);
		}
#endif
	}

	snprintf(buf, bufmax, "tframeworks:%x;", tfnum);
	size += strlen(buf);
	bufmax -= strlen(buf);
	buf += strlen(buf);

	snprintf(buf, bufmax, "tcreated:%x;", atomic_read(&nt32_framework_create));
	size += strlen(buf);
	bufmax -= strlen(buf);
	buf += strlen(buf);

#ifdef NT32_framework_SIMPLE
	snprintf(buf, bufmax, "tsize:%x;", NT32_framework_SIZE);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	if (nt32_framework)
		snprintf(buf, bufmax, "tsize:%lx;",
			 ring_buffer_size(nt32_framework));
	else
		snprintf(buf, bufmax, "tsize:%x;",
			 NT32_framework_SIZE * num_online_cpus());
#endif
#ifdef NT32_RB
	snprintf(buf, bufmax, "tsize:%lx;",
		 nt32_rb_page_count * NT32_RB_DATA_MAX * num_online_cpus());
#endif
	size += strlen(buf);
	bufmax -= strlen(buf);
	buf += strlen(buf);

#ifdef NT32_framework_SIMPLE
	spin_lock(&nt32_framework_lock);
	if (nt32_framework_is_circular)
		tmpaddr = 0;
	else
		tmpaddr = NT32_framework_SIZE - (nt32_framework_w_start - nt32_framework);
	spin_unlock(&nt32_framework_lock);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	/* XXX: Ftrace ring buffer don't have interface to get the size of free
	   buffer. */
	tmpaddr = 0;
#endif
#ifdef NT32_RB
	if (atomic_read(&nt32_framework_create)) {
		int			cpu;

		tmpaddr = 0;
		for_each_online_cpu(cpu) {
			struct nt32_rb_s	*rb
				= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
			void		*tmp;
			unsigned long	flags;

			NT32_RB_LOCK_IRQ(rb, flags);
			tmpaddr += NT32_RB_END(rb->w) - rb->w;
			for (tmp = NT32_RB_NEXT(rb->w);
			     NT32_RB_HEAD(tmp) != NT32_RB_HEAD(rb->r);
			     tmp = NT32_RB_NEXT(tmp))
				tmpaddr += NT32_RB_DATA_MAX;
			tmpaddr += rb->r - NT32_RB_DATA(rb->r);
			NT32_RB_UNLOCK_IRQ(rb, flags);
		}
	} else {
		tmpaddr = nt32_rb_page_count * NT32_RB_DATA_MAX
			  * num_online_cpus();
	}
#endif
	snprintf(buf, bufmax, "tfree:%lx;", (unsigned long)tmpaddr);
	size += strlen(buf);
	bufmax -= strlen(buf);
	buf += strlen(buf);

	snprintf(buf, bufmax, "circular:%x;", nt32_circular);
	size += strlen(buf);
	bufmax -= strlen(buf);
	buf += strlen(buf);

	snprintf(buf, bufmax, "disconn:%x", nt32_disconnected_tracing);
	size += strlen(buf);
	bufmax -= strlen(buf);
	buf += strlen(buf);

	return size;
}

static int
nt32_gdbrsp_qtstatus(void)
{
	struct nt32_entry	*tpe;
	int			tmp;

	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		if (tpe->reason != nt32_stop_normal)
			break;
	}

	if (nt32_start && tpe)	/* Tpe is stop, stop all tpes.  */
		nt32_gdbrsp_qtstop();

	snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "T%x;", nt32_start ? 1 : 0);
	nt32_rw_bufp += 3;
	nt32_rw_size += 3;

	tmp = nt32_get_status(tpe, nt32_rw_bufp, NT32_RW_BUFP_MAX);
	nt32_rw_bufp += tmp;
	nt32_rw_size += tmp;

	return 1;
}

#define NT32_REPORT_TRACEPOINT_MAX	(1 + 16 + 1 + 16 + 1 + 1 + 1 + \
					 20 + 1 + 16 + 1)

static void
nt32_report_tracepoint(struct nt32_entry *nt32, char *buf, int bufmax)
{
	snprintf(buf, bufmax, "T%lx:%lx:%c:%d:%lx", (unsigned long)nt32->num,
		 (unsigned long)nt32->addr, (nt32->disable ? 'D' : 'E'),
		 nt32->step, (unsigned long)nt32->pass);
}

static int
nt32_report_action_max(struct nt32_entry *nt32, struct action *action)
{
	return 1 + 16 + 1 + 16 + 1 + strlen(action->src) + 1;
}

static void
nt32_report_action(struct nt32_entry *nt32, struct action *action, char *buf,
		  int bufmax)
{
	snprintf(buf, bufmax, "A%lx:%lx:%s", (unsigned long)nt32->num,
		 (unsigned long)nt32->addr, action->src);
}

static int
nt32_report_src_max(struct nt32_entry *nt32, struct nt32src *src)
{
	return 1 + 16 + 1 + 16 + 1 + strlen(src->src) + 1;
}

static void
nt32_report_src(struct nt32_entry *nt32, struct nt32src *src, char *buf, int bufmax)
{
	snprintf(buf, bufmax, "Z%lx:%lx:%s", (unsigned long)nt32->num,
		 (unsigned long)nt32->addr, src->src);
}

static void
nt32_current_set_check(void)
{
	if (current_nt32_src == NULL)
		current_nt32 = current_nt32->next;
}

static void
nt32_current_action_check(void)
{
	if (current_nt32_action == NULL) {
		current_nt32_src = current_nt32->src;
		nt32_current_set_check();
	}
}

static int
nt32_gdbrsp_qtfp(void)
{
	if (nt32_list) {
		current_nt32 = nt32_list;
		nt32_report_tracepoint(current_nt32, nt32_rw_bufp,
				      NT32_RW_BUFP_MAX);
		nt32_rw_size += strlen(nt32_rw_bufp);
		nt32_rw_bufp += strlen(nt32_rw_bufp);
		current_nt32_action = current_nt32->action_list;
		nt32_current_action_check();
	} else {
		if (NT32_RW_BUFP_MAX > 1) {
			nt32_rw_bufp[0] = 'l';
			nt32_rw_size += 1;
			nt32_rw_bufp += 1;
		}
	}

	return 1;
}

static int
nt32_gdbrsp_qtsp(void)
{
	if (current_nt32_action) {
		nt32_report_action(current_nt32, current_nt32_action,
				  nt32_rw_bufp, NT32_RW_BUFP_MAX);
		nt32_rw_size += strlen(nt32_rw_bufp);
		nt32_rw_bufp += strlen(nt32_rw_bufp);
		current_nt32_action = current_nt32_action->next;
		nt32_current_action_check();
		goto out;
	}

	if (current_nt32_src) {
		nt32_report_src(current_nt32, current_nt32_src, nt32_rw_bufp,
			       NT32_RW_BUFP_MAX);
		nt32_rw_size += strlen(nt32_rw_bufp);
		nt32_rw_bufp += strlen(nt32_rw_bufp);
		current_nt32_src = current_nt32_src->next;
		nt32_current_set_check();
		goto out;
	}

	if (current_nt32) {
		nt32_report_tracepoint(current_nt32, nt32_rw_bufp,
				      NT32_RW_BUFP_MAX);
		nt32_rw_size += strlen(nt32_rw_bufp);
		nt32_rw_bufp += strlen(nt32_rw_bufp);
		current_nt32_action = current_nt32->action_list;
		nt32_current_action_check();
	} else {
		if (NT32_RW_BUFP_MAX > 1) {
			nt32_rw_bufp[0] = 'l';
			nt32_rw_size += 1;
			nt32_rw_bufp += 1;
		}
	}
out:
	return 1;
}

static void
nt32_report_var(void)
{
	snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "%x:%s", current_nt32_var->num,
		 current_nt32_var->src);
	nt32_rw_size += strlen(nt32_rw_bufp);
	nt32_rw_bufp += strlen(nt32_rw_bufp);
}

static int
nt32_gdbrsp_qtfsv(int f)
{
	if (f)
		current_nt32_var = nt32_var_list;

	if (current_nt32_var) {
		nt32_report_var();
		current_nt32_var = current_nt32_var->next;
	} else {
		if (NT32_RW_BUFP_MAX > 1) {
			nt32_rw_bufp[0] = 'l';
			nt32_rw_size += 1;
			nt32_rw_bufp += 1;
		}
	}

	return 1;
}

static int
nt32_gdbrsp_qtv(char *pkg)
{
	ULONGEST		num;
	struct nt32_var		*var = NULL;
	struct nt32_framework_var	*vr = NULL;
	uint64_t		val = 0;

	pkg = hex2ulongest(pkg, &num);

	if (num == NT32_VAR_CPU_NUMBER_ID) {
		val = (uint64_t)nt32_cpu_number;
		goto output_value;
	} else if (num == NT32_VAR_LAST_ERRNO_ID) {
		val = (uint64_t)nt32_start_last_errno;
		goto output_value;
	} else if (num == NT32_VAR_IGNORE_ERROR_ID) {
		val = (uint64_t)nt32_start_ignore_error;
		goto output_value;
	} else if (num == NT32_VAR_PIPE_TRACE_ID) {
		val = (uint64_t)nt32_pipe_trace;
		goto output_value;
	} else if (num == NT32_VAR_VERSION_ID) {
		val = (uint64_t)NT32_VERSION;
		goto output_value;
	}
#ifdef NT32_RB
	else if (num == NT32_VAR_NT32_RB_DISCARD_PAGE_NUMBER) {
		val = (uint64_t)atomic_read(&nt32_rb_discard_page_number);
		goto output_value;
	}
#endif

#ifdef NT32_framework_SIMPLE
	if (nt32_start || !nt32_framework_current) {
#elif defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (nt32_start || nt32_framework_current_num < 0) {
#endif
		if (num == NT32_VAR_CLOCK_ID) {
			val = (uint64_t)NT32_LOCAL_CLOCK;
			goto output_value;
#ifdef CONFIG_X86
		} else if (num == NT32_VAR_RDTSC_ID) {
			unsigned long long a;
			rdtscll(a);
			val = (uint64_t)a;
			goto output_value;
#endif
		} else if (num == NT32_VAR_XTIME_SEC_ID
			   || num == NT32_VAR_XTIME_NSEC_ID) {
			struct timespec	time;

			getnstimeofday(&time);
			if (num == NT32_VAR_XTIME_SEC_ID)
				val = (uint64_t)time.tv_sec;
			else
				val = (uint64_t)time.tv_nsec;

			goto output_value;
		}

		if (NT32_VAR_IS_SPECIAL(num))
			goto out;
		var = nt32_var_find(num);
		if (var == NULL)
			goto out;
#ifdef NT32_PERF_EVENTS
		if (var->ptid == pe_tv_val
		    || var->ptid == pe_tv_enabled
		    || var->ptid == pe_tv_running) {
			if (nt32_start)
				var->pts->val =
					perf_event_read_value(var->pts->event,
							&(var->pts->enabled),
							&(var->pts->running));
			switch (var->ptid) {
			case pe_tv_val:
				val = (uint64_t)(var->pts->val);
				break;
			case pe_tv_enabled:
				val = (uint64_t)(var->pts->enabled);
				break;
			case pe_tv_running:
				val = (uint64_t)(var->pts->running);
				break;
			default:
				break;
			}
			goto out;
		}
#endif
		val = var->val;
	} else {
#ifdef NT32_framework_SIMPLE
		char	*next;

		for (next = *(char **)(nt32_framework_current + FID_SIZE); next;
		     next = *(char **)(next + FID_SIZE)) {
			if (FID(next) == FID_VAR) {
				vr = (struct nt32_framework_var *)
				     (next + FID_SIZE + sizeof(char *));
				if (vr->num == (unsigned int)num)
					goto while_stop;
			}
		}
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		int				is_first = 1;
		struct ring_buffer_event	*rbe;
		char				*tmp;

		/* Handle $cpu_id and $clock.  */
		if (NT32_VAR_AUTO_TRACEV(num)) {
			if (num == NT32_VAR_CLOCK_ID)
				val = nt32_framework_current_clock;
			else if (num == NT32_VAR_CPU_ID)
				val = nt32_framework_current_cpu;
			goto output_value;
		}
re_find:
		while (1) {
			rbe = ring_buffer_iter_peek
				(nt32_framework_iter[nt32_framework_current_cpu], NULL);
			if (rbe == NULL)
				break;
			tmp = ring_buffer_event_data(rbe);
			if (FID(tmp) == FID_HEAD)
				break;
			if (FID(tmp) == FID_VAR) {
				vr = (struct nt32_framework_var *)(tmp + FID_SIZE);
				if (vr->num == (unsigned int)num)
					goto while_stop;
			}
			ring_buffer_read(nt32_framework_iter[nt32_framework_current_cpu],
					 NULL);
		}
		if (is_first) {
			nt32_framework_head_find_num(nt32_framework_current_num);
			ring_buffer_read(nt32_framework_iter[nt32_framework_current_cpu],
					 NULL);
			is_first = 0;
			goto re_find;
		}
#endif
#ifdef NT32_RB
		struct nt32_rb_walk_s	rbws;
		char			*tmp;

		/* Handle $cpu_id.  */
		if (NT32_VAR_AUTO_TRACEV(num)) {
			val = nt32_framework_current_rb->cpu;
			goto output_value;
		}

		rbws.flags = NT32_RB_WALK_PASS_PAGE | NT32_RB_WALK_CHECK_END
			     | NT32_RB_WALK_CHECK_ID | NT32_RB_WALK_CHECK_TYPE;
		rbws.end = nt32_framework_current_rb->w;
		rbws.id = nt32_framework_current_id;
		rbws.type = FID_VAR;
		tmp = nt32_framework_current_rb->rp;

		while (1) {
			tmp = nt32_rb_walk(&rbws, tmp);
			if (rbws.reason != nt32_rb_walk_type)
				break;

			vr = (struct nt32_framework_var *)(tmp + FID_SIZE);
			if (vr->num == (unsigned int)num)
				goto while_stop;

			tmp += framework_ALIGN(NT32_framework_VAR_SIZE);
		}
#endif
		vr = NULL;
while_stop:
		if (vr)
			val = vr->val;
	}

out:
	if (var || vr) {
output_value:
		snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "V%08x%08x",
			 (unsigned int) (val >> 32),
			 (unsigned int) (val & 0xffffffff));
		nt32_rw_size += strlen(nt32_rw_bufp);
		nt32_rw_bufp += strlen(nt32_rw_bufp);
	} else {
		if (NT32_RW_BUFP_MAX > 1) {
			nt32_rw_bufp[0] = 'U';
			nt32_rw_size += 1;
			nt32_rw_bufp += 1;
		}
	}

	return 1;
}

static int
nt32_gdbrsp_qT(char *pkg)
{
	int	ret = 1;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_qT: %s\n", pkg);
#endif

	if (strcmp("Status", pkg) == 0)
		ret = nt32_gdbrsp_qtstatus();
	else if (strcmp("fP", pkg) == 0)
		ret = nt32_gdbrsp_qtfp();
	else if (strcmp("sP", pkg) == 0)
		ret = nt32_gdbrsp_qtsp();
	else if (strcmp("fV", pkg) == 0)
		ret = nt32_gdbrsp_qtfsv(1);
	else if (strcmp("sV", pkg) == 0)
		ret = nt32_gdbrsp_qtfsv(0);
	else if (strncmp("V:", pkg, 2) == 0)
		ret = nt32_gdbrsp_qtv(pkg + 2);

	return ret;
}

#ifdef NT32_RB
static char		*nt32_traceframework_info;
static unsigned int	nt32_traceframework_info_len;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
/* The 2.6.30 and older version have __module_address.  */

static int		nt32_modules_traceframework_info_need_get;
static char		*nt32_modules_traceframework_info;
static unsigned int	nt32_modules_traceframework_info_len;

static int
nt32_modules_traceframework_info_get(void)
{
	struct module		*mod;
	struct nt32_realloc_s	grs;
	int			ret = 0;

	nt32_realloc_alloc(&grs, 0);

	if (nt32_modules_traceframework_info_len > 0) {
		vfree(nt32_modules_traceframework_info);
		nt32_modules_traceframework_info_len = 0;
	}

	mutex_lock(&module_mutex);
	list_for_each_entry_rcu(mod, &(THIS_MODULE->list), list) {
		if (__module_address((unsigned long)mod)) {
			char	buf[70];

			snprintf(buf, 70,
				 "<memory start=\"0x%llx\" length=\"0x%llx\"/>\n",
				 (ULONGEST)mod->module_core,
				 (ULONGEST)mod->core_text_size);
			ret = nt32_realloc_str(&grs, buf, 0);
			if (ret)
				goto out;
		}
	}
	nt32_modules_traceframework_info = grs.buf;
	nt32_modules_traceframework_info_len = grs.size;
out:
	mutex_unlock(&module_mutex);
	return ret;
}
#endif

static int
nt32_traceframework_info_get(void)
{
	struct nt32_realloc_s	grs;
	int			ret;
	struct nt32_rb_walk_s	rbws;
	char			*tmp;

	if (nt32_traceframework_info_len > 0) {
		vfree(nt32_traceframework_info);
		nt32_traceframework_info_len = 0;
	}
	/* 40 is size for "<traceframework-info>\n</traceframework-info>\n" */
	ret = nt32_realloc_alloc(&grs, 40);
	if (ret != 0)
		return ret;

	ret = nt32_realloc_str(&grs, "<traceframework-info>\n", 0);
	if (ret != 0)
		return ret;

	rbws.flags = NT32_RB_WALK_PASS_PAGE
			| NT32_RB_WALK_CHECK_END
			| NT32_RB_WALK_CHECK_ID
			| NT32_RB_WALK_CHECK_TYPE;
	rbws.end = nt32_framework_current_rb->w;
	rbws.id = nt32_framework_current_id;
	rbws.type = FID_MEM;
	tmp = nt32_framework_current_rb->rp;

	while (1) {
		struct nt32_framework_mem	*mr;
		char			buf[70];

		tmp = nt32_rb_walk(&rbws, tmp);
		if (rbws.reason != nt32_rb_walk_type)
			break;
		mr = (struct nt32_framework_mem *) (tmp + FID_SIZE);
		snprintf(buf, 70,
				"<memory start=\"0x%llx\" length=\"0x%llx\"/>\n",
				(ULONGEST)mr->addr, (ULONGEST)mr->size);
		ret = nt32_realloc_str(&grs, buf, 0);
		if (ret != 0)
			return ret;
		tmp += framework_ALIGN(NT32_framework_MEM_SIZE + mr->size);
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
	if (nt32_modules_traceframework_info_need_get) {
		int	ret = nt32_modules_traceframework_info_get();
		if (ret != 0)
			return ret;
		nt32_modules_traceframework_info_need_get = 0;
	}
	if (nt32_modules_traceframework_info_len > 0) {
		tmp = nt32_realloc(&grs, nt32_modules_traceframework_info_len, 0);
		if (tmp == NULL)
			return -ENOMEM;
		memcpy(tmp, nt32_modules_traceframework_info,
		       nt32_modules_traceframework_info_len);
	}
#endif

	ret = nt32_realloc_str(&grs, "</traceframework-info>\n", 1);
	if (ret != 0)
		return ret;

	nt32_traceframework_info = grs.buf;
	nt32_traceframework_info_len = grs.size;

	return 0;
}

static int
nt32_gdbrsp_qxfer_traceframework_info_read(char *pkg)
{
	ULONGEST	offset, len;

	if (nt32_start || nt32_framework_current_num < 0)
		return -EINVAL;

	pkg = hex2ulongest(pkg, &offset);
	if (pkg[0] != ',')
		return -EINVAL;
	pkg++;
	pkg = hex2ulongest(pkg, &len);
	if (len == 0)
		return -EINVAL;

	if (NT32_RW_BUFP_MAX < 10)
		return -EINVAL;

	if (offset == 0) {
		int	ret = nt32_traceframework_info_get();
		if (ret != 0)
			return ret;
	}

	if (len > NT32_RW_BUFP_MAX - 1)
		len = NT32_RW_BUFP_MAX - 1;

	if (len >= nt32_traceframework_info_len - offset) {
		len = nt32_traceframework_info_len - offset;
		nt32_rw_bufp[0] = 'l';
		nt32_rw_size += 1;
		nt32_rw_bufp += 1;
	} else {
		if (NT32_RW_BUFP_MAX > 1) {
			nt32_rw_bufp[0] = 'm';
			nt32_rw_size += 1;
			nt32_rw_bufp += 1;
		}
	}

	memcpy(nt32_rw_bufp, nt32_traceframework_info + offset, len);
	nt32_rw_size += len;
	nt32_rw_bufp += len;

	return 1;
}
#endif

static uint8_t	nt32_m_buffer[0xffff];

static int
nt32_gdbrsp_m(char *pkg)
{
	int		i;
	ULONGEST	addr, len;

	/* Get add and len.  */
	if (pkg[0] == '\0')
		return -EINVAL;
	pkg = hex2ulongest(pkg, &addr);
	if (pkg[0] != ',')
		return -EINVAL;
	pkg++;
	pkg = hex2ulongest(pkg, &len);
	if (len == 0)
		return -EINVAL;
	len &= 0xffff;
	len = (ULONGEST) min((int)(NT32_RW_BUFP_MAX / 2),
			     (int)len);

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_gdbrsp_m: addr = 0x%lx len = %d\n",
		(unsigned long) addr, (int) len);
#endif

#ifdef NT32_framework_SIMPLE
	if (nt32_start || !nt32_framework_current) {
#elif defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (nt32_start || nt32_framework_current_num < 0) {
#endif
		if (probe_kernel_read(nt32_m_buffer, (void *)(CORE_ADDR)addr,
					(size_t)len))
			return -EFAULT;
	} else {
#ifdef NT32_framework_SIMPLE
		char	*next;
#endif
		int	ret;

		/* XXX: Issue 1: The following part is for nt32ro support.
		   It is not available because it make disassemble cannot
		   work when select a trace framework. */
#if 0
		struct nt32ro_entry	*gtroe;

		memset(nt32_m_buffer, 0, len);

		/* Read the nt32ro.  */
		for (gtroe = nt32ro_list; gtroe; gtroe = gtroe->next) {
			CORE_ADDR	cur_start, cur_end;

			cur_start = max(gtroe->start, (CORE_ADDR)addr);
			cur_end = min(gtroe->end, ((CORE_ADDR)(addr + len)));
			if (cur_start < cur_end) {
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_m: ro read "
						 "start = 0x%lx end = 0x%lx\n",
				       (unsigned long) cur_start,
				       (unsigned long) cur_end);
#endif
				if (probe_kernel_read(nt32_m_buffer,
						       (void *)cur_start,
						       (size_t)(cur_end
								- cur_start)))
					return -EFAULT;
			}
		}
#endif
		ret = probe_kernel_read(nt32_m_buffer, (void *)(CORE_ADDR)addr,
					(size_t)len);
#ifdef NT32_framework_SIMPLE
		for (next = *(char **)(nt32_framework_current + FID_SIZE); next;
		     next = *(char **)(next + FID_SIZE)) {
			if (FID(next) == FID_MEM) {
				struct nt32_framework_mem	*mr;
				ULONGEST		cur_start, cur_end;
				uint8_t			*buf;

				mr = (struct nt32_framework_mem *)
				     (next + FID_SIZE + sizeof(char *));
				buf = next + NT32_framework_MEM_SIZE;
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_m: section "
						 "addr = 0x%lx size = %lu\n",
				       (unsigned long) mr->addr,
				       (unsigned long) mr->size);
#endif
				cur_start = max(((ULONGEST)mr->addr), addr);
				cur_end = min(((ULONGEST)mr->addr
						+ mr->size),
					       (addr + len));
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_m: read "
						 "start = 0x%lx end = 0x%lx\n",
				       (unsigned long) cur_start,
				       (unsigned long) cur_end);
#endif
				if (cur_start < cur_end) {
					memcpy(nt32_m_buffer,
						buf + cur_start - mr->addr,
						cur_end - cur_start);
					ret = 0;
				}
			}
		}
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		nt32_framework_head_find_num(nt32_framework_current_num);
		ring_buffer_read(nt32_framework_iter[nt32_framework_current_cpu], NULL);

		while (1) {
			struct ring_buffer_event	*rbe;
			char				*tmp;

			rbe = ring_buffer_iter_peek
				(nt32_framework_iter[nt32_framework_current_cpu], NULL);
			if (rbe == NULL)
				break;
			tmp = ring_buffer_event_data(rbe);
			if (FID(tmp) == FID_HEAD)
				break;
			if (FID(tmp) == FID_MEM) {
				struct nt32_framework_mem	*mr;
				ULONGEST		cur_start, cur_end;
				uint8_t			*buf;

				mr = (struct nt32_framework_mem *)
				     (tmp + FID_SIZE);
				buf = tmp + NT32_framework_MEM_SIZE;
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_m: section "
						 "addr = 0x%lx size = %lu\n",
				       (unsigned long) mr->addr,
				       (unsigned long) mr->size);
#endif
				cur_start = max(((ULONGEST)mr->addr), addr);
				cur_end = min(((ULONGEST)mr->addr
						+ mr->size),
					       (addr + len));
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_m: read "
						 "start = 0x%lx end = 0x%lx\n",
				       (unsigned long) cur_start,
				       (unsigned long) cur_end);
#endif
				if (cur_start < cur_end) {
					memcpy(nt32_m_buffer,
						buf + cur_start - mr->addr,
						cur_end - cur_start);
					ret = 0;
				}
			}
			ring_buffer_read(nt32_framework_iter[nt32_framework_current_cpu],
					 NULL);
		}
#endif
#ifdef NT32_RB
		{
			struct nt32_rb_walk_s	rbws;
			char			*tmp;

			rbws.flags = NT32_RB_WALK_PASS_PAGE
				     | NT32_RB_WALK_CHECK_END
				     | NT32_RB_WALK_CHECK_ID
				     | NT32_RB_WALK_CHECK_TYPE;
			rbws.end = nt32_framework_current_rb->w;
			rbws.id = nt32_framework_current_id;
			rbws.type = FID_MEM;
			tmp = nt32_framework_current_rb->rp;

			while (1) {
				struct nt32_framework_mem	*mr;
				ULONGEST		cur_start, cur_end;
				uint8_t			*buf;

				tmp = nt32_rb_walk(&rbws, tmp);
				if (rbws.reason != nt32_rb_walk_type)
					break;

				mr = (struct nt32_framework_mem *) (tmp + FID_SIZE);
				buf = tmp + NT32_framework_MEM_SIZE;
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_m: section "
						 "addr = 0x%lx size = %lu\n",
				       (unsigned long) mr->addr,
				       (unsigned long) mr->size);
#endif
				cur_start = max(((ULONGEST)mr->addr), addr);
				cur_end = min(((ULONGEST)mr->addr
						+ mr->size),
					       (addr + len));
#ifdef NT32_DEBUG
				printk(NT32_DEBUG "nt32_gdbrsp_m: read "
						 "start = 0x%lx end = 0x%lx\n",
				       (unsigned long) cur_start,
				       (unsigned long) cur_end);
#endif
				if (cur_start < cur_end) {
					memcpy(nt32_m_buffer,
						buf + cur_start - mr->addr,
						cur_end - cur_start);
					ret = 0;
				}

				tmp += framework_ALIGN(NT32_framework_MEM_SIZE
						   + mr->size);
			}
		}
#endif
		if (ret)
			return -EFAULT;
	}

	for (i = 0; i < (int)len; i++) {
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32_gdbrsp_m: %d %02x\n", i, nt32_m_buffer[i]);
#endif
		sprintf(nt32_rw_bufp, "%02x", nt32_m_buffer[i]);
		nt32_rw_bufp += 2;
		nt32_rw_size += 2;
	}

	return 1;
}

static int
nt32_gdbrsp_g(void)
{
#ifdef NT32_framework_SIMPLE
	char		*next;
#endif
	struct pt_regs	*regs;

	if (NT32_RW_BUFP_MAX < NT32_REG_ASCII_SIZE)
		return -E2BIG;

#ifdef NT32_framework_SIMPLE
	if (nt32_start || !nt32_framework_current) {
#elif defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (nt32_start || nt32_framework_current_num < 0) {
#endif
		memset(nt32_rw_bufp, '0', NT32_REG_ASCII_SIZE);
		goto out;
	}

	/* Get the regs.  */
	regs = NULL;
#ifdef NT32_framework_SIMPLE
	for (next = *(char **)(nt32_framework_current + FID_SIZE); next;
	     next = *(char **)(next + FID_SIZE)) {
		if (FID(next) == FID_REG) {
			regs = (struct pt_regs *)
			       (next + FID_SIZE + sizeof(char *));
			break;
		}
	}
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	{
		int				is_first = 1;
		struct ring_buffer_event	*rbe;
		char				*tmp;

re_find:
		while (1) {
			rbe = ring_buffer_iter_peek
				(nt32_framework_iter[nt32_framework_current_cpu], NULL);
			if (rbe == NULL)
				break;
			tmp = ring_buffer_event_data(rbe);
			if (FID(tmp) == FID_HEAD)
				break;
			if (FID(tmp) == FID_REG) {
				regs = (struct pt_regs *)(tmp + FID_SIZE);
				is_first = 0;
				break;
			}
			ring_buffer_read(nt32_framework_iter[nt32_framework_current_cpu],
					 NULL);
		}
		if (is_first) {
			nt32_framework_head_find_num(nt32_framework_current_num);
			ring_buffer_read(nt32_framework_iter[nt32_framework_current_cpu],
					 NULL);
			is_first = 0;
			goto re_find;
		}
	}
#endif
#ifdef NT32_RB
	{
		struct nt32_rb_walk_s	rbws;
		char			*tmp;

		rbws.flags = NT32_RB_WALK_PASS_PAGE | NT32_RB_WALK_CHECK_END
			     | NT32_RB_WALK_CHECK_ID | NT32_RB_WALK_CHECK_TYPE;
		rbws.end = nt32_framework_current_rb->w;
		rbws.id = nt32_framework_current_id;
		rbws.type = FID_REG;
		tmp = nt32_rb_walk(&rbws, nt32_framework_current_rb->rp);
		if (rbws.reason == nt32_rb_walk_type)
			regs = (struct pt_regs *)(tmp + FID_SIZE);
	}
#endif
	if (regs)
		nt32_regs2ascii(regs, nt32_rw_bufp);
	else {
		struct pt_regs		pregs;
		struct nt32_entry	*tpe;

		memset(&pregs, '\0', sizeof(struct pt_regs));
		tpe = nt32_list_find_without_addr(nt32_framework_current_tpe);
		if (tpe)
			NT32_REGS_PC(&pregs) = (unsigned long)tpe->addr;
		nt32_regs2ascii(&pregs, nt32_rw_bufp);
	}
out:
	nt32_rw_bufp += NT32_REG_ASCII_SIZE;
	nt32_rw_size += NT32_REG_ASCII_SIZE;

	return 1;
}

static DEFINE_SEMAPHORE(nt32_rw_lock);
static DECLARE_WAIT_QUEUE_HEAD(nt32_rw_wq);
static unsigned int	nt32_rw_count;
static unsigned int	nt32_framework_count;

static void
nt32_framework_count_release(void)
{
	nt32_framework_count--;
	if (nt32_framework_count == 0) {
		if (!nt32_disconnected_tracing) {
			nt32_gdbrsp_qtstop();
			nt32_gdbrsp_qtinit();
#ifdef NT32_RB
			if (!NT32_RB_PAGE_IS_EMPTY)
				nt32_rb_page_free();
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
			if (nt32_framework) {
#ifdef NT32_framework_SIMPLE
				vfree(nt32_framework);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
				ring_buffer_free(nt32_framework);
#endif
				nt32_framework = NULL;
			}
#endif
		}
	}
}

static int
nt32_open(struct inode *inode, struct file *file)
{
	int	ret = 0;

	down(&nt32_rw_lock);
	if (nt32_nt32_pid >= 0) {
		if (get_current()->pid != nt32_nt32_pid) {
			ret = -EBUSY;
			goto out;
		}
	}

	if (nt32_rw_count == 0) {
		nt32_read_ack = 0;
		nt32_rw_buf = vmalloc(NT32_RW_MAX);
		if (!nt32_rw_buf) {
			ret = -ENOMEM;
			goto out;
		}
	}
	nt32_rw_count++;

	nt32_framework_count++;

	nt32_nt32_pid_count++;
	if (nt32_nt32_pid < 0)
		nt32_nt32_pid = get_current()->pid;

out:
	up(&nt32_rw_lock);
	return ret;
}

static int
nt32_release(struct inode *inode, struct file *file)
{
#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_release\n");
#endif

	down(&nt32_rw_lock);
	nt32_rw_count--;
	if (nt32_rw_count == 0)
		vfree(nt32_rw_buf);

	nt32_framework_count_release();

	nt32_nt32_pid_count--;
	if (nt32_nt32_pid_count == 0)
		nt32_nt32_pid = -1;

	up(&nt32_rw_lock);

	return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
static int
nt32_ioctl(struct inode *inode, struct file *file,
	  unsigned int cmd, unsigned long arg)
{
#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_ioctl: %x\n", cmd);
#endif

	return 0;
}
#else
static long
nt32_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_ioctl: %x\n", cmd);
#endif

	return 0;
}
#endif

static ssize_t
nt32_write(struct file *file, const char __user *buf, size_t size,
	  loff_t *ppos)
{
	char		*rsppkg = NULL;
	int		i, ret;
	unsigned char	csum = 0;

	if (down_interruptible(&nt32_rw_lock))
		return -EINTR;

	if (size == 0) {
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32_write: try write 0 size.\n");
#endif
		goto error_out;
	}

	size = min_t(size_t, size, NT32_RW_MAX);
	if (copy_from_user(nt32_rw_buf, buf, size)) {
		size = -EFAULT;
		goto error_out;
	}

	if (nt32_rw_buf[0] == '+' || nt32_rw_buf[0] == '-'
	    || nt32_rw_buf[0] == '\3') {
		if (nt32_rw_buf[0] == '+')
			nt32_rw_size = 0;
		size = 1;
		goto out;
	}

	if (size < 4) {
		nt32_read_ack = '-';
		goto out;
	}
	/* Check format and crc and get the rsppkg.  */
	for (i = 0; i < size - 2; i++) {
		if (rsppkg == NULL) {
			if (nt32_rw_buf[i] == '$')
				rsppkg = nt32_rw_buf + i + 1;
		} else {
			if (nt32_rw_buf[i] == '#')
				break;
			else
				csum += nt32_rw_buf[i];
		}
	}
	if (rsppkg && nt32_rw_buf[i] == '#') {
		/* Format is OK.  Check crc.  */
		int		c1, c2;

		nt32_rw_buf[i] = '\0';

		if (!hex2int(nt32_rw_buf[i+1], &c1)
		    || !hex2int(nt32_rw_buf[i+2], &c2)
		    || csum != (c1 << 4) + c2) {
#ifdef NT32_DEBUG
			printk(NT32_DEBUG "nt32_write: crc error\n");
#endif
			nt32_read_ack = '-';
			goto out;
		}
	} else {
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32_write: format error\n");
#endif
		nt32_read_ack = '-';
		goto out;
	}
	nt32_read_ack = '+';
	size = i + 3;

	wake_up_interruptible_nr(&nt32_rw_wq, 1);

	up(&nt32_rw_lock);
	if (down_interruptible(&nt32_rw_lock))
		return -EINTR;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_write: %s\n", rsppkg);
#endif

	/* Handle rsppkg and put return to nt32_rw_buf.  */
	nt32_rw_buf[0] = '$';
	nt32_rw_bufp = nt32_rw_buf + 1;
	nt32_rw_size = 0;
	ret = 1;
	switch (rsppkg[0]) {
	case '?':
		snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "S05");
		nt32_rw_bufp += 3;
		nt32_rw_size += 3;
		break;
	case 'g':
		ret = nt32_gdbrsp_g();
		break;
	case 'm':
		ret = nt32_gdbrsp_m(rsppkg + 1);
		break;
	case 'Q':
		if (rsppkg[1] == 'T')
			ret = nt32_gdbrsp_QT(rsppkg + 2);
		break;
	case 'q':
		if (rsppkg[1] == 'T')
			ret = nt32_gdbrsp_qT(rsppkg + 2);
		else if (strncmp("qSupported", rsppkg, 10) == 0) {
#ifdef NT32_RB
			snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX,
				 "ConditionalTracepoints+;"
				 "TracepointSource+;DisconnectedTracing+;"
				 "qXfer:traceframework-info:read+;");
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
			snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX,
				 "ConditionalTracepoints+;"
				 "TracepointSource+;DisconnectedTracing+;");
#endif
			nt32_rw_size += strlen(nt32_rw_bufp);
			nt32_rw_bufp += strlen(nt32_rw_bufp);
			ret = 1;
		}
#ifdef NT32_RB
		else if (strncmp("qXfer:traceframework-info:read::",
				   rsppkg, 28) == 0)
			ret = nt32_gdbrsp_qxfer_traceframework_info_read(rsppkg
								    + 28);
#endif
		break;
	case 's':
	case 'S':
	case 'c':
	case 'C':
		ret = -1;
		break;
	}
	if (ret == 0) {
		snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "OK");
		nt32_rw_bufp += 2;
		nt32_rw_size += 2;
	} else if (ret < 0) {
		snprintf(nt32_rw_bufp, NT32_RW_BUFP_MAX, "E%02x", -ret);
		nt32_rw_bufp += 3;
		nt32_rw_size += 3;
	}

	nt32_rw_bufp[0] = '#';
	csum = 0;
	for (i = 1; i < nt32_rw_size + 1; i++)
		csum += nt32_rw_buf[i];
	nt32_rw_bufp[1] = INT2CHAR(csum >> 4);
	nt32_rw_bufp[2] = INT2CHAR(csum & 0x0f);
	nt32_rw_bufp = nt32_rw_buf;
	nt32_rw_size += 4;

out:
	wake_up_interruptible_nr(&nt32_rw_wq, 1);
error_out:
	up(&nt32_rw_lock);
	return size;
}

static ssize_t
nt32_read(struct file *file, char __user *buf, size_t size,
	 loff_t *ppos)
{
	int	err;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_read\n");
#endif

	if (size == 0)
		goto out;

	if (down_interruptible(&nt32_rw_lock))
		return -EINTR;

	if (nt32_read_ack) {
		err = put_user(nt32_read_ack, buf);
		if (err) {
			size = -err;
			goto out;
		}
		nt32_read_ack = 0;
		size = 1;
		goto out;
	}

	size = min(nt32_rw_size, size);
	if (size == 0)
		goto out;
	if (copy_to_user(buf, nt32_rw_bufp, size)) {
		size = -EFAULT;
		goto out;
	}
	nt32_rw_bufp += size;
	nt32_rw_size -= size;

out:
	up(&nt32_rw_lock);
	return size;
}

static unsigned int
nt32_poll(struct file *file, poll_table *wait)
{
	unsigned int	mask = POLLOUT | POLLWRNORM;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32_poll\n");
#endif

	down(&nt32_rw_lock);
	poll_wait(file, &nt32_rw_wq, wait);
	if (nt32_read_ack || nt32_rw_size)
		mask |= POLLIN | POLLRDNORM;
	up(&nt32_rw_lock);

	return mask;
}

static int
nt32_framework2file_r(struct nt32_realloc_s *grs, uint32_t *data_size, char *framework)
{
	char	*wbuf;

	wbuf = nt32_realloc(grs, NT32_REG_BIN_SIZE + 1, 0);
	if (!wbuf)
		return -1;

	wbuf[0] = 'R';
#ifdef NT32_framework_SIMPLE
	nt32_regs2bin((struct pt_regs *)(framework + FID_SIZE + sizeof(char *)),
		     wbuf + 1);
#endif
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	nt32_regs2bin((struct pt_regs *)(framework + FID_SIZE), wbuf + 1);
#endif

	*data_size += NT32_REG_BIN_SIZE + 1;

	return 0;
}

static int
nt32_framework2file_m(struct nt32_realloc_s *grs, uint32_t *data_size, char *framework)
{
	struct nt32_framework_mem	*mr;
	uint8_t			*buf;
	ULONGEST		addr;
	size_t			remaining;

#ifdef NT32_framework_SIMPLE
	mr = (struct nt32_framework_mem *) (framework + FID_SIZE + sizeof(char *));
#endif
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	mr = (struct nt32_framework_mem *) (framework + FID_SIZE);
#endif
	buf = framework + NT32_framework_MEM_SIZE;
	addr = mr->addr;
	remaining = mr->size;

	while (remaining > 0) {
		uint16_t	blocklen;
		char		*wbuf;
		size_t		sp;

		blocklen = remaining > 65535 ? 65535 : remaining;

		sp = 1 + sizeof(addr) + sizeof(blocklen) + blocklen;
		wbuf = nt32_realloc(grs, sp, 0);
		if (!wbuf)
			return -1;

		wbuf[0] = 'M';
		wbuf += 1;

		memcpy(wbuf, &addr, sizeof(addr));
		wbuf += sizeof(addr);

		memcpy(wbuf, &blocklen, sizeof(blocklen));
		wbuf += sizeof(blocklen);

		memcpy(wbuf, buf, blocklen);

		addr += blocklen;
		remaining -= blocklen;
		buf += blocklen;

		*data_size += sp;
	}

	return 0;
}

static int
nt32_framework2file_v(struct nt32_realloc_s *grs, uint32_t *data_size, char *framework)
{
	struct nt32_framework_var	*vr;
	size_t			sp = 1 + sizeof(unsigned int)
				     + sizeof(uint64_t);
	char			*wbuf;

	wbuf = nt32_realloc(grs, sp, 0);
	if (!wbuf)
		return -1;

#ifdef NT32_framework_SIMPLE
	vr = (struct nt32_framework_var *) (framework + FID_SIZE + sizeof(char *));
#endif
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	vr = (struct nt32_framework_var *) (framework + FID_SIZE);
#endif

	wbuf[0] = 'V';
	wbuf += 1;

	memcpy(wbuf, &vr->num, sizeof(unsigned int));
	wbuf += sizeof(unsigned int);

	memcpy(wbuf, &vr->val, sizeof(uint64_t));
	wbuf += sizeof(uint64_t);

	*data_size += sp;

	return 0;
}

static int
#ifdef NT32_framework_SIMPLE
nt32_framework2file(struct nt32_realloc_s *grs, char *framework)
#endif
#ifdef NT32_FTRACE_RING_BUFFER
nt32_framework2file(struct nt32_realloc_s *grs, int cpu)
#endif
#ifdef NT32_RB
/* nt32_framework_current_rb will step inside this function.  */
nt32_framework2file(struct nt32_realloc_s *grs)
#endif
{
	int16_t				*tmp16p;
	char				*next;
	char				*wbuf;
	uint32_t			data_size;
#ifdef NT32_FTRACE_RING_BUFFER
	struct ring_buffer_event	*rbe;
	u64				clock;
#endif
#ifdef NT32_RB
	struct nt32_rb_walk_s		rbws;
#endif

	/* Head.  */
	tmp16p = (int16_t *)nt32_realloc(grs, 2, 0);
	if (!tmp16p)
		return -1;
#ifdef NT32_framework_SIMPLE
	*tmp16p = (int16_t)*(ULONGEST *)(framework + FID_SIZE + sizeof(char *));
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	rbe = ring_buffer_read(nt32_framework_iter[cpu], &clock);
	if (rbe == NULL) {
		/* It will not happen, just for safe.  */
		return -1;
	}
	next = ring_buffer_event_data(rbe);
	*tmp16p = (int16_t)*(ULONGEST *)(next + FID_SIZE);
#endif
#ifdef NT32_RB
	*tmp16p = (int16_t)nt32_framework_current_tpe;
#endif
	/* This part is for the data_size.  */
	wbuf = nt32_realloc(grs, 4, 0);
	if (!wbuf)
		return -1;

	/* Body.  */
	data_size = 0;

#ifdef NT32_FTRACE_RING_BUFFER
	{
		/* Handle $cpu_id and $clock.  */
		struct nt32_framework_var	*vr;
		char			framework[NT32_framework_VAR_SIZE];

		vr = (struct nt32_framework_var *) (framework + FID_SIZE);
		vr->num = NT32_VAR_CLOCK_ID;
		vr->val = clock;
		if (nt32_framework2file_v(grs, &data_size, framework))
			return -1;
		vr->num = NT32_VAR_CPU_ID;
		vr->val = cpu;
		if (nt32_framework2file_v(grs, &data_size, framework))
			return -1;
	}
#endif

#ifdef NT32_RB
	{
		/* Handle $cpu_id.  */
		struct nt32_framework_var	*vr;
		char			tmp[NT32_framework_VAR_SIZE];

		vr = (struct nt32_framework_var *) (tmp + FID_SIZE);
		vr->num = NT32_VAR_CPU_ID;
		vr->val = nt32_framework_current_rb->cpu;
		if (nt32_framework2file_v(grs, &data_size, tmp))
			return -1;
	}
#endif

#ifdef NT32_framework_SIMPLE
	for (next = *(char **)(framework + FID_SIZE); next;
	     next = *(char **)(next + FID_SIZE)) {
#elif defined(NT32_FTRACE_RING_BUFFER)
	while (1) {
		rbe = ring_buffer_iter_peek(nt32_framework_iter[cpu], NULL);
		if (rbe == NULL)
			break;
		next = ring_buffer_event_data(rbe);
#endif
#ifdef NT32_RB
	rbws.flags = NT32_RB_WALK_PASS_PAGE | NT32_RB_WALK_CHECK_END
		     | NT32_RB_WALK_CHECK_ID | NT32_RB_WALK_STEP;
	rbws.end = nt32_framework_current_rb->w;
	rbws.id = nt32_framework_current_id;
	rbws.step = 0;
	next = nt32_rb_walk(&rbws, nt32_framework_current_rb->rp);
	rbws.step = 1;
	while (rbws.reason == nt32_rb_walk_step) {
#endif
		switch (FID(next)) {
		case FID_REG:
			if (nt32_framework2file_r(grs, &data_size, next))
				return -1;
			break;
		case FID_MEM:
			if (nt32_framework2file_m(grs, &data_size, next))
				return -1;
			break;
		case FID_VAR:
			if (nt32_framework2file_v(grs, &data_size, next))
				return -1;
			break;
#ifdef NT32_FTRACE_RING_BUFFER
		case FID_HEAD:
			goto out;
			break;
#endif
		}
#ifdef NT32_FTRACE_RING_BUFFER
		ring_buffer_read(nt32_framework_iter[cpu], NULL);
#endif
#ifdef NT32_RB
		next = nt32_rb_walk(&rbws, next);
#endif
	}

#ifdef NT32_FTRACE_RING_BUFFER
out:
#endif
#ifdef NT32_RB
	nt32_framework_current_rb->rp = next;
#endif
	/* Set the data_size.  */
	memcpy(grs->buf + grs->size - data_size - 4,
	       &data_size, 4);

	return 0;
}

static int
nt32_framework_file_header(struct nt32_realloc_s *grs, int is_end)
{
	char			*wbuf;
	struct nt32_entry	*tpe;
	struct nt32_var		*tvar;
	int			tmpsize;
	int			ret = -1;

	/* Head. */
	wbuf = nt32_realloc(grs, 8, 0);
	strcpy(wbuf, "\x7fTRACE0\n");

	/* BUG: will be a new value.  */
	wbuf = nt32_realloc(grs, 100, 0);
	if (!wbuf)
		goto out;
	snprintf(wbuf, 100, "R %x\n", NT32_REG_BIN_SIZE);
	nt32_realloc_sub_size(grs, 100 - strlen(wbuf));

	if (nt32_realloc_str(grs, "status 0;", 0))
		goto out;

	wbuf = nt32_realloc(grs, 300, 0);
	if (!wbuf)
		goto out;
	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		if (tpe->reason != nt32_stop_normal)
			break;
	}
	tmpsize = nt32_get_status(tpe, wbuf, 300);
	nt32_realloc_sub_size(grs, 300 - tmpsize);

	if (nt32_realloc_str(grs, "\n", 0))
		goto out;

	/* Tval. */
	for (tvar = nt32_var_list; tvar; tvar = tvar->next) {
		wbuf = nt32_realloc(grs, 200, 0);
		if (!wbuf)
			goto out;
		snprintf(wbuf, 200, "tsv %x:%s\n", tvar->num, tvar->src);
		nt32_realloc_sub_size(grs, 200 - strlen(wbuf));
	}

	/* Tracepoint.  */
	for (tpe = nt32_list; tpe; tpe = tpe->next) {
		struct action	*ae;
		struct nt32src	*src;

		/* Tpe.  */
		if (nt32_realloc_str(grs, "tp ", 0))
			goto out;
		wbuf = nt32_realloc(grs, NT32_REPORT_TRACEPOINT_MAX, 0);
		if (!wbuf)
			goto out;
		nt32_report_tracepoint(tpe, wbuf, NT32_REPORT_TRACEPOINT_MAX);
		nt32_realloc_sub_size(grs,
				     NT32_REPORT_TRACEPOINT_MAX - strlen(wbuf));
		if (nt32_realloc_str(grs, "\n", 0))
			goto out;
		/* Action.  */
		for (ae = tpe->action_list; ae; ae = ae->next) {
			if (nt32_realloc_str(grs, "tp ", 0))
				goto out;
			tmpsize = nt32_report_action_max(tpe, ae);
			wbuf = nt32_realloc(grs, tmpsize, 0);
			if (!wbuf)
				goto out;
			nt32_report_action(tpe, ae, wbuf, tmpsize);
			nt32_realloc_sub_size(grs, tmpsize - strlen(wbuf));
			if (nt32_realloc_str(grs, "\n", 0))
				goto out;
		}
		/* Src.  */
		for (src = tpe->src; src; src = src->next) {
			if (nt32_realloc_str(grs, "tp ", 0))
				goto out;
			tmpsize = nt32_report_src_max(tpe, src);
			wbuf = nt32_realloc(grs, tmpsize, 0);
			if (!wbuf)
				goto out;
			nt32_report_src(tpe, src, wbuf, tmpsize);
			nt32_realloc_sub_size(grs, tmpsize - strlen(wbuf));
			if (nt32_realloc_str(grs, "\n", 0))
				goto out;
		}
	}

	if (nt32_realloc_str(grs, "\n", is_end))
		goto out;

	ret = 0;
out:
	return ret;
}

static ssize_t
nt32framework_read(struct file *file, char __user *buf, size_t size,
	      loff_t *ppos)
{
	ssize_t	ret = -ENOMEM;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	/* -2 means don't need set the framework back old number.  */
	int	old_num = -2;
#endif

recheck:
	down(&nt32_rw_lock);
	if (nt32_start) {
		up(&nt32_rw_lock);
		if (wait_event_interruptible(nt32framework_wq,
					     !nt32_start) == -ERESTARTSYS)
			return -EINTR;
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32framework_read: goto recheck\n");
#endif
		goto recheck;
	}

	/* Set nt32_framework_file if need.  */
	if (!nt32_framework_file) {
		char			*wbuf;
#ifdef NT32_framework_SIMPLE
		char			*framework;
#endif
		struct nt32_realloc_s	gr;

#ifdef NT32_framework_SIMPLE
		if (nt32_framework_is_circular)
			gr.real_size = NT32_framework_SIZE;
		else
			gr.real_size = nt32_framework_w_start - nt32_framework;
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		gr.real_size =
			ring_buffer_entries(nt32_framework) * NT32_framework_HEAD_SIZE;
#endif
#ifdef NT32_RB
		if (atomic_read(&nt32_framework_create) != 0) {
			int	cpu;

			for_each_online_cpu(cpu) {
				struct nt32_rb_s	*rb
				= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
				void		*tmp;
				unsigned long	flags;

				NT32_RB_LOCK_IRQ(rb, flags);
				gr.real_size = NT32_RB_END(rb->r) - rb->r;
				for (tmp = NT32_RB_NEXT(rb->r);
				     NT32_RB_HEAD(tmp) != NT32_RB_HEAD(rb->w);
				     tmp = NT32_RB_NEXT(tmp))
					gr.real_size += NT32_RB_DATA_MAX;
				gr.real_size += rb->w - NT32_RB_DATA(rb->w);
				NT32_RB_UNLOCK_IRQ(rb, flags);
			}
		}
#endif
		gr.real_size += 200;
		ret = nt32_realloc_alloc(&gr, gr.real_size);
		if (ret != 0)
			goto out;

		if (nt32_framework_file_header(&gr, 0))
			goto out;

		/* framework.  */
		if (atomic_read(&nt32_framework_create) == 0)
			goto end;
#ifdef NT32_framework_SIMPLE
		framework = nt32_framework_r_start;
		do {
			if (framework == nt32_framework_end)
				framework = nt32_framework;

			if (FID(framework) == FID_HEAD) {
				if (nt32_framework2file(&gr, framework))
					goto out;
			}

			framework = nt32_framework_next(framework);
			if (!framework)
				break;
		} while (framework != nt32_framework_w_start);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		old_num = nt32_framework_current_num;
		nt32_framework_iter_reset();
		while (1) {
			int	cpu;

			cpu = nt32_framework_iter_peek_head();
			if (cpu < 0)
				break;

			if (nt32_framework2file(&gr, cpu))
				goto out;
		}
#endif
#ifdef NT32_RB
		old_num = nt32_framework_current_num;
		nt32_rb_read_reset();
		while (1) {
			if (nt32_rb_read() != 0)
				break;
			nt32_framework2file(&gr);
		}
#endif

end:
		/* End.  */
		wbuf = nt32_realloc(&gr, 2, 1);
		if (!wbuf)
			goto out;
		wbuf[0] = '\0';
		wbuf[1] = '\0';

		nt32_framework_file = gr.buf;
		nt32_framework_file_size = gr.size;
	}

	/* Set buf.  */
	ret = size;
	if (*ppos + ret > nt32_framework_file_size) {
		ret = nt32_framework_file_size - *ppos;
		if (ret <= 0) {
			ret = 0;
			goto out;
		}
	}
	if (copy_to_user(buf, nt32_framework_file + *ppos, ret)) {
		size = -EFAULT;
		goto out;
	}
	*ppos += ret;

out:
#ifdef NT32_FTRACE_RING_BUFFER
	if (old_num == -1)
		nt32_framework_iter_reset();
	else if (old_num >= 0) {
		nt32_framework_head_find_num(old_num);
		ring_buffer_read(nt32_framework_iter[nt32_framework_current_cpu], NULL);
	}
#endif
#ifdef NT32_RB
	if (old_num == -1)
		nt32_rb_reset();
	else if (old_num >= 0)
		nt32_framework_head_find_num(old_num);
#endif
	up(&nt32_rw_lock);
	return ret;
}

static int
nt32framework_open(struct inode *inode, struct file *file)
{
recheck:
	down(&nt32_rw_lock);
#ifdef NT32_RB
	if (NT32_RB_PAGE_IS_EMPTY) {
#elif defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
	if (!nt32_framework) {
#endif
		up(&nt32_rw_lock);
#ifdef NT32_RB
		if (wait_event_interruptible(nt32framework_wq,
					     !NT32_RB_PAGE_IS_EMPTY)
		    == -ERESTARTSYS)
#elif defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
		if (wait_event_interruptible(nt32framework_wq,
					     nt32_framework) == -ERESTARTSYS)
#endif
			return -EINTR;
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32framework_open: goto recheck\n");
#endif
		goto recheck;
	}

	if (nt32_nt32framework_pipe_pid >= 0) {
		up(&nt32_rw_lock);
		return -EBUSY;
	}

	if (nt32_nt32framework_pid >= 0) {
		if (get_current()->pid != nt32_nt32framework_pid) {
			up(&nt32_rw_lock);
			return -EBUSY;
		}
	}

	nt32_framework_count++;

	nt32_nt32framework_pid_count++;
	if (nt32_nt32framework_pid < 0)
		nt32_nt32framework_pid = get_current()->pid;

	up(&nt32_rw_lock);
	return 0;
}

static int
nt32framework_release(struct inode *inode, struct file *file)
{
	down(&nt32_rw_lock);
	nt32_framework_count_release();

	nt32_nt32framework_pid_count--;
	if (nt32_nt32framework_pid_count == 0)
		nt32_nt32framework_pid = -1;
	up(&nt32_rw_lock);

	return 0;
}

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
struct nt32framework_pipe_s {
	loff_t			begin;
	struct nt32_realloc_s	*grs;
	int			llseek_move;
#ifdef NT32_RB
	void			**page;
	u64			*page_id;
#endif
};

static int
nt32framework_pipe_open(struct inode *inode, struct file *file)
{
	int			ret = -ENOMEM;
	struct nt32framework_pipe_s	*gps = NULL;

	down(&nt32_rw_lock);

	if (nt32_framework_current_num >= 0 || nt32_nt32framework_pipe_pid >= 0) {
		ret = -EBUSY;
		goto out;
	}
	nt32_nt32framework_pipe_pid = get_current()->pid;

recheck:
#ifdef NT32_RB
	if (NT32_RB_PAGE_IS_EMPTY) {
#elif defined(NT32_FTRACE_RING_BUFFER)
	if (!nt32_framework) {
#endif
		up(&nt32_rw_lock);
		atomic_inc(&nt32framework_pipe_wq_v);
#ifdef NT32_RB
		if (wait_event_interruptible(nt32framework_pipe_wq,
			!NT32_RB_PAGE_IS_EMPTY) == -ERESTARTSYS) {
#elif defined(NT32_FTRACE_RING_BUFFER)
		if (wait_event_interruptible(nt32framework_pipe_wq,
					     nt32_framework) == -ERESTARTSYS) {
#endif
			ret = -EINTR;
			goto out;
		}
#ifdef NT32_DEBUG
		printk(NT32_DEBUG "nt32framework_pipe_open: goto recheck\n");
#endif
		down(&nt32_rw_lock);
		goto recheck;
	}

	gps = kcalloc(1, sizeof(struct nt32framework_pipe_s), GFP_KERNEL);
	if (gps == NULL)
		goto out;
	gps->grs = kcalloc(1, sizeof(struct nt32_realloc_s), GFP_KERNEL);
	if (gps->grs == NULL)
		goto out;
#ifdef NT32_RB
	gps->page = kcalloc(nt32_cpu_number, sizeof(void *), GFP_KERNEL);
	if (gps->page == NULL)
		goto out;
	gps->page_id = kcalloc(nt32_cpu_number, sizeof(u64), GFP_KERNEL);
	if (gps->page_id == NULL)
		goto out;
#endif

	file->private_data = gps;

	nt32_framework_count++;

	ret = 0;
out:
	if (ret) {
		nt32_nt32framework_pipe_pid = -1;
		if (gps) {
			kfree(gps->grs);
#ifdef NT32_RB
			kfree(gps->page);
			kfree(gps->page_id);
#endif
			kfree(gps);
		}
	}
	up(&nt32_rw_lock);
	return ret;
}

static int
nt32framework_pipe_release(struct inode *inode, struct file *file)
{
	struct nt32framework_pipe_s	*gps = file->private_data;

	down(&nt32_rw_lock);
	nt32_framework_count_release();

	nt32_nt32framework_pipe_pid = -1;

	up(&nt32_rw_lock);

	if (gps) {
#ifdef NT32_RB
		int	cpu;

		for_each_online_cpu(cpu) {
			struct nt32_rb_s	*rb
				= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
			if (gps->page[cpu])
				nt32_rb_put_page(rb, gps->page[cpu], 0);
		}

		kfree(gps->page);
		kfree(gps->page_id);
#endif
		if (gps->grs) {
			if (gps->grs->buf)
				vfree(gps->grs->buf);
			kfree(gps->grs);
		}
		kfree(gps);
	}

	return 0;
}

#ifdef NT32_RB
static int
nt32framework_pipe_peek(struct nt32framework_pipe_s *gps)
{
	int			cpu;
	u64			min_id = ULLONG_MAX;
	int			ret = -1;
	struct nt32_rb_walk_s	rbws;

	rbws.flags = 0;

	for_each_online_cpu(cpu) {
		struct nt32_rb_s	*rb
			= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);

		if (gps->page_id[cpu] == 0) {
			/* Get new page.  */
			if (gps->page[cpu] == NULL) {
get_new_page:
				gps->page[cpu] = nt32_rb_get_page(rb);
				if (gps->page[cpu] == NULL)
					continue;
			}
			/* Get new entry.  */
			gps->page[cpu] = nt32_rb_walk(&rbws, gps->page[cpu]);
			if (rbws.reason != nt32_rb_walk_new_entry) {
				/* Put the page back and get a new page.  */
				nt32_rb_put_page(rb, gps->page[cpu], 1);
				goto get_new_page;
			}
			/* Get id.  */
			gps->page_id[cpu] = *(u64 *)(gps->page[cpu] + FID_SIZE);
		}

		if (gps->page_id[cpu] < min_id) {
			min_id = gps->page_id[cpu];
			ret = cpu;
		}
	}

	return ret;
}
#else
static int
nt32framework_pipe_peek(void)
{
	u64				min = 0;
	u64				ts;
	int				cpu;
	struct ring_buffer_event	*rbe;
	char				*next;
	int				ret = -1;

	for_each_online_cpu(cpu) {
		while (1) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)) \
    && !defined(NT32_SELF_RING_BUFFER)
			rbe = ring_buffer_peek(nt32_framework, cpu, &ts);
#else
			rbe = ring_buffer_peek(nt32_framework, cpu, &ts, NULL);
#endif
			if (rbe == NULL)
				break;
			next = ring_buffer_event_data(rbe);
			if (FID(next) == FID_HEAD)
				break;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)) \
    && !defined(NT32_SELF_RING_BUFFER)
			ring_buffer_consume(nt32_framework, cpu, &ts);
#else
			ring_buffer_consume(nt32_framework, cpu, &ts, NULL);
#endif
		}

		if (rbe) {
			if ((min && ts < min) || !min) {
				min = ts;
				ret = cpu;
			}
		}
	}

	return ret;
}
#endif

static int
#ifdef NT32_RB
nt32framework_pipe_get_entry(struct nt32framework_pipe_s *gps)
#endif
#ifdef NT32_FTRACE_RING_BUFFER
nt32framework_pipe_get_entry(struct nt32_realloc_s *grs)
#endif
{
	int				cpu;
	int16_t				*tmp16p;
	uint32_t			data_size;
#ifdef NT32_FTRACE_RING_BUFFER
	char				*next;
	struct ring_buffer_event	*rbe;
	u64				ts;
#endif

#ifdef NT32_RB
	struct nt32_rb_walk_s		rbws;
	struct nt32_realloc_s		*grs = gps->grs;
#endif
	/* Because this function only be called when nt32_realloc_is_empty,
	   so grs don't need reset. */

#ifdef NT32_RB
#define NT32_PIPE_PEEK	(cpu = nt32framework_pipe_peek(gps))
#endif
#ifdef NT32_FTRACE_RING_BUFFER
recheck:
#define NT32_PIPE_PEEK	(cpu = nt32framework_pipe_peek())
#endif
	NT32_PIPE_PEEK;
	if (cpu < 0) {
		/* Didn't get the buffer that have event.
		   Wait and recheck.*/
		atomic_inc(&nt32framework_pipe_wq_v);
		if (wait_event_interruptible(nt32framework_pipe_wq,
					     NT32_PIPE_PEEK >= 0)
			== -ERESTARTSYS)
			return -EINTR;
	}
#undef NT32_PIPE_PEEK

	/* Head.  */
#ifdef NT32_FTRACE_RING_BUFFER
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)) \
    && !defined(NT32_SELF_RING_BUFFER)
	rbe = ring_buffer_consume(nt32_framework, cpu, &ts);
#else
	rbe = ring_buffer_consume(nt32_framework, cpu, &ts, NULL);
#endif
	if (rbe == NULL)
		goto recheck;
	next = ring_buffer_event_data(rbe);
	if (FID(next) != FID_HEAD)
		goto recheck;
#endif
	tmp16p = (int16_t *)nt32_realloc(grs, 2, 0);
	if (!tmp16p)
		return -ENOMEM;
#ifdef NT32_RB
	*tmp16p = (int16_t)*(ULONGEST *)(gps->page[cpu] + FID_SIZE
					 + sizeof(u64));
	gps->page[cpu] += framework_ALIGN(NT32_framework_HEAD_SIZE);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	*tmp16p = (int16_t)*(ULONGEST *)(next + FID_SIZE);
#endif
	/* This part is for the data_size.  */
	if (nt32_realloc(grs, 4, 0) == NULL)
		return -ENOMEM;
	data_size = 0;

#ifdef NT32_RB
	{
		/* Handle $cpu_id.  */
		struct nt32_framework_var	*vr;
		char			framework[NT32_framework_VAR_SIZE];

		vr = (struct nt32_framework_var *) (framework + FID_SIZE);
		vr->num = NT32_VAR_CPU_ID;
		vr->val = cpu;
		if (nt32_framework2file_v(grs, &data_size, framework))
			return -ENOMEM;
	}
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	{
		/* Handle $cpu_id and $clock.  */
		struct nt32_framework_var	*vr;
		char			framework[NT32_framework_VAR_SIZE];

		vr = (struct nt32_framework_var *) (framework + FID_SIZE);
		vr->num = NT32_VAR_CLOCK_ID;
		vr->val = ts;
		if (nt32_framework2file_v(grs, &data_size, framework))
			return -ENOMEM;
		vr->num = NT32_VAR_CPU_ID;
		vr->val = cpu;
		if (nt32_framework2file_v(grs, &data_size, framework))
			return -ENOMEM;
	}
#endif

#ifdef NT32_RB
	rbws.flags = NT32_RB_WALK_CHECK_ID | NT32_RB_WALK_STEP;
	rbws.id = gps->page_id[cpu];
re_walk:
	rbws.step = 0;
	gps->page[cpu] = nt32_rb_walk(&rbws, gps->page[cpu]);
	rbws.step = 1;
	while (rbws.reason == nt32_rb_walk_step) {
		switch (FID(gps->page[cpu])) {
		case FID_REG:
			if (nt32_framework2file_r(grs, &data_size, gps->page[cpu]))
				return -ENOMEM;
			break;

		case FID_MEM:
			if (nt32_framework2file_m(grs, &data_size, gps->page[cpu]))
				return -ENOMEM;
			break;

		case FID_VAR:
			if (nt32_framework2file_v(grs, &data_size, gps->page[cpu]))
				return -ENOMEM;
			break;
		}
		gps->page[cpu] = nt32_rb_walk(&rbws, gps->page[cpu]);
	}
	if (rbws.reason == nt32_rb_walk_end_page
	    || rbws.reason == nt32_rb_walk_error) {
		/* Put this page back.  */
		nt32_rb_put_page((struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu),
				gps->page[cpu], 1);
		gps->page[cpu] = nt32_rb_get_page((struct nt32_rb_s *)per_cpu_ptr
							(nt32_rb, cpu));
		if (gps->page[cpu])
			goto re_walk;
	}
	gps->page_id[cpu] = 0;
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	while (1) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)) \
    && !defined(NT32_SELF_RING_BUFFER)
#define NT32_PIPE_CONSUME (rbe = ring_buffer_consume(nt32_framework, cpu, NULL))
#else
#define NT32_PIPE_CONSUME (rbe = ring_buffer_consume(nt32_framework, cpu, NULL, NULL))
#endif
		NT32_PIPE_CONSUME;
		if (rbe == NULL) {
			if (!nt32_start)
				break;

			atomic_inc(&nt32framework_pipe_wq_v);
			if (wait_event_interruptible(nt32framework_pipe_wq,
							NT32_PIPE_CONSUME
							!= NULL)
					== -ERESTARTSYS)
				return -EINTR;
			continue;
		}
#undef NT32_PIPE_CONSUME
		next = ring_buffer_event_data(rbe);
		switch (FID(next)) {
		case FID_REG:
			if (nt32_framework2file_r(grs, &data_size, next))
				return -ENOMEM;
			break;

		case FID_MEM:
			if (nt32_framework2file_m(grs, &data_size, next))
				return -ENOMEM;
			break;

		case FID_VAR:
			if (nt32_framework2file_v(grs, &data_size, next))
				return -ENOMEM;
			break;

		case FID_HEAD:
		case FID_END:
			goto while_out;
			break;
		}
	}
while_out:
#endif
	/* Set the data_size.  */
	memcpy(grs->buf + grs->size - data_size - 4, &data_size, 4);

	return 0;
}

static ssize_t
nt32framework_pipe_read(struct file *file, char __user *buf, size_t size,
		   loff_t *ppos)
{
	ssize_t			ret = -ENOMEM;
	struct nt32framework_pipe_s	*gps = file->private_data;
	loff_t			entry_offset;

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32framework_pipe_read: size=%u *ppos=%lld\n",
	       size, *ppos);
#endif

	if (!nt32_realloc_is_alloced(gps->grs)) {
		ret = nt32_realloc_alloc(gps->grs, 200);
		if (ret != 0)
			goto out;
	} else if (*ppos < gps->begin
		   || *ppos >= (gps->begin + gps->grs->size)) {
		nt32_realloc_reset(gps->grs);

		if (gps->llseek_move) {
			/* clear user will return NULL.
			   Then GDB tfind got a fail.  */
			if (size > 2)
				size = 2;
			if (clear_user(buf, size)) {
				ret = -EFAULT;
				goto out;
			}
			gps->begin = 0;
			gps->llseek_move = 0;
			ret = size;
			goto out;
		}
	}

	if (nt32_realloc_is_empty(gps->grs)) {
		if (*ppos == 0) {
			if (nt32_framework_file_header(gps->grs, 1))
				goto out;
#ifdef NT32_DEBUG
			printk(NT32_DEBUG "nt32framework_pipe_read: Get header.\n");
#endif
		} else {
#ifdef NT32_RB
			ret = nt32framework_pipe_get_entry(gps);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
			ret = nt32framework_pipe_get_entry(gps->grs);
#endif
			if (ret < 0)
				goto out;
#ifdef NT32_DEBUG
			printk(NT32_DEBUG "nt32framework_pipe_read: Get entry.\n");
#endif
		}
		gps->begin = *ppos;
	}

#ifdef NT32_DEBUG
	printk(NT32_DEBUG "nt32framework_pipe_read: gps->begin=%lld "
			 "gps->grs->size=%u\n",
	       gps->begin, gps->grs->size);
#endif

	entry_offset = *ppos - gps->begin;
	ret = size;
	if (entry_offset + size > gps->grs->size)
		ret = gps->grs->size - entry_offset;
	if (copy_to_user(buf, gps->grs->buf + entry_offset, ret)) {
		ret = -EFAULT;
		goto out;
	}
	*ppos += ret;

out:
	return ret;
}

static loff_t
nt32framework_pipe_llseek(struct file *file, loff_t offset, int origin)
{
	struct nt32framework_pipe_s	*gps = file->private_data;
	loff_t			ret = default_llseek(file, offset, origin);

	if (ret < 0)
		return ret;

	/* True means that GDB tfind to next framework entry.  */
	if (ret >= gps->begin + gps->grs->size && gps->begin)
		gps->llseek_move = 1;

	return ret;
}
#endif

static const struct file_operations nt32_operations = {
	.owner		= THIS_MODULE,
	.open		= nt32_open,
	.release	= nt32_release,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
	.ioctl		= nt32_ioctl,
#else
	.unlocked_ioctl	= nt32_ioctl,
	.compat_ioctl	= nt32_ioctl,
#endif
	.read		= nt32_read,
	.write		= nt32_write,
	.poll		= nt32_poll,
};

static const struct file_operations nt32framework_operations = {
	.owner		= THIS_MODULE,
	.open		= nt32framework_open,
	.release	= nt32framework_release,
	.read		= nt32framework_read,
	.llseek		= default_llseek,
};

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
static const struct file_operations nt32framework_pipe_operations = {
	.owner		= THIS_MODULE,
	.open		= nt32framework_pipe_open,
	.release	= nt32framework_pipe_release,
	.read		= nt32framework_pipe_read,
	.llseek		= nt32framework_pipe_llseek,
};
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
static int
nt32_modules_load_del_notify(struct notifier_block *self, unsigned long val,
			    void *data)
{
	if (val == MODULE_STATE_COMING)
		return 0;

	down(&nt32_rw_lock);
	nt32_modules_traceframework_info_need_get = 1;
	up(&nt32_rw_lock);

	return 0;
}

static struct notifier_block	nt32_modules_load_del_nb = {
	.notifier_call = nt32_modules_load_del_notify,
};
#endif

#ifndef USE_PROC
struct dentry	*nt32_dir;
struct dentry	*nt32framework_dir;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
struct dentry	*nt32framework_pipe_dir;
#endif
#endif

/* Initialize Notrace32 kernel module */
static int __init nt32_init(void)
{
	int		ret = -ENOMEM;

	nt32_nt32_pid = -1;
	nt32_nt32_pid_count = 0;
	nt32_nt32framework_pid = -1;
	nt32_nt32framework_pid_count = 0;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	nt32_nt32framework_pipe_pid = -1;
#endif
	nt32_list = NULL;
	nt32_read_ack = 0;
	nt32_rw_bufp = NULL;
	nt32_rw_size = 0;
	nt32_start = 0;
	nt32_disconnected_tracing = 0;
	nt32_circular = 0;
#if defined(NT32_FTRACE_RING_BUFFER)			\
    && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))	\
    && !defined(NT32_SELF_RING_BUFFER)
	nt32_circular_is_changed = 0;
#endif
	nt32_var_list = NT32_VAR_LIST_FIRST;
	nt32_var_head = NT32_VAR_SPECIAL_MIN;
	nt32_var_tail = NT32_VAR_SPECIAL_MAX;
	nt32_var_array = NULL;
	current_nt32_var = NULL;
#if defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
	nt32_framework = NULL;
#endif
	nt32_framework_current_num = -1;
	nt32_framework_current_tpe = 0;
#ifdef NT32_framework_SIMPLE
	nt32_framework_r_start = NULL;
	nt32_framework_w_start = NULL;
	nt32_framework_end = NULL;
	nt32_framework_current = NULL;
	nt32_framework_is_circular = 0;
#endif
#ifdef NT32_FTRACE_RING_BUFFER
	{
		int	cpu;

		for_each_online_cpu(cpu)
			nt32_framework_iter[cpu] = NULL;
	}
	nt32_framework_current_cpu = 0;
#endif
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	atomic_set(&nt32framework_pipe_wq_v, 0);
#endif
	atomic_set(&nt32_framework_create, 0);
	nt32_rw_count = 0;
	nt32_framework_count = 0;
	current_nt32 = NULL;
	current_nt32_action = NULL;
	current_nt32_src = NULL;
	nt32ro_list = NULL;
	nt32_framework_file = NULL;
	nt32_framework_file_size = 0;
#ifndef USE_PROC
	nt32_dir = NULL;
	nt32framework_dir = NULL;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	nt32framework_pipe_dir = NULL;
#endif
#endif
	{
		int	cpu;

		nt32_cpu_number = 0;
		for_each_online_cpu(cpu) {
			if (cpu > nt32_cpu_number)
				nt32_cpu_number = cpu;
		}
		nt32_cpu_number++;
	}
	nt32_start_last_errno = 0;
	nt32_start_ignore_error = 0;
	nt32_pipe_trace = 0;
#ifdef NT32_RB
	nt32_traceframework_info = NULL;
	nt32_traceframework_info_len = 0;
#endif

#ifdef NT32_RB
	ret = nt32_rb_init();
	if (ret != 0)
		goto out;
#endif
        /* Create kernel thread to provide tracepoint-based tracing */ 
	nt32_wq = create_singlethread_workqueue("nt32d");
	if (nt32_wq == NULL)
		goto out;
#ifdef USE_PROC
	if (proc_create("nt32", S_IFIFO | S_IRUSR | S_IWUSR, NULL,
			&nt32_operations) == NULL)
		goto out;
	if (proc_create("nt32framework", S_IFIFO | S_IRUSR, NULL,
			&nt32framework_operations) == NULL)
		goto out;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (proc_create("nt32framework_pipe", S_IFIFO | S_IRUSR, NULL,
			&nt32framework_pipe_operations) == NULL)
		goto out;
#endif
#else
	ret = -ENODEV;
	/* Create [nt32] debug file with DebugFS */ 
	nt32_dir = debugfs_create_file("nt32", S_IFIFO | S_IRUSR | S_IWUSR, NULL,
				      NULL, &nt32_operations);
	if (nt32_dir == NULL || nt32_dir == ERR_PTR(-ENODEV)) {
		nt32_dir = NULL;
		goto out;
	}
	/* Create [nt32framework] debug file with DebugFS */ 
	nt32framework_dir = debugfs_create_file("nt32framework", S_IFIFO | S_IRUSR, NULL,
					   NULL, &nt32framework_operations);
	if (nt32framework_dir == NULL || nt32framework_dir == ERR_PTR(-ENODEV)) {
		nt32framework_dir = NULL;
		goto out;
	}
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	/* Create [nt32framework_pipe] debug file with DebugFS */ 
	nt32framework_pipe_dir = debugfs_create_file("nt32framework_pipe",
						S_IFIFO | S_IRUSR, NULL, NULL,
						&nt32framework_pipe_operations);
	if (nt32framework_pipe_dir == NULL
	    || nt32framework_pipe_dir == ERR_PTR(-ENODEV)) {
		nt32framework_pipe_dir = NULL;
		goto out;
	}
#endif
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
	nt32_modules_traceframework_info_need_get = 1;
	nt32_modules_traceframework_info = NULL;
	nt32_modules_traceframework_info_len = 0;
	if (register_module_notifier(&nt32_modules_load_del_nb))
		goto out;
#endif

	ret = 0;
out:
	if (ret < 0) {
		if (nt32_wq)
			destroy_workqueue(nt32_wq);
#ifdef USE_PROC
		remove_proc_entry("nt32", NULL);
		remove_proc_entry("nt32framework", NULL);
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
		remove_proc_entry("nt32framework_pipe", NULL);
#endif
#else
		if (nt32_dir)
			debugfs_remove(nt32_dir);
		if (nt32framework_dir)
			debugfs_remove(nt32framework_dir);
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
		if (nt32framework_pipe_dir)
			debugfs_remove(nt32framework_pipe_dir);
#endif
#endif

#ifdef NT32_RB
		nt32_rb_release();
#endif
	}

	return ret;
}

static void __exit nt32_exit(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
	unregister_module_notifier(&nt32_modules_load_del_nb);
#endif

#ifdef USE_PROC
	remove_proc_entry("nt32", NULL);
	remove_proc_entry("nt32framework", NULL);
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	remove_proc_entry("nt32framework_pipe", NULL);
#endif
#else
	if (nt32_dir)
		debugfs_remove(nt32_dir);
	if (nt32framework_dir)
		debugfs_remove(nt32framework_dir);
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
	if (nt32framework_pipe_dir)
		debugfs_remove(nt32framework_pipe_dir);
#endif
#endif

	nt32_gdbrsp_qtstop();
	nt32_gdbrsp_qtinit();
#ifdef NT32_RB
	if (!NT32_RB_PAGE_IS_EMPTY)
		nt32_rb_page_free();
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
	if (nt32_framework) {
#ifdef NT32_framework_SIMPLE
		vfree(nt32_framework);
#endif
#ifdef NT32_FTRACE_RING_BUFFER
		ring_buffer_free(nt32_framework);
#endif
		nt32_framework = NULL;
	}
#endif

	destroy_workqueue(nt32_wq);

#ifdef NT32_RB
	nt32_rb_release();
#endif
}

module_init(nt32_init)
module_exit(nt32_exit)

MODULE_AUTHOR("NoTrace32");
MODULE_LICENSE("GPL");
