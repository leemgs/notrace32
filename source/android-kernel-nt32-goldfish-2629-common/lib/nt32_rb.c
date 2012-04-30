/*
 * @Name: Ring buffer for kernel-level GDB tracepoint module.
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
 * Copyright(C) NoTrace32 team (https://code.google.com/p/notrace32/), 2012
 *
 */

#define ADDR_SIZE			sizeof(size_t)
#define NT32_RB_HEAD(addr)	((void *)((size_t)(addr) & PAGE_MASK))
#define NT32_RB_DATA(addr)	(NT32_RB_HEAD(addr) + ADDR_SIZE)
#define NT32_RB_END(addr)	(NT32_RB_HEAD(addr) + PAGE_SIZE - ADDR_SIZE)
#define NT32_RB_PREV(addr)	(*(void **)NT32_RB_HEAD(addr))
#define NT32_RB_NEXT(addr)	(*(void **)NT32_RB_END(addr))
#define NT32_RB_DATA_MAX	(PAGE_SIZE - ADDR_SIZE - ADDR_SIZE - FID_SIZE \
					 - sizeof(u64))

/* nt32 data structure with ring-buffer */
struct nt32_rb_s {
	spinlock_t	lock;
	void		*w;
	void		*prev_w;
	void		*r;
	void		*rp;
	u64		rp_id;
	int		cpu;
};

static struct nt32_rb_s __percpu	*nt32_rb;

#if defined(CONFIG_ARM) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34))
static atomic_t		nt32_rb_count;
#else
static atomic64_t		nt32_rb_count;
#endif

static unsigned int		nt32_rb_page_count;
static atomic_t		nt32_rb_discard_page_number;

static int
nt32_rb_init(void)
{
	int	cpu;
	/* Recognize per-CPU architecure */ 
	nt32_rb = alloc_percpu(struct nt32_rb_s);
	if (!nt32_rb)
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		struct nt32_rb_s	*rb = (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
		memset(rb, 0, sizeof(struct nt32_rb_s));
		rb->lock = __SPIN_LOCK_UNLOCKED(rb->lock);
		rb->cpu = cpu;
	}

	nt32_rb_page_count = 0;
	atomic_set(&nt32_rb_discard_page_number, 0);

	return 0;
}
/* Free ring buffer entirely */
static void
nt32_rb_release(void)
{
	if (nt32_rb) {
		free_percpu(nt32_rb);
		nt32_rb = NULL;
	}
}

/* Reset ring buffer again */
static void
nt32_rb_reset(void)
{
	int	cpu;

	for_each_online_cpu(cpu) {
		struct nt32_rb_s	*rb
			= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
		rb->w = NT32_RB_DATA(rb->w);
		rb->r = rb->w;
		rb->rp = NULL;
		rb->rp_id = 0;
	}

/* Support atomic settings both X86 and ARM-32bit */
#if defined(CONFIG_ARM) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34))
	atomic_set(&nt32_rb_count, 0);
#else
	atomic64_set(&nt32_rb_count, 0);
#endif

	atomic_set(&nt32_rb_discard_page_number, 0);
}

/* ring buffer clock for atomic increment */
static inline u64
nt32_rb_clock(void)
{
#if defined(CONFIG_ARM) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34))
	return (u64)atomic_inc_return(&nt32_rb_count);
#else
	return atomic64_inc_return(&nt32_rb_count);
#endif
}

#define NT32_RB_PAGE_IS_EMPTY	(nt32_rb_page_count == 0)

/* Page allocation of ring buffer */
static int
nt32_rb_page_alloc(int size)
{
	int	cpu;

	for_each_online_cpu(cpu) {
		struct nt32_rb_s	*rb = (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
		void		*last = NULL, *next = NULL;
		struct page	*page;
		int		current_size;

		nt32_rb_page_count = 0;
		current_size = size;

		/* Seek current size untile there are not any page */ 
		while (1) {
			if (current_size > 0)
				current_size -= PAGE_SIZE;
			else
				break;

			/* Allocate pages of node */
			page = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL, 0);
			if (!page)
				return -1;
			nt32_rb_page_count++;
			rb->w = NT32_RB_DATA(page_address(page));
			NT32_RB_NEXT(rb->w) = next;
			if (next)
				NT32_RB_PREV(next) = rb->w;
			next = rb->w;
			if (!last)
				last = rb->w;
		}

		NT32_RB_NEXT(last) = next;
		NT32_RB_PREV(next) = last;
		rb->r = rb->w;

		if (nt32_rb_page_count < 3)
			return -1;
	}

	return 0;
}

/* Free ring buffer's page of per-cpu */
static void
nt32_rb_page_free(void)
{
	int	cpu;

	for_each_online_cpu(cpu) {
		struct nt32_rb_s	*rb = (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);
		void		*need_free = NULL;
		int		is_first = 1;

		for (rb->r = rb->w = NT32_RB_DATA(rb->w);
		     is_first || rb->w != rb->r;
		     rb->w = NT32_RB_NEXT(rb->w)) {
			if (need_free)
				free_page((unsigned long)need_free);
			need_free = NT32_RB_HEAD(rb->w);
			is_first = 0;
		}
		if (need_free)
			free_page((unsigned long)need_free);
	}

	nt32_rb_page_count = 0;
}

#define NT32_RB_LOCK(r)				spin_lock(&r->lock);
#define NT32_RB_UNLOCK(r)			spin_unlock(&r->lock);
#define NT32_RB_LOCK_IRQ(r, flags)		spin_lock_irqsave(&r->lock, flags);
#define NT32_RB_UNLOCK_IRQ(r, flags)	spin_unlock_irqrestore(&r->lock, flags);
#define NT32_RB_RELEASE(r)			(r->prev_w = r->w)

/* Allocation of rinb buffer using DEBUGFS */ 
static void *
nt32_rb_alloc(struct nt32_rb_s *rb, size_t size, u64 id)
{
	void		*ret;

	size = framework_ALIGN(size);

	if (size > NT32_RB_DATA_MAX) {
		printk(KERN_WARNING "nt32_rb_alloc: The size %zu is too big"
				    "for the NT32 ring buffer.  "
				    "The max size that NT32 ring buffer "
				    "support is %lu (Need sub some size for "
				    "inside structure).\n", size, NT32_RB_DATA_MAX);
		return NULL;
	}

	rb->prev_w = rb->w;

	if (rb->w + size > NT32_RB_END(rb->w)) {
		/* Don't have enough size in current page, insert a
		   FID_PAGE_END and try to get next page.  */
		if (NT32_RB_END(rb->w) - rb->w >= FID_SIZE)
			FID(rb->w) = FID_PAGE_END;

		if (NT32_RB_HEAD(NT32_RB_NEXT(rb->w)) == NT32_RB_HEAD(rb->r)) {
			if (nt32_circular) {
				rb->r = NT32_RB_NEXT(rb->r);
				atomic_inc(&nt32_rb_discard_page_number);
			} else
				return NULL;
		}
		rb->w = NT32_RB_NEXT(rb->w);

		if (id) {
			/* Need insert a FID_PAGE_BEGIN.  */
			FID(rb->w) = FID_PAGE_BEGIN;
			*((u64 *)(rb->w + FID_SIZE)) = id;
			rb->w += framework_ALIGN(NT32_framework_PAGE_BEGIN_SIZE);
		}
	}

	ret = rb->w;
	rb->w += size;

	return ret;
}

/* Assign enumeration data type for waling ring buffer */
enum  nt32_rb_walk_reason {
	nt32_rb_walk_end = 0,
	nt32_rb_walk_end_page,
	nt32_rb_walk_end_entry,
	nt32_rb_walk_new_entry,
	nt32_rb_walk_type,
	nt32_rb_walk_step,
	nt32_rb_walk_error,
};

/* Check *end.  */
#define NT32_RB_WALK_CHECK_END	0x1

/* When to the end of a page, goto next one.  */
#define NT32_RB_WALK_PASS_PAGE	0x2

/* When to the end of a entry, goto next one.  */
#define NT32_RB_WALK_PASS_ENTRY	0x4

/* Check with id and FID_PAGE_BEGIN to make sure this is the current framework. */
#define NT32_RB_WALK_CHECK_ID	0x8

/* Return ff type is same in buffer.  */
#define NT32_RB_WALK_CHECK_TYPE	0x10

/* Return ff type is same in buffer.  */
#define NT32_RB_WALK_STEP	0x20

struct nt32_rb_walk_s {
	unsigned int			flags;
	/* Reason for return.  */
	enum nt32_rb_walk_reason	reason;
	/* NT32_RB_WALK_CHECK_END */
	void					*end;
	/* NT32_RB_WALK_CHECK_ID */
	u64					id;
	/* NT32_RB_WALK_CHECK_TYPE */
	FID_TYPE				type;
	/* NT32_RB_WALK_STEP */
	int					step;
};

/* Walking(=seeking ) of ring-buffer */
static void *
nt32_rb_walk(struct nt32_rb_walk_s *s, void *ret)
{
	int	step;
	void	*page_end = NT32_RB_END(ret);

	if (s->flags & NT32_RB_WALK_STEP)
		step = 0;

	while (1) {
		FID_TYPE	fid;

		if ((s->flags & NT32_RB_WALK_CHECK_END) && ret == s->end) {
			s->reason = nt32_rb_walk_end;
			break;
		}

		if (ret == page_end || page_end - ret < FID_SIZE
		    || FID(ret) == FID_PAGE_END) {
			if (!(s->flags & NT32_RB_WALK_PASS_PAGE)) {
				s->reason = nt32_rb_walk_end_page;
				break;
			}
			ret = NT32_RB_NEXT(ret);
			page_end = NT32_RB_END(ret);
			continue;
		}

		fid = FID(ret);

		if ((s->flags & NT32_RB_WALK_CHECK_TYPE) && s->type == fid) {
			s->reason = nt32_rb_walk_type;
			break;
		}

		if ((s->flags & NT32_RB_WALK_STEP)
		    && (fid == FID_REG || fid == FID_MEM || fid == FID_VAR)) {
			if (step >= s->step) {
				s->reason = nt32_rb_walk_step;
				break;
			}
			step++;
		}

		switch (fid) {
		case FID_HEAD:
			if (!(s->flags & NT32_RB_WALK_PASS_ENTRY)) {
				s->reason = nt32_rb_walk_new_entry;
				goto out;
			}
			ret += framework_ALIGN(NT32_framework_HEAD_SIZE);
			break;
		case FID_REG:
			ret += framework_ALIGN(NT32_framework_REG_SIZE);
			break;
		case FID_MEM: {
				struct nt32_framework_mem	*gfm;

				gfm = (struct nt32_framework_mem *) (ret + FID_SIZE);
				ret += framework_ALIGN(NT32_framework_MEM_SIZE
						   + gfm->size);
			}
			break;
		case FID_VAR:
			ret += framework_ALIGN(NT32_framework_VAR_SIZE);
			break;
		case FID_PAGE_BEGIN:
			if ((s->flags & NT32_RB_WALK_CHECK_ID)
			    && s->id != *(u64 *)(ret + FID_SIZE)) {
				s->reason = nt32_rb_walk_end_entry;
				goto out;
			}
			ret += framework_ALIGN(NT32_framework_PAGE_BEGIN_SIZE);
			break;
		default:
			printk(KERN_WARNING
			       "Walk in nt32 ring buffer got error id 0x%x "
			       "in 0x%p.\n",
			       fid, ret);
			s->reason = nt32_rb_walk_error;
			goto out;
			break;
		}
	}

out:
	return ret;
}

static struct nt32_rb_s	*nt32_framework_current_rb;
static u64		nt32_framework_current_id;

/* Reset reading step of ring buffer */
static void
nt32_rb_read_reset(void)
{
	int	cpu;

	for_each_online_cpu(cpu) {
		struct nt32_rb_s	*rb
			= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);

		rb->rp = rb->r;
		rb->rp_id = 0;
	}
	nt32_framework_current_num = -1;
	nt32_framework_current_rb = NULL;
}

/* Read ring buffer */
static int
nt32_rb_read(void)
{
	int			cpu;
	u64			min_id = ULLONG_MAX;
	struct nt32_rb_walk_s	rbws;

	nt32_framework_current_rb = NULL;

	rbws.flags = NT32_RB_WALK_PASS_PAGE | NT32_RB_WALK_CHECK_END;

	for_each_online_cpu(cpu) {
		struct nt32_rb_s	*rb
			= (struct nt32_rb_s *)per_cpu_ptr(nt32_rb, cpu);

		if (rb->rp == NULL)
			rb->rp = rb->r;

		if (rb->rp_id == 0) {
			rbws.end = rb->w;
			rb->rp = nt32_rb_walk(&rbws, rb->rp);
			if (rbws.reason != nt32_rb_walk_new_entry)
				continue;
			rb->rp_id = *(u64 *)(rb->rp + FID_SIZE);
		}
		if (rb->rp_id < min_id) {
			min_id = rb->rp_id;
			nt32_framework_current_rb = rb;
		}
	}

	if (nt32_framework_current_rb == NULL) {
		nt32_rb_read_reset();
		return -1;
	}

	nt32_framework_current_rb->rp_id = 0;
	nt32_framework_current_id = *(u64 *)(nt32_framework_current_rb->rp + FID_SIZE);
	nt32_framework_current_tpe = *(ULONGEST *)(nt32_framework_current_rb->rp
					      + FID_SIZE + sizeof(u64));
	nt32_framework_current_rb->rp += framework_ALIGN(NT32_framework_HEAD_SIZE);

	nt32_framework_current_num += 1;

	return 0;
}

/* Get a page in ring buffer */
static void *
nt32_rb_get_page(struct nt32_rb_s *rb)
{
	void		*ret = NULL;
	unsigned long	flags;

	NT32_RB_LOCK_IRQ(rb, flags);

	if (NT32_RB_HEAD(rb->r) == NT32_RB_HEAD(rb->w)) {
		if (rb->r == rb->w)
			goto out;
		/* Move rb->w to next page.  */
		if (NT32_RB_END(rb->w) - rb->w >= FID_SIZE)
			FID(rb->w) = FID_PAGE_END;
		rb->w = NT32_RB_NEXT(rb->w);
	}

	ret = rb->r;
	{
		/* Move this page out of ring.  */
		void	*prev = NT32_RB_PREV(rb->r);
		void	*next = NT32_RB_NEXT(rb->r);

		NT32_RB_NEXT(prev) = next;
		NT32_RB_PREV(next) = prev;
		rb->r = next;
	}

out:
	NT32_RB_UNLOCK_IRQ(rb, flags);
	return ret;
}

/* Put a page in ring buffer */
static void
nt32_rb_put_page(struct nt32_rb_s *rb, void *page, int page_is_empty)
{
	void	*prev, *next;
	unsigned long	flags;

	NT32_RB_LOCK_IRQ(rb, flags);

	if (page_is_empty) {
		page = NT32_RB_DATA(page);
		if (rb->w == NT32_RB_DATA(rb->w)) {
			/* Set page before rb->w and set it as rb->w.
			   If need, set it as rb->r.  */
			prev = NT32_RB_PREV(rb->w);
			next = rb->w;
			if (rb->r == rb->w)
				rb->r = page;
			rb->w = page;
		} else {
			/* Set page after rb->w.  */
			prev = NT32_RB_DATA(rb->w);
			next = NT32_RB_NEXT(rb->w);
		}
	} else {
		if (rb->r == NT32_RB_DATA(rb->r)) {
			/* Current rb->r page is point to the begin of a page.
			   Set page before rb->r and set it as rb->r.  */
			prev = NT32_RB_PREV(rb->r);
			next = rb->r;
		} else {
			/* Current rb->r page isn't point to the begin of a
			   page, give up this data.
			   Set page after rb->r and set it as rb->r.  */
			prev = NT32_RB_DATA(rb->r);
			next = NT32_RB_NEXT(rb->r);
		}
		rb->r = page;
	}

	NT32_RB_NEXT(prev) = NT32_RB_DATA(page);
	NT32_RB_PREV(next) = NT32_RB_DATA(page);
	NT32_RB_PREV(page) = prev;
	NT32_RB_NEXT(page) = next;

	NT32_RB_UNLOCK_IRQ(rb, flags);
}
