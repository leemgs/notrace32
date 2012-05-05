/* NT32_framework_SIZE must align with framework_ALIGN_SIZE if use NT32_framework_SIMPLE.  */
#define NT32_framework_SIZE		5242880
#if defined(NT32_framework_SIMPLE) || defined(NT32_RB)
#define framework_ALIGN_SIZE	sizeof(unsigned int)
#define framework_ALIGN(x)		((x + framework_ALIGN_SIZE - 1) \
				 & (~(framework_ALIGN_SIZE - 1)))
#endif
#ifdef NT32_framework_SIMPLE
#define NT32_framework_HEAD_SIZE	(FID_SIZE + sizeof(char *) + sizeof(ULONGEST))
#define NT32_framework_REG_SIZE	(FID_SIZE + sizeof(char *) \
				 + sizeof(struct pt_regs))
#define NT32_framework_MEM_SIZE	(FID_SIZE + sizeof(char *) \
				 + sizeof(struct nt32_framework_mem))
#define NT32_framework_VAR_SIZE	(FID_SIZE + sizeof(char *) \
				 + sizeof(struct nt32_framework_var))
#endif
#ifdef NT32_RB
#define NT32_framework_HEAD_SIZE	(FID_SIZE + sizeof(u64) + sizeof(ULONGEST))
#define NT32_framework_PAGE_BEGIN_SIZE	(FID_SIZE + sizeof(u64))
#endif
#ifdef NT32_FTRACE_RING_BUFFER
#define NT32_framework_HEAD_SIZE	(FID_SIZE + sizeof(ULONGEST))
#endif
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
#define NT32_framework_REG_SIZE	(FID_SIZE + sizeof(struct pt_regs))
#define NT32_framework_MEM_SIZE	(FID_SIZE + sizeof(struct nt32_framework_mem))
#define NT32_framework_VAR_SIZE	(FID_SIZE + sizeof(struct nt32_framework_var))
#endif

#define INT2CHAR(h)		((h) > 9 ? (h) + 'a' - 10 : (h) + '0')
