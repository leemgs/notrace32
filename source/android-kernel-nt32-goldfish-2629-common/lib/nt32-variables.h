/* ---Head file for notrace32 varaibles including performance event: START ---- */
static DEFINE_SPINLOCK(nt32_var_lock);
static struct nt32_var	*nt32_var_list;
static unsigned int		nt32_var_head;
static unsigned int		nt32_var_tail;
static struct nt32_var	**nt32_var_array;
static struct nt32_var	*current_nt32_var;

enum {
	NT32_VAR_SPECIAL_MIN = 1,
	NT32_VAR_VERSION_ID = NT32_VAR_SPECIAL_MIN,
	NT32_VAR_CPU_ID,
	NT32_VAR_CURRENT_TASK_ID,
	NT32_VAR_CURRENT_THREAD_INFO_ID,
	NT32_VAR_CLOCK_ID,
	NT32_VAR_COOKED_CLOCK_ID,
#ifdef CONFIG_X86
	NT32_VAR_RDTSC_ID,
	NT32_VAR_COOKED_RDTSC_ID,
#endif
#ifdef NT32_RB
	NT32_VAR_NT32_RB_DISCARD_PAGE_NUMBER,
#endif
	NT32_VAR_PRINTK_TMP_ID,
	NT32_VAR_PRINTK_LEVEL_ID,
	NT32_VAR_PRINTK_FORMAT_ID,
	NT32_VAR_DUMP_STACK_ID,
	NT32_VAR_NO_SELF_TRACE_ID,
	NT32_VAR_CPU_NUMBER_ID,
	NT32_VAR_PC_PE_EN_ID,
	NT32_VAR_KRET_ID,
	NT32_VAR_XTIME_SEC_ID,
	NT32_VAR_XTIME_NSEC_ID,
	NT32_VAR_IGNORE_ERROR_ID,
	NT32_VAR_LAST_ERRNO_ID,
	NT32_VAR_HARDIRQ_COUNT_ID,
	NT32_VAR_SOFTIRQ_COUNT_ID,
	NT32_VAR_IRQ_COUNT_ID,
	NT32_VAR_PIPE_TRACE_ID,
	NT32_VAR_CURRENT_TASK_PID_ID,
	NT32_VAR_SPECIAL_MAX = NT32_VAR_CURRENT_TASK_PID_ID,
};

#define PREV_VAR	NULL

static struct nt32_var		nt32_var_version = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_VERSION_ID,
	.src		= "0:1:6774705f76657273696f6e",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_version)

static struct nt32_var		nt32_var_cpu_id = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_CPU_ID,
	.src		= "0:1:6370755f6964",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_cpu_id)

static struct nt32_var		nt32_var_current_task = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_CURRENT_TASK_ID,
	.src		= "0:1:63757272656e745f7461736b",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_current_task)

static struct nt32_var		nt32_var_current_task_pid = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_CURRENT_TASK_PID_ID,
	.src		= "0:1:63757272656e745f7461736b5f706964",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_current_task_pid)

static struct nt32_var		nt32_var_current_thread_info = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_CURRENT_THREAD_INFO_ID,
	.src		= "0:1:63757272656e745f7468726561645f696e666f",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_current_thread_info)

static struct nt32_var		nt32_var_clock = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_CLOCK_ID,
	.src		= "0:1:636c6f636b",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_clock)

static struct nt32_var		nt32_var_cooked_clock = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_COOKED_CLOCK_ID,
	.src		= "0:1:636f6f6b65645f636c6f636b",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_cooked_clock)

#ifdef CONFIG_X86
static struct nt32_var		nt32_var_rdtsc = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_RDTSC_ID,
	.src		= "0:1:7264747363",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_rdtsc)
static struct nt32_var		nt32_var_cooked_rdtsc = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_COOKED_RDTSC_ID,
	.src		= "0:1:636f6f6b65645f7264747363",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_cooked_rdtsc)
#endif

#ifdef NT32_RB
static struct nt32_var		nt32_var_nt32_rb_discard_page_number = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_NT32_RB_DISCARD_PAGE_NUMBER,
	.src		= "0:1:646973636172645f706167655f6e756d",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_nt32_rb_discard_page_number)
#endif

static struct nt32_var		nt32_var_printk_tmp = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_PRINTK_TMP_ID,
	.src		= "0:1:7072696e746b5f746d70",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_printk_tmp)

static struct nt32_var		nt32_var_printk_level = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_PRINTK_LEVEL_ID,
	.src		= "8:1:7072696e746b5f6c6576656c",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_printk_level)

static struct nt32_var		nt32_var_printk_format = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_PRINTK_FORMAT_ID,
	.src		= "0:1:7072696e746b5f666f726d6174",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_printk_format)

static struct nt32_var		nt32_var_dump_stack = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_DUMP_STACK_ID,
	.src		= "0:1:64756d705f737461636b",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_dump_stack)

static struct nt32_var		nt32_var_no_self_trace = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_NO_SELF_TRACE_ID,
	.src		= "0:1:6e6f5f73656c665f7472616365",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_no_self_trace)

static struct nt32_var		nt32_var_pipe_trace = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_PIPE_TRACE_ID,
	.src		= "0:1:706970655f7472616365",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_pipe_trace)

static struct nt32_var		nt32_var_cpu_number = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_CPU_NUMBER_ID,
	.src		= "0:1:6370755f6e756d626572",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_cpu_number)

static struct nt32_var		nt32_var_pc_pe_en = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_PC_PE_EN_ID,
	.src		= "0:1:70635f70655f656e",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_pc_pe_en)

static struct nt32_var		nt32_var_kret = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_KRET_ID,
	.src		= "0:1:6b726574",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_kret)

static struct nt32_var		nt32_var_xtime_sec = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_XTIME_SEC_ID,
	.src		= "0:1:7874696d655f736563",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_xtime_sec)

static struct nt32_var		nt32_var_xtime_nsec = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_XTIME_NSEC_ID,
	.src		= "0:1:7874696d655f6e736563",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_xtime_nsec)

static struct nt32_var		nt32_var_ignore_error = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_IGNORE_ERROR_ID,
	.src		= "0:1:69676e6f72655f6572726f72",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_ignore_error)

static struct nt32_var		nt32_var_last_errno = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_LAST_ERRNO_ID,
	.src		= "0:1:6c6173745f6572726e6f",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_last_errno)

static struct nt32_var		nt32_var_hardirq_count = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_HARDIRQ_COUNT_ID,
	.src		= "0:1:686172646972715f636f756e74",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_hardirq_count)

static struct nt32_var		nt32_var_softirq_count = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_SOFTIRQ_COUNT_ID,
	.src		= "0:1:736f66746972715f636f756e74",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR
#define PREV_VAR	(&nt32_var_softirq_count)

static struct nt32_var		nt32_var_irq_count = {
	.next		= PREV_VAR,
	.num		= NT32_VAR_IRQ_COUNT_ID,
	.src		= "0:1:6972715f636f756e74",
	.per_cpu	= NULL,
#ifdef NT32_PERF_EVENTS
	.ptid		= 0,
	.pts		= NULL,
#endif
};
#undef PREV_VAR

#define NT32_VAR_LIST_FIRST		(&nt32_var_irq_count)

#define NT32_VAR_IS_SPECIAL(x)		((x) >= NT32_VAR_SPECIAL_MIN \
					 && (x) <= NT32_VAR_SPECIAL_MAX)
#ifdef NT32_RB
#define NT32_VAR_AUTO_TRACEV(x)		((x) == NT32_VAR_CPU_ID)
#endif
#if defined(NT32_framework_SIMPLE) || defined(NT32_FTRACE_RING_BUFFER)
#define NT32_VAR_AUTO_TRACEV(x)		((x) == NT32_VAR_CLOCK_ID \
					 || (x) == NT32_VAR_CPU_ID)
#endif

/* ---Head file for notrace32 varaibles including performance event: END ---- */
