
/* Definition of operation codes */
enum {
	op_check_add = 0xe5,
	op_check_sub,
	op_check_mul,
	op_check_div_signed,
	op_check_div_unsigned,
	op_check_rem_signed,
	op_check_rem_unsigned,
	op_check_lsh,
	op_check_rsh_signed,
	op_check_rsh_unsigned,
	op_check_trace,
	op_check_bit_and,
	op_check_bit_or,
	op_check_bit_xor,
	op_check_equal,
	op_check_less_signed,
	op_check_less_unsigned,
	op_check_pop,
	op_check_swap,
	op_check_if_goto,
	op_check_printf,	/* XXX: still not used.  */

	op_special_getv = 0xfa,
	op_special_setv,
	op_special_tracev,

	op_trace_printk = 0xfd,
	op_trace_quick_printk,
	op_tracev_printk,
};

struct action_agent_exp {
	unsigned int	size;
	uint8_t		*buf;
	int			need_var_lock;
};

struct action_m {
	int			regnum;
	CORE_ADDR		offset;
	size_t		size;
};

struct action {
	struct action	*next;
	unsigned char	type;
	char			*src;
	union {
		ULONGEST			reg_mask;
		struct action_agent_exp	exp;
		struct action_m		m;
	} u;
};

struct nt32src {
	struct nt32src	*next;
	char			*src;
};

enum nt32_stop_type {
	nt32_stop_normal = 0,
	nt32_stop_framework_full,
	nt32_stop_efault,
	nt32_stop_access_wrong_reg,
	nt32_stop_agent_expr_code_error,
	nt32_stop_agent_expr_stack_overflow,
};

struct nt32_entry {
	int			kpreg;
	int			no_self_trace;
	int			nopass;
	int			have_printk;
	ULONGEST		num;
	struct action	*cond;
	struct action	*action_list;
	int			step;
	struct action	*step_action_list;
	atomic_t		current_pass;
	struct nt32src	*printk_str;
	enum nt32_stop_type	reason;
	struct tasklet_struct	tasklet;
	struct work_struct	work;
	struct nt32_entry		*next;
	struct kretprobe		kp;
	int				disable;
	int				is_kretprobe;
	ULONGEST			addr;
	ULONGEST			pass;
	struct nt32src		*src;
};

#ifdef NT32_PERF_EVENTS
struct pe_tv_s	{
	struct pe_tv_s	*pc_next;
	int			en;
	struct perf_event	*event;
	int			cpu;
	u64			val;
	u64			enabled;	/* The perf inside timer */
	u64			running;	/* The perf inside timer */
	char			*name;
	struct perf_event_attr	attr;
};
#endif

enum pe_tv_id {
	pe_tv_unknown = 0,
	pe_tv_cpu,
	pe_tv_type,
	pe_tv_config,
	pe_tv_en,
	pe_tv_val,
	pe_tv_enabled,
	pe_tv_running,
};

struct nt32_var {
	struct nt32_var	*next;
	unsigned int	num;
	uint64_t		val;
	char			*src;
	struct nt32_var	**per_cpu;
#ifdef NT32_PERF_EVENTS
	enum pe_tv_id	ptid;
	struct pe_tv_s	*pts;
#endif
};

struct nt32_framework_mem {
	CORE_ADDR		addr;
	size_t		size;
};

struct nt32_framework_var {
	unsigned int	num;
	uint64_t		val;
};

struct nt32ro_entry {
	struct nt32ro_entry	*next;
	CORE_ADDR			start;
	CORE_ADDR			end;
};

static pid_t			nt32_nt32_pid;
static unsigned int		nt32_nt32_pid_count;
static pid_t			nt32_nt32framework_pid;
static unsigned int		nt32_nt32framework_pid_count;
#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
static pid_t			nt32_nt32framework_pipe_pid;
#endif

static struct nt32_entry		*nt32_list;
static struct nt32_entry		*current_nt32;
static struct action			*current_nt32_action;
static struct nt32src		*current_nt32_src;

static struct workqueue_struct	*nt32_wq;

static char			nt32_read_ack;
static char			*nt32_rw_buf;
static char			*nt32_rw_bufp;
static size_t			nt32_rw_size;

static int			nt32_start;

static int			nt32_disconnected_tracing;
static int			nt32_circular;
#if defined(NT32_FTRACE_RING_BUFFER)			\
    && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))	\
    && !defined(NT32_SELF_RING_BUFFER)
static int			nt32_circular_is_changed;
#endif

static int			nt32_cpu_number;

// nt32 variables 
#include "nt32-variables.h"

/* Current number in the framework.  */
static int			nt32_framework_current_num;

/* Current tracepoint id.  */
static ULONGEST		nt32_framework_current_tpe;
static atomic_t		nt32_framework_create;
static char			*nt32_framework_file;
static size_t			nt32_framework_file_size;
static DECLARE_WAIT_QUEUE_HEAD(nt32framework_wq);
#ifdef NT32_framework_SIMPLE
static DEFINE_SPINLOCK(nt32_framework_lock);
static char			*nt32_framework;
static char			*nt32_framework_r_start;
static char			*nt32_framework_w_start;
static char			*nt32_framework_end;
static int			nt32_framework_is_circular;
static char			*nt32_framework_current;
#endif
#ifdef NT32_FTRACE_RING_BUFFER
static struct ring_buffer		*nt32_framework;
static struct ring_buffer_iter	*nt32_framework_iter[NR_CPUS];
static int				nt32_framework_current_cpu;
static u64				nt32_framework_current_clock;
#endif

#if defined(NT32_FTRACE_RING_BUFFER) || defined(NT32_RB)
static DECLARE_WAIT_QUEUE_HEAD(nt32framework_pipe_wq);
static atomic_t			nt32framework_pipe_wq_v;
static struct tasklet_struct	nt32framework_pipe_wq_tasklet;
#endif

static struct nt32ro_entry		*nt32ro_list;

#define NT32_PRINTF_MAX		256
static DEFINE_PER_CPU(char[NT32_PRINTF_MAX], nt32_printf);

#ifdef CONFIG_X86
static DEFINE_PER_CPU(u64, rdtsc_current);
static DEFINE_PER_CPU(u64, rdtsc_offset);
#endif
static DEFINE_PER_CPU(u64, local_clock_current);
static DEFINE_PER_CPU(u64, local_clock_offset);

static uint64_t			nt32_start_last_errno;
static int				nt32_start_ignore_error;

static int				nt32_pipe_trace;
