
/* Special configuration: START ------------------------------------------------ */
#define NT32_RB

#ifdef NT32_framework_SIMPLE
/* This is a debug option.
   This define is for simple framework alloc record, then we can get how many
   memory are weste by framework_ALIGN. */
/* #define framework_ALLOC_RECORD */
#undef NT32_RB
#endif

#ifdef NT32_FTRACE_RING_BUFFER
#undef NT32_RB
#endif

/* If define USE_PROC, NT32 will use ProcFS instead DebugFS.  */
#ifndef NT32_NO_AUTO_BUILD
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
#define USE_PROC
#endif
#endif
#ifndef USE_PROC
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
#warning If got some build error about debugfs, you can use "USE_PROC=1" handle it.
#endif
#endif

#ifdef NT32_FTRACE_RING_BUFFER
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
#warning If got some build error about ring buffer, you can use "framework_SIMPLE=1" handle it.
#endif
#endif

/* If define NT32_CLOCK_CYCLE, $clock will return rdtscll.  */
#ifndef NT32_NO_AUTO_BUILD
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
#define NT32_CLOCK_CYCLE
#endif
#endif
#ifndef NT32_CLOCK_CYCLE
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
#warning If got some build error about cpu_clock or local_clock, you can use "CLOCK_CYCLE=1" handle it.
#endif
#endif

#ifdef NT32_FTRACE_RING_BUFFER
#ifndef CONFIG_RING_BUFFER
#define CONFIG_RING_BUFFER
#include "ring_buffer.h"
#include "ring_buffer.c"
#define NT32_SELF_RING_BUFFER
#warning Use the ring buffer inside NT32.
#endif
#endif
/* Special configuration: END ------------------------------------------------ */
