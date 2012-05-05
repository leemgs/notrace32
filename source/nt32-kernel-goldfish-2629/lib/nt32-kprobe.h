/* Verification of existing features(START) : KPROBE , PROCFS , DEBUGFS ----------- */
#ifndef CONFIG_KPROBES
#error "Linux Kernel doesn't support KPROBES.  Please open it in 'General setup->Kprobes'."
#endif

#ifdef USE_PROC
#ifndef CONFIG_PROC_FS
#error "Linux Kernel doesn't support procfs."
#endif
#else
#ifndef CONFIG_DEBUG_FS
#error "Linux Kernel doesn't support debugfs."
#endif
#endif

#if !defined CONFIG_X86 && !defined CONFIG_MIPS && !defined CONFIG_ARM
#error "NT32 support X86_32, X86_64, MIPS and ARM."
#endif
/* Verification of existing features(END) : KPROBE , PROCFS , DEBUGFS ----------- */
