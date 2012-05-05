
/* ---Main header file of  Notrace32 for a lot of CPU Architecture: START ---- */
#ifdef CONFIG_X86
#define ULONGEST			uint64_t
#define LONGEST			int64_t
#define CORE_ADDR			unsigned long

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
#define NT32_REGS_PC(regs)	((regs)->ip)
#else
#ifdef CONFIG_X86_32
#define NT32_REGS_PC(regs)	((regs)->eip)
#else
#define NT32_REGS_PC(regs)	((regs)->rip)
#endif
#endif

#ifdef CONFIG_X86_32
#define NT32_REG_ASCII_SIZE	128
#define NT32_REG_BIN_SIZE	64
#else
#define NT32_REG_ASCII_SIZE	296
#define NT32_REG_BIN_SIZE	148
#endif
#endif

#ifdef CONFIG_MIPS
#define ULONGEST			uint64_t
#define LONGEST			int64_t
#define CORE_ADDR			unsigned long

#define NT32_REGS_PC(regs)	((regs)->cp0_epc)

#ifdef CONFIG_32BIT
#define NT32_REG_ASCII_SIZE	304
#define NT32_REG_BIN_SIZE	152
#else
#define NT32_REG_ASCII_SIZE	608
#define NT32_REG_BIN_SIZE	304
#endif
#endif

#ifdef CONFIG_ARM
#define ULONGEST			uint64_t
#define LONGEST			int64_t
#define CORE_ADDR			unsigned long

#define NT32_REGS_PC(regs)	((regs)->uregs[15])

#define NT32_REG_ASCII_SIZE	336
#define NT32_REG_BIN_SIZE	168
#endif
/* ---Main header file of  Notrace32 for a lot of CPU Architecture: END ---- */
