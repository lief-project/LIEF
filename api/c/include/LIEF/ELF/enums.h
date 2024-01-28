#ifndef LIEF_ELF_C_ENUMS_H_
#define LIEF_ELF_C_ENUMS_H_
#include "LIEF/ELF/undef.h"

#ifdef __cplusplus
extern "C" {
#endif

/** e_ident size and indices. */
enum LIEF_IDENTITY {
  LIEF_EI_MAG0       = 0,  /**< File identification index. */
  LIEF_EI_MAG1       = 1,  /**< File identification index. */
  LIEF_EI_MAG2       = 2,  /**< File identification index. */
  LIEF_EI_MAG3       = 3,  /**< File identification index. */
  LIEF_EI_CLASS      = 4,  /**< File class. */
  LIEF_EI_DATA       = 5,  /**< Data encoding. */
  LIEF_EI_VERSION    = 6,  /**< File version. */
  LIEF_EI_OSABI      = 7,  /**< OS/ABI identification. */
  LIEF_EI_ABIVERSION = 8,  /**< ABI version. */
  LIEF_EI_PAD        = 9,  /**< Start of padding bytes. */
  LIEF_EI_NIDENT     = 16  /**< Number of bytes in e_ident. */
};


/** Enum associated with *e_type* */
enum LIEF_E_TYPE {
  LIEF_ET_NONE   = 0,      /**< No file type */
  LIEF_ET_REL    = 1,      /**< Relocatable file */
  LIEF_ET_EXEC   = 2,      /**< Executable file */
  LIEF_ET_DYN    = 3,      /**< Shared object file */
  LIEF_ET_CORE   = 4,      /**< Core file */
  LIEF_ET_LOPROC = 0xff00, /**< Beginning of processor-specific codes */
  LIEF_ET_HIPROC = 0xffff  /**< Processor-specific */
};


/** Versioning */
enum LIEF_VERSION {
  LIEF_EV_NONE    = 0,
  LIEF_EV_CURRENT = 1  /**< Default value */
};

/**
 * @brief Machine architectures
 * See current registered ELF machine architectures at:
 * http://www.sco.com/developers/gabi/latest/ch4.eheader.html
 */
enum LIEF_ARCH {
  LIEF_EM_NONE          = 0,  /**< No machine */
  LIEF_EM_M32           = 1,  /**< AT&T WE 32100 */
  LIEF_EM_SPARC         = 2,  /**< SPARC */
  LIEF_EM_386           = 3,  /**< Intel 386 */
  LIEF_EM_68K           = 4,  /**< Motorola 68000 */
  LIEF_EM_88K           = 5,  /**< Motorola 88000 */
  LIEF_EM_IAMCU         = 6,  /**< Intel MCU */
  LIEF_EM_860           = 7,  /**< Intel 80860 */
  LIEF_EM_MIPS          = 8,  /**< MIPS R3000 */
  LIEF_EM_S370          = 9,  /**< IBM System/370 */
  LIEF_EM_MIPS_RS3_LE   = 10, /**< MIPS RS3000 Little-endian */
  LIEF_EM_PARISC        = 15, /**< Hewlett-Packard PA-RISC */
  LIEF_EM_VPP500        = 17, /**< Fujitsu VPP500 */
  LIEF_EM_SPARC32PLUS   = 18, /**< Enhanced instruction set SPARC */
  LIEF_EM_960           = 19, /**< Intel 80960 */
  LIEF_EM_PPC           = 20, /**< PowerPC */
  LIEF_EM_PPC64         = 21, /**< PowerPC64 */
  LIEF_EM_S390          = 22, /**< IBM System/390 */
  LIEF_EM_SPU           = 23, /**< IBM SPU/SPC */
  LIEF_EM_V800          = 36, /**< NEC V800 */
  LIEF_EM_FR20          = 37, /**< Fujitsu FR20 */
  LIEF_EM_RH32          = 38, /**< TRW RH-32 */
  LIEF_EM_RCE           = 39, /**< Motorola RCE */
  LIEF_EM_ARM           = 40, /**< ARM */
  LIEF_EM_ALPHA         = 41, /**< DEC Alpha */
  LIEF_EM_SH            = 42, /**< Hitachi SH */
  LIEF_EM_SPARCV9       = 43, /**< SPARC V9 */
  LIEF_EM_TRICORE       = 44, /**< Siemens TriCore */
  LIEF_EM_ARC           = 45, /**< Argonaut RISC Core */
  LIEF_EM_H8_300        = 46, /**< Hitachi H8/300 */
  LIEF_EM_H8_300H       = 47, /**< Hitachi H8/300H */
  LIEF_EM_H8S           = 48, /**< Hitachi H8S */
  LIEF_EM_H8_500        = 49, /**< Hitachi H8/500 */
  LIEF_EM_IA_64         = 50, /**< Intel IA-64 processor architecture */
  LIEF_EM_MIPS_X        = 51, /**< Stanford MIPS-X */
  LIEF_EM_COLDFIRE      = 52, /**< Motorola ColdFire */
  LIEF_EM_68HC12        = 53, /**< Motorola M68HC12 */
  LIEF_EM_MMA           = 54, /**< Fujitsu MMA Multimedia Accelerator */
  LIEF_EM_PCP           = 55, /**< Siemens PCP */
  LIEF_EM_NCPU          = 56, /**< Sony nCPU embedded RISC processor */
  LIEF_EM_NDR1          = 57, /**< Denso NDR1 microprocessor */
  LIEF_EM_STARCORE      = 58, /**< Motorola Star*Core processor */
  LIEF_EM_ME16          = 59, /**< Toyota ME16 processor */
  LIEF_EM_ST100         = 60, /**< STMicroelectronics ST100 processor */
  LIEF_EM_TINYJ         = 61, /**< Advanced Logic Corp. TinyJ embedded processor family */
  LIEF_EM_X86_64        = 62, /**< AMD x86-64 architecture */
  LIEF_EM_PDSP          = 63, /**< Sony DSP Processor */
  LIEF_EM_PDP10         = 64, /**< Digital Equipment Corp. PDP-10 */
  LIEF_EM_PDP11         = 65, /**< Digital Equipment Corp. PDP-11 */
  LIEF_EM_FX66          = 66, /**< Siemens FX66 microcontroller */
  LIEF_EM_ST9PLUS       = 67, /**< STMicroelectronics ST9+ 8/16 bit microcontroller */
  LIEF_EM_ST7           = 68, /**< STMicroelectronics ST7 8-bit microcontroller */
  LIEF_EM_68HC16        = 69, /**< Motorola MC68HC16 Microcontroller */
  LIEF_EM_68HC11        = 70, /**< Motorola MC68HC11 Microcontroller */
  LIEF_EM_68HC08        = 71, /**< Motorola MC68HC08 Microcontroller */
  LIEF_EM_68HC05        = 72, /**< Motorola MC68HC05 Microcontroller */
  LIEF_EM_SVX           = 73, /**< Silicon Graphics SVx */
  LIEF_EM_ST19          = 74, /**< STMicroelectronics ST19 8-bit microcontroller */
  LIEF_EM_VAX           = 75, /**< Digital VAX */
  LIEF_EM_CRIS          = 76, /**< Axis Communications 32-bit embedded processor */
  LIEF_EM_JAVELIN       = 77, /**< Infineon Technologies 32-bit embedded processor */
  LIEF_EM_FIREPATH      = 78, /**< Element 14 64-bit DSP Processor */
  LIEF_EM_ZSP           = 79, /**< LSI Logic 16-bit DSP Processor */
  LIEF_EM_MMIX          = 80, /**< Donald Knuth's educational 64-bit processor */
  LIEF_EM_HUANY         = 81, /**< Harvard University machine-independent object files */
  LIEF_EM_PRISM         = 82, /**< SiTera Prism */
  LIEF_EM_AVR           = 83, /**< Atmel AVR 8-bit microcontroller */
  LIEF_EM_FR30          = 84, /**< Fujitsu FR30 */
  LIEF_EM_D10V          = 85, /**< Mitsubishi D10V */
  LIEF_EM_D30V          = 86, /**< Mitsubishi D30V */
  LIEF_EM_V850          = 87, /**< NEC v850 */
  LIEF_EM_M32R          = 88, /**< Mitsubishi M32R */
  LIEF_EM_MN10300       = 89, /**< Matsushita MN10300 */
  LIEF_EM_MN10200       = 90, /**< Matsushita MN10200 */
  LIEF_EM_PJ            = 91, /**< picoJava */
  LIEF_EM_OPENRISC      = 92, /**< OpenRISC 32-bit embedded processor */
  LIEF_EM_ARC_COMPACT   = 93, /**< ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5 */
  LIEF_EM_XTENSA        = 94,  /**< Tensilica Xtensa Architecture */
  LIEF_EM_VIDEOCORE     = 95,  /**< Alphamosaic VideoCore processor */
  LIEF_EM_TMM_GPP       = 96,  /**< Thompson Multimedia General Purpose Processor */
  LIEF_EM_NS32K         = 97,  /**< National Semiconductor 32000 series */
  LIEF_EM_TPC           = 98,  /**< Tenor Network TPC processor */
  LIEF_EM_SNP1K         = 99,  /**< Trebia SNP 1000 processor */
  LIEF_EM_ST200         = 100, /**< STMicroelectronics (www.st.com ST200 */
  LIEF_EM_IP2K          = 101, /**< Ubicom IP2xxx microcontroller family */
  LIEF_EM_MAX           = 102, /**< MAX Processor */
  LIEF_EM_CR            = 103, /**< National Semiconductor CompactRISC microprocessor */
  LIEF_EM_F2MC16        = 104, /**< Fujitsu F2MC16 */
  LIEF_EM_MSP430        = 105, /**< Texas Instruments embedded microcontroller msp430 */
  LIEF_EM_BLACKFIN      = 106, /**< Analog Devices Blackfin (DSP processor */
  LIEF_EM_SE_C33        = 107, /**< S1C33 Family of Seiko Epson processors */
  LIEF_EM_SEP           = 108, /**< Sharp embedded microprocessor */
  LIEF_EM_ARCA          = 109, /**< Arca RISC Microprocessor */
  LIEF_EM_UNICORE       = 110, /**< Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University */
  LIEF_EM_EXCESS        = 111, /**< eXcess: 16/32/64-bit configurable embedded CPU */
  LIEF_EM_DXP           = 112, /**< Icera Semiconductor Inc. Deep Execution Processor */
  LIEF_EM_ALTERA_NIOS2  = 113, /**< Altera Nios II soft-core processor */
  LIEF_EM_CRX           = 114, /**< National Semiconductor CompactRISC CRX */
  LIEF_EM_XGATE         = 115, /**< Motorola XGATE embedded processor */
  LIEF_EM_C166          = 116, /**< Infineon C16x/XC16x processor */
  LIEF_EM_M16C          = 117, /**< Renesas M16C series microprocessors */
  LIEF_EM_DSPIC30F      = 118, /**< Microchip Technology dsPIC30F Digital Signal */
  /* Controller */
  LIEF_EM_CE            = 119, /**< Freescale Communication Engine RISC core */
  LIEF_EM_M32C          = 120, /**< Renesas M32C series microprocessors */
  LIEF_EM_TSK3000       = 131, /**< Altium TSK3000 core */
  LIEF_EM_RS08          = 132, /**< Freescale RS08 embedded processor */
  LIEF_EM_SHARC         = 133, /**< Analog Devices SHARC family of 32-bit DSP */
  /* processors */
  LIEF_EM_ECOG2         = 134, /**< Cyan Technology eCOG2 microprocessor */
  LIEF_EM_SCORE7        = 135, /**< Sunplus S+core7 RISC processor */
  LIEF_EM_DSP24         = 136, /**< New Japan Radio (NJR 24-bit DSP Processor */
  LIEF_EM_VIDEOCORE3    = 137, /**< Broadcom VideoCore III processor */
  LIEF_EM_LATTICEMICO32 = 138, /**< RISC processor for Lattice FPGA architecture */
  LIEF_EM_SE_C17        = 139, /**< Seiko Epson C17 family */
  LIEF_EM_TI_C6000      = 140, /**< The Texas Instruments TMS320C6000 DSP family */
  LIEF_EM_TI_C2000      = 141, /**< The Texas Instruments TMS320C2000 DSP family */
  LIEF_EM_TI_C5500      = 142, /**< The Texas Instruments TMS320C55x DSP family */
  LIEF_EM_MMDSP_PLUS    = 160, /**< STMicroelectronics 64bit VLIW Data Signal Processor */
  LIEF_EM_CYPRESS_M8C   = 161, /**< Cypress M8C microprocessor */
  LIEF_EM_R32C          = 162, /**< Renesas R32C series microprocessors */
  LIEF_EM_TRIMEDIA      = 163, /**< NXP Semiconductors TriMedia architecture family */
  LIEF_EM_HEXAGON       = 164, /**< Qualcomm Hexagon processor */
  LIEF_EM_8051          = 165, /**< Intel 8051 and variants */
  LIEF_EM_STXP7X        = 166, /**< STMicroelectronics STxP7x family of configurable */
  /* and extensible RISC processors */
  LIEF_EM_NDS32         = 167, /* Andes Technology compact code size embedded RISC */
  /* processor family */
  LIEF_EM_ECOG1         = 168, /**< Cyan Technology eCOG1X family */
  LIEF_EM_ECOG1X        = 168, /**< Cyan Technology eCOG1X family */
  LIEF_EM_MAXQ30        = 169, /**< Dallas Semiconductor MAXQ30 Core Micro-controllers */
  LIEF_EM_XIMO16        = 170, /**< New Japan Radio (NJR 16-bit DSP Processor */
  LIEF_EM_MANIK         = 171, /**< M2000 Reconfigurable RISC Microprocessor */
  LIEF_EM_CRAYNV2       = 172, /**< Cray Inc. NV2 vector architecture */
  LIEF_EM_RX            = 173, /**< Renesas RX family */
  LIEF_EM_METAG         = 174, /**< Imagination Technologies META processor */
  /* architecture */
  LIEF_EM_MCST_ELBRUS   = 175, /**< MCST Elbrus general purpose hardware architecture */
  LIEF_EM_ECOG16        = 176, /**< Cyan Technology eCOG16 family */
  LIEF_EM_CR16          = 177, /**< National Semiconductor CompactRISC CR16 16-bit */
  /* microprocessor */
  LIEF_EM_ETPU          = 178, /**< Freescale Extended Time Processing Unit */
  LIEF_EM_SLE9X         = 179, /**< Infineon Technologies SLE9X core */
  LIEF_EM_L10M          = 180, /**< Intel L10M */
  LIEF_EM_K10M          = 181, /**< Intel K10M */
  LIEF_EM_AARCH64       = 183, /**< ARM AArch64 */
  LIEF_EM_AVR32         = 185, /**< Atmel Corporation 32-bit microprocessor family */
  LIEF_EM_STM8          = 186, /**< STMicroeletronics STM8 8-bit microcontroller */
  LIEF_EM_TILE64        = 187, /**< Tilera TILE64 multicore architecture family */
  LIEF_EM_TILEPRO       = 188, /**< Tilera TILEPro multicore architecture family */
  LIEF_EM_CUDA          = 190, /**< NVIDIA CUDA architecture */
  LIEF_EM_TILEGX        = 191, /**< Tilera TILE-Gx multicore architecture family */
  LIEF_EM_CLOUDSHIELD   = 192, /**< CloudShield architecture family */
  LIEF_EM_COREA_1ST     = 193, /**< KIPO-KAIST Core-A 1st generation processor family */
  LIEF_EM_COREA_2ND     = 194, /**< KIPO-KAIST Core-A 2nd generation processor family */
  LIEF_EM_ARC_COMPACT2  = 195, /**< Synopsys ARCompact V2 */
  LIEF_EM_OPEN8         = 196, /**< Open8 8-bit RISC soft processor core */
  LIEF_EM_RL78          = 197, /**< Renesas RL78 family */
  LIEF_EM_VIDEOCORE5    = 198, /**< Broadcom VideoCore V processor */
  LIEF_EM_78KOR         = 199, /**< Renesas 78KOR family */
  LIEF_EM_56800EX       = 200, /**< Freescale 56800EX Digital Signal Controller (DSC */
  LIEF_EM_BA1           = 201, /**< Beyond BA1 CPU architecture */
  LIEF_EM_BA2           = 202, /**< Beyond BA2 CPU architecture */
  LIEF_EM_XCORE         = 203, /**< XMOS xCORE processor family */
  LIEF_EM_MCHP_PIC      = 204, /**< Microchip 8-bit PIC(r family */
  LIEF_EM_INTEL205      = 205, /**< Reserved by Intel */
  LIEF_EM_INTEL206      = 206, /**< Reserved by Intel */
  LIEF_EM_INTEL207      = 207, /**< Reserved by Intel */
  LIEF_EM_INTEL208      = 208, /**< Reserved by Intel */
  LIEF_EM_INTEL209      = 209, /**< Reserved by Intel */
  LIEF_EM_KM32          = 210, /**< KM211 KM32 32-bit processor */
  LIEF_EM_KMX32         = 211, /**< KM211 KMX32 32-bit processor */
  LIEF_EM_KMX16         = 212, /**< KM211 KMX16 16-bit processor */
  LIEF_EM_KMX8          = 213, /**< KM211 KMX8 8-bit processor */
  LIEF_EM_KVARC         = 214, /**< KM211 KVARC processor */
  LIEF_EM_CDP           = 215, /**< Paneve CDP architecture family */
  LIEF_EM_COGE          = 216, /**< Cognitive Smart Memory Processor */
  LIEF_EM_COOL          = 217, /**< iCelero CoolEngine */
  LIEF_EM_NORC          = 218, /**< Nanoradio Optimized RISC */
  LIEF_EM_CSR_KALIMBA   = 219, /**< CSR Kalimba architecture family */
  LIEF_EM_AMDGPU        = 224, /**< AMD GPU architecture */
  LIEF_EM_RISCV         = 243, /**< RISC-V */
  LIEF_EM_BPF           = 247, /**< eBPF Filter */
  LIEF_EM_LOONGARCH     = 258  /**< LoongArch */
};


/** Object file classes. */
enum LIEF_ELF_CLASS {
  LIEF_ELFCLASSNONE = 0, /**< Unknown */
  LIEF_ELFCLASS32   = 1, /**< 32-bit object file */
  LIEF_ELFCLASS64   = 2  /**< 64-bit object file */
};

/** Object file byte orderings. */
enum LIEF_ELF_DATA {
  LIEF_ELFDATANONE = 0, /**< Invalid data encoding. */
  LIEF_ELFDATA2LSB = 1, /**< Little-endian object file */
  LIEF_ELFDATA2MSB = 2  /**< Big-endian object file */
};

/** OS ABI identification. */
enum LIEF_OS_ABI {
  LIEF_OSABI_SYSTEMV      = 0,  /**< UNIX System V ABI */
  LIEF_OSABI_HPUX         = 1,  /**< HP-UX operating system */
  LIEF_OSABI_NETBSD       = 2,  /**< NetBSD */
  LIEF_OSABI_GNU          = 3,  /**< GNU/Linux */
  LIEF_OSABI_LINUX        = 3,  /**< Historical alias for ELFOSABI_GNU. */
  LIEF_OSABI_HURD         = 4,  /**< GNU/Hurd */
  LIEF_OSABI_SOLARIS      = 6,  /**< Solaris */
  LIEF_OSABI_AIX          = 7,  /**< AIX */
  LIEF_OSABI_IRIX         = 8,  /**< IRIX */
  LIEF_OSABI_FREEBSD      = 9,  /**< FreeBSD */
  LIEF_OSABI_TRU64        = 10, /**< TRU64 UNIX */
  LIEF_OSABI_MODESTO      = 11, /**< Novell Modesto */
  LIEF_OSABI_OPENBSD      = 12, /**< OpenBSD */
  LIEF_OSABI_OPENVMS      = 13, /**< OpenVMS */
  LIEF_OSABI_NSK          = 14, /**< Hewlett-Packard Non-Stop Kernel */
  LIEF_OSABI_AROS         = 15, /**< AROS */
  LIEF_OSABI_FENIXOS      = 16, /**< FenixOS */
  LIEF_OSABI_CLOUDABI     = 17, /**< Nuxi CloudABI */
  LIEF_OSABI_C6000_ELFABI = 64, /**< Bare-metal TMS320C6000 */
  LIEF_OSABI_AMDGPU_HSA   = 64, /**< AMD HSA runtime */
  LIEF_OSABI_C6000_LINUX  = 65, /**< Linux TMS320C6000 */
  LIEF_OSABI_ARM          = 97, /**< ARM */
  LIEF_OSABI_STANDALONE   = 255 /**< Standalone (embedded application */
};

/* ELF Relocations */

#define ELF_RELOC(name, value) name = value,

/** x86_64 relocations. */
enum LIEF_RELOC_x86_64 {
   #include "LIEF/ELF/Relocations/x86_64.def"
};

/** i386 relocations. */
enum  RELOC_i386 {
   #include "LIEF/ELF/Relocations/i386.def"
};

/* ELF Relocation types for PPC32 */
enum LIEF_RELOC_POWERPC32 {
   #include "LIEF/ELF/Relocations/PowerPC.def"
};

/* ELF Relocation types for PPC64 */
enum LIEF_RELOC_POWERPC64 {
   #include "LIEF/ELF/Relocations/PowerPC64.def"
};

/* ELF Relocation types for AArch64 */
enum LIEF_RELOC_AARCH64 {
   #include "LIEF/ELF/Relocations/AArch64.def"
};

/* ELF Relocation types for ARM */
enum LIEF_RELOC_ARM {
  #include "LIEF/ELF/Relocations/ARM.def"
};

/* ELF Relocation types for Mips */
enum LIEF_RELOC_MIPS {
  #include "LIEF/ELF/Relocations/Mips.def"
};

/* ELF Relocation types for Hexagon */
enum LIEF_RELOC_HEXAGON {
  #include "LIEF/ELF/Relocations/Hexagon.def"
};

/* ELF Relocation types for S390/zSeries */
enum LIEF_RELOC_SYSTEMZ {
  #include "LIEF/ELF/Relocations/SystemZ.def"
};

/* ELF Relocation type for Sparc. */
enum LIEF_RELOC_SPARC {
  #include "LIEF/ELF/Relocations/Sparc.def"
};

/* ELF Relocation types for LoongArch. */
enum LIEF_RELOC_LOONGARCH {
  #include "LIEF/ELF/Relocations/LoongArch.def"
};

#undef ELF_RELOC

/* Specific e_flags for PPC64 */
enum LIEF_PPC64_EFLAGS {
  /* e_flags bits specifying ABI: */
  /* 1 for original ABI using function descriptors, */
  /* 2 for revised ABI without function descriptors, */
  /* 0 for unspecified or not using any features affected by the differences. */
  LIEF_EF_PPC64_ABI = 3
};

/* ARM Specific e_flags */
enum LIEF_ARM_EFLAGS {
  LIEF_EF_ARM_SOFT_FLOAT   = 0x00000200U,
  LIEF_EF_ARM_VFP_FLOAT    = 0x00000400U,
  LIEF_EF_ARM_EABI_UNKNOWN = 0x00000000U,
  LIEF_EF_ARM_EABI_VER1    = 0x01000000U,
  LIEF_EF_ARM_EABI_VER2    = 0x02000000U,
  LIEF_EF_ARM_EABI_VER3    = 0x03000000U,
  LIEF_EF_ARM_EABI_VER4    = 0x04000000U,
  LIEF_EF_ARM_EABI_VER5    = 0x05000000U,
  LIEF_EF_ARM_EABIMASK     = 0xFF000000U
};

/* Mips Specific e_flags */
enum LIEF_MIPS_EFLAGS {
  LIEF_EF_MIPS_NOREORDER = 0x00000001, /* Don't reorder instructions */
  LIEF_EF_MIPS_PIC       = 0x00000002, /* Position independent code */
  LIEF_EF_MIPS_CPIC      = 0x00000004, /* Call object with Position independent code */
  LIEF_EF_MIPS_ABI2      = 0x00000020, /* File uses N32 ABI */
  LIEF_EF_MIPS_32BITMODE = 0x00000100, /* Code compiled for a 64-bit machine */
  /* in 32-bit mode */
  LIEF_EF_MIPS_FP64      = 0x00000200, /* Code compiled for a 32-bit machine */
  /* but uses 64-bit FP registers */
  LIEF_EF_MIPS_NAN2008   = 0x00000400, /* Uses IEE 754-2008 NaN encoding */

  /* ABI flags */
  LIEF_EF_MIPS_ABI_O32    = 0x00001000, /* This file follows the first MIPS 32 bit ABI */
  LIEF_EF_MIPS_ABI_O64    = 0x00002000, /* O32 ABI extended for 64-bit architecture. */
  LIEF_EF_MIPS_ABI_EABI32 = 0x00003000, /* EABI in 32 bit mode. */
  LIEF_EF_MIPS_ABI_EABI64 = 0x00004000, /* EABI in 64 bit mode. */
  LIEF_EF_MIPS_ABI        = 0x0000f000, /* Mask for selecting EF_MIPS_ABI_ variant. */

  /* MIPS machine variant */
  LIEF_EF_MIPS_MACH_3900    = 0x00810000, /* Toshiba R3900 */
  LIEF_EF_MIPS_MACH_4010    = 0x00820000, /* LSI R4010 */
  LIEF_EF_MIPS_MACH_4100    = 0x00830000, /* NEC VR4100 */
  LIEF_EF_MIPS_MACH_4650    = 0x00850000, /* MIPS R4650 */
  LIEF_EF_MIPS_MACH_4120    = 0x00870000, /* NEC VR4120 */
  LIEF_EF_MIPS_MACH_4111    = 0x00880000, /* NEC VR4111/VR4181 */
  LIEF_EF_MIPS_MACH_SB1     = 0x008a0000, /* Broadcom SB-1 */
  LIEF_EF_MIPS_MACH_OCTEON  = 0x008b0000, /* Cavium Networks Octeon */
  LIEF_EF_MIPS_MACH_XLR     = 0x008c0000, /* RMI Xlr */
  LIEF_EF_MIPS_MACH_OCTEON2 = 0x008d0000, /* Cavium Networks Octeon2 */
  LIEF_EF_MIPS_MACH_OCTEON3 = 0x008e0000, /* Cavium Networks Octeon3 */
  LIEF_EF_MIPS_MACH_5400    = 0x00910000, /* NEC VR5400 */
  LIEF_EF_MIPS_MACH_5900    = 0x00920000, /* MIPS R5900 */
  LIEF_EF_MIPS_MACH_5500    = 0x00980000, /* NEC VR5500 */
  LIEF_EF_MIPS_MACH_9000    = 0x00990000, /* Unknown */
  LIEF_EF_MIPS_MACH_LS2E    = 0x00a00000, /* ST Microelectronics Loongson 2E */
  LIEF_EF_MIPS_MACH_LS2F    = 0x00a10000, /* ST Microelectronics Loongson 2F */
  LIEF_EF_MIPS_MACH_LS3A    = 0x00a20000, /* Loongson 3A */
  LIEF_EF_MIPS_MACH         = 0x00ff0000, /* EF_MIPS_MACH_xxx selection mask */

  /* ARCH_ASE */
  LIEF_EF_MIPS_MICROMIPS     = 0x02000000, /* microMIPS */
  LIEF_EF_MIPS_ARCH_ASE_M16  = 0x04000000, /* Has Mips-16 ISA extensions */
  LIEF_EF_MIPS_ARCH_ASE_MDMX = 0x08000000, /* Has MDMX multimedia extensions */
  LIEF_EF_MIPS_ARCH_ASE      = 0x0f000000, /* Mask for EF_MIPS_ARCH_ASE_xxx flags */

  /* ARCH */
  LIEF_EF_MIPS_ARCH_1    = 0x00000000, /* MIPS1 instruction set */
  LIEF_EF_MIPS_ARCH_2    = 0x10000000, /* MIPS2 instruction set */
  LIEF_EF_MIPS_ARCH_3    = 0x20000000, /* MIPS3 instruction set */
  LIEF_EF_MIPS_ARCH_4    = 0x30000000, /* MIPS4 instruction set */
  LIEF_EF_MIPS_ARCH_5    = 0x40000000, /* MIPS5 instruction set */
  LIEF_EF_MIPS_ARCH_32   = 0x50000000, /* MIPS32 instruction set per linux not elf.h */
  LIEF_EF_MIPS_ARCH_64   = 0x60000000, /* MIPS64 instruction set per linux not elf.h */
  LIEF_EF_MIPS_ARCH_32R2 = 0x70000000, /* mips32r2, mips32r3, mips32r5 */
  LIEF_EF_MIPS_ARCH_64R2 = 0x80000000, /* mips64r2, mips64r3, mips64r5 */
  LIEF_EF_MIPS_ARCH_32R6 = 0x90000000, /* mips32r6 */
  LIEF_EF_MIPS_ARCH_64R6 = 0xa0000000, /* mips64r6 */
  LIEF_EF_MIPS_ARCH      = 0xf0000000  /* Mask for applying EF_MIPS_ARCH_ variant */
};

/* Hexagon Specific e_flags */
/* Release 5 ABI */
enum LIEF_HEXAGON_EFLAGS {
  /* Object processor version flags, bits[3:0] */
  LIEF_EF_HEXAGON_MACH_V2      = 0x00000001,   /* Hexagon V2 */
  LIEF_EF_HEXAGON_MACH_V3      = 0x00000002,   /* Hexagon V3 */
  LIEF_EF_HEXAGON_MACH_V4      = 0x00000003,   /* Hexagon V4 */
  LIEF_EF_HEXAGON_MACH_V5      = 0x00000004,   /* Hexagon V5 */

  /* Highest ISA version flags */
  LIEF_EF_HEXAGON_ISA_MACH     = 0x00000000,   /* Same as specified in bits[3:0] */
  /* of e_flags */
  LIEF_EF_HEXAGON_ISA_V2       = 0x00000010,   /* Hexagon V2 ISA */
  LIEF_EF_HEXAGON_ISA_V3       = 0x00000020,   /* Hexagon V3 ISA */
  LIEF_EF_HEXAGON_ISA_V4       = 0x00000030,   /* Hexagon V4 ISA */
  LIEF_EF_HEXAGON_ISA_V5       = 0x00000040    /* Hexagon V5 ISA */
};


/* LoongArch Specific e_flags */
enum LIEF_LOONGARCH_EFLAGS {
  LIEF_EF_LOONGARCH_ABI_SOFT_FLOAT        = 0x1,
  LIEF_EF_LOONGARCH_ABI_SINGLE_FLOAT      = 0x2,
  LIEF_EF_LOONGARCH_ABI_DOUBLE_FLOAT      = 0x3
};

/** Special section indices. */
enum LIEF_SYMBOL_SECTION_INDEX {
  LIEF_SHN_UNDEF     = 0,      /**< Undefined, missing, irrelevant, or meaningless */
  LIEF_SHN_LORESERVE = 0xff00, /**< Lowest reserved index */
  LIEF_SHN_LOPROC    = 0xff00, /**< Lowest processor-specific index */
  LIEF_SHN_HIPROC    = 0xff1f, /**< Highest processor-specific index */
  LIEF_SHN_LOOS      = 0xff20, /**< Lowest operating system-specific index */
  LIEF_SHN_HIOS      = 0xff3f, /**< Highest operating system-specific index */
  LIEF_SHN_ABS       = 0xfff1, /**< Symbol has absolute value; does not need relocation */
  LIEF_SHN_COMMON    = 0xfff2, /**< FORTRAN COMMON or C external global variables */
  LIEF_SHN_XINDEX    = 0xffff, /**< Mark that the index is >= SHN_LORESERVE */
  LIEF_SHN_HIRESERVE = 0xffff  /**< Highest reserved index */
};

/** Section types. */
enum LIEF_ELF_SECTION_TYPES {
  LIEF_SHT_NULL                = 0,  /**< No associated section (inactive entry. */
  LIEF_SHT_PROGBITS            = 1,  /**< Program-defined contents. */
  LIEF_SHT_SYMTAB              = 2,  /**< Symbol table. */
  LIEF_SHT_STRTAB              = 3,  /**< String table. */
  LIEF_SHT_RELA                = 4,  /**< Relocation entries; explicit addends. */
  LIEF_SHT_HASH                = 5,  /**< Symbol hash table. */
  LIEF_SHT_DYNAMIC             = 6,  /**< Information for dynamic linking. */
  LIEF_SHT_NOTE                = 7,  /**< Information about the file. */
  LIEF_SHT_NOBITS              = 8,  /**< Data occupies no space in the file. */
  LIEF_SHT_REL                 = 9,  /**< Relocation entries; no explicit addends. */
  LIEF_SHT_SHLIB               = 10, /**< Reserved. */
  LIEF_SHT_DYNSYM              = 11, /**< Symbol table. */
  LIEF_SHT_INIT_ARRAY          = 14, /**< Pointers to initialization functions. */
  LIEF_SHT_FINI_ARRAY          = 15, /**< Pointers to termination functions. */
  LIEF_SHT_PREINIT_ARRAY       = 16, /**< Pointers to pre-init functions. */
  LIEF_SHT_GROUP               = 17, /**< Section group. */
  LIEF_SHT_SYMTAB_SHNDX        = 18, /**< Indices for SHN_XINDEX entries. */
  LIEF_SHT_LOOS                = 0x60000000, /**< Lowest operating system-specific type. */
  LIEF_SHT_ANDROID_REL         = 0x60000001, /**< Packed relocations (Android specific. */
  LIEF_SHT_ANDROID_RELA        = 0x60000002, /**< Packed relocations (Android specific. */
  LIEF_SHT_LLVM_ADDRSIG        = 0x6fff4c03, /**< This section is used to mark symbols as address-significant. */
  LIEF_SHT_RELR                = 0x6fffff00, /**< New relr relocations (Android specific. */
  LIEF_SHT_GNU_ATTRIBUTES      = 0x6ffffff5, /**< Object attributes. */
  LIEF_SHT_GNU_HASH            = 0x6ffffff6, /**< GNU-style hash table. */
  LIEF_SHT_GNU_verdef          = 0x6ffffffd, /**< GNU version definitions. */
  LIEF_SHT_GNU_verneed         = 0x6ffffffe, /**< GNU version references. */
  LIEF_SHT_GNU_versym          = 0x6fffffff, /**< GNU symbol versions table. */
  LIEF_SHT_HIOS                = 0x6fffffff, /**< Highest operating system-specific type. */
  LIEF_SHT_LOPROC              = 0x70000000, /**< Lowest processor arch-specific type. */
  LIEF_SHT_ARM_EXIDX           = 0x70000001U, /**< Exception Index table */
  LIEF_SHT_ARM_PREEMPTMAP      = 0x70000002U, /**< BPABI DLL dynamic linking pre-emption map */
  LIEF_SHT_ARM_ATTRIBUTES      = 0x70000003U, /**<  Object file compatibility attributes */
  LIEF_SHT_ARM_DEBUGOVERLAY    = 0x70000004U,
  LIEF_SHT_ARM_OVERLAYSECTION  = 0x70000005U,
  LIEF_SHT_HEX_ORDERED         = 0x70000000, /**< Link editor is to sort the entries in */

  /* this section based on their sizes */
  LIEF_SHT_X86_64_UNWIND       = 0x70000001, /**< Unwind information */
  LIEF_SHT_MIPS_REGINFO        = 0x70000006, /**< Register usage information */
  LIEF_SHT_MIPS_OPTIONS        = 0x7000000d, /**< General options */
  LIEF_SHT_MIPS_ABIFLAGS       = 0x7000002a, /**< ABI information. */

  LIEF_SHT_HIPROC              = 0x7fffffff, /**< Highest processor arch-specific type. */
  LIEF_SHT_LOUSER              = 0x80000000, /**< Lowest type reserved for applications. */
  LIEF_SHT_HIUSER              = 0xffffffff  /**< Highest type reserved for applications. */
};



/** Section flags. */
enum LIEF_ELF_SECTION_FLAGS {
  LIEF_SHF_NONE             = 0x0,
  LIEF_SHF_WRITE            = 0x1,         /**< Section data should be writable during execution. */
  LIEF_SHF_ALLOC            = 0x2,         /**< Section occupies memory during program execution. */
  LIEF_SHF_EXECINSTR        = 0x4,         /**< Section contains executable machine instructions. */
  LIEF_SHF_MERGE            = 0x10,        /**< The data in this section may be merged. */
  LIEF_SHF_STRINGS          = 0x20,        /**< The data in this section is null-terminated strings. */
  LIEF_SHF_INFO_LINK        = 0x40U,       /**< A field in this section holds a section header table index. */
  LIEF_SHF_LINK_ORDER       = 0x80U,       /**< Adds special ordering requirements for link editors. */
  LIEF_SHF_OS_NONCONFORMING = 0x100U,      /**< This section requires special OS-specific processing to avoid incorrect behavior */
  LIEF_SHF_GROUP            = 0x200U,      /**< This section is a member of a section group. */
  LIEF_SHF_TLS              = 0x400U,      /**< This section holds Thread-Local Storage. */
  LIEF_SHF_EXCLUDE          = 0x80000000U, /**< This section is excluded from the final executable or shared library. */
  /* Start of target-specific flags. */

  /* XCORE_SHF_CP_SECTION - All sections with the "c" flag are grouped
   * together by the linker to form the constant pool and the cp register is
   * set to the start of the constant pool by the boot code.
   */
  LIEF_XCORE_SHF_CP_SECTION = 0x800U,

  /* XCORE_SHF_DP_SECTION - All sections with the "d" flag are grouped
   * together by the linker to form the data section and the dp register is
   * set to the start of the section by the boot code.
   */
  LIEF_XCORE_SHF_DP_SECTION = 0x1000U,
  LIEF_SHF_MASKOS   = 0x0ff00000,
  LIEF_SHF_MASKPROC = 0xf0000000, /**< Bits indicating processor-specific flags. */

  /* If an object file section does not have this flag set, then it may not hold
   * more than 2GB and can be freely referred to in objects using smaller code
   * models. Otherwise, only objects using larger code models can refer to them.
   * For example, a medium code model object can refer to data in a section that
   * sets this flag besides being able to refer to data in a section that does
   * not set it; likewise, a small code model object can refer only to code in a
   * section that does not set this flag.
   */
  LIEF_SHF_X86_64_LARGE = 0x10000000,

  /* All sections with the GPREL flag are grouped into a global data area
   * for faster accesses.
   */
  LIEF_SHF_HEX_GPREL = 0x10000000,

  /* Section contains text/data which may be replicated in other sections.
   * Linker must retain only one copy.
   */
  LIEF_SHF_MIPS_NODUPES = 0x01000000,

  LIEF_SHF_MIPS_NAMES   = 0x02000000, /**< Linker must generate implicit hidden weak names. */
  LIEF_SHF_MIPS_LOCAL   = 0x04000000, /**< Section data local to process. */
  LIEF_SHF_MIPS_NOSTRIP = 0x08000000, /**< Do not strip this section. */
  LIEF_SHF_MIPS_GPREL   = 0x10000000, /**< Section must be part of global data area. */
  LIEF_SHF_MIPS_MERGE   = 0x20000000, /**< This section should be merged. */
  LIEF_SHF_MIPS_ADDR    = 0x40000000, /**< Address size to be inferred from section entry size. */
  LIEF_SHF_MIPS_STRING  = 0x80000000  /**< Section data is string data by default. */
};


/** Symbol bindings. */
enum LIEF_SYMBOL_BINDINGS {
  LIEF_STB_LOCAL      = 0,  /**< Local symbol, not visible outside obj file containing def */
  LIEF_STB_GLOBAL     = 1,  /**< Global symbol, visible to all object files being combined */
  LIEF_STB_WEAK       = 2,  /**< Weak symbol, like global but lower-precedence */
  LIEF_STB_GNU_UNIQUE = 10,
  LIEF_STB_LOOS       = 10, /**< Lowest operating system-specific binding type */
  LIEF_STB_HIOS       = 12, /**< Highest operating system-specific binding type */
  LIEF_STB_LOPROC     = 13, /**< Lowest processor-specific binding type */
  LIEF_STB_HIPROC     = 15  /**< Highest processor-specific binding type */
};


/* Symbol types. */
enum LIEF_ELF_SYMBOL_TYPES {
  LIEF_STT_NOTYPE    = 0,   /* Symbol's type is not specified */
  LIEF_STT_OBJECT    = 1,   /* Symbol is a data object (variable, array, etc. */
  LIEF_STT_FUNC      = 2,   /* Symbol is executable code (function, etc. */
  LIEF_STT_SECTION   = 3,   /* Symbol refers to a section */
  LIEF_STT_FILE      = 4,   /* Local, absolute symbol that refers to a file */
  LIEF_STT_COMMON    = 5,   /* An uninitialized common block */
  LIEF_STT_TLS       = 6,   /* Thread local data object */
  LIEF_STT_GNU_IFUNC = 10,  /* GNU indirect function */
  LIEF_STT_LOOS      = 10,  /* Lowest operating system-specific symbol type */
  LIEF_STT_HIOS      = 12,  /* Highest operating system-specific symbol type */
  LIEF_STT_LOPROC    = 13,  /* Lowest processor-specific symbol type */
  LIEF_STT_HIPROC    = 15   /* Highest processor-specific symbol type */
};

enum LIEF_ELF_SYMBOL_VISIBILITY {
  LIEF_STV_DEFAULT   = 0,  /* Visibility is specified by binding type */
  LIEF_STV_INTERNAL  = 1,  /* Defined by processor supplements */
  LIEF_STV_HIDDEN    = 2,  /* Not visible to other components */
  LIEF_STV_PROTECTED = 3   /* Visible in other components but not preemptable */
};


/** @brief Segment types. */
enum LIEF_SEGMENT_TYPES {
  LIEF_PT_NULL          = 0,          /**< Unused segment. */
  LIEF_PT_LOAD          = 1,          /**< Loadable segment. */
  LIEF_PT_DYNAMIC       = 2,          /**< Dynamic linking information. */
  LIEF_PT_INTERP        = 3,          /**< Interpreter pathname. */
  LIEF_PT_NOTE          = 4,          /**< Auxiliary information. */
  LIEF_PT_SHLIB         = 5,          /**< Reserved. */
  LIEF_PT_PHDR          = 6,          /**< The program header table itself. */
  LIEF_PT_TLS           = 7,          /**< The thread-local storage template. */
  LIEF_PT_LOOS          = 0x60000000, /**< Lowest operating system-specific pt entry type. */
  LIEF_PT_HIOS          = 0x6fffffff, /**< Highest operating system-specific pt entry type. */
  LIEF_PT_LOPROC        = 0x70000000, /**< Lowest processor-specific program hdr entry type. */
  LIEF_PT_HIPROC        = 0x7fffffff, /**< Highest processor-specific program hdr entry type. */

  /* x86-64 program header types. */
  /* These all contain stack unwind tables. */
  LIEF_PT_GNU_EH_FRAME  = 0x6474e550,
  LIEF_PT_SUNW_EH_FRAME = 0x6474e550,
  LIEF_PT_SUNW_UNWIND   = 0x6464e550,

  LIEF_PT_GNU_STACK     = 0x6474e551, /**< Indicates stack executability. */
  LIEF_PT_GNU_PROPERTY  = 0x6474e553, /**< GNU property */
  LIEF_PT_GNU_RELRO     = 0x6474e552, /**< Read-only after relocation. */

  /* ARM program header types. */
  LIEF_PT_ARM_ARCHEXT   = 0x70000000, /**< Platform architecture compatibility info */

  /* These all contain stack unwind tables. */
  LIEF_PT_ARM_EXIDX     = 0x70000001,
  LIEF_PT_ARM_UNWIND    = 0x70000001,

  /* MIPS program header types. */
  LIEF_PT_MIPS_REGINFO  = 0x70000000,  /**< Register usage information. */
  LIEF_PT_MIPS_RTPROC   = 0x70000001,  /**< Runtime procedure table. */
  LIEF_PT_MIPS_OPTIONS  = 0x70000002,  /**< Options segment. */
  LIEF_PT_MIPS_ABIFLAGS = 0x70000003   /**< Abiflags segment. */
};


/** Segment flags. */
enum LIEF_ELF_SEGMENT_FLAGS {
   LIEF_PF_NONE     = 0,
   LIEF_PF_X        = 1,         /**< Execute */
   LIEF_PF_W        = 2,         /**< Write */
   LIEF_PF_R        = 4,         /**< Read */
   LIEF_PF_MASKOS   = 0x0ff00000,/**< Bits for operating system-specific semantics. */
   LIEF_PF_MASKPROC = 0xf0000000 /**< Bits for processor-specific semantics. */
};


/** Dynamic table entry tags. */
enum LIEF_DYNAMIC_TAGS {
  LIEF_DT_NULL                       = 0,          /**< Marks end of dynamic array. */
  LIEF_DT_NEEDED                     = 1,          /**< String table offset of needed library. */
  LIEF_DT_PLTRELSZ                   = 2,          /**< Size of relocation entries in PLT. */
  LIEF_DT_PLTGOT                     = 3,          /**< Address associated with linkage table. */
  LIEF_DT_HASH                       = 4,          /**< Address of symbolic hash table. */
  LIEF_DT_STRTAB                     = 5,          /**< Address of dynamic string table. */
  LIEF_DT_SYMTAB                     = 6,          /**< Address of dynamic symbol table. */
  LIEF_DT_RELA                       = 7,          /**< Address of relocation table (Rela entries. */
  LIEF_DT_RELASZ                     = 8,          /**< Size of Rela relocation table. */
  LIEF_DT_RELAENT                    = 9,          /**< Size of a Rela relocation entry. */
  LIEF_DT_STRSZ                      = 10,         /**< Total size of the string table. */
  LIEF_DT_SYMENT                     = 11,         /**< Size of a symbol table entry. */
  LIEF_DT_INIT                       = 12,         /**< Address of initialization function. */
  LIEF_DT_FINI                       = 13,         /**< Address of termination function. */
  LIEF_DT_SONAME                     = 14,         /**< String table offset of a shared objects name. */
  LIEF_DT_RPATH                      = 15,         /**< String table offset of library search path. */
  LIEF_DT_SYMBOLIC                   = 16,         /**< Changes symbol resolution algorithm. */
  LIEF_DT_REL                        = 17,         /**< Address of relocation table (Rel entries. */
  LIEF_DT_RELSZ                      = 18,         /**< Size of Rel relocation table. */
  LIEF_DT_RELENT                     = 19,         /**< Size of a Rel relocation entry. */
  LIEF_DT_PLTREL                     = 20,         /**< Type of relocation entry used for linking. */
  LIEF_DT_DEBUG                      = 21,         /**< Reserved for debugger. */
  LIEF_DT_TEXTREL                    = 22,         /**< Relocations exist for non-writable segments. */
  LIEF_DT_JMPREL                     = 23,         /**< Address of relocations associated with PLT. */
  LIEF_DT_BIND_NOW                   = 24,         /**< Process all relocations before execution. */
  LIEF_DT_INIT_ARRAY                 = 25,         /**< Pointer to array of initialization functions. */
  LIEF_DT_FINI_ARRAY                 = 26,         /**< Pointer to array of termination functions. */
  LIEF_DT_INIT_ARRAYSZ               = 27,         /**< Size of DT_INIT_ARRAY. */
  LIEF_DT_FINI_ARRAYSZ               = 28,         /**< Size of DT_FINI_ARRAY. */
  LIEF_DT_RUNPATH                    = 29,         /**< String table offset of lib search path. */
  LIEF_DT_FLAGS                      = 30,         /**< Flags. */
  LIEF_DT_ENCODING                   = 32,         /**< Values from here to DT_LOOS follow the rules for the interpretation of the d_un union. */

  LIEF_DT_PREINIT_ARRAY              = 32,         /**< Pointer to array of preinit functions. */
  LIEF_DT_PREINIT_ARRAYSZ            = 33,         /**< Size of the DT_PREINIT_ARRAY array. */

  LIEF_DT_LOOS                       = 0x60000000, /**< Start of environment specific tags. */
  LIEF_DT_HIOS                       = 0x6FFFFFFF, /**< End of environment specific tags. */
  LIEF_DT_LOPROC                     = 0x70000000, /**< Start of processor specific tags. */
  LIEF_DT_HIPROC                     = 0x7FFFFFFF, /**< End of processor specific tags. */

  LIEF_DT_GNU_HASH                   = 0x6FFFFEF5, /**< Reference to the GNU hash table. */
  LIEF_DT_RELACOUNT                  = 0x6FFFFFF9, /**< ELF32_Rela count. */
  LIEF_DT_RELCOUNT                   = 0x6FFFFFFA, /**< ELF32_Rel count. */

  LIEF_DT_FLAGS_1                    = 0x6FFFFFFB, /**< Flags_1. */
  LIEF_DT_VERSYM                     = 0x6FFFFFF0, /**< The address of .gnu.version section. */
  LIEF_DT_VERDEF                     = 0x6FFFFFFC, /**< The address of the version definition table. */
  LIEF_DT_VERDEFNUM                  = 0x6FFFFFFD, /**< The number of entries in DT_VERDEF. */
  LIEF_DT_VERNEED                    = 0x6FFFFFFE, /**< The address of the version Dependency table. */
  LIEF_DT_VERNEEDNUM                 = 0x6FFFFFFF, /**< The number of entries in DT_VERNEED. */

  /* Mips specific dynamic table entry tags. */
  LIEF_DT_MIPS_RLD_VERSION           = 0x70000001, /**< 32 bit version number for runtime linker interface. */
  LIEF_DT_MIPS_TIME_STAMP            = 0x70000002, /**< Time stamp. */
  LIEF_DT_MIPS_ICHECKSUM             = 0x70000003, /**< Checksum of external strings and common sizes. */
  LIEF_DT_MIPS_IVERSION              = 0x70000004, /**< Index of version string in string table. */
  LIEF_DT_MIPS_FLAGS                 = 0x70000005, /**< 32 bits of flags. */
  LIEF_DT_MIPS_BASE_ADDRESS          = 0x70000006, /**< Base address of the segment. */
  LIEF_DT_MIPS_MSYM                  = 0x70000007, /**< Address of .msym section. */
  LIEF_DT_MIPS_CONFLICT              = 0x70000008, /**< Address of .conflict section. */
  LIEF_DT_MIPS_LIBLIST               = 0x70000009, /**< Address of .liblist section. */
  LIEF_DT_MIPS_LOCAL_GOTNO           = 0x7000000a, /**< Number of local global offset table entries. */
  LIEF_DT_MIPS_CONFLICTNO            = 0x7000000b, /**< Number of entries in the .conflict section. */
  LIEF_DT_MIPS_LIBLISTNO             = 0x70000010, /**< Number of entries in the .liblist section. */
  LIEF_DT_MIPS_SYMTABNO              = 0x70000011, /**< Number of entries in the .dynsym section. */
  LIEF_DT_MIPS_UNREFEXTNO            = 0x70000012, /**< Index of first external dynamic symbol not referenced locally. */
  LIEF_DT_MIPS_GOTSYM                = 0x70000013, /**< Index of first dynamic symbol in global offset table. */
  LIEF_DT_MIPS_HIPAGENO              = 0x70000014, /**< Number of page table entries in global offset table. */
  LIEF_DT_MIPS_RLD_MAP               = 0x70000016, /**< Address of run time loader map, used for debugging. */
  LIEF_DT_MIPS_DELTA_CLASS           = 0x70000017, /**< Delta C++ class definition. */
  LIEF_DT_MIPS_DELTA_CLASS_NO        = 0x70000018, /**< Number of entries in DT_MIPS_DELTA_CLASS. */
  LIEF_DT_MIPS_DELTA_INSTANCE        = 0x70000019, /**< Delta C++ class instances. */
  LIEF_DT_MIPS_DELTA_INSTANCE_NO     = 0x7000001A, /**< Number of entries in DT_MIPS_DELTA_INSTANCE. */
  LIEF_DT_MIPS_DELTA_RELOC           = 0x7000001B, /**< Delta relocations. */
  LIEF_DT_MIPS_DELTA_RELOC_NO        = 0x7000001C, /**< Number of entries in DT_MIPS_DELTA_RELOC. */
  LIEF_DT_MIPS_DELTA_SYM             = 0x7000001D, /**< Delta symbols that Delta relocations refer to. */
  LIEF_DT_MIPS_DELTA_SYM_NO          = 0x7000001E, /**< Number of entries in DT_MIPS_DELTA_SYM. */
  LIEF_DT_MIPS_DELTA_CLASSSYM        = 0x70000020, /**< Delta symbols that hold class declarations. */
  LIEF_DT_MIPS_DELTA_CLASSSYM_NO     = 0x70000021, /**< Number of entries in DT_MIPS_DELTA_CLASSSYM. */
  LIEF_DT_MIPS_CXX_FLAGS             = 0x70000022, /**< Flags indicating information about C++ flavor. */
  LIEF_DT_MIPS_PIXIE_INIT            = 0x70000023, /**< Pixie information. */
  LIEF_DT_MIPS_SYMBOL_LIB            = 0x70000024, /**< Address of .MIPS.symlib */
  LIEF_DT_MIPS_LOCALPAGE_GOTIDX      = 0x70000025, /**< The GOT index of the first PTE for a segment */
  LIEF_DT_MIPS_LOCAL_GOTIDX          = 0x70000026, /**< The GOT index of the first PTE for a local symbol */
  LIEF_DT_MIPS_HIDDEN_GOTIDX         = 0x70000027, /**< The GOT index of the first PTE for a hidden symbol */
  LIEF_DT_MIPS_PROTECTED_GOTIDX      = 0x70000028, /**< The GOT index of the first PTE for a protected symbol */
  LIEF_DT_MIPS_OPTIONS               = 0x70000029, /**< Address of `.MIPS.options'. */
  LIEF_DT_MIPS_INTERFACE             = 0x7000002A, /**< Address of `.interface'. */
  LIEF_DT_MIPS_DYNSTR_ALIGN          = 0x7000002B, /**< Unknown. */
  LIEF_DT_MIPS_INTERFACE_SIZE        = 0x7000002C, /**< Size of the .interface section. */
  LIEF_DT_MIPS_RLD_TEXT_RESOLVE_ADDR = 0x7000002D, /**< Size of rld_text_resolve function stored in the GOT. */
  LIEF_DT_MIPS_PERF_SUFFIX           = 0x7000002E, /**< Default suffix of DSO to be added by rld on dlopen( calls. */
  LIEF_DT_MIPS_COMPACT_SIZE          = 0x7000002F, /**< Size of compact relocation section (O32. */
  LIEF_DT_MIPS_GP_VALUE              = 0x70000030, /**< GP value for auxiliary GOTs. */
  LIEF_DT_MIPS_AUX_DYNAMIC           = 0x70000031, /**< Address of auxiliary .dynamic. */
  LIEF_DT_MIPS_PLTGOT                = 0x70000032, /**< Address of the base of the PLTGOT. */
  LIEF_DT_MIPS_RWPLT                 = 0x70000034, /**< Points to the base of a writable PLT. */

  /* Android specific dynamic table entry tags. */
  LIEF_DT_ANDROID_REL_OFFSET         = 0x6000000D, /**< The offset of packed relocation data (older version < M) (Android specific. */
  LIEF_DT_ANDROID_REL_SIZE           = 0x6000000E, /**< The size of packed relocation data in bytes (older version < M) (Android specific. */
  LIEF_DT_ANDROID_REL                = 0x6000000F, /**< The offset of packed relocation data (Android specific. */
  LIEF_DT_ANDROID_RELSZ              = 0x60000010, /**< The size of packed relocation data in bytes (Android specific. */
  LIEF_DT_ANDROID_RELA               = 0x60000011, /**< The offset of packed relocation data (Android specific. */
  LIEF_DT_ANDROID_RELASZ             = 0x60000012, /**< The size of packed relocation data in bytes (Android specific. */
  LIEF_DT_RELR                       = 0x6FFFE000, /**< The offset of new relr relocation data (Android specific. */
  LIEF_DT_RELRSZ                     = 0x6FFFE001, /**< The size of nre relr relocation data in bytes (Android specific. */
  LIEF_DT_RELRENT                    = 0x6FFFE003, /**< The size of a new relr relocation entry (Android specific. */
  LIEF_DT_RELRCOUNT                  = 0x6FFFE005 /**< Specifies the relative count of new relr relocation entries (Android specific. */
};

/** DT_FLAGS and DT_FLAGS_1 values. */
enum LIEF_DYNAMIC_FLAGS {
  LIEF_DF_ORIGIN       = 0x00000001, /**< The object may reference $ORIGIN. */
  LIEF_DF_SYMBOLIC     = 0x00000002, /**< Search the shared lib before searching the exe. */
  LIEF_DF_TEXTREL      = 0x00000004, /**< Relocations may modify a non-writable segment. */
  LIEF_DF_BIND_NOW     = 0x00000008, /**< Process all relocations on load. */
  LIEF_DF_STATIC_TLS   = 0x00000010, /**< Reject attempts to load dynamically. */
};

enum LIEF_DYNAMIC_FLAGS_1 {
  LIEF_DF_1_NOW        = 0x00000001, /**< Set RTLD_NOW for this object. */
  LIEF_DF_1_GLOBAL     = 0x00000002, /**< Set RTLD_GLOBAL for this object. */
  LIEF_DF_1_GROUP      = 0x00000004, /**< Set RTLD_GROUP for this object. */
  LIEF_DF_1_NODELETE   = 0x00000008, /**< Set RTLD_NODELETE for this object. */
  LIEF_DF_1_LOADFLTR   = 0x00000010, /**< Trigger filtee loading at runtime. */
  LIEF_DF_1_INITFIRST  = 0x00000020, /**< Set RTLD_INITFIRST for this object. */
  LIEF_DF_1_NOOPEN     = 0x00000040, /**< Set RTLD_NOOPEN for this object. */
  LIEF_DF_1_ORIGIN     = 0x00000080, /**< $ORIGIN must be handled. */
  LIEF_DF_1_DIRECT     = 0x00000100, /**< Direct binding enabled. */
  LIEF_DF_1_TRANS      = 0x00000200,
  LIEF_DF_1_INTERPOSE  = 0x00000400, /**< Object is used to interpose. */
  LIEF_DF_1_NODEFLIB   = 0x00000800, /**< Ignore default lib search path. */
  LIEF_DF_1_NODUMP     = 0x00001000, /**< Object can't be dldump'ed. */
  LIEF_DF_1_CONFALT    = 0x00002000, /**< Configuration alternative created. */
  LIEF_DF_1_ENDFILTEE  = 0x00004000, /**< Filtee terminates filters search. */
  LIEF_DF_1_DISPRELDNE = 0x00008000, /**< Disp reloc applied at build time. */
  LIEF_DF_1_DISPRELPND = 0x00010000, /**< Disp reloc applied at run-time. */
  LIEF_DF_1_NODIRECT   = 0x00020000, /**< Object has no-direct binding. */
  LIEF_DF_1_IGNMULDEF  = 0x00040000,
  LIEF_DF_1_NOKSYMS    = 0x00080000,
  LIEF_DF_1_NOHDR      = 0x00100000,
  LIEF_DF_1_EDITED     = 0x00200000, /**< Object is modified after built. */
  LIEF_DF_1_NORELOC    = 0x00400000,
  LIEF_DF_1_SYMINTPOSE = 0x00800000, /**< Object has individual interposers. */
  LIEF_DF_1_GLOBAUDIT  = 0x01000000, /**< Global auditing required. */
  LIEF_DF_1_SINGLETON  = 0x02000000,  /**< Singleton symbols are used. */
  LIEF_DF_1_PIE        = 0x08000000  /**< Singleton symbols are used. */
};

/* DT_MIPS_FLAGS values. */
enum {
  LIEF_RHF_NONE                    = 0x00000000, /* No flags. */
  LIEF_RHF_QUICKSTART              = 0x00000001, /* Uses shortcut pointers. */
  LIEF_RHF_NOTPOT                  = 0x00000002, /* Hash size is not a power of two. */
  LIEF_RHS_NO_LIBRARY_REPLACEMENT  = 0x00000004, /* Ignore LD_LIBRARY_PATH. */
  LIEF_RHF_NO_MOVE                 = 0x00000008, /* DSO address may not be relocated. */
  LIEF_RHF_SGI_ONLY                = 0x00000010, /* SGI specific features. */
  LIEF_RHF_GUARANTEE_INIT          = 0x00000020, /* Guarantee that .init will finish */
  /* executing before any non-init */
  /* code in DSO is called. */
  LIEF_RHF_DELTA_C_PLUS_PLUS       = 0x00000040, /* Contains Delta C++ code. */
  LIEF_RHF_GUARANTEE_START_INIT    = 0x00000080, /* Guarantee that .init will start */
  /* executing before any non-init */
  /* code in DSO is called. */
  LIEF_RHF_PIXIE                   = 0x00000100, /* Generated by pixie. */
  LIEF_RHF_DEFAULT_DELAY_LOAD      = 0x00000200, /* Delay-load DSO by default. */
  LIEF_RHF_REQUICKSTART            = 0x00000400, /* Object may be requickstarted */
  LIEF_RHF_REQUICKSTARTED          = 0x00000800, /* Object has been requickstarted */
  LIEF_RHF_CORD                    = 0x00001000, /* Generated by cord. */
  LIEF_RHF_NO_UNRES_UNDEF          = 0x00002000, /* Object contains no unresolved */
  /* undef symbols. */
  LIEF_RHF_RLD_ORDER_SAFE          = 0x00004000  /* Symbol table is in a safe order. */
};

/** ElfXX_VerDef structure version (GNU versioning) */
enum {
  LIEF_VER_DEF_NONE    = 0,
  LIEF_VER_DEF_CURRENT = 1
};

/** VerDef Flags (ElfXX_VerDef::vd_flags) */
enum {
  LIEF_VER_FLG_BASE = 0x1,
  LIEF_VER_FLG_WEAK = 0x2,
  LIEF_VER_FLG_INFO = 0x4
};

/** Special constants for the version table. (SHT_GNU_versym/.gnu.version) */
enum {
  LIEF_VER_NDX_LOCAL  = 0,      /**< Unversioned local symbol */
  LIEF_VER_NDX_GLOBAL = 1,      /**< Unversioned global symbol */
  LIEF_VERSYM_VERSION = 0x7fff, /**< Version Index mask */
  LIEF_VERSYM_HIDDEN  = 0x8000  /**< Hidden bit (non-default version */
};

/** ElfXX_VerNeed structure version (GNU versioning) */
enum {
  LIEF_VER_NEED_NONE = 0,
  LIEF_VER_NEED_CURRENT = 1
};

enum LIEF_AUX_TYPE {
   LIEF_AT_NULL          = 0,     /**< End of vector */
   LIEF_AT_IGNORE        = 1,     /**< Entry should be ignored */
   LIEF_AT_EXECFD        = 2,     /**< File descriptor of program */
   LIEF_AT_PHDR          = 3,     /**< Program headers for program */
   LIEF_AT_PHENT         = 4,     /**< Size of program header entry */
   LIEF_AT_PHNUM         = 5,     /**< Number of program headers */
   LIEF_AT_PAGESZ        = 6,     /**< System page size */
   LIEF_AT_BASE          = 7,     /**< Base address of interpreter */
   LIEF_AT_FLAGS         = 8,     /**< Flags */
   LIEF_AT_ENTRY         = 9,     /**< Entry point of program */
   LIEF_AT_NOTELF        = 10,    /**< Program is not ELF */
   LIEF_AT_UID           = 11,    /**< Real uid */
   LIEF_AT_EUID          = 12,    /**< Effective uid */
   LIEF_AT_GID           = 13,    /**< Real gid */
   LIEF_AT_EGID          = 14,    /**< Effective gid */
   LIEF_AT_CLKTCK        = 17,    /**< Frequency of times( */

   /* Some more special a_type values describing the hardware.  */

   LIEF_AT_PLATFORM      = 15,    /**< String identifying platform.  */
   LIEF_AT_HWCAP         = 16,    /**< Machine dependent hints about processor capabilities.  */

   /* This entry gives some information about the FPU initialization
      performed by the kernel. */

   LIEF_AT_FPUCW        = 18,    /**< Used FPU control word.  */

   /* Cache block sizes. */
   LIEF_AT_DCACHEBSIZE   = 19,    /**< Data cache block size.  */
   LIEF_AT_ICACHEBSIZE   = 20,    /**< Instruction cache block size.  */
   LIEF_AT_UCACHEBSIZE   = 21,    /**< Unified cache block size.  */

   /* A special ignored value for PPC, used by the kernel to control the
      interpretation of the AUXV. Must be > 16.  */

   LIEF_AT_IGNOREPPC     = 22,    /**< Entry should be ignored.  */
   LIEF_AT_SECURE        = 23,    /**< Boolean, was exec setuid-like?  */
   LIEF_AT_BASE_PLATFORM = 24,    /**< String identifying real platforms.*/
   LIEF_AT_RANDOM        = 25,    /**< Address of 16 random bytes.  */
   LIEF_AT_HWCAP2        = 26,    /**< Extension of AT_HWCAP.  */
   LIEF_AT_EXECFN        = 31,    /**< Filename of executable.  */

   /* Pointer to the global system page used for system calls and other
      nice things. */
   LIEF_AT_SYSINFO       = 32,
   LIEF_AT_SYSINFO_EHDR  = 33,

   /* Shapes of the caches.  Bits 0-3 contains associativity; bits 4-7 contains
      log2 of line size; mask those to get cache size.  */
   LIEF_AT_L1I_CACHESHAPE  = 34,
   LIEF_AT_L1D_CACHESHAPE  = 35,
   LIEF_AT_L2_CACHESHAPE   = 36,
   LIEF_AT_L3_CACHESHAPE   = 37
};

/** Methods that can be used by the LIEF::ELF::Parser
    to count the number of dynamic symbols */
enum LIEF_DYNSYM_COUNT_METHODS {
  LIEF_COUNT_AUTO        = 0, /**< Automatic detection */
  LIEF_COUNT_SECTION     = 1, /**< Count based on sections (not very reliable */
  LIEF_COUNT_HASH        = 2, /**< Count based on hash table (reliable */
  LIEF_COUNT_RELOCATIONS = 3, /**< Count based on PLT/GOT relocations (very reliable but not accurate */
};

enum LIEF_NOTE_TYPES {
  LIEF_NT_UNKNOWN                  = 0,
  LIEF_NT_GNU_ABI_TAG              = 1,
  LIEF_NT_GNU_HWCAP                = 2,
  LIEF_NT_GNU_BUILD_ID             = 3,
  LIEF_NT_GNU_GOLD_VERSION         = 4,
  LIEF_NT_GNU_PROPERTY_TYPE_0      = 5,
  LIEF_NT_GNU_BUILD_ATTRIBUTE_OPEN = 0x100,
  LIEF_NT_GNU_BUILD_ATTRIBUTE_FUNC = 0x101,
  LIEF_NT_CRASHPAD                 = 0x4f464e49,
};

enum LIEF_NOTE_TYPES_CORE {
  LIEF_NT_CORE_UNKNOWN     = 0,
  LIEF_NT_PRSTATUS         = 1,
  LIEF_NT_PRFPREG          = 2,
  LIEF_NT_PRPSINFO         = 3,
  LIEF_NT_TASKSTRUCT       = 4,
  LIEF_NT_AUXV             = 6,
  LIEF_NT_SIGINFO          = 0x53494749,
  LIEF_NT_FILE             = 0x46494c45,
  LIEF_NT_PRXFPREG         = 0x46e62b7f,

  LIEF_NT_ARM_VFP          = 0x400,
  LIEF_NT_ARM_TLS          = 0x401,
  LIEF_NT_ARM_HW_BREAK     = 0x402,
  LIEF_NT_ARM_HW_WATCH     = 0x403,
  LIEF_NT_ARM_SYSTEM_CALL  = 0x404,
  LIEF_NT_ARM_SVE          = 0x405,

  LIEF_NT_386_TLS          = 0x200,
  LIEF_NT_386_IOPERM       = 0x201,
  LIEF_NT_386_XSTATE       = 0x202,

};


enum LIEF_NOTE_ABIS {
  LIEF_ELF_NOTE_UNKNOWN     = ~(unsigned int)(0),
  LIEF_ELF_NOTE_OS_LINUX    = 0,
  LIEF_ELF_NOTE_OS_GNU      = 1,
  LIEF_ELF_NOTE_OS_SOLARIS2 = 2,
  LIEF_ELF_NOTE_OS_FREEBSD  = 3,
  LIEF_ELF_NOTE_OS_NETBSD   = 4,
  LIEF_ELF_NOTE_OS_SYLLABLE = 5,
};

enum LIEF_RELOCATION_PURPOSES {
  LIEF_RELOC_PURPOSE_NONE    = 0,
  LIEF_RELOC_PURPOSE_PLTGOT  = 1,
  LIEF_RELOC_PURPOSE_DYNAMIC = 2,
  LIEF_RELOC_PURPOSE_OBJECT  = 3,
};

#ifdef __cplusplus
}
#endif


#endif
