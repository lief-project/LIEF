use std::marker::PhantomData;

use std::pin::Pin;
use lief_ffi as ffi;
use bitflags::bitflags;

use crate::common::FromFFI;
use crate::declare_iterator;


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Tag {
    DT_NULL_,
    NEEDED,
    PLTRELSZ,
    PLTGOT,
    HASH,
    STRTAB,
    SYMTAB,
    RELA,
    RELASZ,
    RELAENT,
    STRSZ,
    SYMENT,
    INIT,
    FINI,
    SONAME,
    RPATH,
    SYMBOLIC,
    REL,
    RELSZ,
    RELENT,
    PLTREL,
    DEBUG_TAG,
    TEXTREL,
    JMPREL,
    BIND_NOW,
    INIT_ARRAY,
    FINI_ARRAY,
    INIT_ARRAYSZ,
    FINI_ARRAYSZ,
    RUNPATH,
    FLAGS,
    PREINIT_ARRAY,
    PREINIT_ARRAYSZ,
    SYMTAB_SHNDX,
    RELRSZ,
    RELR,
    RELRENT,
    GNU_HASH,
    RELACOUNT,
    RELCOUNT,
    FLAGS_1,
    VERSYM,
    VERDEF,
    VERDEFNUM,
    VERNEED,
    VERNEEDNUM,
    ANDROID_REL_OFFSET,
    ANDROID_REL_SIZE,
    ANDROID_REL,
    ANDROID_RELSZ,
    ANDROID_RELA,
    ANDROID_RELASZ,
    ANDROID_RELR,
    ANDROID_RELRSZ,
    ANDROID_RELRENT,
    ANDROID_RELRCOUNT,
    MIPS_RLD_VERSION,
    MIPS_TIME_STAMP,
    MIPS_ICHECKSUM,
    MIPS_IVERSION,
    MIPS_FLAGS,
    MIPS_BASE_ADDRESS,
    MIPS_MSYM,
    MIPS_CONFLICT,
    MIPS_LIBLIST,
    MIPS_LOCAL_GOTNO,
    MIPS_CONFLICTNO,
    MIPS_LIBLISTNO,
    MIPS_SYMTABNO,
    MIPS_UNREFEXTNO,
    MIPS_GOTSYM,
    MIPS_HIPAGENO,
    MIPS_RLD_MAP,
    MIPS_DELTA_CLASS,
    MIPS_DELTA_CLASS_NO,
    MIPS_DELTA_INSTANCE,
    MIPS_DELTA_INSTANCE_NO,
    MIPS_DELTA_RELOC,
    MIPS_DELTA_RELOC_NO,
    MIPS_DELTA_SYM,
    MIPS_DELTA_SYM_NO,
    MIPS_DELTA_CLASSSYM,
    MIPS_DELTA_CLASSSYM_NO,
    MIPS_CXX_FLAGS,
    MIPS_PIXIE_INIT,
    MIPS_SYMBOL_LIB,
    MIPS_LOCALPAGE_GOTIDX,
    MIPS_LOCAL_GOTIDX,
    MIPS_HIDDEN_GOTIDX,
    MIPS_PROTECTED_GOTIDX,
    MIPS_OPTIONS,
    MIPS_INTERFACE,
    MIPS_DYNSTR_ALIGN,
    MIPS_INTERFACE_SIZE,
    MIPS_RLD_TEXT_RESOLVE_ADDR,
    MIPS_PERF_SUFFIX,
    MIPS_COMPACT_SIZE,
    MIPS_GP_VALUE,
    MIPS_AUX_DYNAMIC,
    MIPS_PLTGOT,
    MIPS_RWPLT,
    MIPS_RLD_MAP_REL,
    MIPS_XHASH,
    AARCH64_BTI_PLT,
    AARCH64_PAC_PLT,
    AARCH64_VARIANT_PCS,
    AARCH64_MEMTAG_MODE,
    AARCH64_MEMTAG_HEAP,
    AARCH64_MEMTAG_STACK,
    AARCH64_MEMTAG_GLOBALS,
    AARCH64_MEMTAG_GLOBALSSZ,
    HEXAGON_SYMSZ,
    HEXAGON_VER,
    HEXAGON_PLT,
    PPC_GOT,
    PPC_OPT,
    PPC64_GLINK,
    PPC64_OPT,
    RISCV_VARIANT_CC,
    X86_64_PLT,
    X86_64_PLTSZ,
    X86_64_PLTENT,
    IA_64_PLT_RESERVE,
    IA_64_VMS_SUBTYPE,
    IA_64_VMS_IMGIOCNT,
    IA_64_VMS_LNKFLAGS,
    IA_64_VMS_VIR_MEM_BLK_SIZ,
    IA_64_VMS_IDENT,
    IA_64_VMS_NEEDED_IDENT,
    IA_64_VMS_IMG_RELA_CNT,
    IA_64_VMS_SEG_RELA_CNT,
    IA_64_VMS_FIXUP_RELA_CNT,
    IA_64_VMS_FIXUP_NEEDED,
    IA_64_VMS_SYMVEC_CNT,
    IA_64_VMS_XLATED,
    IA_64_VMS_STACKSIZE,
    IA_64_VMS_UNWINDSZ,
    IA_64_VMS_UNWIND_CODSEG,
    IA_64_VMS_UNWIND_INFOSEG,
    IA_64_VMS_LINKTIME,
    IA_64_VMS_SEG_NO,
    IA_64_VMS_SYMVEC_OFFSET,
    IA_64_VMS_SYMVEC_SEG,
    IA_64_VMS_UNWIND_OFFSET,
    IA_64_VMS_UNWIND_SEG,
    IA_64_VMS_STRTAB_OFFSET,
    IA_64_VMS_SYSVER_OFFSET,
    IA_64_VMS_IMG_RELA_OFF,
    IA_64_VMS_SEG_RELA_OFF,
    IA_64_VMS_FIXUP_RELA_OFF,
    IA_64_VMS_PLTGOT_OFFSET,
    IA_64_VMS_PLTGOT_SEG,
    IA_64_VMS_FPMODE,
    UNKNOWN(u64),
}

impl From<u64> for Tag {
    fn from(value: u64) -> Self {
        match value {
            0x00000000 => Tag::DT_NULL_,
            0x00000001 => Tag::NEEDED,
            0x00000002 => Tag::PLTRELSZ,
            0x00000003 => Tag::PLTGOT,
            0x00000004 => Tag::HASH,
            0x00000005 => Tag::STRTAB,
            0x00000006 => Tag::SYMTAB,
            0x00000007 => Tag::RELA,
            0x00000008 => Tag::RELASZ,
            0x00000009 => Tag::RELAENT,
            0x0000000a => Tag::STRSZ,
            0x0000000b => Tag::SYMENT,
            0x0000000c => Tag::INIT,
            0x0000000d => Tag::FINI,
            0x0000000e => Tag::SONAME,
            0x0000000f => Tag::RPATH,
            0x00000010 => Tag::SYMBOLIC,
            0x00000011 => Tag::REL,
            0x00000012 => Tag::RELSZ,
            0x00000013 => Tag::RELENT,
            0x00000014 => Tag::PLTREL,
            0x00000015 => Tag::DEBUG_TAG,
            0x00000016 => Tag::TEXTREL,
            0x00000017 => Tag::JMPREL,
            0x00000018 => Tag::BIND_NOW,
            0x00000019 => Tag::INIT_ARRAY,
            0x0000001a => Tag::FINI_ARRAY,
            0x0000001b => Tag::INIT_ARRAYSZ,
            0x0000001c => Tag::FINI_ARRAYSZ,
            0x0000001d => Tag::RUNPATH,
            0x0000001e => Tag::FLAGS,
            0x00000020 => Tag::PREINIT_ARRAY,
            0x00000021 => Tag::PREINIT_ARRAYSZ,
            0x00000022 => Tag::SYMTAB_SHNDX,
            0x00000023 => Tag::RELRSZ,
            0x00000024 => Tag::RELR,
            0x00000025 => Tag::RELRENT,
            0x6ffffef5 => Tag::GNU_HASH,
            0x6ffffff9 => Tag::RELACOUNT,
            0x6ffffffa => Tag::RELCOUNT,
            0x6ffffffb => Tag::FLAGS_1,
            0x6ffffff0 => Tag::VERSYM,
            0x6ffffffc => Tag::VERDEF,
            0x6ffffffd => Tag::VERDEFNUM,
            0x6ffffffe => Tag::VERNEED,
            0x6fffffff => Tag::VERNEEDNUM,
            0x6000000d => Tag::ANDROID_REL_OFFSET,
            0x6000000e => Tag::ANDROID_REL_SIZE,
            0x6000000f => Tag::ANDROID_REL,
            0x60000010 => Tag::ANDROID_RELSZ,
            0x60000011 => Tag::ANDROID_RELA,
            0x60000012 => Tag::ANDROID_RELASZ,
            0x6fffe000 => Tag::ANDROID_RELR,
            0x6fffe001 => Tag::ANDROID_RELRSZ,
            0x6fffe003 => Tag::ANDROID_RELRENT,
            0x6fffe005 => Tag::ANDROID_RELRCOUNT,
            0x170000001 => Tag::MIPS_RLD_VERSION,
            0x170000002 => Tag::MIPS_TIME_STAMP,
            0x170000003 => Tag::MIPS_ICHECKSUM,
            0x170000004 => Tag::MIPS_IVERSION,
            0x170000005 => Tag::MIPS_FLAGS,
            0x170000006 => Tag::MIPS_BASE_ADDRESS,
            0x170000007 => Tag::MIPS_MSYM,
            0x170000008 => Tag::MIPS_CONFLICT,
            0x170000009 => Tag::MIPS_LIBLIST,
            0x17000000a => Tag::MIPS_LOCAL_GOTNO,
            0x17000000b => Tag::MIPS_CONFLICTNO,
            0x170000010 => Tag::MIPS_LIBLISTNO,
            0x170000011 => Tag::MIPS_SYMTABNO,
            0x170000012 => Tag::MIPS_UNREFEXTNO,
            0x170000013 => Tag::MIPS_GOTSYM,
            0x170000014 => Tag::MIPS_HIPAGENO,
            0x170000016 => Tag::MIPS_RLD_MAP,
            0x170000017 => Tag::MIPS_DELTA_CLASS,
            0x170000018 => Tag::MIPS_DELTA_CLASS_NO,
            0x170000019 => Tag::MIPS_DELTA_INSTANCE,
            0x17000001a => Tag::MIPS_DELTA_INSTANCE_NO,
            0x17000001b => Tag::MIPS_DELTA_RELOC,
            0x17000001c => Tag::MIPS_DELTA_RELOC_NO,
            0x17000001d => Tag::MIPS_DELTA_SYM,
            0x17000001e => Tag::MIPS_DELTA_SYM_NO,
            0x170000020 => Tag::MIPS_DELTA_CLASSSYM,
            0x170000021 => Tag::MIPS_DELTA_CLASSSYM_NO,
            0x170000022 => Tag::MIPS_CXX_FLAGS,
            0x170000023 => Tag::MIPS_PIXIE_INIT,
            0x170000024 => Tag::MIPS_SYMBOL_LIB,
            0x170000025 => Tag::MIPS_LOCALPAGE_GOTIDX,
            0x170000026 => Tag::MIPS_LOCAL_GOTIDX,
            0x170000027 => Tag::MIPS_HIDDEN_GOTIDX,
            0x170000028 => Tag::MIPS_PROTECTED_GOTIDX,
            0x170000029 => Tag::MIPS_OPTIONS,
            0x17000002a => Tag::MIPS_INTERFACE,
            0x17000002b => Tag::MIPS_DYNSTR_ALIGN,
            0x17000002c => Tag::MIPS_INTERFACE_SIZE,
            0x17000002d => Tag::MIPS_RLD_TEXT_RESOLVE_ADDR,
            0x17000002e => Tag::MIPS_PERF_SUFFIX,
            0x17000002f => Tag::MIPS_COMPACT_SIZE,
            0x170000030 => Tag::MIPS_GP_VALUE,
            0x170000031 => Tag::MIPS_AUX_DYNAMIC,
            0x170000032 => Tag::MIPS_PLTGOT,
            0x170000034 => Tag::MIPS_RWPLT,
            0x170000035 => Tag::MIPS_RLD_MAP_REL,
            0x170000036 => Tag::MIPS_XHASH,
            0x270000001 => Tag::AARCH64_BTI_PLT,
            0x270000003 => Tag::AARCH64_PAC_PLT,
            0x270000005 => Tag::AARCH64_VARIANT_PCS,
            0x270000009 => Tag::AARCH64_MEMTAG_MODE,
            0x27000000b => Tag::AARCH64_MEMTAG_HEAP,
            0x27000000c => Tag::AARCH64_MEMTAG_STACK,
            0x27000000d => Tag::AARCH64_MEMTAG_GLOBALS,
            0x27000000f => Tag::AARCH64_MEMTAG_GLOBALSSZ,
            0x370000000 => Tag::HEXAGON_SYMSZ,
            0x370000001 => Tag::HEXAGON_VER,
            0x370000002 => Tag::HEXAGON_PLT,
            0x470000000 => Tag::PPC_GOT,
            0x470000001 => Tag::PPC_OPT,
            0x570000000 => Tag::PPC64_GLINK,
            0x570000003 => Tag::PPC64_OPT,
            0x670000003 => Tag::RISCV_VARIANT_CC,
            0x770000000 => Tag::X86_64_PLT,
            0x770000001 => Tag::X86_64_PLTSZ,
            0x770000003 => Tag::X86_64_PLTENT,
            0x870000000 => Tag::IA_64_PLT_RESERVE,
            0x860000000 => Tag::IA_64_VMS_SUBTYPE,
            0x860000002 => Tag::IA_64_VMS_IMGIOCNT,
            0x860000008 => Tag::IA_64_VMS_LNKFLAGS,
            0x86000000a => Tag::IA_64_VMS_VIR_MEM_BLK_SIZ,
            0x86000000c => Tag::IA_64_VMS_IDENT,
            0x860000010 => Tag::IA_64_VMS_NEEDED_IDENT,
            0x860000012 => Tag::IA_64_VMS_IMG_RELA_CNT,
            0x860000014 => Tag::IA_64_VMS_SEG_RELA_CNT,
            0x860000016 => Tag::IA_64_VMS_FIXUP_RELA_CNT,
            0x860000018 => Tag::IA_64_VMS_FIXUP_NEEDED,
            0x86000001a => Tag::IA_64_VMS_SYMVEC_CNT,
            0x86000001e => Tag::IA_64_VMS_XLATED,
            0x860000020 => Tag::IA_64_VMS_STACKSIZE,
            0x860000022 => Tag::IA_64_VMS_UNWINDSZ,
            0x860000024 => Tag::IA_64_VMS_UNWIND_CODSEG,
            0x860000026 => Tag::IA_64_VMS_UNWIND_INFOSEG,
            0x860000028 => Tag::IA_64_VMS_LINKTIME,
            0x86000002a => Tag::IA_64_VMS_SEG_NO,
            0x86000002c => Tag::IA_64_VMS_SYMVEC_OFFSET,
            0x86000002e => Tag::IA_64_VMS_SYMVEC_SEG,
            0x860000030 => Tag::IA_64_VMS_UNWIND_OFFSET,
            0x860000032 => Tag::IA_64_VMS_UNWIND_SEG,
            0x860000034 => Tag::IA_64_VMS_STRTAB_OFFSET,
            0x860000036 => Tag::IA_64_VMS_SYSVER_OFFSET,
            0x860000038 => Tag::IA_64_VMS_IMG_RELA_OFF,
            0x86000003a => Tag::IA_64_VMS_SEG_RELA_OFF,
            0x86000003c => Tag::IA_64_VMS_FIXUP_RELA_OFF,
            0x86000003e => Tag::IA_64_VMS_PLTGOT_OFFSET,
            0x860000040 => Tag::IA_64_VMS_PLTGOT_SEG,
            0x860000042 => Tag::IA_64_VMS_FPMODE,
            _ => Tag::UNKNOWN(value),

        }
    }
}

impl From<Tag> for u64 {
    fn from(value: Tag) -> u64 {
        match value {
            Tag::DT_NULL_ => 0x00000000,
            Tag::NEEDED => 0x00000001,
            Tag::PLTRELSZ => 0x00000002,
            Tag::PLTGOT => 0x00000003,
            Tag::HASH => 0x00000004,
            Tag::STRTAB => 0x00000005,
            Tag::SYMTAB => 0x00000006,
            Tag::RELA => 0x00000007,
            Tag::RELASZ => 0x00000008,
            Tag::RELAENT => 0x00000009,
            Tag::STRSZ => 0x0000000a,
            Tag::SYMENT => 0x0000000b,
            Tag::INIT => 0x0000000c,
            Tag::FINI => 0x0000000d,
            Tag::SONAME => 0x0000000e,
            Tag::RPATH => 0x0000000f,
            Tag::SYMBOLIC => 0x00000010,
            Tag::REL => 0x00000011,
            Tag::RELSZ => 0x00000012,
            Tag::RELENT => 0x00000013,
            Tag::PLTREL => 0x00000014,
            Tag::DEBUG_TAG => 0x00000015,
            Tag::TEXTREL => 0x00000016,
            Tag::JMPREL => 0x00000017,
            Tag::BIND_NOW => 0x00000018,
            Tag::INIT_ARRAY => 0x00000019,
            Tag::FINI_ARRAY => 0x0000001a,
            Tag::INIT_ARRAYSZ => 0x0000001b,
            Tag::FINI_ARRAYSZ => 0x0000001c,
            Tag::RUNPATH => 0x0000001d,
            Tag::FLAGS => 0x0000001e,
            Tag::PREINIT_ARRAY => 0x00000020,
            Tag::PREINIT_ARRAYSZ => 0x00000021,
            Tag::SYMTAB_SHNDX => 0x00000022,
            Tag::RELRSZ => 0x00000023,
            Tag::RELR => 0x00000024,
            Tag::RELRENT => 0x00000025,
            Tag::GNU_HASH => 0x6ffffef5,
            Tag::RELACOUNT => 0x6ffffff9,
            Tag::RELCOUNT => 0x6ffffffa,
            Tag::FLAGS_1 => 0x6ffffffb,
            Tag::VERSYM => 0x6ffffff0,
            Tag::VERDEF => 0x6ffffffc,
            Tag::VERDEFNUM => 0x6ffffffd,
            Tag::VERNEED => 0x6ffffffe,
            Tag::VERNEEDNUM => 0x6fffffff,
            Tag::ANDROID_REL_OFFSET => 0x6000000d,
            Tag::ANDROID_REL_SIZE => 0x6000000e,
            Tag::ANDROID_REL => 0x6000000f,
            Tag::ANDROID_RELSZ => 0x60000010,
            Tag::ANDROID_RELA => 0x60000011,
            Tag::ANDROID_RELASZ => 0x60000012,
            Tag::ANDROID_RELR => 0x6fffe000,
            Tag::ANDROID_RELRSZ => 0x6fffe001,
            Tag::ANDROID_RELRENT => 0x6fffe003,
            Tag::ANDROID_RELRCOUNT => 0x6fffe005,
            Tag::MIPS_RLD_VERSION => 0x170000001,
            Tag::MIPS_TIME_STAMP => 0x170000002,
            Tag::MIPS_ICHECKSUM => 0x170000003,
            Tag::MIPS_IVERSION => 0x170000004,
            Tag::MIPS_FLAGS => 0x170000005,
            Tag::MIPS_BASE_ADDRESS => 0x170000006,
            Tag::MIPS_MSYM => 0x170000007,
            Tag::MIPS_CONFLICT => 0x170000008,
            Tag::MIPS_LIBLIST => 0x170000009,
            Tag::MIPS_LOCAL_GOTNO => 0x17000000a,
            Tag::MIPS_CONFLICTNO => 0x17000000b,
            Tag::MIPS_LIBLISTNO => 0x170000010,
            Tag::MIPS_SYMTABNO => 0x170000011,
            Tag::MIPS_UNREFEXTNO => 0x170000012,
            Tag::MIPS_GOTSYM => 0x170000013,
            Tag::MIPS_HIPAGENO => 0x170000014,
            Tag::MIPS_RLD_MAP => 0x170000016,
            Tag::MIPS_DELTA_CLASS => 0x170000017,
            Tag::MIPS_DELTA_CLASS_NO => 0x170000018,
            Tag::MIPS_DELTA_INSTANCE => 0x170000019,
            Tag::MIPS_DELTA_INSTANCE_NO => 0x17000001a,
            Tag::MIPS_DELTA_RELOC => 0x17000001b,
            Tag::MIPS_DELTA_RELOC_NO => 0x17000001c,
            Tag::MIPS_DELTA_SYM => 0x17000001d,
            Tag::MIPS_DELTA_SYM_NO => 0x17000001e,
            Tag::MIPS_DELTA_CLASSSYM => 0x170000020,
            Tag::MIPS_DELTA_CLASSSYM_NO => 0x170000021,
            Tag::MIPS_CXX_FLAGS => 0x170000022,
            Tag::MIPS_PIXIE_INIT => 0x170000023,
            Tag::MIPS_SYMBOL_LIB => 0x170000024,
            Tag::MIPS_LOCALPAGE_GOTIDX => 0x170000025,
            Tag::MIPS_LOCAL_GOTIDX => 0x170000026,
            Tag::MIPS_HIDDEN_GOTIDX => 0x170000027,
            Tag::MIPS_PROTECTED_GOTIDX => 0x170000028,
            Tag::MIPS_OPTIONS => 0x170000029,
            Tag::MIPS_INTERFACE => 0x17000002a,
            Tag::MIPS_DYNSTR_ALIGN => 0x17000002b,
            Tag::MIPS_INTERFACE_SIZE => 0x17000002c,
            Tag::MIPS_RLD_TEXT_RESOLVE_ADDR => 0x17000002d,
            Tag::MIPS_PERF_SUFFIX => 0x17000002e,
            Tag::MIPS_COMPACT_SIZE => 0x17000002f,
            Tag::MIPS_GP_VALUE => 0x170000030,
            Tag::MIPS_AUX_DYNAMIC => 0x170000031,
            Tag::MIPS_PLTGOT => 0x170000032,
            Tag::MIPS_RWPLT => 0x170000034,
            Tag::MIPS_RLD_MAP_REL => 0x170000035,
            Tag::MIPS_XHASH => 0x170000036,
            Tag::AARCH64_BTI_PLT => 0x270000001,
            Tag::AARCH64_PAC_PLT => 0x270000003,
            Tag::AARCH64_VARIANT_PCS => 0x270000005,
            Tag::AARCH64_MEMTAG_MODE => 0x270000009,
            Tag::AARCH64_MEMTAG_HEAP => 0x27000000b,
            Tag::AARCH64_MEMTAG_STACK => 0x27000000c,
            Tag::AARCH64_MEMTAG_GLOBALS => 0x27000000d,
            Tag::AARCH64_MEMTAG_GLOBALSSZ => 0x27000000f,
            Tag::HEXAGON_SYMSZ => 0x370000000,
            Tag::HEXAGON_VER => 0x370000001,
            Tag::HEXAGON_PLT => 0x370000002,
            Tag::PPC_GOT => 0x470000000,
            Tag::PPC_OPT => 0x470000001,
            Tag::PPC64_GLINK => 0x570000000,
            Tag::PPC64_OPT => 0x570000003,
            Tag::RISCV_VARIANT_CC => 0x670000003,
            Tag::X86_64_PLT => 0x770000000,
            Tag::X86_64_PLTSZ => 0x770000001,
            Tag::X86_64_PLTENT => 0x770000003,
            Tag::IA_64_PLT_RESERVE => 0x870000000,
            Tag::IA_64_VMS_SUBTYPE => 0x860000000,
            Tag::IA_64_VMS_IMGIOCNT => 0x860000002,
            Tag::IA_64_VMS_LNKFLAGS => 0x860000008,
            Tag::IA_64_VMS_VIR_MEM_BLK_SIZ => 0x86000000a,
            Tag::IA_64_VMS_IDENT => 0x86000000c,
            Tag::IA_64_VMS_NEEDED_IDENT => 0x860000010,
            Tag::IA_64_VMS_IMG_RELA_CNT => 0x860000012,
            Tag::IA_64_VMS_SEG_RELA_CNT => 0x860000014,
            Tag::IA_64_VMS_FIXUP_RELA_CNT => 0x860000016,
            Tag::IA_64_VMS_FIXUP_NEEDED => 0x860000018,
            Tag::IA_64_VMS_SYMVEC_CNT => 0x86000001a,
            Tag::IA_64_VMS_XLATED => 0x86000001e,
            Tag::IA_64_VMS_STACKSIZE => 0x860000020,
            Tag::IA_64_VMS_UNWINDSZ => 0x860000022,
            Tag::IA_64_VMS_UNWIND_CODSEG => 0x860000024,
            Tag::IA_64_VMS_UNWIND_INFOSEG => 0x860000026,
            Tag::IA_64_VMS_LINKTIME => 0x860000028,
            Tag::IA_64_VMS_SEG_NO => 0x86000002a,
            Tag::IA_64_VMS_SYMVEC_OFFSET => 0x86000002c,
            Tag::IA_64_VMS_SYMVEC_SEG => 0x86000002e,
            Tag::IA_64_VMS_UNWIND_OFFSET => 0x860000030,
            Tag::IA_64_VMS_UNWIND_SEG => 0x860000032,
            Tag::IA_64_VMS_STRTAB_OFFSET => 0x860000034,
            Tag::IA_64_VMS_SYSVER_OFFSET => 0x860000036,
            Tag::IA_64_VMS_IMG_RELA_OFF => 0x860000038,
            Tag::IA_64_VMS_SEG_RELA_OFF => 0x86000003a,
            Tag::IA_64_VMS_FIXUP_RELA_OFF => 0x86000003c,
            Tag::IA_64_VMS_PLTGOT_OFFSET => 0x86000003e,
            Tag::IA_64_VMS_PLTGOT_SEG => 0x860000040,
            Tag::IA_64_VMS_FPMODE => 0x860000042,
            Tag::UNKNOWN(value) => value,
        }
    }
}

#[derive(Debug)]
/// Enum that represents the different variants of a dynamic entry
pub enum Entries<'a> {
    /// Entry for `DT_NEEDED`
    Library(Library<'a>),

    /// Entry for `DT_INIT_ARRAY, DT_FINI_ARRAY`, ...
    Array(Array<'a>),

    /// Entry for `DT_RPATH`
    Rpath(Rpath<'a>),

    /// Entry for `DT_RUNPATH`
    RunPath(RunPath<'a>),

    /// Entry for `DT_SONAME`
    SharedObject(SharedObject<'a>),

    /// Entry for `DT_FLAGS` and `DT_FLAGS_1`
    Flags(Flags<'a>),

    /// Generic value
    Generic(Generic<'a>),
}

impl Entries<'_> {
    /// Create a new dynamic entry with the given Tag
    pub fn with_tag(tag: Tag) -> Entries<'static> {
        Entries::from_ffi(lief_ffi::ELF_DynamicEntry::create(tag.into()))
    }
}

/// Trait shared by all the [`Entries`]
pub trait DynamicEntry {
    #[doc(hidden)]
    fn as_base(&self) -> &ffi::ELF_DynamicEntry;

    #[doc(hidden)]
    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry>;

    /// Dynamic TAG associated with the entry
    fn tag(&self) -> Tag {
        Tag::from(self.as_base().tag())
    }

    /// Raw value which should be interpreted according to the [`DynamicEntry::tag`]
    fn value(&self) -> u64 {
        self.as_base().value()
    }

    fn set_value(&mut self, value: u64) {
        self.as_mut_base().set_value(value);
    }
}


impl std::fmt::Display for &dyn DynamicEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_base().to_string())
    }
}

impl DynamicEntry for Entries<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        match &self {
            Entries::Library(entry) => {
                entry.as_base()
            }

            Entries::Array(entry) => {
                entry.as_base()
            }

            Entries::Rpath(entry) => {
                entry.as_base()
            }

            Entries::RunPath(entry) => {
                entry.as_base()
            }

            Entries::SharedObject(entry) => {
                entry.as_base()
            }

            Entries::Flags(entry) => {
                entry.as_base()
            }

            Entries::Generic(entry) => {
                entry.as_base()
            }
        }
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        match self {
            Entries::Library(entry) => {
                entry.as_mut_base()
            }

            Entries::Array(entry) => {
                entry.as_mut_base()
            }

            Entries::Rpath(entry) => {
                entry.as_mut_base()
            }

            Entries::RunPath(entry) => {
                entry.as_mut_base()
            }

            Entries::SharedObject(entry) => {
                entry.as_mut_base()
            }

            Entries::Flags(entry) => {
                entry.as_mut_base()
            }

            Entries::Generic(entry) => {
                entry.as_mut_base()
            }
        }
    }


}


impl FromFFI<ffi::ELF_DynamicEntry> for Entries<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::ELF_DynamicEntry>) -> Self {
        unsafe {
            let cmd_ref = ffi_entry.as_ref().unwrap();

            if ffi::ELF_DynamicEntryLibrary::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Library(Library::from_ffi(raw))
            }
            else if ffi::ELF_DynamicEntryArray::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryArray>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Array(Array::from_ffi(raw))
            }
            else if ffi::ELF_DynamicEntryRpath::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Rpath(Rpath::from_ffi(raw))
            }
            else if ffi::ELF_DynamicEntryRunPath::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::RunPath(RunPath::from_ffi(raw))
            }
            else if ffi::ELF_DynamicSharedObject::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicSharedObject>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::SharedObject(SharedObject::from_ffi(raw))
            }
            else if ffi::ELF_DynamicEntryFlags::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryFlags>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Flags(Flags::from_ffi(raw))
            }
            else {
                Entries::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}


/// Generic structure for the dynamic entries whose [`DynamicEntry::value`] can be interpreted
/// as is.
pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntry>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl FromFFI<ffi::ELF_DynamicEntry> for Generic<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }

}

impl DynamicEntry for Generic<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}


impl std::fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generic").finish()
    }
}

/// Structure that represents a dynamic entry associated with a library name (e.g. `DT_NEEDED`)
pub struct Library<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Library<'_> {
    /// Name of the library (e.g. `libc.so.6`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Set a new library name
    pub fn set_name(&mut self, new_name: &str) {
        self.ptr.pin_mut().set_name(new_name.to_string());
    }
}

impl FromFFI<ffi::ELF_DynamicEntryLibrary> for Library<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}


impl DynamicEntry for Library<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for Library<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Library").finish()
    }
}

/// Structure that represents a dynamic entry associated with an array (e.g. `DT_INIT_ARRAY`)
pub struct Array<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryArray>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Array<'_> {
    pub fn array(&self) -> Vec<u64> {
        Vec::from(self.ptr.array().as_slice())
    }
}

impl FromFFI<ffi::ELF_DynamicEntryArray> for Array<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryArray>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl DynamicEntry for Array<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for Array<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Array").finish()
    }
}

/// Structure that represents a dynamic entry associated with the rpath info
pub struct Rpath<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Rpath<'_> {
    /// Create a new Rpath entry with the given path(s)
    ///
    /// For instance:
    ///
    /// ```
    /// Rpath::new("$ORIGIN/../:/lib64")
    /// ```
    pub fn new(value: &str) -> Rpath<'static> {
        Rpath::from_ffi(lief_ffi::ELF_DynamicEntryRpath::create(value.to_string()))
    }

    /// Create a new Rpath entry from a slice of paths
    ///
    /// For instance:
    ///
    /// ```
    /// Rpath::with_paths(&vec!["$ORIGIN/../", "/lib64"])
    /// ```
    pub fn with_paths(values: &[&str]) -> Rpath<'static> {
        Rpath::new(&values.join(":"))
    }

    /// The actual rpath as a string
    pub fn rpath(&self) -> String {
        self.ptr.rpath().to_string()
    }

    /// Change the rpath value
    pub fn set_rpath(&mut self, value: &str) {
        self.ptr.pin_mut().set_rpath(value.to_string());
    }

    /// Change the rpath value with the given slice
    pub fn set_rpath_with_value(&mut self, values: &[&str]) {
        self.ptr.pin_mut().set_rpath(values.join(":"));
    }

    /// The specified paths as a list of string
    pub fn paths(&self) -> Vec<String> {
        let mut result = Vec::new();
        for entry in self.ptr.paths().into_iter() {
            result.push(entry.to_string());
        }
        result
    }

    /// Insert a `path` at the given `position`
    pub fn insert(&mut self, pos: u32, path: &str) {
        self.ptr.pin_mut().insert(pos, path.to_string());
    }

    /// Append the given path
    pub fn append(&mut self, path: &str) {
        self.ptr.pin_mut().append(path.to_string());
    }

    /// The given path
    pub fn remove(&mut self, path: &str) {
        self.ptr.pin_mut().remove(path.to_string());
    }
}

impl FromFFI<ffi::ELF_DynamicEntryRpath> for Rpath<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}


impl DynamicEntry for Rpath<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for Rpath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rpath").finish()
    }
}

/// Structure that represents a dynamic entry associated with the runpath info
pub struct RunPath<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl RunPath<'_> {
    /// Create a new RunPath entry with the given path(s)
    ///
    /// For instance:
    ///
    /// ```
    /// RunPath::new("$ORIGIN/../:/lib64")
    /// ```
    pub fn new(value: &str) -> RunPath<'static> {
        RunPath::from_ffi(lief_ffi::ELF_DynamicEntryRunPath::create(value.to_string()))
    }

    /// Create a new RunPath entry from a slice of paths
    ///
    /// For instance:
    ///
    /// ```
    /// RunPath::with_paths(&vec!["$ORIGIN/../", "/lib64"])
    /// ```
    pub fn with_paths(values: &[&str]) -> RunPath<'static> {
        RunPath::new(&values.join(":"))
    }

    pub fn runpath(&self) -> String {
        self.ptr.runpath().to_string()
    }

    /// The specified paths as a list of string
    pub fn paths(&self) -> Vec<String> {
        let mut result = Vec::new();
        for entry in self.ptr.paths().into_iter() {
            result.push(entry.to_string());
        }
        result
    }

    /// Change the runpath value
    pub fn set_runpath(&mut self, value: &str) {
        self.ptr.pin_mut().set_runpath(value.to_string());
    }

    /// Change the runpath value with the given slice
    pub fn set_runpath_with_value(&mut self, values: &[&str]) {
        self.ptr.pin_mut().set_runpath(values.join(":"));
    }

    /// Insert a `path` at the given `position`
    pub fn insert(&mut self, pos: u32, path: &str) {
        self.ptr.pin_mut().insert(pos, path.to_string());
    }

    /// Append the given path
    pub fn append(&mut self, path: &str) {
        self.ptr.pin_mut().append(path.to_string());
    }

    /// The given path
    pub fn remove(&mut self, path: &str) {
        self.ptr.pin_mut().remove(path.to_string());
    }
}

impl FromFFI<ffi::ELF_DynamicEntryRunPath> for RunPath<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}


impl DynamicEntry for RunPath<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for RunPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunPath").finish()
    }
}

/// Structure that represents a dynamic entry associated with the name of a library (`DT_SONAME`)
pub struct SharedObject<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicSharedObject>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl SharedObject<'_> {
    pub fn new(name: &str) -> SharedObject<'static> {
        SharedObject::from_ffi(lief_ffi::ELF_DynamicSharedObject::create(name.to_string()))
    }

    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    pub fn set_name(&mut self, name: &str) {
        self.ptr.pin_mut().set_name(name.to_string());
    }
}

impl FromFFI<ffi::ELF_DynamicSharedObject> for SharedObject<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicSharedObject>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl DynamicEntry for SharedObject<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for SharedObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedObject").finish()
    }
}

/// Structure that represents a dynamic flag entry: `DT_FLAGS` or `DT_FLAGS_1`
pub struct Flags<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryFlags>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Flags<'_> {
    pub fn flags(&self) -> DtFlags {
        DtFlags::from(self.ptr.flags())
    }

    pub fn add_flag(&mut self, flag: DtFlags) {
        self.ptr.pin_mut().add_flag(flag.into())
    }

    pub fn remove_flag(&mut self, flag: DtFlags) {
        self.ptr.pin_mut().remove_flag(flag.into())
    }

    pub fn create_dt_flag(value: u64) -> Self {
        Self::from_ffi(ffi::ELF_DynamicEntryFlags::create_dt_flag(value))
    }

    pub fn create_dt_flag_1(value: u64) -> Self {
        Self::from_ffi(ffi::ELF_DynamicEntryFlags::create_dt_flag_1(value))
    }
}

impl FromFFI<ffi::ELF_DynamicEntryFlags> for Flags<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryFlags>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl DynamicEntry for Flags<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for Flags<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flags").finish()
    }
}


bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct DtFlags: u64 {
        const ORIGIN = 0x1;
        const SYMBOLIC = 0x2;
        const TEXTREL = 0x4;
        const BIND_NOW = 0x8;
        const STATIC_TLS = 0x10;
        const NOW = 0x100000001;
        const GLOBAL = 0x100000002;
        const GROUP = 0x100000004;
        const NODELETE = 0x100000008;
        const LOADFLTR = 0x100000010;
        const INITFIRST = 0x100000020;
        const NOOPEN = 0x100000040;
        const HANDLE_ORIGIN = 0x100000080;
        const DIRECT = 0x100000100;
        const TRANS = 0x100000200;
        const INTERPOSE = 0x100000400;
        const NODEFLIB = 0x100000800;
        const NODUMP = 0x100001000;
        const CONFALT = 0x100002000;
        const ENDFILTEE = 0x100004000;
        const DISPRELDNE = 0x100008000;
        const DISPRELPND = 0x100010000;
        const NODIRECT = 0x100020000;
        const IGNMULDEF = 0x100040000;
        const NOKSYMS = 0x100080000;
        const NOHDR = 0x100100000;
        const EDITED = 0x100200000;
        const NORELOC = 0x100400000;
        const SYMINTPOSE = 0x100800000;
        const GLOBAUDIT = 0x101000000;
        const SINGLETON = 0x102000000;
        const PIE = 0x108000000;
        const KMOD = 0x110000000;
        const WEAKFILTER = 0x120000000;
        const NOCOMMON = 0x140000000;
    }
}


impl From<u64> for DtFlags {
    fn from(value: u64) -> Self {
        DtFlags::from_bits_truncate(value)
    }
}
impl From<DtFlags> for u64 {
    fn from(value: DtFlags) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for DtFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

declare_iterator!(DynamicEntries, Entries<'a>, ffi::ELF_DynamicEntry, ffi::ELF_Binary, ffi::ELF_Binary_it_dynamic_entries);
