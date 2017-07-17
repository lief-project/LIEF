
struct mach_header {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  //uint32_t reserved; not for 32 bits
};

struct mach_header_64 {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

struct load_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct segment_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  char     segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct segment_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  char     segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct section_32 {
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
};

struct section_64 {
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
};

struct fvmlib {
  uint32_t name;
  uint32_t minor_version;
  uint32_t header_addr;
};

struct fvmlib_command {
  uint32_t  cmd;
  uint32_t cmdsize;
  struct fvmlib fvmlib;
};

struct dylib {
  uint32_t name;
  uint32_t timestamp;
  uint32_t current_version;
  uint32_t compatibility_version;
};

struct dylib_command {
  uint32_t cmd;
  uint32_t cmdsize;
  struct dylib dylib;
};

struct sub_framework_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t umbrella;
};

struct sub_client_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t client;
};

struct sub_umbrella_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t sub_umbrella;
};

struct sub_library_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t sub_library;
};

struct prebound_dylib_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
  uint32_t nmodules;
  uint32_t linked_modules;
};

struct dylinker_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
};

struct thread_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t flavor;
  uint32_t count;
};

struct routines_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t init_address;
  uint32_t init_module;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
  uint32_t reserved4;
  uint32_t reserved5;
  uint32_t reserved6;
};

struct routines_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t init_address;
  uint64_t init_module;
  uint64_t reserved1;
  uint64_t reserved2;
  uint64_t reserved3;
  uint64_t reserved4;
  uint64_t reserved5;
  uint64_t reserved6;
};

struct symtab_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t symoff;
  uint32_t nsyms;
  uint32_t stroff;
  uint32_t strsize;
};

struct dysymtab_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t iundefsym;
  uint32_t nundefsym;
  uint32_t tocoff;
  uint32_t ntoc;
  uint32_t modtaboff;
  uint32_t nmodtab;
  uint32_t extrefsymoff;
  uint32_t nextrefsyms;
  uint32_t indirectsymoff;
  uint32_t nindirectsyms;
  uint32_t extreloff;
  uint32_t nextrel;
  uint32_t locreloff;
  uint32_t nlocrel;
};

struct dylib_table_of_contents {
  uint32_t symbol_index;
  uint32_t module_index;
};

struct dylib_module_32 {
  uint32_t module_name;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextrel;
  uint32_t nextrel;
  uint32_t iinit_iterm;
  uint32_t ninit_nterm;
  uint32_t objc_module_info_addr;
  uint32_t objc_module_info_size;
};

struct dylib_module_64 {
  uint32_t module_name;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextrel;
  uint32_t nextrel;
  uint32_t iinit_iterm;
  uint32_t ninit_nterm;
  uint32_t objc_module_info_size;
  uint64_t objc_module_info_addr;
};

struct dylib_reference {
  uint32_t isym:24,
           flags:8;
};

struct twolevel_hints_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t nhints;
};

struct twolevel_hint {
  uint32_t isub_image:8,
           itoc:24;
};

struct prebind_cksum_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cksum;
};

struct uuid_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint8_t uuid[16];
};

struct rpath_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t path;
};

struct linkedit_data_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t dataoff;
  uint32_t datasize;
};

struct data_in_code_entry {
  uint32_t offset;
  uint16_t length;
  uint16_t kind;
};

struct source_version_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t version;
};

struct encryption_info_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
};

struct encryption_info_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
  uint32_t pad;
};

struct version_min_command {
  uint32_t cmd;       // LC_VERSION_MIN_MACOSX or
                      // LC_VERSION_MIN_IPHONEOS
  uint32_t cmdsize;   // sizeof(struct version_min_command)
  uint32_t version;   // X.Y.Z is encoded in nibbles xxxx.yy.zz
  uint32_t sdk;       // X.Y.Z is encoded in nibbles xxxx.yy.zz
};

struct dyld_info_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t rebase_off;
  uint32_t rebase_size;
  uint32_t bind_off;
  uint32_t bind_size;
  uint32_t weak_bind_off;
  uint32_t weak_bind_size;
  uint32_t lazy_bind_off;
  uint32_t lazy_bind_size;
  uint32_t export_off;
  uint32_t export_size;
};

struct linker_option_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t count;
};

struct symseg_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t size;
};

struct ident_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct fvmfile_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
  uint32_t header_addr;
};

struct tlv_descriptor_32 {
  uint32_t thunk;
  uint32_t key;
  uint32_t offset;
};

struct tlv_descriptor_64 {
  uint64_t thunk;
  uint64_t key;
  uint64_t offset;
};

struct tlv_descriptor {
  uintptr_t thunk;
  uintptr_t key;
  uintptr_t offset;
};

struct entry_point_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t entryoff;
  uint64_t stacksize;
};

// Structs from <mach-o/fat.h>
struct fat_header {
  uint32_t magic;
  uint32_t nfat_arch;
};

struct fat_arch {
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
};

// Structs from <mach-o/reloc.h>
struct relocation_info {
  int32_t r_address;
  uint32_t r_symbolnum:24,
           r_pcrel:1,
           r_length:2,
           r_extern:1,
           r_type:4;
};


struct scattered_relocation_info {
  uint32_t r_address:24,
           r_type:4,
           r_length:2,
           r_pcrel:1,
           r_scattered:1;
  int32_t r_value;
};


// Structs NOT from <mach-o/reloc.h>, but that make LLVM's life easier
struct any_relocation_info {
  uint32_t r_word0, r_word1;
};

// Structs from <mach-o/nlist.h>
struct nlist_base {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  uint16_t n_desc;
};

struct nlist_32 {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  int16_t n_desc;
  uint32_t n_value;
};

struct nlist_64 {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  uint16_t n_desc;
  uint64_t n_value;
};


struct x86hread_state64 {
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint64_t rflags;
  uint64_t cs;
  uint64_t fs;
  uint64_t gs;
};


struct fp_control_t {
  unsigned short
   invalid :1,
   denorm  :1,
   zdiv    :1,
   ovrfl   :1,
   undfl   :1,
   precis  :1,
           :2,
   pc      :2,
   rc      :2,
           :1,
           :3;
};

struct fp_status_t {
  unsigned short
    invalid :1,
    denorm  :1,
    zdiv    :1,
    ovrfl   :1,
    undfl   :1,
    precis  :1,
    stkflt  :1,
    errsumm :1,
    c0      :1,
    c1      :1,
    c2      :1,
    tos     :3,
    c3      :1,
    busy    :1;
};


struct mmst_reg_t {
  char mmst_reg[10];
  char mmst_rsrv[6];
};

struct xmm_reg_t {
  char xmm_reg[16];
};

struct x86_float_state64 {
  int32_t fpu_reserved[2];
  fp_control_t fpu_fcw;
  fp_status_t fpu_fsw;
  uint8_t fpu_ftw;
  uint8_t fpu_rsrv1;
  uint16_t fpu_fop;
  uint32_t fpu_ip;
  uint16_t fpu_cs;
  uint16_t fpu_rsrv2;
  uint32_t fpu_dp;
  uint16_t fpu_ds;
  uint16_t fpu_rsrv3;
  uint32_t fpu_mxcsr;
  uint32_t fpu_mxcsrmask;
  mmst_reg_t fpu_stmm0;
  mmst_reg_t fpu_stmm1;
  mmst_reg_t fpu_stmm2;
  mmst_reg_t fpu_stmm3;
  mmst_reg_t fpu_stmm4;
  mmst_reg_t fpu_stmm5;
  mmst_reg_t fpu_stmm6;
  mmst_reg_t fpu_stmm7;
  xmm_reg_t fpu_xmm0;
  xmm_reg_t fpu_xmm1;
  xmm_reg_t fpu_xmm2;
  xmm_reg_t fpu_xmm3;
  xmm_reg_t fpu_xmm4;
  xmm_reg_t fpu_xmm5;
  xmm_reg_t fpu_xmm6;
  xmm_reg_t fpu_xmm7;
  xmm_reg_t fpu_xmm8;
  xmm_reg_t fpu_xmm9;
  xmm_reg_t fpu_xmm10;
  xmm_reg_t fpu_xmm11;
  xmm_reg_t fpu_xmm12;
  xmm_reg_t fpu_xmm13;
  xmm_reg_t fpu_xmm14;
  xmm_reg_t fpu_xmm15;
  char fpu_rsrv4[6*16];
  uint32_t fpu_reserved1;
};

struct x86_exception_state64 {
  uint16_t trapno;
  uint16_t cpu;
  uint32_t err;
  uint64_t faultvaddr;
};


struct x86_state_hdr_t {
  uint32_t flavor;
  uint32_t count;
};

struct x86hread_state_t {
  x86_state_hdr_t tsh;
  union {
    x86hread_state64 ts64;
  } uts;
};

struct x86_float_state_t {
  x86_state_hdr_t fsh;
  union {
    x86_float_state64 fs64;
  } ufs;
};

struct x86_exception_state_t {
  x86_state_hdr_t esh;
  union {
    x86_exception_state64 es64;
  } ues;
};
