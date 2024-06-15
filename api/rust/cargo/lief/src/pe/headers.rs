//! This module exposes the different headers that we can find in a PE binary.
//! It includes:
//! - [`DosHeader`]
//! - [`Header`]
//! - [`OptionalHeader`]

use bitflags::bitflags;
use std::marker::PhantomData;

use crate::common::FromFFI;
use lief_ffi as ffi;

/// Structure which represents the DosHeader, the **first** structure presents at the beginning of
/// a PE file.
///
/// Most of the attributes of this structures are no longer relevant
pub struct DosHeader<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DosHeader>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl FromFFI<ffi::PE_DosHeader> for DosHeader<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DosHeader>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> DosHeader<'a> {
    /// Magic bytes identifying a DOS/PE binary
    pub fn magic(&self) -> u16 {
        self.ptr.magic()
    }

    pub fn used_bytes_in_last_page(&self) -> u16 {
        self.ptr.used_bytes_in_last_page()
    }

    pub fn file_size_in_pages(&self) -> u16 {
        self.ptr.file_size_in_pages()
    }

    pub fn numberof_relocation(&self) -> u16 {
        self.ptr.numberof_relocation()
    }

    pub fn header_size_in_paragraphs(&self) -> u16 {
        self.ptr.header_size_in_paragraphs()
    }

    pub fn minimum_extra_paragraphs(&self) -> u16 {
        self.ptr.minimum_extra_paragraphs()
    }

    pub fn maximum_extra_paragraphs(&self) -> u16 {
        self.ptr.maximum_extra_paragraphs()
    }

    pub fn initial_relative_ss(&self) -> u16 {
        self.ptr.initial_relative_ss()
    }

    pub fn initial_sp(&self) -> u16 {
        self.ptr.initial_sp()
    }

    pub fn checksum(&self) -> u16 {
        self.ptr.checksum()
    }

    pub fn initial_ip(&self) -> u16 {
        self.ptr.initial_ip()
    }

    pub fn initial_relative_cs(&self) -> u16 {
        self.ptr.initial_relative_cs()
    }

    pub fn addressof_relocation_table(&self) -> u16 {
        self.ptr.addressof_relocation_table()
    }

    pub fn overlay_number(&self) -> u16 {
        self.ptr.overlay_number()
    }

    pub fn reserved(&self) -> Vec<u16> {
        Vec::from_iter(self.ptr.reserved().iter().map(|x| *x as u16))
    }

    pub fn oem_id(&self) -> u16 {
        self.ptr.oem_id()
    }

    pub fn oem_info(&self) -> u16 {
        self.ptr.oem_info()
    }

    pub fn reserved2(&self) -> Vec<u16> {
        Vec::from_iter(self.ptr.reserved().iter().map(|x| *x as u16))
    }

    /// Return the offset to the [`Header`] structure.
    pub fn addressof_new_exeheader(&self) -> u32 {
        self.ptr.addressof_new_exeheader()
    }
}

impl std::fmt::Debug for DosHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DosHeader")
            .field("magic", &self.magic())
            .field("used_bytes_in_last_page", &self.used_bytes_in_last_page())
            .field("file_size_in_pages", &self.file_size_in_pages())
            .field("numberof_relocation", &self.numberof_relocation())
            .field(
                "header_size_in_paragraphs",
                &self.header_size_in_paragraphs(),
            )
            .field("minimum_extra_paragraphs", &self.minimum_extra_paragraphs())
            .field("maximum_extra_paragraphs", &self.maximum_extra_paragraphs())
            .field("initial_relative_ss", &self.initial_relative_ss())
            .field("initial_sp", &self.initial_sp())
            .field("checksum", &self.checksum())
            .field("initial_ip", &self.initial_ip())
            .field("initial_relative_cs", &self.initial_relative_cs())
            .field(
                "addressof_relocation_table",
                &self.addressof_relocation_table(),
            )
            .field("overlay_number", &self.overlay_number())
            .field("reserved", &self.reserved())
            .field("oem_info", &self.oem_info())
            .field("oem_id", &self.oem_id())
            .field("reserved2", &self.reserved2())
            .field("addressof_new_exeheader", &self.addressof_new_exeheader())
            .finish()
    }
}

/// Structure that represents the PE header (which follows the [`DosHeader`])
pub struct Header<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Header>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl FromFFI<ffi::PE_Header> for Header<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Header>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MachineType {
    /// Matsushita AM33
    AM33,
    /// AMD x64
    AMD64,
    /// ARM little endian
    ARM,
    /// ARMv7 Thumb mode only
    ARMNT,
    /// ARMv8 in 64-bits mode
    ARM64,
    /// EFI byte code
    EBC,
    /// Intel 386 or later
    I386,
    /// Intel Itanium processor family
    IA64,
    /// Mitsubishi M32R little endian
    M32R,
    /// MIPS16
    MIPS16,
    /// MIPS with FPU
    MIPSFPU,
    /// MIPS16 with FPU
    MIPSFPU16,
    /// Power PC little endian
    POWERPC,
    /// Power PC with floating point
    POWERPCFP,
    /// MIPS with little endian
    R4000,
    /// RISC-V 32-bit address space
    RISCV32,
    /// RISC-V 64-bit address space
    RISCV64,
    /// RISC-V 128-bit address space
    RISCV128,
    /// Hitachi SH3
    SH3,
    /// Hitachi SH3 DSP
    SH3DSP,
    /// Hitachi SH4
    SH4,
    /// Hitachi SH5
    SH5,
    /// ARM or Thumb
    THUMB,
    /// MIPS little-endian WCE v2
    WCEMIPSV2,
    UNKNOWN(u32),
}

impl From<u32> for MachineType {
    fn from(value: u32) -> Self {
        match value {
            0x000001d3 => MachineType::AM33,
            0x00008664 => MachineType::AMD64,
            0x000001c0 => MachineType::ARM,
            0x000001c4 => MachineType::ARMNT,
            0x0000aa64 => MachineType::ARM64,
            0x00000ebc => MachineType::EBC,
            0x0000014c => MachineType::I386,
            0x00000200 => MachineType::IA64,
            0x00009041 => MachineType::M32R,
            0x00000266 => MachineType::MIPS16,
            0x00000366 => MachineType::MIPSFPU,
            0x00000466 => MachineType::MIPSFPU16,
            0x000001f0 => MachineType::POWERPC,
            0x000001f1 => MachineType::POWERPCFP,
            0x00000166 => MachineType::R4000,
            0x00005032 => MachineType::RISCV32,
            0x00005064 => MachineType::RISCV64,
            0x00005128 => MachineType::RISCV128,
            0x000001a2 => MachineType::SH3,
            0x000001a3 => MachineType::SH3DSP,
            0x000001a6 => MachineType::SH4,
            0x000001a8 => MachineType::SH5,
            0x000001c2 => MachineType::THUMB,
            0x00000169 => MachineType::WCEMIPSV2,
            _ => MachineType::UNKNOWN(value),

        }
    }
}
impl From<MachineType> for u32 {
    fn from(value: MachineType) -> u32 {
        match value {
            MachineType::AM33 => 0x000001d3,
            MachineType::AMD64 => 0x00008664,
            MachineType::ARM => 0x000001c0,
            MachineType::ARMNT => 0x000001c4,
            MachineType::ARM64 => 0x0000aa64,
            MachineType::EBC => 0x00000ebc,
            MachineType::I386 => 0x0000014c,
            MachineType::IA64 => 0x00000200,
            MachineType::M32R => 0x00009041,
            MachineType::MIPS16 => 0x00000266,
            MachineType::MIPSFPU => 0x00000366,
            MachineType::MIPSFPU16 => 0x00000466,
            MachineType::POWERPC => 0x000001f0,
            MachineType::POWERPCFP => 0x000001f1,
            MachineType::R4000 => 0x00000166,
            MachineType::RISCV32 => 0x00005032,
            MachineType::RISCV64 => 0x00005064,
            MachineType::RISCV128 => 0x00005128,
            MachineType::SH3 => 0x000001a2,
            MachineType::SH3DSP => 0x000001a3,
            MachineType::SH4 => 0x000001a6,
            MachineType::SH5 => 0x000001a8,
            MachineType::THUMB => 0x000001c2,
            MachineType::WCEMIPSV2 => 0x00000169,
            MachineType::UNKNOWN(_) => 0,

        }
    }
}


bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Characteristics: u32 {
        const NONE = 0x0;

        /// The file does not contain base relocations and must be loaded at its preferred base.
        /// If this cannot be done, the loader will error.
        const RELOCS_STRIPPED = 0x1;

        /// File is executable (i.e. no unresolved externel references).
        const EXECUTABLE_IMAGE = 0x2;

        /// COFF line numbers have been stripped. This is deprecated and should be 0
        const LINE_NUMS_STRIPPED = 0x4;

        /// COFF symbol table entries for local symbols have been removed.
        /// This is deprecated and should be 0.
        const LOCAL_SYMS_STRIPPED = 0x8;

        /// Aggressively trim working set. This is deprecated and must be 0.
        const AGGRESSIVE_WS_TRIM = 0x10;

        /// App can handle >2gb addresses
        const LARGE_ADDRESS_AWARE = 0x20;

        /// Little endian: the LSB precedes the MSB in memory. This is deprecated and should be 0.
        const BYTES_REVERSED_LO = 0x80;

        /// Machine is based on a 32bit word architecture.
        const NEED_32BIT_MACHINE = 0x100;

        /// Debugging info has been removed.
        const DEBUG_STRIPPED = 0x200;

        /// If the image is on removable media, fully load it and copy it to swap.
        const REMOVABLE_RUN_FROM_SWAP = 0x400;

        /// If the image is on network media, fully load it and copy it to swap.
        const NET_RUN_FROM_SWAP = 0x800;

        /// The image file is a system file, not a user program.
        const SYSTEM = 0x1000;

        /// The image file is a DLL.
        const DLL = 0x2000;

        /// This file should only be run on a uniprocessor machine.
        const UP_SYSTEM_ONLY = 0x4000;

        /// Big endian: the MSB precedes the LSB in memory. This is deprecated
        const BYTES_REVERSED_HI = 0x8000;
    }
}

impl std::fmt::Display for Characteristics {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}


impl From<u32> for Characteristics {
    fn from(value: u32) -> Self {
        Characteristics::from_bits_truncate(value)
    }
}
impl From<Characteristics> for u32 {
    fn from(value: Characteristics) -> Self {
        value.bits()
    }
}

impl Header<'_> {
    /// The targeted machine architecture like ARM, x86, AMD64, ...
    pub fn machine(&self) -> MachineType {
        MachineType::from(self.ptr.machine())
    }

    /// The number of sections in the binary.
    pub fn nb_sections(&self) -> u16 {
        self.ptr.numberof_sections()
    }

    /// The low 32 bits of the number of seconds since January 1, 1970.
    /// It **indicates** when the file was created.
    pub fn time_date_stamp(&self) -> u32 {
        self.ptr.time_date_stamp()
    }

    /// The offset of the **COFF** symbol table.
    /// This value should be zero for an image because COFF debugging information is deprecated on
    /// in PE binary
    pub fn pointerto_symbol_table(&self) -> u32 {
        self.ptr.pointerto_symbol_table()
    }


    /// The number of entries in the symbol table. This data can be used to locate the string table
    /// which immediately follows the symbol table.
    ///
    /// This value should be zero for an image because COFF debugging information is deprecated in
    /// PE binary
    pub fn numberof_symbols(&self) -> u32 {
        self.ptr.numberof_symbols()
    }

    /// Size of the OptionalHeader **AND** the data directories which follows this header.
    ///
    /// This value is equivalent to:
    /// `sizeof(pe_optional_header) + NB_DATA_DIR * sizeof(data_directory)`
    ///
    /// This size **should** be either:
    /// * 0xE0 (224) for a PE32  (32 bits)
    /// * 0xF0 (240) for a PE32+ (64 bits)
    pub fn sizeof_optional_header(&self) -> u16 {
        self.ptr.sizeof_optional_header()
    }

    /// Characteristics of the binary like whether it is a DLL or an executable
    pub fn characteristics(&self) -> Characteristics {
        Characteristics::from(self.ptr.characteristics())
    }
}

impl std::fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("machine", &self.machine())
            .field("nb_sections", &self.nb_sections())
            .field("time_date_stamp", &self.time_date_stamp())
            .field("pointerto_symbol_table", &self.pointerto_symbol_table())
            .field("numberof_symbols", &self.numberof_symbols())
            .field("sizeof_optional_header", &self.sizeof_optional_header())
            .field("characteristics", &self.characteristics())
            .finish()
    }
}


/// Structure which represents the PE OptionalHeader (after [`Header`]).
///
/// Note that the term *optional* comes from the COFF specifications but this header is
/// **mandatory** for a PE binary.
pub struct OptionalHeader<'a> {
    ptr: cxx::UniquePtr<ffi::PE_OptionalHeader>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl FromFFI<ffi::PE_OptionalHeader> for OptionalHeader<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_OptionalHeader>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct DllCharacteristics: u32 {
        /// ASLR with 64 bit address space.
        const HIGH_ENTROPY_VA = 0x20;

        /// DLL can be relocated at load time.
        const DYNAMIC_BASE = 0x40;

        /// Code integrity checks are enforced.
        const FORCE_INTEGRITY = 0x80;

        /// Image is NX compatible.
        const NX_COMPAT = 0x100;

        /// Isolation aware, but do not isolate the image.
        const NO_ISOLATION = 0x200;

        /// Does not use structured exception handling (SEH).
        /// No SEH handler may be called in this image.
        const NO_SEH = 0x400;

        /// Do not bind the image.
        const NO_BIND = 0x800;

        /// Image should execute in an AppContainer.
        const APPCONTAINER = 0x1000;

        /// A WDM driver.
        const WDM_DRIVER = 0x2000;

        /// Image supports Control Flow Guard.
        const GUARD_CF = 0x4000;

        /// Terminal Server aware.
        const TERMINAL_SERVER_AWARE = 0x8000;
    }
}


impl From<u32> for DllCharacteristics {
    fn from(value: u32) -> Self {
        DllCharacteristics::from_bits_truncate(value)
    }
}
impl From<DllCharacteristics> for u32 {
    fn from(value: DllCharacteristics) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for DllCharacteristics {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Subsystem {
    /// Device drivers and native Windows processes
    NATIVE,

    /// The Windows GUI subsystem.
    WINDOWS_GUI,

    /// The Windows character subsystem.
    WINDOWS_CUI,

    /// The OS/2 character subsytem.
    OS2_CUI,

    /// The POSIX character subsystem.
    POSIX_CUI,

    /// Native Windows 9x driver.
    NATIVE_WINDOWS,

    /// Windows CE.
    WINDOWS_CE_GUI,

    /// An EFI application.
    EFI_APPLICATION,

    /// An EFI driver with boot services.
    EFI_BOOT_SERVICE_DRIVER,

    /// An EFI driver with run-time services.
    EFI_RUNTIME_DRIVER,

    /// An EFI ROM image.
    EFI_ROM,

    /// XBOX
    XBOX,

    /// A BCD application.
    WINDOWS_BOOT_APPLICATION,

    /// An unknown subsystem.
    UNKNOWN(u64),
}

impl From<u64> for Subsystem {
    fn from(value: u64) -> Self {
        match value {
            0x00000001 => Subsystem::NATIVE,
            0x00000002 => Subsystem::WINDOWS_GUI,
            0x00000003 => Subsystem::WINDOWS_CUI,
            0x00000005 => Subsystem::OS2_CUI,
            0x00000007 => Subsystem::POSIX_CUI,
            0x00000008 => Subsystem::NATIVE_WINDOWS,
            0x00000009 => Subsystem::WINDOWS_CE_GUI,
            0x0000000a => Subsystem::EFI_APPLICATION,
            0x0000000b => Subsystem::EFI_BOOT_SERVICE_DRIVER,
            0x0000000c => Subsystem::EFI_RUNTIME_DRIVER,
            0x0000000d => Subsystem::EFI_ROM,
            0x0000000e => Subsystem::XBOX,
            0x00000010 => Subsystem::WINDOWS_BOOT_APPLICATION,
            _ => Subsystem::UNKNOWN(value),

        }
    }
}
impl From<Subsystem> for u64 {
    fn from(value: Subsystem) -> u64 {
        match value {
            Subsystem::NATIVE => 0x00000001,
            Subsystem::WINDOWS_GUI => 0x00000002,
            Subsystem::WINDOWS_CUI => 0x00000003,
            Subsystem::OS2_CUI => 0x00000005,
            Subsystem::POSIX_CUI => 0x00000007,
            Subsystem::NATIVE_WINDOWS => 0x00000008,
            Subsystem::WINDOWS_CE_GUI => 0x00000009,
            Subsystem::EFI_APPLICATION => 0x0000000a,
            Subsystem::EFI_BOOT_SERVICE_DRIVER => 0x0000000b,
            Subsystem::EFI_RUNTIME_DRIVER => 0x0000000c,
            Subsystem::EFI_ROM => 0x0000000d,
            Subsystem::XBOX => 0x0000000e,
            Subsystem::WINDOWS_BOOT_APPLICATION => 0x00000010,
            Subsystem::UNKNOWN(_) => 0,

        }
    }
}

impl OptionalHeader<'_> {
    /// The linker major version
    pub fn major_linker_version(&self) -> u8 {
        self.ptr.major_linker_version()
    }

    /// The linker minor version
    pub fn minor_linker_version(&self) -> u8 {
        self.ptr.minor_linker_version()
    }

    /// The size of the code `.text` section or the sum of
    /// all the sections that contain code (i.e. sections with `CNT_CODE` flag)
    pub fn sizeof_code(&self) -> u32 {
        self.ptr.sizeof_code()
    }

    /// The size of the initialized data which are usually located in the `.data` section.
    /// If the initialized data are split across multiple sections, it is the sum of the sections.
    pub fn sizeof_initialized_data(&self) -> u32 {
        self.ptr.sizeof_initialized_data()
    }

    /// The size of the uninitialized data which are usually located in the `.bss` section.
    /// If the uninitialized data are split across multiple sections, it is the sum of the sections.
    pub fn sizeof_uninitialized_data(&self) -> u32 {
        self.ptr.sizeof_uninitialized_data()
    }

    /// The address of the entry point relative to the image base when the executable file is
    /// loaded into memory. For program images, this is the starting address. For device
    /// drivers, this is the address of the initialization function.
    ///
    /// An entry point is optional for DLLs. When no entry point is present, this field must be zero.
    pub fn addressof_entrypoint(&self) -> u32 {
        self.ptr.addressof_entrypoint()
    }

    /// Address relative to the imagebase where the binary's code starts.
    pub fn baseof_code(&self) -> u32 {
        self.ptr.baseof_code()
    }

    /// Address relative to the imagebase where the binary's data starts.
    ///
    /// <div class="warning">This value is not present for PE64 files</div>
    pub fn baseof_data(&self) -> u32 {
        self.ptr.baseof_data()
    }

    /// The preferred base address when mapping the binary in memory
    pub fn imagebase(&self) -> u64 {
        self.ptr.imagebase()
    }

    /// The alignment (in bytes) of sections when they are loaded into memory.
    ///
    /// It must be greater than or equal to file_alignment and
    /// the default is the page size for the architecture.
    pub fn section_alignment(&self) -> u32 {
        self.ptr.section_alignment()
    }

    /// The section's file alignment. This value must be a power of 2 between 512 and 64K.
    /// The default value is usually 512
    pub fn file_alignment(&self) -> u32 {
        self.ptr.file_alignment()
    }

    /// The **major** version number of the required operating system
    pub fn major_operating_system_version(&self) -> u32 {
        self.ptr.major_operating_system_version()
    }

    /// The **minor** version number of the required operating system
    pub fn minor_operating_system_version(&self) -> u32 {
        self.ptr.minor_operating_system_version()
    }

    /// The major version number of the image
    pub fn major_image_version(&self) -> u32 {
        self.ptr.major_image_version()
    }

    /// The minor version number of the image
    pub fn minor_image_version(&self) -> u32 {
        self.ptr.minor_image_version()
    }

    /// The major version number of the subsystem
    pub fn major_subsystem_version(&self) -> u32 {
        self.ptr.major_subsystem_version()
    }

    /// The minor version number of the subsystem
    pub fn minor_subsystem_version(&self) -> u32 {
        self.ptr.minor_subsystem_version()
    }

    /// According to the official PE specifications, this value
    /// is reserved and **should** be 0.
    pub fn win32_version_value(&self) -> u32 {
        self.ptr.win32_version_value()
    }

    /// The size (in bytes) of the image, including all headers, as the image is loaded in memory.
    ///
    /// It must be a multiple of section_alignment and should match [`crate::pe::Binary::virtual_size`]
    pub fn sizeof_image(&self) -> u32 {
        self.ptr.sizeof_image()
    }

    /// Size of the DosHeader + PE Header + Section headers rounded up to a multiple of the file_alignment
    pub fn sizeof_headers(&self) -> u32 {
        self.ptr.sizeof_headers()
    }

    /// The image file checksum. The algorithm for computing the checksum is incorporated into `IMAGHELP.DLL`.
    ///
    /// The following are checked for validation at load time all **drivers**, any **DLL loaded at boot**
    /// time, and any **DLL** that is loaded into a **critical** Windows process.
    pub fn checksum(&self) -> u32 {
        self.ptr.checksum()
    }

    /// Target subsystem like Driver, XBox, Windows GUI, ...
    pub fn subsystem(&self) -> Subsystem {
        Subsystem::from(self.ptr.subsystem())
    }

    /// Some characteristics of the underlying binary like the support of the PIE.
    /// The prefix ``dll`` comes from the official PE specifications but these characteristics
    /// are also used for **executables**
    pub fn dll_characteristics(&self) -> DllCharacteristics {
        DllCharacteristics::from(self.ptr.dll_characteristics())
    }


    /// Size of the stack to reserve when loading the PE binary
    ///
    /// Only [`OptionalHeader::sizeof_stack_commit`] is committed, the rest
    /// available one page at a time until the reserve size is reached.
    pub fn sizeof_stack_reserve(&self) -> u64 {
        self.ptr.sizeof_stack_reserve()
    }

    /// Size of the stack to commit
    pub fn sizeof_stack_commit(&self) -> u64 {
        self.ptr.sizeof_stack_commit()
    }

    /// Size of the heap to reserve when loading the PE binary
    pub fn sizeof_heap_reserve(&self) -> u64 {
        self.ptr.sizeof_heap_reserve()
    }

    /// Size of the stack to commit
    pub fn sizeof_heap_commit(&self) -> u64 {
        self.ptr.sizeof_heap_commit()
    }

    /// According to the PE specifications, this value is *reserved* and **should** be 0.
    pub fn loader_flags(&self) -> u32 {
        self.ptr.loader_flags()
    }

    /// The number of DataDirectory that follow this header.
    pub fn numberof_rva_and_size(&self) -> u32 {
        self.ptr.numberof_rva_and_size()
    }
}

impl std::fmt::Debug for OptionalHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OptionalHeader")
            .field("major_linker_version", &self.major_linker_version())
            .field("minor_linker_version", &self.minor_linker_version())
            .field("sizeof_code", &self.sizeof_code())
            .field("sizeof_initialized_data", &self.sizeof_initialized_data())
            .field(
                "sizeof_uninitialized_data",
                &self.sizeof_uninitialized_data(),
            )
            .field("addressof_entrypoint", &self.addressof_entrypoint())
            .field("baseof_code", &self.baseof_code())
            .field("baseof_data", &self.baseof_data())
            .field("imagebase", &self.imagebase())
            .field("section_alignment", &self.section_alignment())
            .field("file_alignment", &self.file_alignment())
            .field(
                "major_operating_system_version",
                &self.major_operating_system_version(),
            )
            .field(
                "minor_operating_system_version",
                &self.minor_operating_system_version(),
            )
            .field("major_image_version", &self.major_image_version())
            .field("minor_image_version", &self.minor_image_version())
            .field("major_subsystem_version", &self.major_subsystem_version())
            .field("minor_subsystem_version", &self.minor_subsystem_version())
            .field("win32_version_value", &self.win32_version_value())
            .field("sizeof_image", &self.sizeof_image())
            .field("sizeof_headers", &self.sizeof_headers())
            .field("checksum", &self.checksum())
            .field("subsystem", &self.subsystem())
            .field("dll_characteristics", &self.dll_characteristics())
            .field("sizeof_stack_reserve", &self.sizeof_stack_reserve())
            .field("sizeof_stack_commit", &self.sizeof_stack_commit())
            .field("sizeof_heap_reserve", &self.sizeof_heap_reserve())
            .field("sizeof_heap_commit", &self.sizeof_heap_commit())
            .field("loader_flags", &self.loader_flags())
            .field("numberof_rva_and_size", &self.numberof_rva_and_size())
            .finish()
    }
}
