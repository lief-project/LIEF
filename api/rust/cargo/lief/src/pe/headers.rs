use std::marker::PhantomData;

use crate::common::FromFFI;
use lief_ffi as ffi;

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

impl Header<'_> {
    pub fn machine(&self) -> u32 {
        self.ptr.machine()
    }

    pub fn nb_sections(&self) -> u16 {
        self.ptr.numberof_sections()
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.ptr.time_date_stamp()
    }

    pub fn pointerto_symbol_table(&self) -> u32 {
        self.ptr.pointerto_symbol_table()
    }

    pub fn numberof_symbols(&self) -> u32 {
        self.ptr.numberof_symbols()
    }

    pub fn sizeof_optional_header(&self) -> u16 {
        self.ptr.sizeof_optional_header()
    }

    pub fn characteristics(&self) -> u32 {
        self.ptr.characteristics()
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

impl OptionalHeader<'_> {
    pub fn major_linker_version(&self) -> u8 {
        self.ptr.major_linker_version()
    }

    pub fn minor_linker_version(&self) -> u8 {
        self.ptr.minor_linker_version()
    }

    pub fn sizeof_code(&self) -> u32 {
        self.ptr.sizeof_code()
    }

    pub fn sizeof_initialized_data(&self) -> u32 {
        self.ptr.sizeof_initialized_data()
    }

    pub fn sizeof_uninitialized_data(&self) -> u32 {
        self.ptr.sizeof_uninitialized_data()
    }

    pub fn addressof_entrypoint(&self) -> u32 {
        self.ptr.addressof_entrypoint()
    }

    pub fn baseof_code(&self) -> u32 {
        self.ptr.baseof_code()
    }

    pub fn baseof_data(&self) -> u32 {
        self.ptr.baseof_data()
    }

    pub fn imagebase(&self) -> u64 {
        self.ptr.imagebase()
    }

    pub fn section_alignment(&self) -> u32 {
        self.ptr.section_alignment()
    }

    pub fn file_alignment(&self) -> u32 {
        self.ptr.file_alignment()
    }

    pub fn major_operating_system_version(&self) -> u32 {
        self.ptr.major_operating_system_version()
    }

    pub fn minor_operating_system_version(&self) -> u32 {
        self.ptr.minor_operating_system_version()
    }

    pub fn major_image_version(&self) -> u32 {
        self.ptr.major_image_version()
    }

    pub fn minor_image_version(&self) -> u32 {
        self.ptr.minor_image_version()
    }

    pub fn major_subsystem_version(&self) -> u32 {
        self.ptr.major_subsystem_version()
    }

    pub fn minor_subsystem_version(&self) -> u32 {
        self.ptr.minor_subsystem_version()
    }

    pub fn win32_version_value(&self) -> u32 {
        self.ptr.win32_version_value()
    }

    pub fn sizeof_image(&self) -> u32 {
        self.ptr.sizeof_image()
    }

    pub fn sizeof_headers(&self) -> u32 {
        self.ptr.sizeof_headers()
    }

    pub fn checksum(&self) -> u32 {
        self.ptr.checksum()
    }

    pub fn computed_checksum(&self) -> u32 {
        self.ptr.computed_checksum()
    }

    pub fn subsystem(&self) -> u32 {
        self.ptr.subsystem()
    }

    pub fn dll_characteristics(&self) -> u32 {
        self.ptr.dll_characteristics()
    }

    pub fn sizeof_stack_reserve(&self) -> u64 {
        self.ptr.sizeof_stack_reserve()
    }

    pub fn sizeof_stack_commit(&self) -> u64 {
        self.ptr.sizeof_stack_commit()
    }

    pub fn sizeof_heap_reserve(&self) -> u64 {
        self.ptr.sizeof_heap_reserve()
    }

    pub fn sizeof_heap_commit(&self) -> u64 {
        self.ptr.sizeof_heap_commit()
    }

    pub fn loader_flags(&self) -> u32 {
        self.ptr.loader_flags()
    }

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
