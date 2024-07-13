mod utils;
use std::env;
use lief::logging;
use lief::elf::dynamic;
use lief::elf::dynamic::DynamicEntry;
use lief::elf::note::NoteBase;
use lief::elf::relocation;
use lief::elf::segment;
use lief::elf::Notes;
use lief::generic::Binary as GenericBinary;
use lief::generic::Section;
use lief::generic::Symbol;
use lief::Binary;

fn explore_elf(name: &str, elf: &lief::elf::Binary) {
    format!("{elf:?}");
    format!("{} {} {}", elf.entrypoint(), elf.imagebase(), elf.is_pie());
    format!("{} {} {}", elf.has_nx(), elf.original_size(), elf.virtual_size());
    format!("{}", elf.interpreter());

    if let Some(sysv) = elf.sysv_hash() {
        format!("{sysv:?}");
    }

    if let Some(text) = elf.section_by_name(".text") {
        format!("{text:?}");
    }


    if let Some(gnu) = elf.gnu_hash() {
        format!("{gnu:?}");
    }

    for section in elf.sections() {
        format!("Section: {section:?}: {section}");
        format!("Name: {}", section.name());
        format!("{}", section.content().len());
        format!("{size}", size = section.size());
        format!(
            "{virtual_address}",
            virtual_address = section.virtual_address()
        );
        format!("{offset}", offset = section.offset());
        if section.name() == ".text" && section.size() > 0 {
            assert!(!section.content().is_empty())
        }
    }

    for segment in elf.segments() {
        format!("{segment:?}: {segment}");
        if segment.p_type() == segment::Type::PHDR {
            assert!(!segment.content().is_empty())
        }
    }

    for sym in elf.exported_symbols() {
        format!("{sym:?}");
    }

    for sym in elf.imported_symbols() {
        format!("{sym:?}");
    }

    for sym in elf.symtab_symbols() {
        format!("{sym:?}");
    }

    for version in elf.symbols_version() {
        format!("{version:?}");
    }

    for note in elf.notes() {
        format!("{note:?}");
        #[allow(irrefutable_let_patterns)]
        if let Notes::Generic(generic) = note {
            assert!(!generic.description().is_empty());
            assert!(!generic.original_type() != 0);
        }
    }

    for reloc in elf.pltgot_relocations() {
        format!("{reloc:?}");
    }

    for reloc in elf.dynamic_relocations() {
        if reloc.encoding() == relocation::Encoding::REL {
            assert!(reloc.is_rel());
        }

        if reloc.encoding() == relocation::Encoding::RELA {
            assert!(reloc.is_rela());
        }
        format!("{reloc:?}");
    }

    for reloc in elf.object_relocations() {
        format!("{reloc:?}");
    }

    for reloc in elf.relocations() {
        format!("{reloc:?}");
    }

    for sym in elf.dynamic_symbols() {
        format!("{sym:?}: {sym}");
        format!("{}: {} ({})", sym.name(), sym.value(), sym.size());
    }

    for sym_ver in elf.symbols_version() {
        format!("{sym_ver:?}");
    }

    for sym_def in elf.symbols_version_definition() {
        format!("{sym_def:?}");
        for aux in sym_def.auxiliary_symbols() {
            println!("{aux:?}");
        }
    }

    for sym_req in elf.symbols_version_requirement() {
        format!("{sym_req:?}");
        for aux in sym_req.auxiliary_symbols() {
            println!("{aux:?}");
        }
    }

    for entry in elf.dynamic_entries() {
        format!("{entry:?}");

        match entry {
            dynamic::Entries::Generic(gen) => {
                format!("{:?}: {}", gen.tag(), gen.value());
            }
            dynamic::Entries::Library(lib) => {
                format!("{:?}: {} {}", lib.tag(), lib.value(), lib.name());
            }
            dynamic::Entries::Array(array) => {
                format!("{:?}: {} {:?}", array.tag(), array.value(), array.array());
            }
            dynamic::Entries::Rpath(rpath) => {
                format!("{:?}: {}", rpath.tag(), rpath.rpath());
            }
            dynamic::Entries::RunPath(runpath) => {
                format!("{:?}: {}", runpath.tag(), runpath.runpath());
            }
            dynamic::Entries::SharedObject(shared) => {
                format!("{:?}: {}", shared.tag(), shared.name());
            }
        }
    }

    elf.get_relocated_dynamic_array(dynamic::Tag::INIT_ARRAY);
    elf.get_relocated_dynamic_array(dynamic::Tag::FINI_ARRAY);
    elf.get_relocated_dynamic_array(dynamic::Tag::PREINIT_ARRAY);

    if name == "ELF64_x86-64_library_libfreebl3.so" {
        assert!(elf.relocation_by_addr(0x1234).is_none());
        assert!(elf.relocation_by_addr(0x003369c01df0).is_some());

        assert!(elf.relocation_for_symbol("tooto").is_none());
        assert!(elf.relocation_for_symbol("_Jv_RegisterClasses").is_some());

        assert!(elf.dynamic_symbol_by_name("_Jv_RegisterClasses").is_some());
    }
    if name == "simple-gcc-c.bin" {
        assert!(elf.symtab_symbol_by_name("test.c").is_some());
        assert!(elf.get_library("libc.so.6").is_some());
        assert!(elf.get_library("libtoto.so").is_none());
        assert!(elf.virtual_address_to_offset(0x100000000).is_err());
        assert!(elf.virtual_address_to_offset(0x401000).is_ok());

        assert!(elf.segment_from_virtual_address(0x401000).is_some());
        assert!(elf.segment_from_virtual_address(0x100000000).is_none());

        assert!(elf.segment_from_offset(0).is_some());
        assert!(elf.segment_from_offset(0x100000000).is_none());

        assert!(elf.section_from_offset(0x318, /*skip_nobits*/ true).is_some());
        assert!(elf.section_from_offset(0x100000000, /*skip_nobits*/ true).is_none());

        assert!(elf.section_from_virtual_address(0x400318, /*skip_nobits*/ true).is_some());
        assert!(elf.section_from_virtual_address(0x100000000, /*skip_nobits*/ true).is_none());
        assert!(!elf.content_from_virtual_address(0x400318, 0x10).is_empty());
    }
}

fn test_with(bin_name: &str) {
    let path = utils::get_elf_sample(bin_name).unwrap();
    let path_str = path.to_str();
    if let Some(Binary::ELF(bin)) = Binary::parse(path_str.unwrap()) {
        explore_elf(bin_name, &bin);
    }

    // Test Read + Seek interface
    let mut file = std::fs::File::open(path).expect("Can't open the file");
    let binary = Binary::from(&mut file);
    assert!(matches!(binary, Some(Binary::ELF(_))));
}

#[test]
fn test_api() {
    let mut dir = env::temp_dir();
    dir.push("lief_elf_test.log");
    logging::set_path(dir.as_path());

    test_with("elf_reader.mips.elf");
    test_with("issue_975_aarch64.o");
    test_with("ELF_Core_issue_808.core");
    test_with("ELF64_x86-64_library_libfreebl3.so");
    test_with("ELF64_x86-64_binary_etterlog.bin");
    test_with("ELF64_x86-64_binary_systemd-resolve.bin");
    test_with("art_reader.loongarch");
    test_with("simple-gcc-c.bin");
}

