mod utils;

use lief::elf::note;
use lief::elf::note::NoteBase;
use lief::elf::Notes;
use lief::Binary;

fn parse_elf(name: &str) -> lief::elf::Binary {
    let path = utils::get_elf_sample(name).unwrap();
    match Binary::parse(path.to_str().unwrap()) {
        Some(Binary::ELF(elf)) => elf,
        _ => panic!("Failed to parse ELF: {name}"),
    }
}

// ============================================================================
// Core dump tests: ARM 32-bit
// ============================================================================

#[test]
fn test_core_arm() {
    let core = parse_elf("ELF32_ARM_core_hello.core");
    let notes: Vec<Notes<'_>> = core.notes().collect();
    assert_eq!(notes.len(), 6);

    // All notes should have debug representations
    for note in &notes {
        let dbg = format!("{note:?}");
        assert!(!dbg.is_empty());
    }

    // NT_PRPSINFO
    let Notes::CorePrPsInfo(prpsinfo) = &notes[0] else {
        panic!("Expected CorePrPsInfo, got {:?}", notes[0]);
    };
    assert_eq!(prpsinfo.get_type(), note::Type::CORE_PRPSINFO);

    // NOTE(romain): not yet correctly implemented
    //let info = prpsinfo.info().expect("info should be present");
    //assert_eq!(info.filename.trim_end_matches('\0'), "hello-exe");
    //assert!(info.args.starts_with("./hello-exe "));
    //assert_eq!(info.uid, 2000);
    //assert_eq!(info.gid, 2000);
    //assert_eq!(info.pid, 8166);
    //assert_eq!(info.ppid, 8163);
    //assert_eq!(info.pgrp, 8166);
    //assert_eq!(info.sid, 7997);

    // NT_PRSTATUS
    let Notes::CorePrStatus(prstatus) = &notes[1] else {
        panic!("Expected CorePrStatus, got {:?}", notes[1]);
    };
    assert_eq!(prstatus.get_type(), note::Type::CORE_PRSTATUS);
    assert_eq!(prstatus.architecture(), lief::elf::header::Arch::ARM);

    let status = prstatus.status();
    assert_eq!(status.cursig, 7);
    assert_eq!(status.sigpend, 0);
    assert_eq!(status.sighold, 0);
    assert_eq!(status.pid, 8166);
    assert_eq!(status.ppid, 0);
    assert_eq!(status.pgrp, 0);
    assert_eq!(status.sid, 0);

    let regs = prstatus.register_values();
    assert_eq!(regs.len(), 17);
    // R0
    assert_eq!(regs[0], 0xAAD75074);
    // R1
    assert_eq!(regs[1], 0);
    // R2
    assert_eq!(regs[2], 0xB);
    // R3-R11 are 0
    for i in 3..=11 {
        assert_eq!(regs[i], 0, "R{i} should be 0");
    }
    // R12
    assert_eq!(regs[12], 0xA);
    // R13
    assert_eq!(regs[13], 1);
    // R14
    assert_eq!(regs[14], 0xF7728841);
    // R15
    assert_eq!(regs[15], 0xAAD7507C);
    // CPSR (index 16)
    assert_eq!(regs[16], 0x60010010);

    // pc/sp helpers
    assert_eq!(prstatus.pc(), Ok(0xAAD7507C));
    assert_eq!(prstatus.sp(), Ok(1));
    assert_eq!(prstatus.return_value(), Ok(0xAAD75074));

    // NT_SIGINFO
    let Notes::CoreSigInfo(siginfo) = &notes[3] else {
        panic!("Expected CoreSigInfo, got {:?}", notes[3]);
    };
    assert_eq!(siginfo.get_type(), note::Type::CORE_SIGINFO);
    assert_eq!(siginfo.signo(), Ok(7));
    assert_eq!(siginfo.sigcode(), Ok(0));
    assert_eq!(siginfo.sigerrno(), Ok(1));

    // NT_AUXV
    let Notes::CoreAuxv(auxv) = &notes[4] else {
        panic!("Expected CoreAuxv, got {:?}", notes[4]);
    };
    assert_eq!(auxv.get_type(), note::Type::CORE_AUXV);
    let values = auxv.values();
    assert_eq!(values.len(), 18);
    assert_eq!(values[&note::core::auxv::Type::PHDR], 0xAAD74034);
    assert_eq!(values[&note::core::auxv::Type::PHENT], 0x20);
    assert_eq!(values[&note::core::auxv::Type::PHNUM], 0x9);
    assert_eq!(values[&note::core::auxv::Type::PAGESZ], 4096);
    assert_eq!(values[&note::core::auxv::Type::BASE], 0xF7716000);
    assert_eq!(values[&note::core::auxv::Type::FLAGS], 0);
    assert_eq!(values[&note::core::auxv::Type::ENTRY], 0xAAD75074);
    assert_eq!(values[&note::core::auxv::Type::UID], 2000);
    assert_eq!(values[&note::core::auxv::Type::EUID], 2000);
    assert_eq!(values[&note::core::auxv::Type::GID], 2000);
    assert_eq!(values[&note::core::auxv::Type::EGID], 2000);
    assert_eq!(values[&note::core::auxv::Type::CLKTCK], 0x64);
    assert_eq!(values[&note::core::auxv::Type::SECURE], 0);

    // NT_FILE
    let Notes::CoreFile(corefile) = &notes[5] else {
        panic!("Expected CoreFile, got {:?}", notes[5]);
    };
    assert_eq!(corefile.get_type(), note::Type::CORE_FILE);
    assert_eq!(corefile.count(), 21);

    let files: Vec<_> = corefile.files().collect();
    assert_eq!(files.len(), 21);

    assert_eq!(files[0].start(), 0xAAD74000);
    assert_eq!(files[0].end(), 0xAAD78000);
    assert_eq!(files[0].file_ofs(), 0);
    assert_eq!(files[0].path(), "/data/local/tmp/hello-exe");

    let last = &files[files.len() - 1];
    assert_eq!(last.start(), 0xF77A1000);
    assert_eq!(last.end(), 0xF77A2000);
    assert_eq!(last.file_ofs(), 0x8A000);
    assert_eq!(last.path(), "/system/bin/linker");

    // All file entries should have non-empty paths
    for f in &files {
        assert!(!f.path().is_empty());
    }
}

// ============================================================================
// Core dump tests: AArch64 64-bit
// ============================================================================

#[test]
fn test_core_aarch64() {
    let core = parse_elf("ELF64_AArch64_core_hello.core");
    let notes: Vec<Notes<'_>> = core.notes().collect();
    assert_eq!(notes.len(), 6);

    // NT_PRPSINFO
    let Notes::CorePrPsInfo(prpsinfo) = &notes[0] else {
        panic!("Expected CorePrPsInfo, got {:?}", notes[0]);
    };
    assert_eq!(prpsinfo.get_type(), note::Type::CORE_PRPSINFO);
    // NOTE(romain): not yet correctly implemented
    //let info = prpsinfo.info().expect("info should be present");
    //assert_eq!(info.filename.trim_end_matches('\0'), "hello-exe");
    //assert!(info.args.starts_with("./hello-exe "));
    //assert_eq!(info.uid, 2000);
    //assert_eq!(info.gid, 2000);
    //assert_eq!(info.pid, 8104);
    //assert_eq!(info.ppid, 8101);
    //assert_eq!(info.pgrp, 8104);
    //assert_eq!(info.sid, 7997);

    // NT_PRSTATUS
    let Notes::CorePrStatus(prstatus) = &notes[1] else {
        panic!("Expected CorePrStatus, got {:?}", notes[1]);
    };
    assert_eq!(prstatus.get_type(), note::Type::CORE_PRSTATUS);
    assert_eq!(prstatus.architecture(), lief::elf::header::Arch::AARCH64);

    let status = prstatus.status();
    assert_eq!(status.cursig, 5);
    assert_eq!(status.sigpend, 0);
    assert_eq!(status.sighold, 0);
    assert_eq!(status.pid, 8104);
    assert_eq!(status.ppid, 0);
    assert_eq!(status.pgrp, 0);
    assert_eq!(status.sid, 0);

    let regs = prstatus.register_values();
    assert_eq!(regs.len(), 34);
    // X0
    assert_eq!(regs[0], 0x5580B86F50);
    // X1
    assert_eq!(regs[1], 0);
    // X2
    assert_eq!(regs[2], 0x1);
    // X3
    assert_eq!(regs[3], 0x7FB7E2E160);
    // X4
    assert_eq!(regs[4], 0x7FB7E83030);
    // X5
    assert_eq!(regs[5], 0x4);
    // X6
    assert_eq!(regs[6], 0x6F6C2F617461642F);
    // X7
    assert_eq!(regs[7], 0x2F706D742F6C6163);
    // X30
    assert_eq!(regs[30], 0x7FB7EB6068);
    // X31
    assert_eq!(regs[31], 0x7FFFFFF950);
    // PC
    assert_eq!(regs[32], 0x5580B86F50);

    assert_eq!(prstatus.pc(), Ok(0x5580B86F50));

    // NT_SIGINFO
    let Notes::CoreSigInfo(siginfo) = &notes[3] else {
        panic!("Expected CoreSigInfo, got {:?}", notes[3]);
    };
    assert_eq!(siginfo.signo(), Ok(5));
    assert_eq!(siginfo.sigcode(), Ok(0));
    assert_eq!(siginfo.sigerrno(), Ok(1));

    // NT_AUXV
    let Notes::CoreAuxv(auxv) = &notes[4] else {
        panic!("Expected CoreAuxv, got {:?}", notes[4]);
    };
    assert_eq!(auxv.get_type(), note::Type::CORE_AUXV);
    let values = auxv.values();
    assert_eq!(values.len(), 18);
    assert_eq!(values[&note::core::auxv::Type::PHDR], 0x5580B86040);
    assert_eq!(values[&note::core::auxv::Type::PHENT], 0x38);
    assert_eq!(values[&note::core::auxv::Type::PHNUM], 0x9);
    assert_eq!(values[&note::core::auxv::Type::PAGESZ], 4096);
    assert_eq!(values[&note::core::auxv::Type::BASE], 0x7FB7E93000);
    assert_eq!(values[&note::core::auxv::Type::FLAGS], 0);
    assert_eq!(values[&note::core::auxv::Type::ENTRY], 0x5580B86F50);
    assert_eq!(values[&note::core::auxv::Type::UID], 2000);
    assert_eq!(values[&note::core::auxv::Type::EUID], 2000);
    assert_eq!(values[&note::core::auxv::Type::GID], 2000);
    assert_eq!(values[&note::core::auxv::Type::EGID], 2000);
    assert_eq!(values[&note::core::auxv::Type::HWCAP], 0xFF);
    assert_eq!(values[&note::core::auxv::Type::CLKTCK], 0x64);
    assert_eq!(values[&note::core::auxv::Type::SECURE], 0);
    assert_eq!(values[&note::core::auxv::Type::SYSINFO_EHDR], 0x7FB7E91000);

    // NT_FILE
    let Notes::CoreFile(corefile) = &notes[5] else {
        panic!("Expected CoreFile, got {:?}", notes[5]);
    };
    assert_eq!(corefile.count(), 22);

    let files: Vec<_> = corefile.files().collect();
    assert_eq!(files.len(), 22);

    assert_eq!(files[0].start(), 0x5580B86000);
    assert_eq!(files[0].end(), 0x5580B88000);
    assert_eq!(files[0].file_ofs(), 0);
    assert_eq!(files[0].path(), "/data/local/tmp/hello-exe");

    let last = &files[files.len() - 1];
    assert_eq!(last.start(), 0x7FB7F8C000);
    assert_eq!(last.end(), 0x7FB7F8D000);
    assert_eq!(last.file_ofs(), 0xF8000);
    assert_eq!(last.path(), "/system/bin/linker64");
}

// ============================================================================
// Android identification note
// ============================================================================

#[test]
fn test_android_note() {
    let elf = parse_elf("ELF64_AArch64_piebinary_ndkr16.bin");

    let mut found_android = false;
    for note_entry in elf.notes() {
        if let Notes::AndroidIdent(android) = note_entry {
            found_android = true;
            assert_eq!(android.get_type(), note::Type::ANDROID_IDENT);
            assert_eq!(android.sdk_version(), 21);
            assert!(android.ndk_version().starts_with("r16b"));
            assert!(android.ndk_build_number().starts_with("4479499"));
        }
    }
    assert!(found_android, "Should find an AndroidIdent note");
}

// ============================================================================
// GNU notes (generic iteration with NoteBase)
// ============================================================================

#[test]
fn test_generic_notes() {
    let elf = parse_elf("ELF64_x86-64_binary_etterlog.bin");

    let mut found_build_id = false;
    let mut found_abi_tag = false;
    for note_entry in elf.notes() {
        let dbg = format!("{note_entry:?}");
        assert!(!dbg.is_empty());

        match &note_entry {
            Notes::NoteAbi(abi) => {
                found_abi_tag = true;
                assert_eq!(abi.get_type(), note::Type::GNU_ABI_TAG);
                assert_eq!(abi.name(), "GNU");
                let _abi_enum = abi.abi();
                let _version = abi.version();
                format!("{abi:?}");
            }
            Notes::Generic(g) => {
                if g.get_type() == note::Type::GNU_BUILD_ID {
                    found_build_id = true;
                    assert!(!g.description().is_empty());
                    assert_eq!(g.name(), "GNU");
                }
            }
            _ => {}
        }
    }
    assert!(found_build_id, "Should find GNU_BUILD_ID");
    assert!(found_abi_tag, "Should find GNU_ABI_TAG");
}

// ============================================================================
// GNU Property notes with properties (from simple-gcc-c.bin)
// ============================================================================

#[test]
fn test_gnu_property_notes() {
    let elf = parse_elf("simple-gcc-c.bin");

    let mut found_gnu_property = false;
    for note_entry in elf.notes() {
        if let Notes::NoteGnuProperty(gnu_prop) = note_entry {
            found_gnu_property = true;
            assert_eq!(gnu_prop.get_type(), note::Type::GNU_PROPERTY_TYPE_0);
            assert_eq!(gnu_prop.name(), "GNU");

            let props: Vec<_> = gnu_prop.properties().collect();
            assert!(!props.is_empty(), "Should have at least one property");

            for prop in &props {
                use note::properties::NoteProperty;
                let _ptype = prop.property_type();
                let dbg = format!("{prop:?}");
                assert!(!dbg.is_empty());
            }
        }
    }
    assert!(found_gnu_property, "Should find NoteGnuProperty");
}

// ============================================================================
// Issue 816: binary with many notes
// ============================================================================

#[test]
fn test_notes_issue_816() {
    let elf = parse_elf("elf_notes_issue_816.bin");
    let notes: Vec<Notes<'_>> = elf.notes().collect();
    assert_eq!(notes.len(), 40);

    for note_entry in &notes {
        let dbg = format!("{note_entry:?}");
        assert!(!dbg.is_empty());
    }
}

// ============================================================================
// NoteBase trait coverage: size, description, original_type
// ============================================================================

#[test]
fn test_note_base_trait() {
    let core = parse_elf("ELF32_ARM_core_hello.core");
    for note_entry in core.notes() {
        // Every note must have a non-empty name
        let name = match &note_entry {
            Notes::CorePrPsInfo(n) => n.name(),
            Notes::CorePrStatus(n) => n.name(),
            Notes::CoreSigInfo(n) => n.name(),
            Notes::CoreAuxv(n) => n.name(),
            Notes::CoreFile(n) => n.name(),
            Notes::Generic(n) => n.name(),
            Notes::AndroidIdent(n) => n.name(),
            Notes::NoteAbi(n) => n.name(),
            Notes::NoteGnuProperty(n) => n.name(),
            Notes::QNXStack(n) => n.name(),
        };
        assert!(!name.is_empty(), "Note name should not be empty");

        // description should return bytes
        let desc = match &note_entry {
            Notes::CorePrPsInfo(n) => n.description().to_vec(),
            Notes::CorePrStatus(n) => n.description().to_vec(),
            Notes::CoreSigInfo(n) => n.description().to_vec(),
            Notes::CoreAuxv(n) => n.description().to_vec(),
            Notes::CoreFile(n) => n.description().to_vec(),
            Notes::Generic(n) => n.description().to_vec(),
            Notes::AndroidIdent(n) => n.description().to_vec(),
            Notes::NoteAbi(n) => n.description().to_vec(),
            Notes::NoteGnuProperty(n) => n.description().to_vec(),
            Notes::QNXStack(n) => n.description().to_vec(),
        };
        assert!(!desc.is_empty(), "Note description should not be empty");

        // original_type should be non-zero for core notes
        let otype = match &note_entry {
            Notes::CorePrPsInfo(n) => n.original_type(),
            Notes::CorePrStatus(n) => n.original_type(),
            Notes::CoreSigInfo(n) => n.original_type(),
            Notes::CoreAuxv(n) => n.original_type(),
            Notes::CoreFile(n) => n.original_type(),
            Notes::Generic(n) => n.original_type(),
            Notes::AndroidIdent(n) => n.original_type(),
            Notes::NoteAbi(n) => n.original_type(),
            Notes::NoteGnuProperty(n) => n.original_type(),
            Notes::QNXStack(n) => n.original_type(),
        };
        assert!(otype != 0, "Core note original_type should be non-zero");
    }
}

// ============================================================================
// GNU Property: X86 properties from multiple binaries
// ============================================================================

#[test]
fn test_gnu_property_x86_features() {
    use note::properties::{NoteProperty, Properties, PropertyType};

    // docker-init.elf has GNU properties with X86 features
    let elf = parse_elf("docker-init.elf");

    let mut found_x86_feature = false;
    for note_entry in elf.notes() {
        if let Notes::NoteGnuProperty(gnu_prop) = note_entry {
            for prop in gnu_prop.properties() {
                match prop {
                    Properties::X86Features(x86f) => {
                        found_x86_feature = true;
                        assert_eq!(x86f.property_type(), PropertyType::X86_FEATURE);
                        let feats = x86f.features();
                        assert!(!feats.is_empty());
                        format!("{x86f:?}");
                    }
                    Properties::X86ISA(x86isa) => {
                        assert_eq!(x86isa.property_type(), PropertyType::X86_ISA);
                        let vals = x86isa.values();
                        assert!(!vals.is_empty());
                        format!("{x86isa:?}");
                    }
                    _ => {
                        format!("{prop:?}");
                    }
                }
            }
        }
    }
    assert!(found_x86_feature, "Should find X86Features property");
}

// ============================================================================
// AArch64 property notes from aarch64 binaries
// ============================================================================

#[test]
fn test_gnu_property_aarch64() {
    use note::properties::{NoteProperty, Properties, PropertyType};

    let elf = parse_elf("issue_975_aarch64.o");

    for note_entry in elf.notes() {
        if let Notes::NoteGnuProperty(gnu_prop) = note_entry {
            for prop in gnu_prop.properties() {
                match prop {
                    Properties::AArch64Feature(aarch64f) => {
                        assert_eq!(aarch64f.property_type(), PropertyType::AARCH64_FEATURES);
                        let features = aarch64f.features();
                        assert!(!features.is_empty());
                        format!("{aarch64f:?}");
                    }
                    _ => {
                        format!("{prop:?}");
                    }
                }
            }
        }
    }
}

// ============================================================================
// Iterate all note types from the Core issue 808 sample
// ============================================================================

#[test]
fn test_core_issue_808() {
    let core = parse_elf("ELF_Core_issue_808.core");
    let notes: Vec<Notes<'_>> = core.notes().collect();
    assert!(!notes.is_empty());

    for note_entry in &notes {
        let dbg = format!("{note_entry:?}");
        assert!(!dbg.is_empty());
    }
}

// ============================================================================
// Debug formatting for all property types
// ============================================================================

#[test]
fn test_property_debug_formatting() {
    use note::properties::Properties;

    let elf = parse_elf("simple-gcc-c.bin");

    for note_entry in elf.notes() {
        if let Notes::NoteGnuProperty(gnu_prop) = note_entry {
            for prop in gnu_prop.properties() {
                // Exercise Debug on every property variant
                match &prop {
                    Properties::AArch64Feature(p) => {
                        format!("{p:?}");
                    }
                    Properties::AArch64PAuth(p) => {
                        format!("{p:?}");
                    }
                    Properties::X86Features(p) => {
                        format!("{p:?}");
                    }
                    Properties::X86ISA(p) => {
                        format!("{p:?}");
                    }
                    Properties::StackSize(p) => {
                        format!("{p:?}");
                    }
                    Properties::NoCopyOnProtected(p) => {
                        format!("{p:?}");
                    }
                    Properties::Needed(p) => {
                        format!("{p:?}");
                    }
                    Properties::Generic(p) => {
                        format!("{p:?}");
                    }
                }
            }
        }
    }
}

// ============================================================================
// GNU Property: find() method
// ============================================================================

#[test]
fn test_gnu_property_find() {
    use note::properties::{NoteProperty, PropertyType};

    let elf = parse_elf("simple-gcc-c.bin");

    for note_entry in elf.notes() {
        if let Notes::NoteGnuProperty(gnu_prop) = note_entry {
            let props: Vec<_> = gnu_prop.properties().collect();
            if props.is_empty() {
                continue;
            }

            // The find method should return a property when searching for
            // a type we know exists
            let first_type = props[0].property_type();
            let found = gnu_prop.find(first_type);
            assert!(
                found.is_some(),
                "find() should return a property for known type"
            );

            // Searching for an unlikely type should return None
            let not_found = gnu_prop.find(255.into());
            assert!(
                not_found.is_none(),
                "find() should return None for unknown type"
            );
        }
    }
}

// ============================================================================
// Comprehensive note iteration over various ELF binaries
// ============================================================================

#[test]
fn test_notes_comprehensive_iteration() {
    let samples = [
        "ELF64_x86-64_binary_etterlog.bin",
        "simple-gcc-c.bin",
        "ELF64_AArch64_piebinary_ndkr16.bin",
        "issue_975_aarch64.o",
        "elf_notes_issue_816.bin",
        "ELF32_ARM_core_hello.core",
        "ELF64_AArch64_core_hello.core",
        "ELF_Core_issue_808.core",
    ];

    for name in &samples {
        let path = utils::get_elf_sample(name);
        if path.is_none() {
            continue;
        }
        let path = path.unwrap();
        let Some(Binary::ELF(elf)) = Binary::parse(path.to_str().unwrap()) else {
            continue;
        };

        let mut count = 0;
        for note_entry in elf.notes() {
            count += 1;
            // Exercise debug formatting on every note
            let dbg = format!("{note_entry:?}");
            assert!(!dbg.is_empty());
        }
        assert!(count > 0, "{name} should have at least one note");
    }
}
