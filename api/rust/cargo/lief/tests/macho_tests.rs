mod utils;
use std::env;
use lief::logging;
use lief::generic::Binary as GenericBinary;
use lief::macho::binding_info::{self, AsGeneric};
use lief::macho::commands::{Command, Commands};
use lief::Binary;

fn print_binding(binding: &binding_info::BindingInfo) {
    format!("{:?}", binding);
    match binding {
        binding_info::BindingInfo::Generic(generic) => {
            format!("{:?}", generic.symbol());
            format!("{:?}", generic.library());
            format!("{:?}", generic.segment());
        }

        binding_info::BindingInfo::Dyld(dyld) => {
            format!("{:?}", dyld.symbol());
            format!("{:?}", dyld.library());
            format!("{:?}", dyld.segment());
        }

        binding_info::BindingInfo::Chained(chained) => {
            format!("{:?}", chained.symbol());
            format!("{:?}", chained.library());
            format!("{:?}", chained.segment());
        }
    }
}

fn explore_macho(_: &str, macho: &lief::macho::Binary) {
    format!("{macho:?}");
    format!("{}", macho.entrypoint());
    format!("{:?}", macho.header());
    for section in macho.sections() {
        format!("{section:?}");
        format!("{:?}", section.segment());
        for relocation in section.relocations() {
            format!("{relocation:?}");
        }
    }

    for command in macho.commands() {
        format!("{command:?}");
        match command {
            Commands::Generic(gen) => {
                println!("TYPE: {:?}", gen.command_type());
            }
            Commands::DyldChainedFixups(cmd) => {
                for binding in cmd.bindings() {
                    format!("{:?}", binding);
                }
            }
            Commands::DataInCode(cmd) => {
                format!("{}", cmd.content().len());
                for entry in cmd.entries() {
                    format!("{:?}", entry);
                }
            }
            Commands::SymbolCommand(cmd) => {
                format!("{}", cmd.symbol_table().len());
                format!("{}", cmd.string_table().len());
                format!("{}", cmd.original_str_size());
                format!("{}", cmd.original_nb_symbols());
            }
            Commands::FunctionStarts(cmd) => {
                format!("{}", cmd.content().len());
                for entry in cmd.functions() {
                    format!("{:?}", entry);
                }
            }
            Commands::DyldExportsTrie(cmd) => {
                format!("{}", cmd.content().len());
                for export in cmd.exports() {
                    format!("{:?}", export);
                    format!("{:?}", export.symbol());
                    format!("{:?}", export.alias());
                    format!("{:?}", export.alias_library());
                }
            }
            Commands::ThreadCommand(cmd) => {
                format!("{}", cmd.state().len());
            }
            Commands::CodeSignature(cmd) => {
                format!("{}", cmd.content().len());
            }
            Commands::CodeSignatureDir(cmd) => {
                format!("{}", cmd.content().len());
            }
            Commands::LinkerOptHint(cmd) => {
                format!("{}", cmd.content().len());
            }
            Commands::TwoLevelHints(cmd) => {
                format!("{}", cmd.original_nb_hints());
                format!("{}", cmd.content().len());
            }
            Commands::SegmentSplitInfo(cmd) => {
                format!("{}", cmd.content().len());
            }
            Commands::DyldInfo(cmd) => {
                format!("{}", cmd.rebase_opcodes().len());
                format!("{}", cmd.bind_opcodes().len());
                format!("{}", cmd.weak_bind_opcodes().len());
                format!("{}", cmd.lazy_bind_opcodes().len());
                format!("{}", cmd.export_trie().len());
                for binding in cmd.bindings() {
                    format!("{:?}", binding);
                    print_binding(&binding);
                }
                for export in cmd.exports() {
                    format!("{:?}", export);
                }
            }

            Commands::Unknown(ukn) => {
                println!("Original: {:?}", ukn.original_command());
            }
            _ => {}
        }
    }

    for segment in macho.segments() {
        format!("{segment:?}");
        for section in segment.sections() {
            format!("{section:?}");
        }

        for relocation in segment.relocations() {
            format!("{relocation:?}");
        }

        format!("len: {}", segment.content().len());
    }

    for lib in macho.libraries() {
        format!("{lib:?}");
    }

    for reloc in macho.relocations() {
        format!("{reloc:?}");
    }

    for sym in macho.symbols() {
        format!("{sym:?}");
    }

    if let Some(info) = macho.dyld_info() {
        format!("{info:?}");
    }

    if let Some(uuid) = macho.uuid() {
        format!("{uuid:?}");
    }

    if let Some(main) = macho.main_command() {
        format!("{main:?}");
    }

    if let Some(linker) = macho.dylinker() {
        format!("{linker:?}");
    }

    if let Some(starts) = macho.function_starts() {
        format!("{starts:?}");
    }

    if let Some(version) = macho.source_version() {
        format!("{version:?}");
    }

    if let Some(cmd) = macho.thread_command() {
        format!("{cmd:?}");
    }

    if let Some(rpath) = macho.rpath() {
        format!("{rpath:?}");
    }

    if let Some(symbol_command) = macho.symbol_command() {
        format!("{symbol_command:?}");
    }

    if let Some(dynamic_symbol) = macho.dynamic_symbol() {
        format!("{dynamic_symbol:?}");
    }

    if let Some(code_signature) = macho.code_signature() {
        format!("{code_signature:?}");
    }

    if let Some(code_signature_dir) = macho.code_signature_dir() {
        format!("{code_signature_dir:?}");
    }

    if let Some(data_in_code) = macho.data_in_code() {
        format!("{data_in_code:?}");
    }

    if let Some(segment_split_info) = macho.segment_split_info() {
        format!("{segment_split_info:?}");
    }

    if let Some(encryption_info) = macho.encryption_info() {
        format!("{encryption_info:?}");
    }

    if let Some(sub_framework) = macho.sub_framework() {
        format!("{sub_framework:?}");
    }

    if let Some(dyld_environment) = macho.dyld_environment() {
        format!("{dyld_environment:?}");
    }

    if let Some(build_version) = macho.build_version() {
        format!("{build_version:?}");
    }

    if let Some(dyld_chained_fixups) = macho.dyld_chained_fixups() {
        format!("{dyld_chained_fixups:?}");
    }

    if let Some(dyld_exports_trie) = macho.dyld_exports_trie() {
        format!("{dyld_exports_trie:?}");
    }

    if let Some(two_level_hints) = macho.two_level_hints() {
        format!("{two_level_hints:?}");
    }

    if let Some(linker_opt_hint) = macho.linker_opt_hint() {
        format!("{linker_opt_hint:?}");
    }

    if let Some(version_min) = macho.version_min() {
        format!("{version_min:?}");
    }
}

fn test_with(bin_name: &str) {
    let path = utils::get_macho_sample(bin_name).unwrap();
    let path_str = path.to_str();
    if let Some(Binary::MachO(fat)) = Binary::parse(path_str.unwrap()) {
        for bin in fat.iter() {
            explore_macho(bin_name, &bin);
        }
    }

    // Test Read + Seek interface
    let mut file = std::fs::File::open(path).expect("Can't open the file");
    let binary = Binary::from(&mut file);
    assert!(matches!(binary, Some(Binary::MachO(_))));
}

#[test]
fn test_api() {

    let mut dir = env::temp_dir();
    dir.push("lief_macho_test.log");
    logging::set_path(dir.as_path());

    test_with("alivcffmpeg_armv7.dylib");
    test_with(
        "9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho",
    );
    test_with("MachO64_x86-64_binary_safaridriver.bin");
    test_with("FAT_MachO_x86_x86-64_library_libdyld.dylib");
    test_with("ios1-expr.bin");
    test_with("json_api.cpp_1.o");
    test_with("python3_issue_476.bin");
    test_with("FAT_MachO_x86_x86-64_library_libc++abi.dylib");
    test_with("libadd_unknown_cmd.so");
}
