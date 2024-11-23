mod utils;
use lief;
use lief::dwarf::types::{Base, ClassLike, DwarfType};
use lief::dwarf::{Parameter, Scope, Type};
use lief::assembly::Instruction;
use lief::generic::Binary;

use std::path::{Path, PathBuf};

fn explore_variable(name: &str, var: &lief::dwarf::Variable) {
    println!(
        "{} {}",
        var.name(),
        var.linkage_name().unwrap_or("".to_string())
    );
    println!("{} {}", var.address().unwrap_or(0), var.size().unwrap_or(0));
    println!("{}", var.is_constexpr());
    println!("{:?}", var.debug_location());
    if let Some(ty) = var.get_type() {
        explore_type(name, &ty);
    }

    if let Some(scope) = var.scope() {
        explore_scope(&scope);
    }
}

fn explore_trait_classlike(classlike: &dyn ClassLike) {
    for func in classlike.functions() {
        println!("{}", func.name());
    }
    for member in classlike.members() {
        println!(
            "{} {} {} {} {}",
            member.name(),
            member.offset().unwrap_or(0),
            member.bit_offset().unwrap_or(0),
            member.is_external(),
            member.is_declaration()
        );
        if let Some(ty) = member.get_type() {
            match ty {
                lief::dwarf::Type::Base(_) => {
                    println!("Base");
                }
                lief::dwarf::Type::Pointer(_) => {
                    println!("Pointer");
                }
                lief::dwarf::Type::Const(_) => {
                    println!("Const");
                }
                lief::dwarf::Type::Array(_) => {
                    println!("Array");
                }
                lief::dwarf::Type::Structure(_) => {
                    println!("Structure");
                }
                lief::dwarf::Type::Class(_) => {
                    println!("Class");
                }
                lief::dwarf::Type::Union(_) => {
                    println!("Union");
                }
                lief::dwarf::Type::Packed(_) => {
                    println!("Packed");
                }
                lief::dwarf::Type::Typedef(_) => {
                    println!("Typedef");
                }
                lief::dwarf::Type::Atomic(_) => {
                    println!("Atomic");
                }
                lief::dwarf::Type::Coarray(_) => {
                    println!("Coarray");
                }
                lief::dwarf::Type::Dynamic(_) => {
                    println!("Dynamic");
                }
                lief::dwarf::Type::Enum(_) => {
                    println!("Enum");
                }
                lief::dwarf::Type::File(_) => {
                    println!("File");
                }
                lief::dwarf::Type::Immutable(_) => {
                    println!("Immutable");
                }
                lief::dwarf::Type::Interface(_) => {
                    println!("Interface");
                }
                lief::dwarf::Type::PointerToMember(_) => {
                    println!("PointerToMember");
                }
                lief::dwarf::Type::RValueReference(_) => {
                    println!("RValueReference");
                }
                lief::dwarf::Type::Reference(_) => {
                    println!("Reference");
                }
                lief::dwarf::Type::Restrict(_) => {
                    println!("Restrict");
                }
                lief::dwarf::Type::SetTy(_) => {
                    println!("SetTy");
                }
                lief::dwarf::Type::Shared(_) => {
                    println!("Shared");
                }
                lief::dwarf::Type::StringTy(_) => {
                    println!("StringTy");
                }
                lief::dwarf::Type::Subroutine(_) => {
                    println!("Subroutine");
                }
                lief::dwarf::Type::TemplateAlias(_) => {
                    println!("TemplateAlias");
                }
                lief::dwarf::Type::Thrown(_) => {
                    println!("Thrown");
                }
                lief::dwarf::Type::Volatile(_) => {
                    println!("Volatile");
                }
                lief::dwarf::Type::Generic(_) => {
                    println!("Generic");
                }
            }
        }
    }
}

fn explore_trait_type(type_: &dyn DwarfType) {
    println!(
        "{} {} {:?} {}",
        type_.name().unwrap_or("".to_string()),
        type_.size().unwrap_or(0),
        type_.location(),
        type_.is_unspecified(),
    );
    if let Some(scope) = type_.scope() {
        explore_scope(&scope);
    }
}

fn explore_scope(scope: &Scope) {
    println!(
        "{} {:?} {}",
        scope.name(),
        scope.get_type(),
        scope.chained("::")
    );
    if let Some(parent) = scope.parent() {
        explore_scope(&parent);
    }
}

fn explore_type(name: &str, type_: &lief::dwarf::Type) {
    match type_ {
        lief::dwarf::Type::Base(t) => {
            explore_trait_type(t);
            println!("{:?}", t.encoding());
        }

        lief::dwarf::Type::Pointer(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }

        lief::dwarf::Type::Const(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }

        lief::dwarf::Type::Array(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
            let size_info = t.size_info();
            println!("{}{}", size_info.name(), size_info.size());

            if let Some(ty) = size_info.get_type() {
                println!("{}", ty.name().unwrap_or("".to_string()));
            }
        }

        lief::dwarf::Type::Structure(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }

        lief::dwarf::Type::Class(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }
        lief::dwarf::Type::Union(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }

        lief::dwarf::Type::Packed(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }

        lief::dwarf::Type::Typedef(t) => {
            explore_trait_type(t);
            println!("{}", t.name().unwrap_or("".to_string()));
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Atomic(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Coarray(t) => {
            explore_trait_type(t);
        }
        lief::dwarf::Type::Dynamic(t) => {
            explore_trait_type(t);
        }
        lief::dwarf::Type::Enum(t) => {
            explore_trait_type(t);
        }
        lief::dwarf::Type::File(t) => {
            explore_trait_type(t);
        }
        lief::dwarf::Type::Immutable(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Interface(t) => {
            explore_trait_type(t);
        }
        lief::dwarf::Type::PointerToMember(t) => {
            explore_trait_type(t);

            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }

            if let Some(containing_type) = t.containing_type() {
                explore_type(name, &containing_type);
            }
        }
        lief::dwarf::Type::RValueReference(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Reference(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Restrict(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::SetTy(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Shared(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::StringTy(t) => {
            explore_trait_type(t);
        }
        lief::dwarf::Type::Subroutine(t) => {
            explore_trait_type(t);
            for p in t.parameters() {
                explore_parameters(name, &p);
            }
        }
        lief::dwarf::Type::TemplateAlias(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
            for p in t.parameters() {
                explore_parameters(name, &p);
            }
        }
        lief::dwarf::Type::Thrown(t) => {
            explore_trait_type(t);

            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Volatile(t) => {
            explore_trait_type(t);

            if let Some(underlying) = t.underlying_type() {
                explore_type(name, &underlying);
            }
        }
        lief::dwarf::Type::Generic(t) => {
            explore_trait_type(t);
        }
    }
}

fn explore_parameters(name: &str, param: &lief::dwarf::Parameters) {
    println!("{}", param.name());
    if let Some(ty) = param.get_type() {
        explore_type(name, &ty);
    }
}

fn explore_function(name: &str, func: &lief::dwarf::Function) {
    if let Some(scope) = func.scope() {
        explore_scope(&scope);
    }
    println!(
        "{} {} {}",
        func.name(),
        func.linkage_name(),
        func.address().unwrap_or(0)
    );
    println!(
        "{} {} {} {}",
        func.is_artificial(),
        func.is_external(),
        func.size(),
        func.ranges().len()
    );
    println!("{:?}", func.debug_location());

    for param in func.parameters() {
        explore_parameters(name, &param);
    }

    if let Some(ty) = func.return_type() {
        explore_type(name, &ty);
    }

    for var in func.variables() {
        explore_variable(name, &var);
    }

    for ty in func.thrown_types() {
        explore_type(name, &ty);
    }

    //println!("{} {}", name, func.name());
    for inst in func.instructions() {
        format!("{}", inst.to_string());
    }
}

fn explore_dwarf(name: &str, dwarf: &lief::dwarf::DebugInfo) {
    let func = dwarf.function_by_name("__empty__function__");
    assert!(func.is_none());
    for cu in dwarf.compilation_units() {
        println!("{} {} {}", cu.name(), cu.producer(), cu.compilation_dir());
        println!("{} {} {}", cu.low_address(), cu.high_address(), cu.size());
        println!("{:?}", cu.language());

        println!("{:?}", cu.ranges());

        for func in cu.functions() {
            explore_function(name, &func);
        }

        for func in cu.imported_functions() {
            explore_function(name, &func);
        }

        for var in cu.variables() {
            explore_variable(name, &var);
        }

        for ty in cu.types() {
            explore_type(name, &ty);
        }

        if name == "simple-gcc-c.bin" {
            assert!(cu.function_by_name("main").is_some());
            assert!(cu.function_by_name("_main_").is_none());

            assert!(cu.function_by_addr(0x401126).is_some());
            assert!(cu.function_by_addr(0x123456).is_none());
        }

        if name == "vars_1.elf" {
            assert!(cu.variable_by_name("g_map").is_some());
            assert!(cu.variable_by_name("__g_map__").is_none());

            assert!(cu.variable_by_addr(0x40e0).is_some());
            assert!(cu.variable_by_addr(0).is_none());
        }
    }
    if name == "libLIEF.so" {
        assert!(dwarf
            .variable_by_name("_ZN3fmt3v1012format_facetISt6localeE2idE")
            .is_some());
        assert!(dwarf.variable_by_name("foo").is_none());

        assert!(dwarf.variable_by_addr(0x44f5f8).is_some());
        assert!(dwarf.variable_by_addr(0xdeadc0de).is_none());

        assert!(dwarf.function_by_name("mbedtls_ct_memcmp").is_some());
        assert!(dwarf.variable_by_name("_mbedtls_ct_memcmp_").is_none());

        assert!(dwarf.function_by_addr(0x2e6b40).is_some());
        assert!(dwarf.function_by_addr(0xdeadc0de).is_none());

        assert!(dwarf.function_by_addr(0x2e6b40).is_some());
        assert!(dwarf.function_by_addr(0xdeadc0de).is_none());

        assert!(dwarf
            .type_by_name(
                "unique_ptr<LIEF::BinaryStream, std::default_delete<LIEF::BinaryStream> >"
            )
            .is_some());
        assert!(dwarf.type_by_name("foo").is_none());
    }
}

fn test_with_str(name: &str, path_str: &str) {
    if let Some(lief::Binary::ELF(bin)) = lief::Binary::parse(path_str) {
        let debug_info = bin.debug_info();
        assert!(debug_info.is_some());
        if let Some(lief::debug_info::DebugInfo::Dwarf(dwarf)) = debug_info {
            explore_dwarf(name, &dwarf);
        } else {
            panic!("Expecting a Dwarf");
        }
    }
}

fn test_with_elf(name: &str) {
    let path = utils::get_elf_sample(name).unwrap();
    let path_str = path.to_str().unwrap();
    test_with_str(name, path_str);
}

fn test_with_fullpath(name: &str, suffix: &str) {
    let path = utils::get_sample(Path::new(suffix)).unwrap();
    let path_str = path.to_str().unwrap();
    test_with_str(name, path_str);
}

#[test]
fn test_api() {
    if !lief::is_extended() {
        return;
    }

    println!("{}", lief::extended_version_info());

    let elf = lief::elf::Binary::parse("/bin/ls").unwrap();
    if let Some(lief::DebugInfo::Dwarf(dwarf)) = elf.debug_info() {}

    test_with_elf("simple-gcc-c.bin");
    test_with_fullpath("vars_1.elf", "DWARF/vars_1.elf");
    test_with_fullpath("libLIEF.so", "private/DWARF/libLIEF.so");
    test_with_fullpath("lsd", "private/DWARF/lsd");
    test_with_fullpath("libLIEF.dylib", "private/DWARF/libLIEF.dylib");
    test_with_fullpath(
        "liblinker.debug",
        "private/DWARF/binaryninja/liblinker.debug",
    );
    test_with_fullpath("dxp.debug", "private/DWARF/binaryninja/dxp.debug");
    test_with_fullpath("cobol_hello.o", "private/DWARF/cobol_hello.o");
    test_with_fullpath("D_test.bin", "private/DWARF/D_test.bin");
    test_with_fullpath("java_Pig.o", "private/DWARF/java_Pig.o");
    test_with_fullpath(
        "DW_TAG_string_type.o",
        "private/DWARF/types/DW_TAG_string_type.o",
    );
    test_with_fullpath(
        "DW_TAG_ptr_to_member_type.o",
        "private/DWARF/types/DW_TAG_ptr_to_member_type.o",
    );
    test_with_fullpath("DW_TAG_set_type.o", "private/DWARF/types/DW_TAG_set_type.o");
    test_with_fullpath(
        "DW_TAG_restrict_type.o",
        "private/DWARF/types/DW_TAG_restrict_type.o",
    );
    test_with_fullpath(
        "DW_TAG_rvalue_reference_type.o",
        "private/DWARF/types/DW_TAG_rvalue_reference_type.o",
    );
    test_with_fullpath(
        "DW_TAG_reference_type.o",
        "private/DWARF/types/DW_TAG_reference_type.o",
    );
    test_with_fullpath(
        "DW_TAG_packed_type.ps.o",
        "private/DWARF/types/DW_TAG_packed_type.ps.o",
    );
    test_with_fullpath(
        "DW_TAG_subrange_type.o",
        "private/DWARF/types/DW_TAG_subrange_type.o",
    );
    test_with_fullpath(
        "DW_TAG_immutable_type.o",
        "private/DWARF/types/DW_TAG_immutable_type.o",
    );
    test_with_fullpath(
        "DW_TAG_thrown_type.o",
        "private/DWARF/types/DW_TAG_thrown_type.o",
    );
    test_with_fullpath(
        "DW_TAG_subroutine_type.o",
        "private/DWARF/types/DW_TAG_subroutine_type.o",
    );
    test_with_fullpath(
        "DW_TAG_enumeration_type.o",
        "private/DWARF/types/DW_TAG_enumeration_type.o",
    );
    test_with_fullpath(
        "DW_TAG_atomic_type.o",
        "private/DWARF/types/DW_TAG_atomic_type.o",
    );
    test_with_fullpath(
        "DW_TAG_template_alias.o",
        "private/DWARF/types/DW_TAG_template_alias.o",
    );
    test_with_fullpath(
        "DW_TAG_volatile_type.o",
        "private/DWARF/types/DW_TAG_volatile_type.o",
    );
}
