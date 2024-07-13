mod utils;
use lief::{self, pdb::types::PdbType};
use lief::pdb::types::classlike::ClassLike;

use std::path::Path;

fn explore_trait_type(ty: &dyn PdbType) {

}

fn explore_trait_classlike(ty: &dyn ClassLike) {
    println!("{} {} {}", ty.name(), ty.unique_name(), ty.size());
    for meth in ty.methods() {
        println!("{}", meth.name());
    }
    for attr in ty.attributes() {
        println!("{} {}", attr.name(), attr.field_offset());
        if let Some(attr_ty) = attr.get_type() {
            match attr_ty {
                lief::pdb::Type::Simple(_) => {
                    println!("Simple");
                }
                lief::pdb::Type::Array(_) => {
                    println!("Array");
                }
                lief::pdb::Type::BitField(_) => {
                    println!("BitField");
                }
                lief::pdb::Type::Class(_) => {
                    println!("Class");
                }
                lief::pdb::Type::Structure(_) => {
                    println!("Structure");
                }
                lief::pdb::Type::Interface(_) => {
                    println!("Interface");
                }
                lief::pdb::Type::Enum(_) => {
                    println!("Enum");
                }
                lief::pdb::Type::Function(_) => {
                    println!("Function");
                }
                lief::pdb::Type::Modifier(_) => {
                    println!("Modifier");
                }
                lief::pdb::Type::Pointer(_) => {
                    println!("Pointer");
                }
                lief::pdb::Type::Union(_) => {
                    println!("Union");
                }
                lief::pdb::Type::Generic(_) => {
                    println!("Generic");
                }
            }
        }
    }
}

fn explore_type(ty: &lief::pdb::Type) {
    match ty {
        lief::pdb::Type::Simple(t) => {
            explore_trait_type(t);
        }
        lief::pdb::Type::Array(t) => {
            explore_trait_type(t);
        }
        lief::pdb::Type::BitField(t) => {
            explore_trait_type(t);
        }
        lief::pdb::Type::Class(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }
        lief::pdb::Type::Structure(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }
        lief::pdb::Type::Interface(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }
        lief::pdb::Type::Enum(t) => {
            explore_trait_type(t);
        }
        lief::pdb::Type::Function(t) => {
            explore_trait_type(t);
        }
        lief::pdb::Type::Modifier(t) => {
            explore_trait_type(t);
            if let Some(underlying) = t.underlying_type() {
                explore_type(&underlying);
            }
        }
        lief::pdb::Type::Pointer(t) => {
            explore_trait_type(t);

            if let Some(underlying) = t.underlying_type() {
                explore_type(&underlying);
            }
        }
        lief::pdb::Type::Union(t) => {
            explore_trait_type(t);
            explore_trait_classlike(t);
        }
        lief::pdb::Type::Generic(t) => {
            explore_trait_type(t);
        }
    }
}

fn explore_pdb(name: &str, pdb: &lief::pdb::DebugInfo) {
    println!("{} {}", pdb.age(), pdb.guid());

    pdb.public_symbol_by_name("foo");
    pdb.public_symbol_by_name("MiSyncSystemPdes");

    for ty in pdb.types() {
        explore_type(&ty);
    }

    for sym in pdb.public_symbols() {
        println!(
            "{}{}{}0x{:x}",
            sym.name(),
            sym.demangled_name(),
            sym.section_name().unwrap_or("".to_string()),
            sym.rva(),
        );
    }

    for cu in pdb.compilation_units() {
        println!("{}{}", cu.module_name(), cu.object_filename());
        for src in cu.sources() {
            println!("{}", src);
        }
        for func in cu.functions() {
            println!(
                "{} {} {} {} {:?}",
                func.name(),
                func.rva(),
                func.code_size(),
                func.section_name(),
                func.debug_location()
            );
        }
    }
}

fn test_with(name: &str) {
    let path = utils::get_pdb_sample(name).unwrap();
    let path_str = path.to_str();
    if let Some(pdb) = lief::pdb::load(path_str.unwrap()) {
        explore_pdb(name, &pdb);
    }
}

fn test_with_fullpath(name: &str, suffix: &str) {
    let path = utils::get_sample(Path::new(suffix)).unwrap();
    let path_str = path.to_str().unwrap();
    if let Some(pdb) = lief::pdb::load(path_str) {
        explore_pdb(name, &pdb);
    }
}

#[test]
fn test_api() {
    if !lief::is_extended() {
        return;
    }
    test_with("ntkrnlmp.pdb");
    test_with("libdispatch.pdb");
    test_with("libobjc2.pdb");

    test_with_fullpath("LIEF.pdb", "private/PDB/LIEF.pdb");
    test_with_fullpath("ast_grep.pdb", "private/PDB/ast_grep.pdb");
    test_with_fullpath("libcrypto-3-x64.pdb", "private/PDB/libcrypto-3-x64.pdb");
    test_with_fullpath("libssl-3-x64.pdb", "private/PDB/libssl-3-x64.pdb");
}
