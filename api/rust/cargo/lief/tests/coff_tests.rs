mod utils;
use std::fmt::format;
use std::env;
use lief::logging;
use lief::generic::{Symbol, Section};

fn explore_coff(bin_name: &str, coff: &lief::coff::Binary) {
    match coff.header() {
        lief::coff::Header::BigObj(big) => {
            format!("{:?}{}", big, big);
        },
        lief::coff::Header::Regular(regular) => {
            format!("{:?}{}", regular, regular);
        },
    }

    for section in coff.sections() {
        format!("{section:?} {section}");
        format!("nb relocs: {}", section.relocations().len());
        for symbol in section.symbols() {
            format!("{symbol:?} {symbol}");
        }
        if let Some(comdat) = section.comdat_info() {
            format!("{comdat:?}");
        }
    }

    for symbol in coff.symbols() {
        format!("{symbol:?} {symbol}");
        for aux in symbol.auxiliary_symbols() {
            format!("{aux:?}");
        }
        if let Some(section) = symbol.section() {
            format!("{section:?} {section}");
        }
    }

    for relocation in coff.relocations() {
        format!("{relocation:?} {relocation}");
        if let Some(section) = relocation.section() {
            format!("{}", section.name());
        }
        if let Some(symbol) = relocation.symbol() {
            format!("{}", symbol.name());
        }
    }

    for function in coff.functions() {
        format!("{function:?} {function}");
    }

    assert!(coff.find_string(0).is_none());
    assert!(coff.find_string(4).is_some());
}

fn test_with(bin_name: &str) {
    let path = utils::get_coff_sample(bin_name).unwrap();
    let path_str = path.to_str();
    if let Some(coff) = lief::coff::Binary::parse(path_str.unwrap()) {
        explore_coff(bin_name, &coff);
    }
}


#[test]
fn test_api() {
    let mut dir = env::temp_dir();
    dir.push("lief_coff_test.log");
    logging::set_path(dir.as_path());

    test_with("psetargv.obj");
    test_with("comdata_tls_msvc.obj");
    test_with("comdata_tls.obj");
    test_with("x64_debug_cl_bigobj_gl.obj");
    test_with("x64_debug_cl_bigobj.obj");
    test_with("x64_debug_cl.obj");
    test_with("arm64_debug_cl_bigobj.obj");
    test_with("arm64_debug_cl.obj");
}
