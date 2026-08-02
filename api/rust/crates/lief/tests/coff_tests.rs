#![allow(warnings)]
mod utils;
use lief::generic::{Section, Symbol};
use lief::logging;
use std::env;
use std::fmt::format;

fn explore_coff(bin_name: &str, coff: &lief::coff::Binary) {
    match coff.header() {
        lief::coff::Header::BigObj(big) => {
            format!("{:?}{}", big, big);
        }
        lief::coff::Header::Regular(regular) => {
            format!("{:?}{}", regular, regular);
        }
    }

    for section in coff.sections() {
        format!("{section:?} {section}");
        format!("nb relocs: {}", section.relocations().len());
        assert!(coff.section_by_name(&section.name()).is_some());
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
    assert!(coff.section_by_name("<not-a-section>").is_none());
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

#[test]
fn test_section_by_name() {
    let path = utils::get_coff_sample("arm64_debug_cl.obj").unwrap();
    let coff = lief::coff::Binary::parse(path.to_str().unwrap()).unwrap();

    assert!(coff.section_by_name("<not-a-section>").is_none());

    let section = coff.section_by_name(".drectve").unwrap();
    assert_eq!(section.name(), ".drectve");
    assert_eq!(section.sizeof_raw_data(), 0x91);
    assert!(section.coff_string().is_none());

    let path = utils::get_coff_sample("dwarf.obj").unwrap();
    let coff = lief::coff::Binary::parse(path.to_str().unwrap()).unwrap();

    let section = coff.section_by_name(".debug_rnglists").unwrap();
    assert_eq!(section.name(), "/18");
    assert_eq!(section.coff_string().unwrap().str(), ".debug_rnglists");

    let section = coff.section_by_name("/18").unwrap();
    assert_eq!(section.coff_string().unwrap().str(), ".debug_rnglists");

    assert!(coff.section_by_name(".debug_line").is_none());
}
