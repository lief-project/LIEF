use lief::Binary;

use lief::elf;
use lief::pe;
//use lief::macho::FatBinary;
//use lief::macho::commands::Commands;
use lief::generic::Relocation;
use lief::pe::DosHeader;
// use lief::elf::dynamic::DynamicEntry;

fn explore_elf(elf: &elf::Binary) {
    for section in elf.sections() {
        println!("{:?}", section);
    }
    for segment in elf.segments() {
        println!("{:?}", segment);
    }
    for note in elf.notes() {
        println!("{:?}", note);
    }
    for symbol in elf.dynamic_symbols() {
        println!("{:?}", symbol);
    }
}


fn main() {
    let path = std::env::args().last().unwrap();
    let mut file = std::fs::File::open(path).expect("Can't open the file");
    match Binary::from(&mut file) {
        Some(Binary::ELF(elf)) => {
            explore_elf(&elf);
        },
        Some(Binary::PE(pe)) => {
        },
        _ => {}
    }
    return;
}
