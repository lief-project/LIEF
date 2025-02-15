//! This examples iterates over the PE exceptions entries and pretty print their content

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();
    let mut file = std::fs::File::open(&path).expect("Can't open the file");
    if let Some(lief::Binary::PE(pe)) = lief::Binary::from(&mut file) {
        let entries = pe.exceptions();
        if entries.len() == 0 {
            println!("No entry");
            return ExitCode::SUCCESS;
        }

        for entry in entries {
            match entry {
                lief::pe::RuntimeExceptionFunction::X86_64(rfunc) => {
                    println!("x86-64 Entry: {}", &rfunc as &dyn lief::pe::ExceptionInfo);
                }

                lief::pe::RuntimeExceptionFunction::AArch64(rfunc) => {
                    println!("AArch64 Entry: {}", &rfunc as &dyn lief::pe::ExceptionInfo);
                }
            }
        }

        return ExitCode::SUCCESS;
    }
    println!("Can't process {}", path);
    ExitCode::FAILURE
}
