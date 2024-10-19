/// This example shows how to inspect a dyld shared cache with LIEF using the Rust API
use std::process::{self, ExitCode};

fn main() -> ExitCode {
    if !lief::is_extended() {
        println!("This example requires the extended version of LIEF")
    }
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();

    let cache = lief::dsc::load_from_path(&path.as_str(), "").unwrap_or_else(|| {
        process::exit(1);
    });

    for dylib in cache.libraries() {
        println!("0x{:016x} {}", dylib.address(), dylib.path());
    }

    for minfo in cache.mapping_info() {
        println!(
            "[0x{:016x}, 0x{:016x}]: 0x{:016x}",
            minfo.address(),
            minfo.end_address(),
            minfo.file_offset()
        )
    }

    ExitCode::SUCCESS
}
