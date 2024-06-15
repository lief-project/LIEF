use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();
    let mut file = std::fs::File::open(&path).expect("Can't open the file");
    if let Some(lief::Binary::MachO(fat)) = lief::Binary::from(&mut file) {
        for macho in fat.iter() {
            for cmd in macho.commands() {
                if let lief::macho::Commands::EncryptionInfo(info) = cmd {
                    println!("Encrypted area: 0x{:08x} - 0x{:08x} (id: {})",
                        info.crypt_offset(), info.crypt_offset() + info.crypt_size(),
                        info.crypt_id()
                    )
                }
            }
        }
        return ExitCode::SUCCESS;
    }
    println!("Can't process {}", path);
    ExitCode::FAILURE
}
