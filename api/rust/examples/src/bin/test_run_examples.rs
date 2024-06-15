use std::process::ExitCode;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn get_sample(format: &str, name: &str, private: bool) -> PathBuf {
    let mut sample_dir = PathBuf::from(env::var_os("LIEF_SAMPLES_DIR")
        .expect("LIEF_SAMPLES_DIR not set"));
    if private {
        sample_dir.push("private");
    }
    sample_dir.push(format);
    sample_dir.push(name);
    sample_dir
}

fn call_example_with(mut example_dir: PathBuf, example: &str, sample: PathBuf) {
    example_dir.push(example);
    example_dir.with_extension(std::env::consts::EXE_EXTENSION);
    let status = Command::new(example_dir.to_str().unwrap())
        .arg(sample.to_str().unwrap())
        .status()
        .expect("Command failed");
    println!("process finished with: {status}");
    assert!(status.success());
}

fn main() -> ExitCode {
    let argv0 = std::env::args().next().expect("argv[0]");
    let program_path = PathBuf::from(argv0);
    let example_dir = program_path.parent().expect("Parent path").to_path_buf();

    call_example_with(example_dir.clone(), "pe_check_authenticode",
        get_sample("PE", "PE32_x86-64_binary_avast-free-antivirus-setup-online.exe", false));

    call_example_with(example_dir.clone(), "pe_deps",
        get_sample("PE", "PE64_x86-64_binary_WinApp.exe", false));

    call_example_with(example_dir.clone(), "pe_rich_header",
        get_sample("PE", "PE32_x86_binary_cmd.exe", false));

    call_example_with(example_dir.clone(), "list_macho_encryption.rs",
        get_sample("MachO", "pgo.enc", true));

    call_example_with(example_dir.clone(), "elf_deps",
        get_sample("ELF", "ELF64_x86-64_binary_etterlog.bin", false));

    ExitCode::SUCCESS
}

