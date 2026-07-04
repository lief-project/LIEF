use clap::Parser;
use proc_macro2::TokenStream;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    output_dir: String,

    #[arg(long)]
    source_dir: Option<String>,
}

fn should_skip(file: &Path) -> bool {
    let filename = file.file_name().unwrap().to_str().unwrap();
    if filename == "mod.rs" || filename == "lib.rs" {
        return true;
    }
    // Skip module-declaration files that have no #[cxx::bridge].
    if let Ok(text) = fs::read_to_string(file) {
        if !text.contains("#[cxx::bridge]") {
            return true;
        }
    }
    false
}

fn iter_dir(dir: &Path, recursive: bool) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .flat_map(|entry| {
                    let path = entry.path();
                    if should_skip(&path) {
                        return vec![];
                    }
                    if path.is_file() {
                        return vec![path];
                    }
                    if path.is_dir() && recursive {
                        return iter_dir(&path, recursive);
                    }
                    vec![]
                })
                .collect()
        })
        .unwrap_or_default()
}

fn file_to_ts(file: &Path) -> TokenStream {
    match fs::read_to_string(file).unwrap().parse::<TokenStream>() {
        Ok(tokens) => tokens,
        Err(e) => panic!("Failed to parse string to TokenStream: {}", e),
    }
}

fn main() -> miette::Result<()> {
    let args = Args::parse();

    let ffi_dir = args.source_dir.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("lief-ffi")
    });

    let dst_root_dir = PathBuf::from(args.output_dir);
    let ffi_src_dir = ffi_dir.join("src");
    let files = iter_dir(&ffi_src_dir, true);
    let opt = cxx_gen::Opt::default();
    for f in files {
        let code = cxx_gen::generate_header_and_cc(file_to_ts(&f), &opt).unwrap();
        let dir = f.parent().unwrap().strip_prefix(&ffi_src_dir).unwrap();
        let dst_dir = dst_root_dir.join(dir);
        fs::create_dir_all(&dst_dir).unwrap();

        let cpp = dst_dir.join(
            f.with_extension("cpp")
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
        );

        let header = dst_dir.join(
            f.with_extension("hpp")
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
        );

        fs::write(&header, code.header).unwrap();
        fs::write(&cpp, code.implementation).unwrap();
    }

    Ok(())
}
