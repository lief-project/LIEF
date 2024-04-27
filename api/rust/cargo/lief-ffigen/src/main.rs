use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    output_dir: String,

    #[arg(long)]
    lief_dir: String,

    #[arg(long)]
    host: String,

    #[arg(short, long)]
    target: String,
}

fn main() -> miette::Result<()> {
    let args = Args::parse();
    std::env::set_var("PROFILE", "release");
    std::env::set_var("OPT_LEVEL", "3");
    std::env::set_var("DEBUG", "0");

    let host = args.host;
    let target = args.target;

    let precompiled_dir = PathBuf::from(args.output_dir);
    let lief_dir = PathBuf::from(args.lief_dir);

    let lief_lib_dir = lief_dir.join("lib");
    let lief_ffi_file = lief_lib_dir.join("LIEF").join("autocxx_ffi.rs");
    let lief_inc_dir = lief_dir.join("include");

    let autocxx_gen_dir = precompiled_dir.join("autocxx_builder");

    let autocxx_builder = autocxx_build::Builder::new(
        &lief_ffi_file, [&lief_inc_dir]
    );

    let mut cxx_builder = autocxx_builder
        .custom_gendir(autocxx_gen_dir)
        .extra_clang_args(&["-std=c++17"])
        .build()?;

    cxx_builder
        .out_dir(precompiled_dir.join("cxx_builder"))
        .host(&host)
        .target(&target)
        .std("c++17")
        .flag("-O3")
        .compile("lief-sys");


    Ok(())
}
