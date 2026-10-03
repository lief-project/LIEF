use anyhow::{Context, Result, ensure};
use clap::{Arg, ArgAction, Command, value_parser};
use clap_complete::aot::{Generator, Shell, generate};
use common::version::get_lief_version;
use indoc::indoc;
use lief::DeclOpt;
use lief::dwarf::types::DwarfType;
use lief::logging::{self, Level};
use std::io;
use std::path::PathBuf;

fn parse_address(value: &str) -> Result<u64, String> {
    let (digits, radix) = match value.as_bytes() {
        [b'0', b'x' | b'X', ..] => (&value[2..], 16),
        [b'0', b'b' | b'B', ..] => (&value[2..], 2),
        [b'0', b'o' | b'O', ..] => (&value[2..], 8),
        [b'0', _, ..] => (&value[1..], 8),
        _ => (value, 10),
    };
    if digits.starts_with('+') {
        return Err(format!("Invalid address: {value}"));
    }
    u64::from_str_radix(digits, radix).map_err(|e| format!("Invalid address {value}: {e}"))
}

fn print_completions<G: Generator>(generator: G, cmd: &mut Command) {
    generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut io::stdout(),
    );
}

fn build_cli() -> Command {
    Command::new("lief-dwarfdump")
        .about("Reconstruct C++ declarations from DWARF")
        .long_about(indoc! {"
        Reconstruct C++ declarations from the DWARF debug info of a binary.

        Without a selector, lief-dwarfdump prints the declarations of every
        compilation unit. --type, --function and --address each select a single
        declaration instead. An empty name and the address 0 do not select anything.

        This tool requires LIEF extended.
        "})
        .version(get_lief_version())
        .arg_required_else_help(true)
        .arg(
            Arg::new("input")
                .help("Binary or DWARF file holding the debug info")
                .required_unless_present_any(["generator", "generate-manpage"]),
        )
        .arg(
            Arg::new("debug-log")
                .long("debug-log")
                .help("Enable debug logging")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-types")
                .long("show-types")
                .help("Show type definitions")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .value_name("NAME")
                .help("Reconstruct a single type by its short name"),
        )
        .arg(
            Arg::new("function")
                .long("function")
                .value_name("NAME")
                .help("Reconstruct a single function by demangled name with its stack variables"),
        )
        .arg(
            Arg::new("address")
                .long("address")
                .value_name("ADDRESS")
                .value_parser(parse_address)
                .help(
                    "Reconstruct a single function by its address (decimal, hex, octal or binary)",
                ),
        )
        .arg(
            Arg::new("generator")
                .long("generate")
                .hide(true)
                .action(ArgAction::Set)
                .value_parser(value_parser!(Shell)),
        )
        .arg(
            Arg::new("generate-manpage")
                .long("generate-manpage")
                .hide(true)
                .action(ArgAction::Set)
                .value_parser(value_parser!(PathBuf)),
        )
}

fn main() -> Result<()> {
    let matches = build_cli().get_matches();

    if let Some(generator) = matches.get_one::<Shell>("generator").copied() {
        let mut cmd = build_cli();
        print_completions(generator, &mut cmd);
        return Ok(());
    }

    if let Some(man_path) = matches.get_one::<PathBuf>("generate-manpage") {
        let cmd = build_cli();
        let man = clap_mangen::Man::new(cmd);
        let mut buffer: Vec<u8> = Default::default();
        man.render(&mut buffer)?;

        std::fs::write(man_path, buffer)?;
        return Ok(());
    }

    ensure!(lief::is_extended(), "This tool requires LIEF extended");

    let input = matches.get_one::<String>("input").unwrap();
    let dwarf = lief::dwarf::load(input).with_context(|| format!("Can't parse: {input}"))?;

    logging::set_level(if matches.get_flag("debug-log") {
        Level::Debug
    } else {
        Level::Info
    });

    let mut options = DeclOpt {
        is_cpp: true,
        ..Default::default()
    };

    if let Some(name) = matches.get_one::<String>("type").filter(|s| !s.is_empty()) {
        let ty = dwarf
            .type_by_name(name)
            .with_context(|| format!("Can't find type: {name}"))?;
        logging::log(Level::Info, &ty.to_decl_with_opt(&options));
        return Ok(());
    }

    options.include_locals = true;
    if let Some(name) = matches
        .get_one::<String>("function")
        .filter(|s| !s.is_empty())
    {
        let function = dwarf
            .function_by_name(name)
            .with_context(|| format!("Can't find function: {name}"))?;
        logging::log(Level::Info, &function.to_decl_with_opt(&options));
        return Ok(());
    }

    if let Some(&address) = matches.get_one::<u64>("address").filter(|&&addr| addr != 0) {
        let function = dwarf
            .function_by_addr(address)
            .with_context(|| format!("Can't find function at: {address:#x}"))?;
        logging::log(Level::Info, &function.to_decl_with_opt(&options));
        return Ok(());
    }

    options.include_locals = false;
    options.include_types = matches.get_flag("show-types");
    for unit in dwarf.compilation_units() {
        logging::log(Level::Info, &unit.to_decl_with_opt(&options));
    }

    Ok(())
}
