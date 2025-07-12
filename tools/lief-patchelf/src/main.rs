use anyhow::{Context, Ok, Result};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use clap_complete::aot::{generate, Generator, Shell};
use indoc::indoc;
use lief::elf::{dynamic, Segment};
use lief::generic::Symbol;
use lief::{
    self,
    elf::{header, segment},
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone)]
struct NeededLibrary {
    pub name: String,
    pub found: bool,
}

impl NeededLibrary {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            found: false,
        }
    }
}

struct PatchContext {
    pub elf: lief::elf::Binary,
    pub options: ArgMatches,
    pub modified: bool,
    pub output: PathBuf,
}

impl PatchContext {
    pub fn new(input: &Path, options: &ArgMatches, output: &Path) -> Result<PatchContext> {
        let mut parser_config = lief::elf::parser_config::Config::default();
        if let Some(pagesize) = options.get_one::<u64>("page-size") {
            parser_config.page_size = *pagesize;
        }

        let str_path = input
            .to_str()
            .with_context(|| format!("Can't convert {input:?} into a string"))?;
        let elf = lief::elf::parse_with_config(str_path, &parser_config)
            .with_context(|| format!("Can't parse ELF: {input:?}"))?;
        Ok(Self {
            elf,
            options: options.clone(),
            modified: false,
            output: output.to_path_buf(),
        })
    }

    pub fn process(&mut self) -> Result<()> {
        if self.options.get_flag("no-sort") {
            lief::logging::log(
                lief::logging::Level::WARN,
                "--no-sort is not supported by LIEF",
            )
        }

        self.process_print()?;
        self.update_soname()?;
        self.update_osabi()?;
        self.update_interpreter()?;
        self.update_rpath()?;
        self.update_needed()?;
        self.update_symbol_version()?;
        self.update_execstack()?;
        self.rename_dynamic_symbols()?;
        self.add_debug_tag()?;
        self.update_defaultlibs()?;

        if self.modified {
            let exist = self.output.exists();
            self.elf.write(&self.output);

            #[cfg(unix)]
            if !exist {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.output, fs::Permissions::from_mode(0o755))?;
            }
        }
        Ok(())
    }

    fn update_interpreter(&mut self) -> Result<()> {
        if let Some(interpreter) = self.options.get_one::<String>("interpreter") {
            self.elf.set_interpreter(interpreter);
            self.modified = true;
        }
        Ok(())
    }

    fn add_debug_tag(&mut self) -> Result<()> {
        if !self.options.get_flag("add-debug-tag") {
            return Ok(());
        }

        if self
            .elf
            .dynamic_entry_by_tag(dynamic::Tag::DEBUG_TAG)
            .is_none()
        {
            self.modified = true;
            self.elf
                .add_dynamic_entry(&dynamic::Entries::with_tag(dynamic::Tag::DEBUG_TAG));
        }

        Ok(())
    }

    fn process_print(&mut self) -> Result<()> {
        if self.options.get_flag("print-interpreter") {
            println!("{}", self.elf.interpreter());
        }

        if self.options.get_flag("print-os-abi") {
            let os_abi = self.elf.header().identity_os_abi();
            match os_abi {
                header::OsAbi::SYSTEMV => println!("System V"),
                header::OsAbi::HPUX => println!("HP-UX"),
                header::OsAbi::NETBSD => println!("NetBSD"),
                header::OsAbi::LINUX => println!("Linux"),
                header::OsAbi::HURD => println!("GNU Hurd"),
                header::OsAbi::SOLARIS => println!("Solaris"),
                header::OsAbi::AIX => println!("AIX"),
                header::OsAbi::IRIX => println!("IRIX"),
                header::OsAbi::FREEBSD => println!("FreeBSD"),
                header::OsAbi::TRU64 => println!("Tru64"),
                header::OsAbi::OPENBSD => println!("OpenBSD"),
                header::OsAbi::OPENVMS => println!("OpenVMS"),
                _ => println!("{os_abi:?}"),
            }
        }

        if self.options.get_flag("print-soname") {
            if let Some(dynamic::Entries::SharedObject(so)) =
                self.elf.dynamic_entry_by_tag(dynamic::Tag::SONAME)
            {
                println!("{}", so.name());
            } else {
                return Err(PatchElfError::Missing("DT_SONAME".to_string()).into());
            }
        }

        if self.options.get_flag("print-rpath") {
            let rpath_entries = self
                .elf
                .dynamic_entries()
                .filter(|e| matches!(e, dynamic::Entries::Rpath(_) | dynamic::Entries::RunPath(_)));
            for entry in rpath_entries {
                match entry {
                    dynamic::Entries::Rpath(e) => {
                        println!("{} (legacy)", e.rpath());
                    }
                    dynamic::Entries::RunPath(e) => {
                        println!("{}", e.runpath());
                    }
                    _ => panic!("Should not be present"),
                }
            }
        }

        if self.options.get_flag("print-needed") {
            for entry in self.elf.dynamic_entries() {
                if let dynamic::Entries::Library(lib) = entry {
                    println!("{}", lib.name());
                }
            }
        }

        if self.options.get_flag("print-execstack") {
            let mut result = '?';
            if let Some(gnu_stack) = self.elf.segment_by_type(segment::Type::GNU_STACK) {
                let flags = segment::Flags::from_value(gnu_stack.flags());
                if (flags & segment::Flags::X) == segment::Flags::X {
                    result = 'X';
                } else {
                    result = '-';
                }
            }
            println!("execstack: {result}")
        }
        Ok(())
    }

    fn update_soname(&mut self) -> Result<()> {
        if let Some(soname) = self.options.get_one::<String>("set-soname") {
            self.modified = true;
            if let Some(dynamic::Entries::SharedObject(mut so)) =
                self.elf.dynamic_entry_by_tag(dynamic::Tag::SONAME)
            {
                so.set_name(soname);
                return Ok(());
            }

            let new_entry = dynamic::SharedObject::new(soname);
            self.elf.add_dynamic_entry(&new_entry);
        }
        Ok(())
    }

    fn update_osabi(&mut self) -> Result<()> {
        if let Some(new_osabi) = self.options.get_one::<String>("set-os-abi") {
            self.modified = true;
            match new_osabi.to_lowercase().as_str() {
                "system v" | "system-v" | "sysv" => {
                    self.elf.header().set_osabi(header::OsAbi::SYSTEMV)
                }
                "hp-ux" => self.elf.header().set_osabi(header::OsAbi::HPUX),
                "netbsd" => self.elf.header().set_osabi(header::OsAbi::NETBSD),
                "linux" | "gnu" => self.elf.header().set_osabi(header::OsAbi::GNU),
                "gnu hurd" | "gnu-hurd" | "hurd" => {
                    self.elf.header().set_osabi(header::OsAbi::HURD)
                }
                "solaris" => self.elf.header().set_osabi(header::OsAbi::SOLARIS),
                "aix" => self.elf.header().set_osabi(header::OsAbi::AIX),
                "irix" => self.elf.header().set_osabi(header::OsAbi::IRIX),
                "freebsd" => self.elf.header().set_osabi(header::OsAbi::FREEBSD),
                "tru64" => self.elf.header().set_osabi(header::OsAbi::TRU64),
                "openbsd" => self.elf.header().set_osabi(header::OsAbi::OPENBSD),
                "openvms" => self.elf.header().set_osabi(header::OsAbi::OPENVMS),
                _ => {
                    return Err(PatchElfError::Other("unrecognized OS ABI".to_string()).into());
                }
            }
        }
        Ok(())
    }

    fn shrink_rpath(&mut self, allowed_rpath: &[String]) -> Result<()> {
        let mut rpaths = Vec::new();
        let mut deps = Vec::new();

        for entry in self.elf.dynamic_entries() {
            match entry {
                dynamic::Entries::RunPath(runpath) => {
                    rpaths.push(runpath.runpath());
                }
                dynamic::Entries::Rpath(rpath) => {
                    rpaths.push(rpath.rpath());
                }
                dynamic::Entries::Library(needed) => {
                    deps.push(NeededLibrary::new(&needed.name()));
                }
                _ => {}
            }
        }

        let mut new_rpath = Vec::new();
        for rpath in rpaths.iter() {
            for path in rpath.split(':') {
                let mut keep_path = false;
                if path.starts_with("@") {
                    new_rpath.push(path.to_string());
                    continue;
                }

                if !allowed_rpath.is_empty()
                    && !allowed_rpath
                        .iter()
                        .any(|e| path == e || path.starts_with(e.as_str()))
                {
                    lief::logging::log(
                        lief::logging::Level::DEBUG,
                        &format!(
                            "removing directory '{path}' from RPATH because of non-allowed prefix"
                        ),
                    );
                    continue;
                }

                for dep in deps.iter_mut().filter(|e| !e.found) {
                    let mut lib_path = PathBuf::from(path);
                    lib_path.push(dep.name.clone());
                    if lib_path.exists() {
                        // TODO(romain): Check machine / ELF class
                        dep.found = true;
                        keep_path = true;
                    }
                }

                if keep_path {
                    new_rpath.push(path.to_string());
                }
            }
        }

        for entry in self.elf.dynamic_entries() {
            match entry {
                dynamic::Entries::RunPath(mut runpath) => {
                    self.modified = true;
                    runpath.set_runpath_with_value(
                        &new_rpath.iter().map(String::as_str).collect::<Vec<&str>>(),
                    );
                }
                dynamic::Entries::Rpath(mut rpath) => {
                    self.modified = true;
                    rpath.set_rpath_with_value(
                        &new_rpath.iter().map(String::as_str).collect::<Vec<&str>>(),
                    )
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn update_rpath(&mut self) -> Result<()> {
        if self.options.get_flag("remove-rpath") {
            self.modified = true;
            self.elf.remove_dynamic_entries_by_tag(dynamic::Tag::RPATH);
            self.elf
                .remove_dynamic_entries_by_tag(dynamic::Tag::RUNPATH);
        }

        // Make sure we have one rpath/runpath
        let nb_rpath = self
            .elf
            .dynamic_entries()
            .filter(|e| matches!(e, dynamic::Entries::Rpath(_)))
            .count();
        let nb_runpath = self
            .elf
            .dynamic_entries()
            .filter(|e| matches!(e, dynamic::Entries::RunPath(_)))
            .count();

        if nb_rpath > 0 && nb_runpath > 0 {
            return Err(PatchElfError::MixingRpathRunPath.into());
        }

        let force_rpath = self.options.get_flag("force-rpath");

        if let Some(dynamic::Entries::RunPath(mut runpath)) =
            self.elf.dynamic_entry_by_tag(dynamic::Tag::RUNPATH)
        {
            if let Some(new_runpaths) = self.options.get_many::<String>("add-rpath") {
                self.modified = true;
                for new_runpath in new_runpaths {
                    runpath.append(new_runpath);
                }
            } else if let Some(new_path) = self.options.get_one::<String>("set-rpath") {
                self.modified = true;
                runpath.set_runpath(new_path);
            }
        } else if let Some(dynamic::Entries::Rpath(mut rpath)) =
            self.elf.dynamic_entry_by_tag(dynamic::Tag::RPATH)
        {
            if let Some(new_rpaths) = self.options.get_many::<String>("add-rpath") {
                self.modified = true;
                for new_rpath in new_rpaths {
                    rpath.append(new_rpath);
                }
            } else if let Some(new_path) = self.options.get_one::<String>("set-rpath") {
                self.modified = true;
                rpath.set_rpath(new_path);
            }
        } else if force_rpath {
            let mut rpath = dynamic::Rpath::new("");
            if let Some(new_rpaths) = self.options.get_many::<String>("add-rpath") {
                self.modified = true;
                for new_rpath in new_rpaths {
                    rpath.append(new_rpath);
                }
            } else if let Some(new_path) = self.options.get_one::<String>("set-rpath") {
                self.modified = true;
                rpath.set_rpath(new_path);
            }

            if !rpath.rpath().is_empty() {
                self.modified = true;
                self.elf.add_dynamic_entry(&rpath);
            }
        } else {
            let mut runpath = dynamic::RunPath::new("");
            if let Some(new_rpaths) = self.options.get_many::<String>("add-rpath") {
                self.modified = true;
                for new_rpath in new_rpaths {
                    runpath.append(new_rpath);
                }
            } else if let Some(new_path) = self.options.get_one::<String>("set-rpath") {
                self.modified = true;
                runpath.set_runpath(new_path);
            }
            if !runpath.runpath().is_empty() {
                self.modified = true;
                self.elf.add_dynamic_entry(&runpath);
            }
        }

        if !force_rpath {
            let mut opt_rpath = None;
            if let Some(dynamic::Entries::Rpath(rpath)) =
                self.elf.dynamic_entry_by_tag(dynamic::Tag::RPATH)
            {
                opt_rpath = Some(rpath.rpath());
            }
            if let Some(rpath_str) = opt_rpath {
                self.modified = true;
                self.elf.remove_dynamic_entries_by_tag(dynamic::Tag::RPATH);
                let runpath = dynamic::RunPath::new(&rpath_str);
                self.elf.add_dynamic_entry(&runpath);
            }
        } else {
            let mut opt_runpath = None;
            if let Some(dynamic::Entries::RunPath(runpath)) =
                self.elf.dynamic_entry_by_tag(dynamic::Tag::RUNPATH)
            {
                opt_runpath = Some(runpath.runpath());
            }
            if let Some(runpath_str) = opt_runpath {
                self.modified = true;
                self.elf
                    .remove_dynamic_entries_by_tag(dynamic::Tag::RUNPATH);
                let rpath = dynamic::Rpath::new(&runpath_str);
                self.elf.add_dynamic_entry(&rpath);
            }
        }

        if self.options.get_flag("shrink-rpath") {
            let mut allowed_rpath = Vec::new();
            if let Some(allowed) = self.options.get_many::<String>("allowed-rpath-prefixes") {
                for path in allowed {
                    for spath in path.split(":") {
                        allowed_rpath.push(spath.to_string());
                    }
                }
            }
            self.shrink_rpath(allowed_rpath.as_slice())?;
        }

        Ok(())
    }

    fn update_needed(&mut self) -> Result<()> {
        if let Some(new_deps) = self.options.get_many::<String>("add-needed") {
            for deps in new_deps {
                self.modified = true;
                self.elf.add_library(deps);
            }
        }

        if let Some(remove_deps) = self.options.get_many::<String>("remove-needed") {

            for deps in remove_deps {
                self.modified = true;
                self.elf.remove_library(deps);
                self.elf.remove_version_requirement(deps);
            }

        }

        if let Some(remove_deps) = self.options.get_many::<String>("replace-needed") {
            assert_eq!(remove_deps.len() % 2, 0);
            for chunk in remove_deps
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .chunks(2)
            {
                let (original, new) = (&chunk[0], &chunk[1]);
                if let Some(mut lib) = self.elf.get_library(original) {
                    lib.set_name(new);
                    if let Some(mut req) = self.elf.find_version_requirement(original) {
                        req.set_name(new);
                    }
                    self.modified = true;
                } else {
                    lief::logging::log(
                        lief::logging::Level::WARN,
                        &format!("Library '{original}' not found"),
                    );
                }
            }
        }

        Ok(())
    }

    fn update_symbol_version(&mut self) -> Result<()> {
        if let Some(sym_clear) = self.options.get_many::<String>("clear-symbol-version") {
            for symname in sym_clear {
                if let Some(dynsym) = self.elf.dynamic_symbol_by_name(symname) {
                    lief::logging::log(
                        lief::logging::Level::DEBUG,
                        &format!("clearing symbol version for {symname}"),
                    );
                    if let Some(mut symver) = dynsym.symbol_version() {
                        self.modified = true;
                        symver.as_global();
                    }
                } else {
                    lief::logging::log(lief::logging::Level::INFO, &format!("Symbol {symname} not found"));
                }
            }
        }

        if let Some(rem_needed) = self.options.get_many::<String>("remove-needed-version") {
            assert_eq!(rem_needed.len() % 2, 0);
            for chunk in rem_needed
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .chunks(2)
            {
                let (libname, version) = (&chunk[0], &chunk[1]);
                for dynsym in self.elf.dynamic_symbols() {
                    if let Some(mut sym_ver) = dynsym.symbol_version() {
                        if let Some(aux) = sym_ver.symbol_version_auxiliary() {
                            if aux.name() == *version {
                                sym_ver.as_global();
                                self.modified = true;
                            }
                        }
                    }
                }
                if let Some(mut req) = self.elf.find_version_requirement(libname) {
                    if req.remove_aux_requirement_by_name(version) {
                        self.modified = true;
                    } else {
                        lief::logging::log(lief::logging::Level::ERR,
                            &format!("Can't remove {version} in {libname}"));
                    }
                } else {
                    lief::logging::log(lief::logging::Level::ERR,
                        &format!("Can't find library {libname}"));
                }

            }

        }
        Ok(())
    }

    fn update_defaultlibs(&mut self) -> Result<()> {
        if !self.options.get_flag("no-default-lib") {
            return Ok(());
        }
        if let Some(dynamic::Entries::Flags(mut flags)) =
            self.elf.dynamic_entry_by_tag(dynamic::Tag::FLAGS_1)
        {
            flags.add_flag(dynamic::DtFlags::NODEFLIB);
            self.modified = true;
        }
        Ok(())
    }

    fn update_execstack(&mut self) -> Result<()> {
        if let Some(mut seg) = self.elf.segment_by_type(segment::Type::GNU_STACK) {
            let original_flags = segment::Flags::from_value(seg.flags());
            let mut flags = original_flags;
            if self.options.get_flag("set-execstack") {
                flags |= segment::Flags::X;
            }

            if self.options.get_flag("clear-execstack") {
                flags -= segment::Flags::X;
            }

            if original_flags != flags {
                self.modified = true;
            }
            seg.set_flags(flags);
            return Ok(());
        }

        if !self.options.get_flag("set-execstack") {
            return Ok(());
        }

        let mut gnu_stack = Segment::new();
        gnu_stack.set_type(segment::Type::GNU_STACK);
        gnu_stack.set_flags(segment::Flags::R | segment::Flags::W | segment::Flags::X);
        gnu_stack.set_alignment(1);

        self.modified = true;
        self.elf.add_segment(&gnu_stack).unwrap();

        Ok(())
    }

    fn rename_dynamic_symbols(&mut self) -> Result<()> {
        if let Some(map_file) = self
            .options
            .get_one::<std::path::PathBuf>("rename-dynamic-symbols")
        {
            let mut hmap = HashMap::new();
            let file = File::open(map_file)?;
            let reader = BufReader::new(file);
            let lines = reader.lines().map(|l| l.unwrap());
            for (i, line) in lines.enumerate() {
                let pos = line.find(' ').ok_or_else(|| {
                    PatchElfError::Other(format!(
                        "{map_file:?}:{i} Map file line is missing the second element"
                    ))
                })?;
                let key = line[..pos].to_string();
                let value = line[pos + 1..].to_string();
                if key.contains('@') || value.contains('@') {
                    return Err(PatchElfError::Other(format!(
                        "{map_file:?}:{i} Name pair contains version tag: {key} {value}"
                    ))
                    .into());
                }
                if let Some(existing) = hmap.insert(key.clone(), value) {
                    return Err(PatchElfError::Other(format!(
                        "{map_file:?}:{i} '{key}' appears twice in the map file ({existing})"
                    ))
                    .into());
                }
            }
            for (k, v) in hmap {
                if let Some(mut dynsym) = self.elf.dynamic_symbol_by_name(&k) {
                    self.modified = true;
                    dynsym.set_name(&v);
                }
            }
        }
        Ok(())
    }
}

fn print_completions<G: Generator>(generator: G, cmd: &mut Command) {
    generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut io::stdout(),
    );
}

fn resolve_args(arg: &str) -> Result<String> {
    if arg.is_empty() || !arg.starts_with("@") {
        return Ok(arg.to_string());
    }
    let mut file_path = arg.to_string();
    file_path.drain(..1);
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let mut output = String::new();
    reader.read_to_string(&mut output)?;
    Ok(output)
}

fn get_lief_version() -> &'static str {
    // Command::version takes an "IntoResettable" string whose simplest form is
    // a 'static str.
    //
    // Ideally we should use
    //
    // ```
    // static LIEF_VERSION: LazyLock<String> = LazyLock::new(|| format!("{}", lief::version()));
    // Command::new("...)
    //     .version(&**LIEF_VERSION)
    // ```
    //
    // but `LazyLock` requires a more recent version of `rustc` compared to the LIEF's min rust
    // version. Therefore, we workaround with this leak.
    //
    Box::leak(format!("{}", lief::version()).into_boxed_str())
}

fn build_cli() -> Command {
    Command::new("lief-patchelf")
        .about("Patchelf based on LIEF")
        .arg_required_else_help(true)
        .version(get_lief_version())
        .arg(
            Arg::new("interpreter")
                .long("set-interpreter")
                .alias("interpreter")
                .help("Change the interpreter")
                .value_parser(resolve_args)
                .value_name("INTERPRETER")
                .help("Change the dynamic loader ('ELF interpreter') of executable given to INTERPRETER.")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("page-size")
                .long("page-size")
                .action(ArgAction::Set)
                .value_name("SIZE")
                .help("Uses the given page size instead of the default")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("print-interpreter")
                .long("print-interpreter")
                .help("Prints the ELF interpreter of the executable. (e.g. `/lib64/ld-linux-x86-64.so.2`)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print-os-abi")
                .long("print-os-abi")
                .help("Prints the OS ABI of the executable (`EI_OSABI` field of an ELF file).")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("set-os-abi")
                .long("set-os-abi")
                .help("Changes the OS ABI of the executable (`EI_OSABI` field of an ELF file).")
                .long_help(indoc! {r#"
                Changes the OS ABI of the executable (EI_OSABI field of an ELF file).

                The ABI parameter is pretty flexible. For example, you can specify it
                as a "Linux", "linux", or even "lInUx" - all those names will set `EI_OSABI`
                field of the ELF header to the value "3", which corresponds to Linux OS ABI.
                The same applies to other ABI names - System V, FreeBSD, Solaris, etc.
                "#})
                .value_parser(resolve_args)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("print-soname")
                .long("print-soname")
                .help(indoc! {"
                Prints DT_SONAME entry of .dynamic section.
                Raises an error if DT_SONAME doesn't exist.
                "})
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("set-soname")
                .long("set-soname")
                .help("Sets DT_SONAME entry of a library to SONAME.")
                .value_parser(resolve_args)
                .value_name("SONAME")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("print-rpath")
                .long("print-rpath")
                .help("Prints the DT_RUNPATH or DT_RPATH for an executable or library.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("set-rpath")
                .long("set-rpath")
                .value_parser(resolve_args)
                .help("Change the `DT_RUNPATH` of the executable or library to RUNPATH.")
                .value_name("RUNPATH")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("add-rpath")
                .long("add-rpath")
                .value_parser(resolve_args)
                .value_name("RUNPATH")
                .help("Add RUNPATH to the existing DT_RUNPATH of the executable or library.")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("shrink-rpath")
                .long("shrink-rpath")
                .help(indoc! {"
                Remove from the DT_RUNPATH or DT_RPATH all directories that do not contain a
                library referenced by DT_NEEDED fields of the executable or library.
                "})
                .long_help(indoc! {"
                Remove from the DT_RUNPATH or DT_RPATH all directories that do not contain a
                library referenced by DT_NEEDED fields of the executable or library.

                For instance, if an executable references one library libfoo.so, has
                an RPATH `/lib:/usr/lib:/foo/lib`, and `libfoo.so` can only be found
                in `/foo/lib`, then the new RPATH will be `/foo/lib`.
                "})
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("remove-rpath")
                .long("remove-rpath")
                .help("Removes the DT_RPATH or DT_RUNPATH entry of the executable or library.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("allowed-rpath-prefixes")
                .long("allowed-rpath-prefixes")
                .value_parser(resolve_args)
                .value_name("PREFIXES")
                .long_help(indoc! {"
                Combined with the `--shrink-rpath` option, this can be used for
                further rpath tuning. For instance, if an executable has an RPATH
                `/tmp/build-foo/.libs:/foo/lib`, it is probably desirable to keep
                the `/foo/lib` reference instead of the `/tmp` entry.
                "})
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("force-rpath")
                .long("force-rpath")
                .help("Forces the use of the obsolete DT_RPATH in the file instead of DT_RUNPATH \
                      By default DT_RPATH is converted to DT_RUNPATH.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print-needed")
                .long("print-needed")
                .help("Prints all DT_NEEDED entries of the executable.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("add-needed")
                .long("add-needed")
                .help("Adds a declared dependency on a dynamic library (DT_NEEDED). \
                      This option can be given multiple times.")
                .value_parser(resolve_args)
                .value_name("LIBRARY")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("remove-needed")
                .long("remove-needed")
                .help("Removes a declared dependency on LIBRARY (DT_NEEDED entry). This option can \
                      be given multiple times.")
                .value_parser(resolve_args)
                .value_name("LIBRARY")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("replace-needed")
                .long("replace-needed")
                .value_parser(resolve_args)
                .action(ArgAction::Append)
                .value_names(vec!["LIB_ORIG", "LIB_NEW"])
                .help("Replaces a declared dependency on a dynamic library with another one (DT_NEEDED).\
                      This option can be given multiple times.")
                .num_args(2),
        )
        .arg(
            Arg::new("clear-symbol-version")
                .long("clear-symbol-version")
                .value_parser(resolve_args)
                .help(indoc! {"
                Clear the symbol version requirement for the given symbol name. This option can be
                given multiple times.
                "})
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("remove-needed-version")
                .long("remove-needed-version")
                .value_parser(resolve_args)
                .help(indoc! {"
                Removes VERSION_SYMBOL from LIBRARY in .gnu.version_r and resets entries referenced
                the version in .gnu.version, could be used to remove symbol versioning. LIBRARY and
                VERSION_SYMBOL can be retrieved from the output of `readelf -V`.
                "})
                .num_args(2)
                .value_names(vec!["LIBRARY", "VERSION_SYMBOL"])
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("print-execstack")
                .long("print-execstack")
                .help("Prints the state of the executable flag of the GNU_STACK program header, if present.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("clear-execstack")
                .long("clear-execstack")
                .help("Clears the executable flag of the GNU_STACK program header, or adds a new header.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("set-execstack")
                .long("set-execstack")
                .help("Sets the executable flag of the GNU_STACK program header, or adds a new header.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(std::path::PathBuf)),
        )
        .arg(
            Arg::new("no-sort")
                .long("no-sort")
                .long_help(indoc! {"
                Do not sort program headers or section headers. This is useful when debugging
                patchelf, because it makes it easier to read diffs of the output of `readelf -a`.
                "})
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("Prints details of the changes made to the input file.")
                .action(ArgAction::SetTrue))
        .arg(
            Arg::new("no-default-lib")
                .long("no-default-lib")
                .help("Marks the object so that the search for dependencies of this object will \
                      ignore any default library search paths.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-clobber-old-sections")
                .long("no-clobber-old-sections")
                .long_help(indoc! {"
                Do not clobber old section values.

                patchelf defaults to overwriting replaced header sections with garbage to ensure they are not
                used accidentally. This option allows to opt out of that behavior, so that binaries that attempt
                to read their own headers from a fixed offset (e.g. Firefox) continue working.

                Use sparingly and with caution.
                "})
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("add-debug-tag")
                .long("add-debug-tag")
                .help("Adds DT_DEBUG tag to the `.dynamic` section")
                .long_help(indoc! {"
                Adds DT_DEBUG tag to the `.dynamic` section if not yet present in an ELF
                object. A shared library (-shared) by default does not receive DT_DEBUG tag.
                This means that when a shared library has an entry point (so that it
                can be run as an executable), the debugger does not connect to it correctly and
                symbols are not resolved.
                "})
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("rename-dynamic-symbols")
                .long("rename-dynamic-symbols")
                .action(ArgAction::Set)
                .help("Renames dynamic symbols")
                .long_help(indoc! {"
                Renames dynamic symbols. The name map file should contain lines
                with the old and the new name separated by spaces like this:

                old_name new_name

                Symbol names do not contain version specifier that are also shown in the output of
                the nm -D command from binutils.
                So instead of the name `write@GLIBC_2.2.5` it is just `write`.
                "})
                .value_parser(clap::value_parser!(std::path::PathBuf)),
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
                .value_parser(clap::value_parser!(std::path::PathBuf)),
        )
        .arg(
            Arg::new("filenames")
                .action(ArgAction::Set)
                .num_args(1..)
                .value_parser(clap::value_parser!(std::path::PathBuf)),
        )
}

#[derive(Error, Debug)]
pub enum PatchElfError {
    #[error("MixingRpathRunPath")]
    MixingRpathRunPath,

    #[error("'{0}' is missing")]
    Missing(String),

    #[error("{0}")]
    Other(String),
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

    let filenames = matches
        .get_many::<std::path::PathBuf>("filenames")
        .ok_or_else(|| PatchElfError::Other("Filenames error".to_string()))?;

    let filenames = filenames.collect::<Vec<_>>();

    lief::logging::set_level(lief::logging::Level::WARN);

    if matches.get_flag("debug") {
        lief::logging::set_level(lief::logging::Level::DEBUG);
    }

    let mut parser_config = lief::elf::parser_config::Config::default();
    if let Some(pagesize) = matches.get_one::<u64>("page-size") {
        parser_config.page_size = *pagesize;
    }

    let opt_output = matches.get_one::<std::path::PathBuf>("output");
    if opt_output.is_some() && filenames.len() > 1 {
        return Err(PatchElfError::Other(
            "--output option only allowed with single input file".to_string(),
        )
        .into());
    }

    for filename in filenames {
        let output = {
            if let Some(out) = opt_output {
                out
            } else {
                filename
            }
        };
        let mut ctx = PatchContext::new(filename, &matches, output)?;
        ctx.process()?;
    }

    Ok(())
}
