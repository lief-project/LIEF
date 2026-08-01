use std::process::ExitCode;
use std::sync::Arc;

use lief::assembly::{AssemblerConfig, Instruction};
use lief::generic::{Binary, Symbol};
use lief::runtime;
use lief::runtime::memory::{MmapFlags, Perm};
use lief::runtime::module::Module;

fn host_info() {
    println!("Host");
    // lief-doc: host-start
    println!("    Hostname: {}", runtime::Host::name());
    println!("    Home:     {}", runtime::Host::home_dir());
    println!("    Cache:    {}", runtime::Host::cache_dir());
    println!("    Temp:     {}", runtime::Host::tmp_dir());
    println!("    Config:   {}", runtime::Host::config_dir());
    // lief-doc: host-end

    // lief-doc: host-osx-start
    println!("    Version:  {}", runtime::osx::Host::os_version_name());
    println!(
        "    SIP:      {}",
        if runtime::osx::Host::is_sip_enabled() {
            "enabled"
        } else {
            "disabled"
        }
    );
    // lief-doc: host-osx-end
}

fn process_info() {
    println!("Process");
    // lief-doc: process-start
    println!("    PID:       {}", runtime::Process::pid());
    println!("    TID:       {}", runtime::Process::tid());
    println!("    Page size: {:#06x}", runtime::Process::page_size());
    println!("    Arch:      {:?}", runtime::Process::arch());
    println!("    Platform:  {:?}", runtime::Process::platform());
    // lief-doc: process-end

    // lief-doc: process-osx-start
    println!("    dyld:      {}", runtime::osx::Process::dyld_version());
    // lief-doc: process-osx-end
}

fn modules_info() {
    println!("Module API");

    // Module referencing libsystem_c.dylib in memory
    let mut libsystem: Option<runtime::osx::Module> = None;

    // lief-doc: modules-start
    for module in runtime::modules() {
        println!(
            "{} ({:#010x} - {:#010x})",
            module.name(),
            module.imagebase(),
            module.end()
        );
        if let runtime::Modules::Osx(osx_mod) = module {
            if osx_mod.name().ends_with("libsystem_c.dylib") {
                println!(
                    "libsystem_c.dylib found: {} ([{:#010x}, {:#010x}])",
                    osx_mod.path(),
                    osx_mod.imagebase(),
                    osx_mod.end()
                );
                libsystem = Some(osx_mod);
            }
        }
    }
    // lief-doc: modules-end

    let libsystem = match libsystem {
        Some(m) => m,
        None => return,
    };

    // lief-doc: modules-osx-start
    println!("libsystem_c path: {}", libsystem.path());
    let arc4_init = libsystem.dlsym("arc4_init".to_string());
    if !arc4_init.is_null() {
        println!(
            "{}!arc4_init: {:#010x}",
            libsystem.name(),
            arc4_init as usize
        );

        // Disassemble arc4_init directly from its resolved memory address
        for inst in runtime::disassemble(arc4_init as u64).take(4) {
            println!("    {}", inst.to_string());
        }
    }

    // libsystem.path() looks like a valid path but libsystem_c.dylib lives in
    // the dyld-shared-cache. Therefore, it's pointless to try to parse the
    // library from its filepath as the library does not exist on the disk.
    let macho_on_disk = {
        let _scoped = lief::logging::Scoped::new(lief::logging::Level::Off);
        libsystem.parse_from_path()
    };
    if macho_on_disk.is_none() {
        println!(
            "As expected, {} is not present in the filesystem",
            libsystem.path()
        );
    }

    // But we can parse it from memory:
    if let Some(macho_memory) = libsystem.parse_from_memory() {
        println!("in-memory imagebase: {:#010x}", macho_memory.imagebase());
        // List 'exported' symbols
        for sym in macho_memory.exported_symbols() {
            println!("{:10}: {:#010x}", sym.name(), sym.value());
        }
    }
    // lief-doc: modules-osx-end
}

fn memory_example() {
    println!("Memory");
    // lief-doc: memory-start
    // The JIT below allocates and executes RWX memory. On macOS this is only
    // permitted when System Integrity Protection (SIP) is disabled, so gate the
    // example on it.
    if runtime::osx::Host::is_sip_enabled() {
        eprintln!("SIP is enabled: skipping the JIT memory example");
        return;
    }

    // Note the `JIT` flag here that is used to switch the allocated chunk into
    // R-X once the shellcode is committed.
    let mut chunk = match runtime::Memory::mmap(
        runtime::Process::page_size() as u64,
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::JIT,
        Perm::READ | Perm::WRITE,
    ) {
        Some(c) => c,
        None => return,
    };

    // libSystem re-exports the libc symbols (write, ...)
    let libsystem = match runtime::osx::dlopen("libSystem.B.dylib") {
        Some(m) => m,
        None => {
            eprintln!("Failed to dlopen libSystem.B.dylib");
            let _ = runtime::Memory::munmap(&mut chunk);
            return;
        }
    };

    let p_write = libsystem.dlsym("write".to_string());
    if p_write.is_null() {
        eprintln!("Failed to resolve write");
        let _ = runtime::Memory::munmap(&mut chunk);
        return;
    }
    let p_write = p_write as u64;

    // The message printed by the shellcode.
    const HELLO: &[u8] = b"Hello World\n";
    let msg_ptr = HELLO.as_ptr() as u64;
    let msg_len = HELLO.len() as u64;

    let mut config = AssemblerConfig::default();
    config.symbol_resolver = Some(Arc::new(move |name: &str| -> Option<u64> {
        match name {
            "write" => Some(p_write),
            "var_msg" => Some(msg_ptr),
            "var_msg_len" => Some(msg_len),
            _ => None,
        }
    }));

    // Shellcode dynamically compiled and whose referenced symbols are resolved
    // at runtime by the provided config
    let raw_inst = runtime::assemble_with_config(
        chunk.addr(),
        r#"
        .text
            .global main
            .align 2

        main:
            stp     x29, x30, [sp, -16]!
            mov     x29, sp

            // Here we use symbols that are **dynamically** resolved by the
            // AssemblerConfig
            ldr     x8, =write          // write(2) libc wrapper
            ldr     x1, =var_msg        // buffer
            ldr     w2, =var_msg_len    // length

            // write(STDOUT_FILENO, msg, len)
            mov     x0, 1
            blr     x8

            mov     x0, xzr
            ldp     x29, x30, [sp], 16
            ret
        "#,
        &config,
    );

    println!(
        "{} bytes assembled at {:#010x}",
        raw_inst.len(),
        chunk.addr()
    );

    // Flush the instruction cache
    chunk.cache_flush();

    // Change the permission to R-X and invoke the JITed function
    chunk.make_rx();

    let hello_jit: unsafe extern "C" fn() = unsafe { std::mem::transmute(chunk.addr() as usize) };

    // This call prints the message "Hello World" on the console
    unsafe { hello_jit() };

    // Don't miss good practices!
    let _ = runtime::Memory::munmap(&mut chunk);
    // lief-doc: memory-end
}

fn main() -> ExitCode {
    if !runtime::enabled() {
        eprintln!("Error: LIEF's runtime is not enabled");
        return ExitCode::SUCCESS;
    }

    host_info();
    process_info();
    modules_info();
    memory_example();
    ExitCode::SUCCESS
}
