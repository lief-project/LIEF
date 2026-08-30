#![allow(warnings)]
use lief;
use lief::runtime::memory::{MmapFlags, Perm};
use lief::runtime::{Memory, Module, Process};

fn test_process() {
    println!(
        "{} {} {} {:?} {:?}",
        Process::pid(),
        Process::tid(),
        Process::page_size(),
        Process::arch(),
        Process::platform()
    );
}

fn test_modules() {
    for m in lief::runtime::modules() {
        println!(
            "{} {} {:#x} {:#x} {:#x} {:?}",
            m.name(),
            m.path(),
            m.imagebase(),
            m.size(),
            m.end(),
            m.contains(0)
        );
        assert!(lief::runtime::module_from_addr(m.imagebase()).is_some());
        assert!(lief::runtime::module_from_path(m.path()).is_some());
        assert!(lief::runtime::module_from_name(&m.name()).is_some());
        match &m {
            lief::runtime::Modules::Linux(linux) => {}

            lief::runtime::Modules::Android(android) => {}

            lief::runtime::Modules::Windows(win) => {}

            lief::runtime::Modules::Osx(osx) => {}
        }
    }
}

fn test_osx_host() {
    use lief::runtime::osx::Host;
    let version = Host::os_version_name();
    println!("os_version_name: {}", version);
    assert!(!version.is_empty());
}

fn test_windows_host() {
    use lief::runtime::windows::{Host, Version};
    let version = Host::version().expect("missing version");
    println!("windows version: {}", version);

    // Sanity checks on the Version type.
    let v = Version::new(10, 0, 26200);
    assert_eq!(v.major, 10);
    assert_eq!(v.minor, 0);
    assert_eq!(v.build_number, 26200);
    assert_eq!(format!("{}", v), "10.0.26200");

    assert!(Version::new(10, 0, 10240) < Version::new(10, 0, 26100));
    assert_eq!(Version::new(6, 1, 7600), Version::new(6, 1, 7600));

    // Any supported Windows host should be at least Windows 7 (6.1.x).
    assert!(version >= Version::new(6, 1, 0));
}

fn test_windows_process() {
    use lief::runtime::windows::Process;
    let peb = Process::peb().expect("missing PEB");

    println!(
        "being_debugged={} ldr={:#x} process_parameters={:#x} session_id={}",
        peb.being_debugged(),
        peb.ldr(),
        peb.process_parameters(),
        peb.session_id()
    );

    // The loader data and the process parameters are always populated by the
    // Windows loader.
    assert_ne!(peb.ldr(), 0);
    assert_ne!(peb.process_parameters(), 0);

    let _ = peb.atl_thunk_slist_ptr();
    let _ = peb.atl_thunk_slist_ptr32();
    let _ = peb.post_process_init_routine();

    // Iterate the loader's module list.
    let entries: Vec<_> = peb.entries().collect();
    assert!(entries.len() > 1);

    let first = &entries[0];
    assert_ne!(first.dll_base(), 0);
    assert!(first.size_of_image() > 0);
    assert!(!first.base_dll_name().is_empty());
    assert!(
        first
            .full_dll_name()
            .to_lowercase()
            .ends_with(&first.base_dll_name().to_lowercase())
    );

    // ntdll.dll is always loaded in a Windows process.
    assert!(
        entries
            .iter()
            .any(|e| e.base_dll_name().eq_ignore_ascii_case("ntdll.dll"))
    );
}

fn test_linux_process() {
    use lief::runtime::linux::Process;
    let version = Process::glibc_version();
    println!("glibc_version: {:?}", version);
    assert!(version.is_some());

    let cmdline = Process::cmdline();
    println!("cmdline: {:?}", cmdline);
    assert!(cmdline.is_some());
}

fn test_linux_module() {
    let libc = lief::runtime::modules()
        .find_map(|m| match m {
            lief::runtime::Modules::Linux(linux) if linux.name().starts_with("libc") => Some(linux),
            _ => None,
        })
        .expect("expected libc to be loaded in the current process");

    assert!(!libc.handle().is_null());
    assert!(!libc.dlsym("malloc".to_string()).is_null());
    assert!(libc.dlsym("__lief_does_not_exist__".to_string()).is_null());

    let from_hdl = lief::runtime::linux::Module::from_handle(libc.handle());
    assert!(from_hdl.is_some());

    let parsed = libc.parse_from_path().expect("parse_from_path failed");
    assert!(parsed.header().entrypoint() > 0);

    let config = lief::elf::ParserConfig::default();
    let parsed = libc
        .parse_from_path_with_config(&config)
        .expect("parse_from_path_with_config failed");
    assert!(parsed.header().entrypoint() > 0);

    let _ = libc.parse_from_memory();
    let _ = libc.parse_from_memory_with_config(&config);

    let data = libc.dump();
    assert_eq!(data.len() as u64, libc.size());
    assert_eq!(&data[..4], b"\x7fELF");

    let out = std::env::temp_dir().join("lief_runtime_libc.dump");
    let written = libc.dump_to_file(&out);
    assert_eq!(written.len() as u64, libc.size());
    assert_eq!(&written[..4], b"\x7fELF");
    assert_eq!(std::fs::read(&out).expect("dump file not written"), written);
    let _ = std::fs::remove_file(&out);
}

fn test_android() {
    use lief::runtime::android::{Host, Process};

    let sdk = Host::sdk_version();
    println!("android sdk_version: {:?}", sdk);

    let prop = Process::get_system_property("ro.build.version.sdk");
    println!("android ro.build.version.sdk: {:?}", prop);

    let cmdline = Process::cmdline();
    println!("android cmdline: {:?}", cmdline);

    let props: Vec<_> = Process::properties().collect();
    println!("android #properties: {}", props.len());
    for prop in &props {
        assert!(!prop.name().is_empty());
    }

    if cfg!(target_os = "android") {
        assert!(sdk.is_some_and(|v| v > 0));

        let prop = prop.expect("missing ro.build.version.sdk");
        assert_eq!(prop.name(), "ro.build.version.sdk");
        assert!(!prop.value().is_empty());
        println!(
            "property: {} = {} (serial: {})",
            prop.name(),
            prop.value(),
            prop.serial()
        );

        assert!(cmdline.is_some());
        assert!(Process::get_system_property("lief.does.not.exist").is_none());

        assert!(!props.is_empty());
        assert!(props.iter().any(|p| p.name() == "ro.build.version.sdk"));
    }
}

fn test_memory_layout() {
    let regions: Vec<_> = lief::runtime::memory_layout().collect();

    for region in &regions {
        println!(
            "{:#x}-{:#x} ({:#x}) {}",
            region.addr(),
            region.end_addr(),
            region.size(),
            region.name()
        );
        assert_eq!(region.end_addr(), region.addr() + region.size());
    }

    if lief::is_extended() {
        assert!(!regions.is_empty());
        assert!(regions.iter().all(|r| !format!("{r}").is_empty()));

        // The regions backing this test binary must be part of the layout.
        let self_addr = test_memory_layout as usize as u64;
        assert!(regions.iter().any(|r| r.contains(self_addr)));
    }
}

fn test_memory() {
    let mut chunk = Memory::mmap(
        0x4000,
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
        Perm::READ,
    )
    .unwrap();
    println!(
        "{:#x} {:#x} {:?} {:#x} {:#x}",
        chunk.addr(),
        chunk.size(),
        chunk.permissions(),
        chunk.page_start(),
        chunk.page_end()
    );

    assert_eq!(chunk.permissions(), Perm::READ);
    {
        chunk.change_permissions(Perm::READ | Perm::WRITE);
        assert_eq!(chunk.permissions(), Perm::READ | Perm::WRITE);
        unsafe {
            Memory::write::<u64>(chunk.addr(), 1);
            assert_eq!(Memory::read::<u64>(chunk.addr()), 1);
        }
        chunk.change_permissions(Perm::READ);
        assert_eq!(chunk.permissions(), Perm::READ);
    }

    chunk.change_permissions(Perm::READ);
    chunk.make_x();
    chunk.make_rw();
    chunk.make_rx();
    chunk.make_rwx();
    chunk.make_ro();

    chunk.cache_flush();
    assert!(chunk.is_valid());

    Memory::munmap(&mut chunk);
}

fn test_memory_hint() {
    let page_size = Process::page_size() as u64;

    let mut reserved = Memory::mmap(
        2 * page_size,
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
        Perm::READ | Perm::WRITE,
    )
    .unwrap();

    // A misaligned hint is rounded up to the next page boundary
    let mut chunk = Memory::mmap_hint(
        reserved.addr() + page_size + 1,
        page_size,
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
        Perm::READ,
    )
    .unwrap();

    assert_eq!(chunk.addr() % page_size, 0);
    assert_eq!(chunk.size(), page_size);
    Memory::munmap(&mut chunk);

    // A hint set to 0 is equivalent to the non-hinted version
    let mut chunk = Memory::mmap_hint(
        0,
        page_size,
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
        Perm::READ,
    )
    .unwrap();
    assert!(chunk.is_valid());
    Memory::munmap(&mut chunk);

    // A hint that can't be page-aligned is rejected
    assert!(
        Memory::mmap_hint(
            u64::MAX,
            page_size,
            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
            Perm::READ,
        )
        .is_none()
    );

    Memory::munmap(&mut reserved);
}

#[test]
fn test_runtime() {
    if !lief::runtime::enabled() {
        return;
    }
    test_process();
    test_modules();
    test_memory();
    test_memory_hint();
    test_memory_layout();
    test_android();

    if cfg!(target_os = "macos") {
        test_osx_host();
    }

    if cfg!(target_os = "windows") {
        test_windows_host();
        test_windows_process();
    }

    if cfg!(target_os = "linux") {
        test_linux_module();
        test_linux_process();
    }
}
