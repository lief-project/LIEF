use std::collections::BTreeMap;

pub fn iterate() {
    // lief-doc: iterate-start
    for region in lief::runtime::memory_layout() {
        println!(
            "{:#014x}-{:#014x} {}",
            region.addr(),
            region.end_addr(),
            region.name()
        );
    }
    // lief-doc: iterate-end
}

pub fn inspect(address: u64) {
    // lief-doc: inspect-start
    let mut count = 0usize;
    let mut mapped = 0u64;
    let mut footprint: BTreeMap<String, u64> = BTreeMap::new();
    let mut enclosing: Option<lief::runtime::Region> = None;

    for region in lief::runtime::memory_layout() {
        count += 1;
        mapped += region.size();

        let mut name = region.name();
        if name.is_empty() {
            name = String::from("<anonymous>");
        }

        *footprint.entry(name).or_insert(0) += region.size();

        if region.contains(address) {
            enclosing = Some(region);
        }
    }

    println!("{count} regions, {} KB mapped", mapped / 1024);

    for (name, size) in &footprint {
        println!("{size:#010x} {name}");
    }

    if let Some(region) = enclosing {
        println!(
            "{address:#x}: {}+{:#x}",
            region.name(),
            address - region.addr()
        );
    }
    // lief-doc: inspect-end
}

pub fn stack_and_heap() {
    // lief-doc: stack-heap-start
    for region in lief::runtime::memory_layout() {
        // On Linux and Android, the kernel names the regions that back the
        // stack and the heap of the process.
        let name = region.name();
        if name == "[stack]" || name == "[heap]" {
            println!(
                "{name}: {:#014x}-{:#014x}",
                region.addr(),
                region.end_addr()
            );
        }
    }
    // lief-doc: stack-heap-end
}
