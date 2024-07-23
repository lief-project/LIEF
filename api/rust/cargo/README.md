# LIEF Rust Bindings

These are the offical rust bindings for LIEF.

![LIEF Architecture](https://raw.githubusercontent.com/lief-project/LIEF/main/.github/images/architecture.png)

## Getting Started

```toml
[dependencies]
lief = "0.15.1"
```

The bindings require Rust edition 2021 and `rustc >= 1.74.0`

```rust
use lief;

if let Some(lief::Binary::ELF(elf)) = lief::Binary::from(&mut file) {
    println!("Dependencies:");
    for entry in elf.dynamic_entries() {
        if let dynamic::Entries::Library(lib) = entry {
            println!("  - {}", lib.name());
        }
    }
    println!("Versions:");
    for version in elf.symbols_version_requirement() {
        println!("  From {}", version.name());
        for aux in version.auxiliary_symbols() {
            println!("    - {}", aux.name());
        }
    }
}
```
