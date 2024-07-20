.. _extended-pdb:

:fa:`brands fa-windows` PDB
----------------------------

Compared to DWARF debug info, the PDB debug info are always externalized from
the original binary. Nevertheless, the original binary keeps the
path of the PDB file in the attribute :attr:`lief.PE.CodeViewPDB.filename` /
:cpp:func:`LIEF::PE::CodeViewPDB::filename`.

Based on this fact, :attr:`lief.Binary.debug_info` or :cpp:func:`LIEF::Binary::debug_info`
tries to instantiate a :class:`lief.pdb.DebugInfo` or a
:cpp:class:`LIEF::pdb::DebugInfo` based on this file path. If it fails, it
returns a nullptr/None.

One can also instantiate a :class:`lief.pdb.DebugInfo`/:cpp:class:`LIEF::pdb::DebugInfo`
using :cpp:func:`LIEF::pdb::load` or :func:`lief.pdb.load`:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        pe = lief.PE.parse("some.exe")
        if debug_info := pe.debug_info:
            assert isinstance(debug_info, lief.pdb.DebugInfo)
            print(f"PDB Debug handler: {debug_info}")

        # Or you can load the PDB directly:
        pdb: lief.pdb.DebugInfo = lief.pdb.load("some.pdb")

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("some.exe");
        if (const LIEF::DebugInfo* info = pe->debug_info()) {
          assert(LIEF::pdb::DebugInfo::classof(info) && "Wrong DebugInfo type");
          const auto& pdb = static_cast<const LIEF::pdb::DebugInfo&>(*info);
        }

        // Or loading directly the pdb file
        std::unique_ptr<LIEF::pdb::DebugInfo> pdb = LIEF::pdb::load("some.pdb");

    .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let pe = lief::pe::Binary::parse("some.exe");
        if let Some(lief::DebugInfo::Pdb(pdb)) = pe.debug_info() {
            // PDB debug info
        }

        let pdb = lief::pdb::load("some.pdb");


At this point, the PDB instance
(:class:`lief.pdb.DebugInfo`/:cpp:class:`LIEF::pdb::DebugInfo`) can be used to
explore the PDB debug info:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        print("arg={}, guid={}", pdb.age, pdb.guid)

        for sym in pdb.public_symbols:
            print("name={}, section={}, RVA={}",
                  sym.name, sym.section_name, sym.RVA)

        for ty in pdb.types:
            if isinstance(ty, lief.pdb.types.Class):
                print("Class[name]={}", ty.name)

        for cu in pdb.compilation_units:
            print("module={}", cu.module_name)
            for src in cu.sources:
                print("  - {}", src)

            for func in cu.functions:
                print("name={}, section={}, RVA={}, code_size={}",
                      func.name, func.section_name, func.RVA, func.code_size)

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        log(LEVEL::INFO, "age={}, guid={}", std::to_string(pdb->age()), pdb->guid());

        for (std::unique_ptr<LIEF::pdb::PublicSymbol> symbol : pdb->public_symbols()) {
          log(LEVEL::INFO, "name={}, section={}, RVA={}",
              symbol->name(), symbol->section_name(), symbol->RVA());
        }

        for (std::unique_ptr<LIEF::pdb::Type> ty : pdb->types()) {
          if (LIEF::pdb::types::Class::classof(ty.get())) {
            auto* clazz = ty->as<LIEF::pdb::types::Class>();
            log(LEVEL::INFO, "Class[name]={}", clazz->name());
          }
        }

        for (std::unique_ptr<LIEF::pdb::CompilationUnit> CU : pdb->compilation_units()) {
          log(LEVEL::INFO, "module={}", CU->module_name());
          for (const std::string& src : CU->sources()) {
            log(LEVEL::INFO, "  - {}", src);
          }

          for (std::unique_ptr<LIEF::pdb::Function> func : CU->functions()) {
            log(LEVEL::INFO, "name={}, section={}, RVA={}, code size={}",
                func->name(), func->section_name(), func->RVA(), func->code_size());
          }
        }


    .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let pdb = lief::pdb::load(&path).unwrap_or_else(|| {
            process::exit(1);
        });

        println!("age={}, guid={}", pdb.age(), pdb.guid());

        for symbol in pdb.public_symbols() {
            println!("name={}, section={}, RVA={}",
                symbol.name(), symbol.section_name().unwrap_or("".to_string()),
                symbol.rva());
        }

        for ty in pdb.types() {
            if let lief::pdb::Type::Class(clazz) = ty {
                println!("Class[name]={}", clazz.name());
            }
        }

        for cu in pdb.compilation_units() {
            println!("module={}", cu.module_name());
            for src in cu.sources() {
                println!("  - {}", src);
            }

            for func in cu.functions() {
                println!("name={}, section={}, RVA={}, code_size={}",
                    func.name(), func.section_name(), func.rva(), func.code_size()
                );
            }
        }


You can find the documentation of the API for the different languages here:

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` Rust API: |lief-rust-doc-nightly|
