.. _extended-pdb:

:fa:`brands fa-windows` PDB
----------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

Compared to DWARF debug info, the PDB debug info are always externalized from
the original binary. Nevertheless, the original binary keeps the
path of the PDB file in the attribute |lief-pe-codeviewpdb-filename|.

Based on this fact, |lief-pdb-binary-debug-info|
tries to instantiate a |lief-pdb-debug-info| based on this file path. If it fails, it
returns a nullptr or None.

One can also instantiate a |lief-pdb-debug-info| using |lief-pdb-load|:

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


At this point, the PDB instance (|lief-pdb-debug-info|) can be used to explore
the PDB debug info:

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

.. _extended-pdb-load-ext:

You can also use the function |lief-abstract-binary-load_debug_info| to bind
an PDB file to an existing |lief-abstract-binary|:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        binary: lief.Binary = ... # Can be an ELF/PE/Mach-O [...]

        dbg: lief.DebugInfo = binary.load_debug_info(r"C:\Users\romain\LIEF.pdb")

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::Binary> binary; // Can be an ELF/PE/Mach-O

        binary->load_debug_info("C:\\Users\\romain\\LIEF.pdb");

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        bin: &mut dyn lief::generic::Binary = ...;

        let path = PathBuf::from("C:\\Users\\romain\\LIEF.pdb");

        bin.load_debug_info(&path);

Note that |lief-abstract-binary-load_debug_info| can also attach an external
DWARF file on a PE binary even if this is not the regular use case.
For instance, :ref:`BinaryNinja <plugins-binaryninja-dwarf>` and
:ref:`Ghidra <plugins-ghidra-dwarf>` DWARF export plugin can generate
a DWARF file based on the analyses performed by these frameworks for a PE
binary.

This external loading API is useful for adding debug information that might not
already be present in the binary. For instance, the |lief-disassemble| function
can leverage this additional debug information to disassemble functions
defined in the debug file previously loaded:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        binary: lief.Binary = ... # Can be an ELF/PE/Mach-O [...]

        dbg: lief.DebugInfo = binary.load_debug_info(r"C:\Users\romain\LIEF.pdb")

        # The location (address/size) of `my_function` is defined in LIEF.pdb
        for inst in binary.disassemble("my_function"):
            print(inst)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::Binary> binary; // Can be an ELF/PE/Mach-O

        binary->load_debug_info("C:\\Users\\romain\\LIEF.pdb");

        // The location (address/size) of `my_function` is defined in LIEF.pdb
        for (std::unique_ptr<LIEF::asm::Instruction> inst : binary->disassemble("my_function")) {
          std::cout << *inst << '\n';
        }

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        bin: &mut dyn lief::generic::Binary = ...;

        let path = PathBuf::from("C:\\Users\\romain\\LIEF.pdb");

        bin.load_debug_info(&path);

        // The location (address/size) of `my_function` is defined in LIEF.pdb
        for inst in bin.disassemble_symbol("my_function") {
            println!("{inst}");
        }


----

API
****

You can find the documentation of the API for the different languages here:

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` Rust API: :rust:module:`lief::pdb`

.. include:: ../../_cross_api.rst
