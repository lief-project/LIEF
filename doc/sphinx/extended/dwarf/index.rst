.. _extended-dwarf:

:fa:`solid fa-bars-staggered` DWARF
-----------------------------------

DWARF debug info can be embedded in the binary itself (default behavior for ELF)
or externalized in a dedicated file.

If the DWARF debug info are embedded in the binary itself, one can use the
attribute: :attr:`lief.Binary.debug_info` or :cpp:func:`LIEF::Binary::debug_info`
to access an instance of :class:`lief.dwarf.DebugInfo` or
:cpp:class:`LIEF::dwarf::DebugInfo`:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        elf = lief.ELF.parse("/bin/with_debug")
        if debug_info := elf.debug_info:
            assert isinstance(debug_info, lief.dwarf.DebugInfo)
            print(f"DWARF Debug handler: {debug_info}")

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto elf = LIEF::ELF::Parser::parse("/bin/with_debug");
        if (const LIEF::DebugInfo* info = elf->debug_info()) {
          assert(LIEF::dwarf::DebugInfo::classof(info) && "Wrong debug type");

          const auto& dwarf_dbg = static_cast<const LIEF::dwarf::DebugInfo&>(*info);
        }

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let elf = lief::elf::Binary::parse("/bin/ls");
        if let Some(lief::DebugInfo::Dwarf(dwarf)) = elf.debug_info() {
            // DWARF debug info
        }

On the other hand, we can also use the function: :cpp:func:`LIEF::dwarf::load`
or :func:`lief.dwarf.load` to load a DWARF file regardless whether it is
embedded or not:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        dbg: lief.dwarf.DebugInfo = lief.dwarf.load("/bin/with_debug")
        dbg: lief.dwarf.DebugInfo = lief.dwarf.load("external_dwarf")
        dbg: lief.dwarf.DebugInfo = lief.dwarf.load("debug.dwo")

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto dbg = LIEF::dwarf::load("/bin/with_debug");
        auto dbg = LIEF::dwarf::load("external_dwarf");
        auto dbg = LIEF::dwarf::load("debug.dwo");

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let dbg = lief::dwarf::load("/bin/with_debug");
        let dbg = lief::dwarf::load("external_dwarf");
        let dbg = lief::dwarf::load("debug.dwo");

At this point, one can use all the API exposed in :class:`lief.dwarf.DebugInfo` or
:cpp:class:`LIEF::dwarf::DebugInfo` on the instantiated debug info:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        dbg: lief.dwarf.DebugInfo = ...

        for compilation_unit in dbg.compilation_units:
            print(compilation_unit.producer)
            for func in compilation_unit.functions:
                print(func.name, func.linkage_name, func.address)

            for var in compilation_unit.variables:
                print(var.name, var.address)

            for ty in compilation_unit.types:
                print(ty.name, ty.size)

        dbg.find_function("_ZNSi4peekEv")
        dbg.find_function("std::basic_istream<char, std::char_traits<char> >::peek()")
        dbg.find_function(0x137a70)

        dbg.find_variable("_ZNSt12out_of_rangeC1EPKc")
        dbg.find_variable("std::out_of_range::out_of_range(char const*)")
        dbg.find_variable(0x2773a0)

        dbg.find_type("my_type_t")

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        for (std::unique_ptr<LIEF::dwarf::CompilationUnit> CU : dbg->compilation_units()) {
          log(LEVEL::INFO, "Producer: {}", CU->producer());
          for (std::unique_ptr<LIEF::dwarf::Function> func : CU->functions()) {
            log(LEVEL::INFO, "name={}, linkage={}, address={}",
                func->name(), func->linkage_name(), func->address().value_or(0));
          }

          for (std::unique_ptr<LIEF::dwarf::Variable> var : CU->variables()) {
            log(LEVEL::INFO, "name={}, address={}", var->name(), var->address().value_or(0));
          }

          for (std::unique_ptr<LIEF::dwarf::Type> ty : CU->types()) {
            log(LEVEL::INFO, "name={}, size={}", ty->name().value_or(""), std::to_string(ty->size().value_or(0)));
          }
        }

        dbg->find_function("_ZNSi4peekEv");
        dbg->find_function("std::basic_istream<char, std::char_traits<char> >::peek()");
        dbg->find_function(0x137a70);

        dbg->find_variable("_ZNSt12out_of_rangeC1EPKc");
        dbg->find_function("std::out_of_range::out_of_range(char const*)");
        dbg->find_function(0x2773a0);

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let dbg = lief::dwarf::load(&path).unwrap_or_else(|| {
            process::exit(1);
        });

        for cu in dbg.compilation_units() {
            println!("Producer: {}", cu.producer());
            for func in cu.functions() {
                println!("name={}, linkage={}, address={}",
                    func.name(), func.linkage_name(),
                    func.address().unwrap_or(0)
                );
            }

            for var in cu.variables() {
                println!("name={}, address={}", var.name(), var.address().unwrap_or(0));
            }

            for ty in cu.types() {
                println!("name={}, size={}", ty.name().unwrap_or("".to_string()), ty.size().unwrap_or(0));
            }
        }

        dbg.function_by_name("_ZNSi4peekEv");
        dbg.function_by_name("std::basic_istream<char, std::char_traits<char> >::peek()");
        dbg.function_by_addr(0x137a70);

        dbg.variable_by_name("_ZNSt12out_of_rangeC1EPKc");
        dbg.variable_by_name("std::out_of_range::out_of_range(char const*)");
        dbg.variable_by_addr(0x137a70);

----

You can find the documentation of the API for the different languages here:

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` Rust API: |lief-rust-doc-nightly|
