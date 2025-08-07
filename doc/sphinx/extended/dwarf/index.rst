.. _extended-dwarf:

:fa:`solid fa-bars-staggered` DWARF
-----------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

DWARF debug information can be included directly in the binary
(which is the default behavior for ELF binaries) or stored in a separate
dedicated file.

When the DWARF debug information is embedded within the binary,
you can access it using the following attribute: |lief-dwarf-binary-debug-info|.
This attribute returns a |lief-dwarf-debug-info|:

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

Additionally, we can use the function: |lief-dwarf-load| to load a
DWARF file, regardless of whether it is embedded or not:

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

At this point, one can use all the API exposed in |lief-dwarf-debug-info| on the
instantiated debug info:

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


.. _extended-dwarf-load-ext:

In the case of an external DWARF file, you can bind this debug file to
a |lief-abstract-binary| by using the function: |lief-abstract-binary-load_debug_info|.

Here's an example:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        binary: lief.Binary = ... # Can be an ELF/PE/Mach-O [...]

        dbg: lief.DebugInfo = binary.load_debug_info("/home/romain/dev/LIEF/some.dwo")

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::Binary> binary; // Can be an ELF/PE/Mach-O

        binary->load_debug_info("/home/romain/dev/LIEF/some.dwo");

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        bin: &mut dyn lief::generic::Binary = ...;

        let path = PathBuf::from("/home/romain/dev/LIEF/some.dwo");

        bin.load_debug_info(&path);

This external loading API is useful for adding debug information that might not
already be present in the binary. For instance, the |lief-disassemble| function
can leverage this additional debug information to disassemble functions
defined in the debug file previously loaded:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        binary: lief.Binary = ... # Can be an ELF/PE/Mach-O [...]

        dbg: lief.DebugInfo = binary.load_debug_info("/home/romain/dev/LIEF/some.dwo")

        # The location (address/size) of `my_function` is defined in some.dwo
        for inst in binary.disassemble("my_function"):
            print(inst)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::Binary> binary; // Can be an ELF/PE/Mach-O

        binary->load_debug_info("/home/romain/dev/LIEF/some.dwo");

        // The location (address/size) of `my_function` is defined in some.dwo
        for (std::unique_ptr<LIEF::asm::Instruction> inst : binary->disassemble("my_function")) {
          std::cout << *inst << '\n';
        }

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        bin: &mut dyn lief::generic::Binary = ...;

        let path = PathBuf::from("/home/romain/dev/LIEF/some.dwo");

        bin.load_debug_info(&path);

        // The location (address/size) of `my_function` is defined in some.dwo
        for inst in bin.disassemble_symbol("my_function") {
            println!("{inst}");
        }

Additionally, you may want to check out the
:ref:`BinaryNinja <plugins-binaryninja-dwarf>` and
:ref:`Ghidra <plugins-ghidra-dwarf>` DWARF export plugin which can generate
debug information based on the analyses performed by these frameworks.

.. _extended-dwarf-editor:

DWARF Editor
************

.. admonition:: Editing Existing DWARF
  :class: warning

  Currently, LIEF **does not** support modifying an **existing** DWARF file

LIEF provides a comprehensive high-level API to create DWARF files programmatically.
This works by using the |lief-dwarf-editor| interface that can be instantiated using
|lief-dwarf-editor-from_binary|:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        pe = lief.PE.parse("demo.exe")

        editor: lief.dwarf.Editor = lief.dwarf.Editor.from_binary(pe)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("demo.exe");

        std::unique_ptr<LIEF::dwarf::Editor> editor =
          LIEF::dwarf::Editor::from_binary(*pe);


   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut bin = lief::pe::Binary::parse(&path).unwrap();
        let editor = lief::dwarf::Editor::from_binary(&mut bin);


Given this |lief-dwarf-editor|, one can create one or several |lief-dwarf-editor-CompilationUnit|
that own the different |lief-dwarf-editor-Function|, |lief-dwarf-editor-Variable|, |lief-dwarf-editor-Type|

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        unit: lief.dwarf.editor.CompilationUnit = editor.create_compilation_unit()
        unit.set_producer("LIEF")

        func: lief.dwarf.editor.Function = unit.create_function("hello")
        func.set_address(0x123)
        func.set_return_type(
            unit.create_structure("my_struct_t").pointer_to()
        )

        var: lief.dwarf.editor.Variable = func.create_stack_variable("local_var")
        var.set_stack_offset(8)

        editor.write("/tmp/out.debug")

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::dwarf::editor::CompilationUnit>
          unit = editor->create_compilation_unit();
        unit->set_producer("LIEF");

        std::unique_ptr<LIEF::dwarf::editor::Function>
          func = unit->create_function("hello");
        func->set_address(0x123);

        func->set_return_type(
          *unit->create_structure("my_struct_t")->pointer_to()
        );

        std::unique_ptr<LIEF::dwarf::editor::Variable> var =
          func->create_stack_variable("local_var");

        var->set_stack_offset(8);
        editor->write("/tmp/out.debug");

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut unit = editor.create_compile_unit().unwrap();
        unit.set_producer("LIEF");

        let mut func = unit.create_function("hello").unwrap();
        func.set_address(0x123);
        func.set_return_type(
            &unit.create_structure("my_struct_t").pointer_to()
        );

        let mut var = func.create_stack_variable("local_var");
        var.set_stack_offset(8);

        editor.write("/tmp/out.debug");

.. admonition:: BinaryNinja & Ghidra
  :class: note

  This feature is provided as a plugin for: :ref:`BinaryNinja <plugins-binaryninja-dwarf>`
  and :ref:`Ghidra <plugins-binaryninja>`

----

API
****

You can find the documentation of the API for the different languages here:

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` Rust API: :rust:module:`lief::dwarf`

.. include:: ../../_cross_api.rst
