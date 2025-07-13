.. _extended-assembler:

:fa:`solid fa-user-secret` Assembler
-------------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

In addition to regular file formats modifications, we might want to patch code with
custom assembly code. This functionality is available thanks to the |lief-assemble|
function:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        elf = lief.ELF.parse("/bin/hello")

        syscall_addresses = [
          inst.address for inst in elf.disassemble(0x400090) if inst.is_syscall
        ]

        for syscall_addr in syscall_addresses:
            elf.assemble(syscall_addr, """
            mov x1, x0;
            str x1, [x2, #8];
            """)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto elf = LIEF::ELF::Parser::parse("/bin/hello");

        std::vector<uint64_t> syscall_addresses =
            elf->disassemble(0x400090)
          | std::view::filter([] (const std::unique_ptr<LIEF::assembly::Instruction> I) {
              return I->is_syscall();
            })
          | std::view::transform([] (const std::unique_ptr<LIEF::assembly::Instruction> I) {
              return I->address();
            })
          | std::ranges::to<std::vector>();

        for (uint64_t addr : syscall_addresses) {
          elf->assemble(addr, R"asm(
            mov x1, x0;
            str x1, [x2, #8];
          )asm");
        }

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf = lief::elf::Binary::parse("/bin/hello");

        let syscall_addresses =
            elf.disassemble(0x400090)
               .filter(|I| I.is_syscall())
               .transform(|I| I.address())
               .collect::<Vec<u64>>();

        for addr in syscall_addresses {
            elf.assemble(addr, r#"
              mov x1, x0;
              str x1, [x2, #8];
            "#);
        }

.. warning::

  The assembler is working decently for ``AArch64/ARM64E`` and ``x86/x86-64`` but
  the support is highly limited for the other architectures.

Technical Details
*****************

In the same way that the :ref:`disassembler <extended-disassembler>` is based on
the LLVM MC layer, this assembler is also based on this component of LLVM.

The assembly text is consumed by the ``llvm::MCAsmParser`` object, and we *intercept*
the raw generated assembly bytes from the ``llvm::MCObjectWriter``.

We also resolve ``llvm::MCFixup`` for a vast majority of the generated fixups.
One important feature that has been introduced in LIEF 0.17.0 is the support
for resolving symbols or label **on the fly**.

.. _extended-assembler-contextual-patching:

Contextual Assembly Patching
****************************

Given an assembly code and an address to patch, we might want to use a **context**
that is used to resolve symbols referenced in the assembly listing.

For instance, let's consider the following patching:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        elf = lief.ELF.parse("/bin/ssh")

        elf.assemble(elf.entrypoint, """
          mov rdi, rax;
          call a_custom_function
        """)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto elf = LIEF::ELF::Parser::parse("/bin/ssh");

        elf->assemble(elf->entrypoint(), R"asm(
          mov rdi, rax;
          call a_custom_function;
        )asm");

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf = lief::elf::Binary::parse("/bin/ssh");

        elf.assemble(addr, r#"
          mov rdi, rax;
          call a_custom_function;
        "#);

In this example, ``a_custom_function`` is not defined so the assembler engine does not know
how to resolve it and raises this error:

.. code-block:: text

    warning: Fixup not resolved:
        call a_custom_function

LIEF exposes a |lief-asm-AssemblerConfig| interface that can be used to
configure the engine and to **dynamically** resolve symbols used in the assembly
listing:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python
        :emphasize-lines: 3-11,18

        import lief

        class MyConfig(lief.assembly.AssemblerConfig):
            def __init__(self):
                super().__init__() # Important!

            @override
            def resolve_symbol(self, name: str) -> int | None:
                if name == "a_custom_function":
                    return 0x1000
                return None

        elf = lief.ELF.parse("/bin/ssh")

        elf.assemble(elf.entrypoint, """
          mov rdi, rax;
          call a_custom_function
        """, MyConfig())

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp
        :emphasize-lines: 1-9,13,18

        class MyConfig : public LIEF::assembly::AssemblerConfig {
          public:
          LIEF::optional<uint64_t> resolve_symbol(const std::string& name) const override {
            if (name == "a_custom_function") {
              return 0x1000;
            }
            return LIEF::nullopt();
          }
        };

        auto elf = LIEF::ELF::Parser::parse("/bin/ssh");

        MyConfig myconfig;

        elf->assemble(elf->entrypoint(), R"asm(
          mov rdi, rax;
          call a_custom_function;
        )asm", myconfig);

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust
        :emphasize-lines: 3-10,17

        let mut elf = lief::elf::Binary::parse("/bin/ssh");

        let mut config = lief::assembly::AssemblerConfig::default();

        let resolver = Arc::new(move |symbol: &str| {
            if symbol == "a_custom_function" {
                return Some(0x1000);
            }
            None
        });

        config.symbol_resolver = Some(resolver);

        elf.assemble(addr, r#"
          mov rdi, rax;
          call a_custom_function;
        "#, &config);

This interface can be used to wrap a context which can be, for instance, a
generic |lief-abstract-binary|:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python
        :emphasize-lines: 7,11-14,18

        import lief

        class MyConfig(lief.assembly.AssemblerConfig):
            def __init__(self, target: lief.Binary):
                super().__init__() # Important!

                self._target = target

            @override
            def resolve_symbol(self, name: str) -> int | None:
                addr = self._target.get_function_address(name)
                if isinstance(addr, lief.lief_errors):
                    return None
                return addr

        elf = lief.ELF.parse("/bin/ssh")

        config = MyConfig(elf)

        elf.assemble(elf.entrypoint, """
          mov rdi, rax;
          call a_custom_function
        """, config)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp
        :emphasize-lines: 4-8,11-13,25

        class MyConfig : public LIEF::assembly::AssemblerConfig {
          public:
          MyConfig() = delete;
          MyConfig(LIEF::Binary& target) :
            LIEF::assembly::AssemblerConfig()
          {
            target_ = &target;
          }

          LIEF::optional<uint64_t> resolve_symbol(const std::string& name) const override {
            if (auto addr = target_->get_function_address(name)) {
              return *addr;
            }
            return LIEF::nullopt();
          }

          ~MyConfig() override = default;

          private:
          LIEF::Binary* target_ = nullptr;
        };

        auto elf = LIEF::ELF::Parser::parse("/bin/ssh");

        MyConfig myconfig(*elf);

        elf->assemble(elf->entrypoint(), R"asm(
          mov rdi, rax;
          call a_custom_function;
        )asm", myconfig);

The Rust bindings do not offer the same flexibility to capture the
|lief-abstract-binary|. Nevertheless, the closure associated with the
:rust:member:`lief::assembly::AssemblerConfig::symbol_resolver [struct]`
can capture most of its context:

.. tabs::

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust
        :emphasize-lines: 5-13

        let mut elf = lief::elf::Binary::parse("/bin/ssh");

        let mut config = lief::assembly::AssemblerConfig::default();

        let mut sym_map = HashMap::new();

        for sym in ls.exported_symbols() {
            sym_map.insert(sym.name(), sym.value());
        }

        let resolver = Arc::new(move |symbol: &str| {
            sym_map.get(symbol).copied()
        });

        config.symbol_resolver = Some(resolver);

        elf.assemble(addr, r#"
          mov rdi, rax;
          call a_custom_function;
        "#, &config);


:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` :doc:`Rust API <rust>`

.. include:: ../../_cross_api.rst
