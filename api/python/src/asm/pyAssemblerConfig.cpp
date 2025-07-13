#include "LIEF/asm/AssemblerConfig.hpp"
#include "asm/pyAssembly.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/trampoline.h>
#include "nanobind/extra/stl/lief_optional.h"

#include "nanobind/extra/stl/lief_optional.h"

namespace LIEF::assembly::py {

class PyAssemblerConfig : public assembly::AssemblerConfig {
  public:
  static constexpr auto NB_NUM_SLOTS = 3;
  NB_TRAMPOLINE(assembly::AssemblerConfig, NB_NUM_SLOTS);

  optional<uint64_t> resolve_symbol(const std::string& name) override {
    NB_OVERRIDE(resolve_symbol, name);
  }

  ~PyAssemblerConfig() override = default;
};

template<>
void create<assembly::AssemblerConfig>(nb::module_& m) {
  nb::class_<assembly::AssemblerConfig, PyAssemblerConfig> obj(m, "AssemblerConfig",
    R"doc(
    This class exposes the different elements that can be configured to assemble
    code.
    )doc"_doc
  );

  nb::enum_<assembly::AssemblerConfig::DIALECT>(obj, "DIALECT",
    "The different supported dialects"_doc
  )
    .value("DEFAULT_DIALECT", assembly::AssemblerConfig::DIALECT::DEFAULT_DIALECT)
    .value("X86_INTEL", assembly::AssemblerConfig::DIALECT::X86_INTEL,
           "Intel syntax"_doc)
    .value("X86_ATT", assembly::AssemblerConfig::DIALECT::X86_ATT,
           "AT&T syntax"_doc)
  ;

  obj
    .def(nb::init<>())
    .def_static("default_config", &assembly::AssemblerConfig::default_config,
      "Default configuration"_doc
    )
    .def_rw("dialect", &assembly::AssemblerConfig::dialect,
      "The dialect of the input assembly code"_doc
    )
    .def("resolve_symbol", &assembly::AssemblerConfig::resolve_symbol,
      R"doc(
      This function aims to be overloaded in order to resolve symbols used
      in the assembly listing.

      For instance, given this assembly code:

      .. code-block:: text

        0x1000: mov rdi, rbx
        0x1003: call _my_function

      The function ``_my_function`` will remain undefined unless we return its
      address in :meth:`~.resolve_symbol`:

      .. code-block:: python

        class MyConfig(lief.assembly.AssemblerConfig):
            def __init__(self):
                super().__init__() # This is important

            @override
            def resolve_symbol(self, name: str) -> int | None:
                if name == '_my_function':
                    return 0x4000
                return None # Or super().resolve_symbol(name)
      )doc"_doc, "name"_a)
  ;
}
}
