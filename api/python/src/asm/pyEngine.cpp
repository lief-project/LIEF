#include "LIEF/asm/Engine.hpp"
#include "asm/pyAssembly.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::py {
template<>
void create<assembly::Engine>(nb::module_& m) {
  nb::class_<assembly::Engine> obj(m, "Engine",
    R"doc(
    This class interfaces the assembler/disassembler support
    )doc"_doc
  );
}
}
