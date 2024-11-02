#include <ostream>
#include <sstream>
#include "pyLIEF.hpp"
#include "LIEF/asm/Instruction.hpp"
#include "asm/pyAssembly.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::py {
template<>
void create<assembly::Instruction>(nb::module_& m) {
  nb::class_<assembly::Instruction> obj(m, "Instruction",
    R"doc(
    This class represents an assembly instruction
    )doc"_doc
  );

  obj
    .def_prop_ro("address", &Instruction::address,
      R"doc(Address of the instruction)doc"_doc
    )

    .def_prop_ro("size", &Instruction::size,
      R"doc(Size of the instruction in bytes)doc"_doc
    )

    .def_prop_ro("mnemonic", &Instruction::mnemonic,
      R"doc(Instruction mnemonic (e.g. ``br``))doc"_doc
    )

    .def("to_string", &Instruction::to_string,
      R"doc(Representation of the current instruction in a pretty assembly way)doc"_doc
    )

    .def_prop_ro("raw", [] (const Instruction& inst) {
        const std::vector<uint8_t>& raw = inst.raw();
        return nb::bytes((const char*)raw.data(), raw.size());
      }, R"doc(Raw bytes of the current instruction)doc"_doc
    )

    LIEF_DEFAULT_STR(Instruction)
  ;
}
}
