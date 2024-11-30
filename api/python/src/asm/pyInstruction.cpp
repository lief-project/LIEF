#include <ostream>
#include <sstream>
#include "pyLIEF.hpp"
#include "LIEF/asm/Instruction.hpp"
#include "asm/pyAssembly.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "nanobind/utils.hpp"

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
      "with_address"_a = true,
      R"doc(Representation of the current instruction in a pretty assembly way)doc"_doc
    )

    .def_prop_ro("raw", [] (const Instruction& inst) {
        return nb::to_bytes(inst.raw());
      }, R"doc(Raw bytes of the current instruction)doc"_doc
    )

    .def_prop_ro("is_call", &Instruction::is_call,
      R"doc(True if the instruction is a call)doc"_doc
    )

    .def_prop_ro("is_terminator", &Instruction::is_terminator,
      R"doc(True if the instruction marks the end of a basic block)doc"_doc
    )

    .def_prop_ro("is_branch", &Instruction::is_branch,
      R"doc(True if the instruction is a branch)doc"_doc
    )

    .def_prop_ro("is_syscall", &Instruction::is_syscall,
      R"doc(True if the instruction is a syscall)doc"_doc
    )

    LIEF_DEFAULT_STR(Instruction)
  ;
}
}
