#include "LIEF/asm/ebpf/Instruction.hpp"

#include "asm/ebpf/init.hpp"

namespace LIEF::assembly::ebpf::py {
template<>
void create<ebpf::Instruction>(nb::module_& m) {
  nb::class_<ebpf::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents an eBPF instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
