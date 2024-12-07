#include <ostream>
#include <sstream>
#include "pyLIEF.hpp"
#include "pyErr.hpp"
#include "enums_wrapper.hpp"
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

  enum_<assembly::Instruction::MemoryAccess>(obj, "MemoryAccess", nb::is_flag())
    .value("NONE", Instruction::MemoryAccess::NONE)
    .value("READ", Instruction::MemoryAccess::READ)
    .value("WRITE", Instruction::MemoryAccess::WRITE);

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

    .def_prop_ro("is_memory_access", &Instruction::is_memory_access,
      R"doc(True if the instruction performs a memory access)doc"_doc
    )

    .def_prop_ro("is_move_reg", &Instruction::is_move_reg,
      R"doc(True if the instruction is a register to register move.)doc"_doc
    )

    .def_prop_ro("is_add", &Instruction::is_add,
      R"doc(True if the instruction performs an arithmetic addition.)doc"_doc
    )

    .def_prop_ro("is_trap", &Instruction::is_trap,
      R"doc(
      True if the instruction is a trap.

      - On ``x86/x86-64`` this includes the ``ud1/ud2`` instructions
      - On ``AArch64`` this includes the ``brk/udf`` instructions
      )doc"_doc
    )

    .def_prop_ro("is_barrier", &Instruction::is_barrier,
      R"doc(
      True if the instruction prevents executing the instruction
      that immediatly follows the current. This includes return
      or unconditional branch instructions
      )doc"_doc
    )

    .def_prop_ro("is_return", &Instruction::is_return,
      R"doc(True if the instruction is a return)doc"_doc
    )

    .def_prop_ro("is_indirect_branch", &Instruction::is_indirect_branch,
      R"doc(
      True if the instruction is and indirect branch.

      This includes instructions that branch through a register (e.g.
      ``jmp rax``, ``br x1``).
      )doc"_doc)

    .def_prop_ro("is_conditional_branch", &Instruction::is_conditional_branch,
      R"doc(
      True if the instruction is **conditionally** jumping to the next
      instruction **or** an instruction into some other basic block.
      )doc"_doc
    )

    .def_prop_ro("is_unconditional_branch", &Instruction::is_unconditional_branch,
      R"doc(
      True if the instruction is jumping (**unconditionally**) to some other
      basic block.
      )doc"_doc
    )

    .def_prop_ro("is_compare", &Instruction::is_compare,
      R"doc(True if the instruction is a comparison)doc"_doc
    )

    .def_prop_ro("is_move_immediate", &Instruction::is_move_immediate,
      R"doc(True if the instruction is moving an immediate)doc"_doc
    )

    .def_prop_ro("is_bitcast", &Instruction::is_bitcast,
      R"doc(True if the instruction is doing a bitcast)doc"_doc
    )

    .def_prop_ro("memory_access", &Instruction::memory_access,
      R"doc(Memory access flags)doc"_doc
    )

    .def_prop_ro("branch_target",
      [] (Instruction& self) {
        return LIEF::py::error_or(&Instruction::branch_target, self);
      },
      R"doc(
      Given a :attr:`~.Instruction.is_branch` instruction, try to evaluate the
      address of the destination.
      )doc"_doc
    )

    LIEF_DEFAULT_STR(Instruction)
  ;
}
}
