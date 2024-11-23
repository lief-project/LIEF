#include "asm/ebpf/init.hpp"

#include "LIEF/asm/ebpf/registers.hpp"

namespace LIEF::assembly::ebpf::py {
template<>
void create<LIEF::assembly::ebpf::REG>(nb::module_& m) {
  nb::enum_<LIEF::assembly::ebpf::REG> reg(m, "REG");
  reg.value("NoRegister", LIEF::assembly::ebpf::REG::NoRegister)
  .value("R0", LIEF::assembly::ebpf::REG::R0)
  .value("R1", LIEF::assembly::ebpf::REG::R1)
  .value("R2", LIEF::assembly::ebpf::REG::R2)
  .value("R3", LIEF::assembly::ebpf::REG::R3)
  .value("R4", LIEF::assembly::ebpf::REG::R4)
  .value("R5", LIEF::assembly::ebpf::REG::R5)
  .value("R6", LIEF::assembly::ebpf::REG::R6)
  .value("R7", LIEF::assembly::ebpf::REG::R7)
  .value("R8", LIEF::assembly::ebpf::REG::R8)
  .value("R9", LIEF::assembly::ebpf::REG::R9)
  .value("R10", LIEF::assembly::ebpf::REG::R10)
  .value("R11", LIEF::assembly::ebpf::REG::R11)
  .value("W0", LIEF::assembly::ebpf::REG::W0)
  .value("W1", LIEF::assembly::ebpf::REG::W1)
  .value("W2", LIEF::assembly::ebpf::REG::W2)
  .value("W3", LIEF::assembly::ebpf::REG::W3)
  .value("W4", LIEF::assembly::ebpf::REG::W4)
  .value("W5", LIEF::assembly::ebpf::REG::W5)
  .value("W6", LIEF::assembly::ebpf::REG::W6)
  .value("W7", LIEF::assembly::ebpf::REG::W7)
  .value("W8", LIEF::assembly::ebpf::REG::W8)
  .value("W9", LIEF::assembly::ebpf::REG::W9)
  .value("W10", LIEF::assembly::ebpf::REG::W10)
  .value("W11", LIEF::assembly::ebpf::REG::W11)
  .value("NUM_TARGET_REGS", LIEF::assembly::ebpf::REG::NUM_TARGET_REGS)
  ;
}
}
