/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/map.h>
#include <nanobind/stl/vector.h>

#include "pyErr.hpp"
#include "ELF/pyELF.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"

#include "enums_wrapper.hpp"

#define GET_SET_REGISTER(ARCH)                                                                                                         \
    .def("get", [] (const CorePrStatus& self, CorePrStatus::Registers::ARCH reg) {                                                     \
          return LIEF::py::value_or_none(nb::overload_cast<CorePrStatus::Registers::ARCH>(&CorePrStatus::get, nb::const_), self, reg); \
        }, "Get the register value or non if it is not present", "reg"_a)                                                              \
    .def("__getitem__", [] (const CorePrStatus& self, CorePrStatus::Registers::ARCH reg) {                                             \
          return LIEF::py::value_or_none(nb::overload_cast<CorePrStatus::Registers::ARCH>(&CorePrStatus::get, nb::const_), self, reg); \
        })                                                                                                                             \
    .def("set", nb::overload_cast<CorePrStatus::Registers::ARCH, uint64_t>(&CorePrStatus::set),                                        \
         "Change the register value", "reg"_a, "value"_a)                                                                              \
    .def("__setitem__", nb::overload_cast<CorePrStatus::Registers::ARCH, uint64_t>(&CorePrStatus::set))

namespace LIEF::ELF::py {

template<>
void create<CorePrStatus>(nb::module_& m) {
  nb::class_<CorePrStatus, Note> cls(m, "CorePrStatus");

  nb::class_<CorePrStatus::timeval_t>(cls, "timeval_t")
    .def_rw("sec",  &CorePrStatus::timeval_t::sec)
    .def_rw("usec", &CorePrStatus::timeval_t::usec);

  nb::class_<CorePrStatus::siginfo_t>(cls, "siginfo_t")
    .def_rw("sicode", &CorePrStatus::siginfo_t::code)
    .def_rw("errno",  &CorePrStatus::siginfo_t::err)
    .def_rw("signo",  &CorePrStatus::siginfo_t::signo);

  nb::class_<CorePrStatus::pr_status_t>(cls, "pr_status_t")
    .def_rw("info",  &CorePrStatus::pr_status_t::info)
    .def_rw("cursig",  &CorePrStatus::pr_status_t::cursig)
    .def_rw("reserved",  &CorePrStatus::pr_status_t::reserved)
    .def_rw("sigpend",  &CorePrStatus::pr_status_t::sigpend)
    .def_rw("sighold",  &CorePrStatus::pr_status_t::sighold)
    .def_rw("pid",  &CorePrStatus::pr_status_t::pid)
    .def_rw("ppid",  &CorePrStatus::pr_status_t::ppid)
    .def_rw("pgrp",  &CorePrStatus::pr_status_t::pgrp)
    .def_rw("sid",  &CorePrStatus::pr_status_t::sid)
    .def_rw("utime",  &CorePrStatus::pr_status_t::utime)
    .def_rw("stime",  &CorePrStatus::pr_status_t::stime)
    .def_rw("cutime",  &CorePrStatus::pr_status_t::cutime)
    .def_rw("cstime",  &CorePrStatus::pr_status_t::cstime);

  nb::class_<CorePrStatus::Registers> Registers(cls, "Registers");
  cls
    .def_prop_rw("status",
        nb::overload_cast<>(&CorePrStatus::status, nb::const_),
        nb::overload_cast<const CorePrStatus::pr_status_t&>(&CorePrStatus::status),
        "Info associated with the signal"_doc)

    .def_prop_ro("architecture", &CorePrStatus::architecture,
        R"doc(Original target architecture.)doc"_doc)

    .def_prop_ro("pc", [] (const CorePrStatus& self) {
          return LIEF::py::value_or_none(&CorePrStatus::pc, self);
        },
        R"doc(
        Return the program counter value (`rip`, `pc`, `eip` etc)
        )doc"_doc)

    .def_prop_ro("sp", [] (const CorePrStatus& self) {
          return LIEF::py::value_or_none(&CorePrStatus::sp, self);
        },
        R"doc(
        Return the stack pointer value
        )doc"_doc)

    .def_prop_ro("return_value", [] (const CorePrStatus& self) {
          return LIEF::py::value_or_none(&CorePrStatus::return_value, self);
        },
        R"doc(
        The value of the register that holds the return value according to
        the calling convention.
        )doc"_doc)

    .def_prop_ro("register_values", &CorePrStatus::register_values,
      R"doc(
      List of the register values.
      This list is **guarantee** to be as long as the number of registers defined
      in the :class:`~.Registers` or empty if it can't be resolved.

      Thus, one can access a specific register through:

      .. code-block:: python

        reg_vals: list[int] = note.register_values()
        x20 = reg_vals[CorePrStatus.Registesr.AARCH64.X20.value]
      )doc"_doc
    )

    GET_SET_REGISTER(X86)
    GET_SET_REGISTER(X86_64)
    GET_SET_REGISTER(ARM)
    GET_SET_REGISTER(AARCH64)
    LIEF_DEFAULT_STR(CorePrStatus);


  #define ENTRY(X) .value(to_string(CorePrStatus::Registers::X86::X), CorePrStatus::Registers::X86::X)
  enum_<CorePrStatus::Registers::X86>(Registers, "X86",
    R"doc(
    Registers for the x86 architecture (:attr:`~.ARCH.i386`)
    )doc"_doc)
    ENTRY(EBX)
    ENTRY(ECX)
    ENTRY(EDX)
    ENTRY(ESI)
    ENTRY(EDI)
    ENTRY(EBP)
    ENTRY(EAX)
    ENTRY(DS)
    ENTRY(ES)
    ENTRY(FS)
    ENTRY(GS)
    ENTRY(ORIG_EAX)
    ENTRY(EIP)
    ENTRY(CS)
    ENTRY(EFLAGS)
    ENTRY(ESP)
    ENTRY(SS)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(CorePrStatus::Registers::X86_64::X), CorePrStatus::Registers::X86_64::X)
  enum_<CorePrStatus::Registers::X86_64>(Registers, "X86_64",
    R"doc(
    Registers for the x86-64 architecture (:attr:`~.ARCH.x86_64`)
    )doc"_doc)
    ENTRY(R15)
    ENTRY(R14)
    ENTRY(R13)
    ENTRY(R12)
    ENTRY(RBP)
    ENTRY(RBX)
    ENTRY(R11)
    ENTRY(R10)
    ENTRY(R9)
    ENTRY(R8)
    ENTRY(RAX)
    ENTRY(RCX)
    ENTRY(RDX)
    ENTRY(RSI)
    ENTRY(RDI)
    ENTRY(ORIG_RAX)
    ENTRY(RIP)
    ENTRY(CS)
    ENTRY(EFLAGS)
    ENTRY(RSP)
    ENTRY(SS)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(CorePrStatus::Registers::ARM::X), CorePrStatus::Registers::ARM::X)
  enum_<CorePrStatus::Registers::ARM>(Registers, "ARM",
    R"doc(
    Registers for the ARM architecture (:attr:`~.ARCH.ARM`)
    )doc"_doc)
    ENTRY(R0)
    ENTRY(R1)
    ENTRY(R2)
    ENTRY(R3)
    ENTRY(R4)
    ENTRY(R5)
    ENTRY(R6)
    ENTRY(R7)
    ENTRY(R8)
    ENTRY(R9)
    ENTRY(R10)
    ENTRY(R11)
    ENTRY(R12)
    ENTRY(R13)
    ENTRY(R14)
    ENTRY(R15)
    ENTRY(CPSR)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(CorePrStatus::Registers::AARCH64::X), CorePrStatus::Registers::AARCH64::X)
  enum_<CorePrStatus::Registers::AARCH64>(Registers, "AARCH64",
    R"doc(
    Registers for the AARCH64 architecture (:attr:`~.ARCH.AARCH64`)
    )doc"_doc)
    ENTRY(X0)
    ENTRY(X1)
    ENTRY(X2)
    ENTRY(X3)
    ENTRY(X4)
    ENTRY(X5)
    ENTRY(X6)
    ENTRY(X7)
    ENTRY(X8)
    ENTRY(X9)
    ENTRY(X10)
    ENTRY(X11)
    ENTRY(X12)
    ENTRY(X13)
    ENTRY(X14)
    ENTRY(X15)
    ENTRY(X15)
    ENTRY(X16)
    ENTRY(X17)
    ENTRY(X18)
    ENTRY(X19)
    ENTRY(X20)
    ENTRY(X21)
    ENTRY(X22)
    ENTRY(X23)
    ENTRY(X24)
    ENTRY(X25)
    ENTRY(X26)
    ENTRY(X27)
    ENTRY(X28)
    ENTRY(X29)
    ENTRY(X30)
    ENTRY(X31)
    ENTRY(PC)
    ENTRY(PSTATE)
  ;
  #undef ENTRY


}
}
