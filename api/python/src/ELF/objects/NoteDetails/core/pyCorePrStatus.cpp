/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"

#include "LIEF/ELF/EnumToString.hpp"
#include "enums_wrapper.hpp"

#define PY_ENUM(x) LIEF::ELF::to_string(x), x

namespace LIEF::ELF::py {

template<>
void create<CorePrStatus>(nb::module_& m) {

  nb::class_<CorePrStatus, NoteDetails> cls(m, "CorePrStatus");

  nb::class_<CorePrStatus::timeval_t>(cls, "timeval")
    .def_rw("sec",  &CorePrStatus::timeval_t::sec)
    .def_rw("usec", &CorePrStatus::timeval_t::usec);

  nb::class_<CorePrStatus::siginfo_t>(cls, "siginfo_t")
    .def_rw("sicode", &CorePrStatus::siginfo_t::si_code)
    .def_rw("errno",  &CorePrStatus::siginfo_t::si_errno)
    .def_rw("signo",  &CorePrStatus::siginfo_t::si_signo);

  cls
    .def_prop_rw("siginfo",
        nb::overload_cast<>(&CorePrStatus::siginfo, nb::const_),
        nb::overload_cast<const CorePrStatus::siginfo_t&>(&CorePrStatus::siginfo),
        "Info associated with the signal"_doc)

    .def_prop_rw("current_sig",
        nb::overload_cast<>(&CorePrStatus::current_sig, nb::const_),
        nb::overload_cast<uint16_t>(&CorePrStatus::current_sig),
        "Current Signal"_doc)

    .def_prop_rw("sigpend",
        nb::overload_cast<>(&CorePrStatus::sigpend, nb::const_),
        nb::overload_cast<uint64_t>(&CorePrStatus::sigpend),
        "Set of pending signals"_doc)

    .def_prop_rw("sighold",
        nb::overload_cast<>(&CorePrStatus::sighold, nb::const_),
        nb::overload_cast<uint64_t>(&CorePrStatus::sighold),
        "Set of held signals"_doc)

    .def_prop_rw("pid",
        nb::overload_cast<>(&CorePrStatus::pid, nb::const_),
        nb::overload_cast<int32_t>(&CorePrStatus::pid),
        "Process ID"_doc)

    .def_prop_rw("ppid",
        nb::overload_cast<>(&CorePrStatus::ppid, nb::const_),
        nb::overload_cast<int32_t>(&CorePrStatus::ppid),
        "Process parent ID"_doc)

    .def_prop_rw("pgrp",
        nb::overload_cast<>(&CorePrStatus::pgrp, nb::const_),
        nb::overload_cast<int32_t>(&CorePrStatus::pgrp),
        "Process group ID"_doc)

    .def_prop_rw("sid",
        nb::overload_cast<>(&CorePrStatus::sid, nb::const_),
        nb::overload_cast<int32_t>(&CorePrStatus::sid),
        "Process session ID"_doc)

    .def_prop_rw("utime",
        nb::overload_cast<>(&CorePrStatus::utime, nb::const_),
        nb::overload_cast<CorePrStatus::timeval_t>(&CorePrStatus::utime),
        "User time (" RST_CLASS_REF(lief.ELF.CorePrStatus.timeval) ")"_doc)

    .def_prop_rw("utime",
        nb::overload_cast<>(&CorePrStatus::utime, nb::const_),
        nb::overload_cast<CorePrStatus::timeval_t>(&CorePrStatus::utime),
        "User time (" RST_CLASS_REF(lief.ELF.CorePrStatus.timeval) ")"_doc)

    .def_prop_rw("stime",
        nb::overload_cast<>(&CorePrStatus::stime, nb::const_),
        nb::overload_cast<CorePrStatus::timeval_t>(&CorePrStatus::stime),
        "System time (" RST_CLASS_REF(lief.ELF.CorePrStatus.timeval) ")"_doc)

    .def_prop_rw("cutime",
        nb::overload_cast<>(&CorePrStatus::cutime, nb::const_),
        nb::overload_cast<CorePrStatus::timeval_t>(&CorePrStatus::cutime),
        "Cumulative user time (" RST_CLASS_REF(lief.ELF.CorePrStatus.timeval) ")"_doc)

    .def_prop_rw("cstime",
        nb::overload_cast<>(&CorePrStatus::cstime, nb::const_),
        nb::overload_cast<CorePrStatus::timeval_t>(&CorePrStatus::cstime),
        "Cumulative system time (" RST_CLASS_REF(lief.ELF.CorePrStatus.timeval) ")"_doc)

    .def_prop_rw("register_context",
        nb::overload_cast<>(&CorePrStatus::reg_context, nb::const_),
        nb::overload_cast<const CorePrStatus::reg_context_t&>(&CorePrStatus::reg_context),
        "Current registers state as a dictionary where the keys are "
        RST_CLASS_REF(lief.ELF.CorePrStatus.REGISTERS) " and the values the register's value"_doc)

    .def("get",
        [] (const CorePrStatus& status, CorePrStatus::REGISTERS reg) -> nb::object {
          bool error;
          const uint64_t val = status.get(reg, &error);
          if (error) {
            return nb::none();
          }
          return nb::int_(val);
        },
        "Return the register value"_doc,
        "register"_a)

    .def("set",
        &CorePrStatus::set,
        "Set register value"_doc,
        "register"_a, "value"_a)

    .def("has",
        &CorePrStatus::has,
        "Check if a value is associated with the given register"_doc,
        "register"_a)

    .def("__getitem__",
        &CorePrStatus::operator[],
        nb::rv_policy::copy)

    .def("__setitem__",
        [] (CorePrStatus& status, CorePrStatus::REGISTERS reg, uint64_t val) {
          status.set(reg, val);
        })

    .def("__contains__",
        &CorePrStatus::has)

    LIEF_DEFAULT_STR(CorePrStatus);


  LIEF::enum_<CorePrStatus::REGISTERS>(cls, "REGISTERS")
    .value(PY_ENUM(CorePrStatus::REGISTERS::UNKNOWN))

    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_EBX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_ECX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_EDX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_ESI))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_EDI))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_EBP))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_EAX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_DS))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_ES))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_FS))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_GS))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86__))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_EIP))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_CS))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_EFLAGS))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_ESP))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_SS))

    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R15))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R14))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R13))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R12))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RBP))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RBX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R11))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R10))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R9))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_R8))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RAX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RCX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RDX))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RSI))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RDI))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64__))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RIP))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_CS))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_EFLAGS))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_RSP))
    .value(PY_ENUM(CorePrStatus::REGISTERS::X86_64_SS))

    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R0))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R1))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R2))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R3))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R4))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R5))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R6))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R7))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R8))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R9))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R10))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R11))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R12))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R13))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R14))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_R15))
    .value(PY_ENUM(CorePrStatus::REGISTERS::ARM_CPSR))

    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X0))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X1))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X2))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X3))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X4))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X5))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X6))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X7))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X8))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X9))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X10))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X11))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X12))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X13))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X14))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X15))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X16))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X17))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X18))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X19))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X20))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X21))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X22))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X23))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X24))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X25))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X26))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X27))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X28))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X29))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X30))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_X31))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64_PC))
    .value(PY_ENUM(CorePrStatus::REGISTERS::AARCH64__));
}
}
