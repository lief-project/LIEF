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
#include <nanobind/stl/vector.h>
#include <nanobind/operators.h>

#include "LIEF/MachO/Header.hpp"

#include "MachO/pyMachO.hpp"

#include "enums_wrapper.hpp"

namespace LIEF::MachO::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, LIEF::Object> cls(m, "Header",
      "Class that represents the Mach-O header"_doc);
  cls
    .def(nb::init<>())

    .def_prop_rw("magic",
        nb::overload_cast<>(&Header::magic, nb::const_),
        nb::overload_cast<MACHO_TYPES>(&Header::magic),
        R"delim(
        The Mach-O magic bytes. These bytes determine whether it is
        a 32 bits Mach-O, a 64 bits Mach-O files etc.
        )delim"_doc)

    .def_prop_rw("cpu_type",
        nb::overload_cast<>(&Header::cpu_type, nb::const_),
        nb::overload_cast<Header::CPU_TYPE>(&Header::cpu_type),
        "Target CPU"_doc)

    .def_prop_rw("cpu_subtype",
        nb::overload_cast<>(&Header::cpu_subtype, nb::const_),
        nb::overload_cast<uint32_t>(&Header::cpu_subtype),
        R"delim(
        Return the CPU subtype supported by the Mach-O binary.
        For ARM architectures, this value could represent the minimum version
        for which the Mach-O binary has been compiled for.
        )delim"_doc)

    .def_prop_rw("file_type",
        nb::overload_cast<>(&Header::file_type, nb::const_),
        nb::overload_cast<Header::FILE_TYPE>(&Header::file_type),
        "Binary's type"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&Header::flags, nb::const_),
        nb::overload_cast<uint32_t>(&Header::flags),
        "Binary's flags"_doc)

    .def_prop_rw("nb_cmds",
        nb::overload_cast<>(&Header::nb_cmds, nb::const_),
        nb::overload_cast<uint32_t>(&Header::nb_cmds),
        "Number of " RST_CLASS_REF(lief.MachO.LoadCommand) ""_doc)

    .def_prop_rw("sizeof_cmds",
        nb::overload_cast<>(&Header::sizeof_cmds, nb::const_),
        nb::overload_cast<uint32_t>(&Header::sizeof_cmds),
        "Size of all " RST_CLASS_REF(lief.MachO.LoadCommand) ""_doc)

    .def_prop_rw("reserved",
        nb::overload_cast<>(&Header::reserved, nb::const_),
        nb::overload_cast<uint32_t>(&Header::reserved),
        "According to the official documentation, a reserved value"_doc)

    .def_prop_ro("flags_list",
        &Header::flags_list,
        "" RST_CLASS_REF(lief.MachO.Header.FLAGS) " as a list"_doc)

    .def("add",
        nb::overload_cast<Header::FLAGS>(&Header::add),
        "Add the given " RST_CLASS_REF(lief.MachO.Header.FLAGS) ""_doc,
        "flag"_a)

    .def("remove",
        nb::overload_cast<Header::FLAGS>(&Header::remove),
        "Remove the given " RST_CLASS_REF(lief.MachO.Header.FLAGS) ""_doc,
        "flag"_a)

    .def("has",
        nb::overload_cast<Header::FLAGS>(&Header::has, nb::const_),
        "``True`` if the given " RST_CLASS_REF(lief.MachO.Header.FLAGS) " is in the "
        ":attr:`~lief.MachO.Header.flags`"_doc,
        "flag"_a)

    .def(nb::self += Header::FLAGS(), nb::rv_policy::reference_internal)
    .def(nb::self -= Header::FLAGS(), nb::rv_policy::reference_internal)

    .def("__contains__",
        nb::overload_cast<Header::FLAGS>(&Header::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.MachO.Header.FLAGS) " is present"_doc)

    LIEF_DEFAULT_STR(Header);

  enum_<Header::CPU_TYPE>(cls, "CPU_TYPE")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(Header::CPU_TYPE::ANY))
    .value(PY_ENUM(Header::CPU_TYPE::X86))
    .value(PY_ENUM(Header::CPU_TYPE::X86_64))
    .value(PY_ENUM(Header::CPU_TYPE::MIPS))
    .value(PY_ENUM(Header::CPU_TYPE::MC98000))
    .value(PY_ENUM(Header::CPU_TYPE::ARM))
    .value(PY_ENUM(Header::CPU_TYPE::ARM64))
    .value(PY_ENUM(Header::CPU_TYPE::SPARC))
    .value(PY_ENUM(Header::CPU_TYPE::POWERPC))
    .value(PY_ENUM(Header::CPU_TYPE::POWERPC64))
  #undef PY_ENUM
  ;

  enum_<Header::FILE_TYPE>(cls, "FILE_TYPE")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(Header::FILE_TYPE::UNKNOWN))
    .value(PY_ENUM(Header::FILE_TYPE::OBJECT))
    .value(PY_ENUM(Header::FILE_TYPE::EXECUTE))
    .value(PY_ENUM(Header::FILE_TYPE::FVMLIB))
    .value(PY_ENUM(Header::FILE_TYPE::CORE))
    .value(PY_ENUM(Header::FILE_TYPE::PRELOAD))
    .value(PY_ENUM(Header::FILE_TYPE::DYLIB))
    .value(PY_ENUM(Header::FILE_TYPE::DYLINKER))
    .value(PY_ENUM(Header::FILE_TYPE::BUNDLE))
    .value(PY_ENUM(Header::FILE_TYPE::DYLIB_STUB))
    .value(PY_ENUM(Header::FILE_TYPE::DSYM))
    .value(PY_ENUM(Header::FILE_TYPE::KEXT_BUNDLE))
  #undef PY_ENUM
  ;

  enum_<Header::FLAGS>(cls, "FLAGS", nb::is_arithmetic())
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(Header::FLAGS::NOUNDEFS))
    .value(PY_ENUM(Header::FLAGS::INCRLINK))
    .value(PY_ENUM(Header::FLAGS::DYLDLINK))
    .value(PY_ENUM(Header::FLAGS::BINDATLOAD))
    .value(PY_ENUM(Header::FLAGS::PREBOUND))
    .value(PY_ENUM(Header::FLAGS::SPLIT_SEGS))
    .value(PY_ENUM(Header::FLAGS::LAZY_INIT))
    .value(PY_ENUM(Header::FLAGS::TWOLEVEL))
    .value(PY_ENUM(Header::FLAGS::FORCE_FLAT))
    .value(PY_ENUM(Header::FLAGS::NOMULTIDEFS))
    .value(PY_ENUM(Header::FLAGS::NOFIXPREBINDING))
    .value(PY_ENUM(Header::FLAGS::PREBINDABLE))
    .value(PY_ENUM(Header::FLAGS::ALLMODSBOUND))
    .value(PY_ENUM(Header::FLAGS::SUBSECTIONS_VIA_SYMBOLS))
    .value(PY_ENUM(Header::FLAGS::CANONICAL))
    .value(PY_ENUM(Header::FLAGS::WEAK_DEFINES))
    .value(PY_ENUM(Header::FLAGS::BINDS_TO_WEAK))
    .value(PY_ENUM(Header::FLAGS::ALLOW_STACK_EXECUTION))
    .value(PY_ENUM(Header::FLAGS::ROOT_SAFE))
    .value(PY_ENUM(Header::FLAGS::SETUID_SAFE))
    .value(PY_ENUM(Header::FLAGS::NO_REEXPORTED_DYLIBS))
    .value(PY_ENUM(Header::FLAGS::PIE))
    .value(PY_ENUM(Header::FLAGS::DEAD_STRIPPABLE_DYLIB))
    .value(PY_ENUM(Header::FLAGS::HAS_TLV_DESCRIPTORS))
    .value(PY_ENUM(Header::FLAGS::NO_HEAP_EXECUTION))
    .value(PY_ENUM(Header::FLAGS::APP_EXTENSION_SAFE))
  #undef PY_ENUM
  ;
}
}
