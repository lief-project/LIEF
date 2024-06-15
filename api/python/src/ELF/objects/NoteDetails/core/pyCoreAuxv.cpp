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

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/core/CoreAuxv.hpp"

#include "pyErr.hpp"
#include "enums_wrapper.hpp"


namespace LIEF::ELF::py {

template<>
void create<CoreAuxv>(nb::module_& m) {

  nb::class_<CoreAuxv, Note> cls(m, "CoreAuxv");
  #define PY_ENUM(X) .value(LIEF::ELF::to_string(CoreAuxv::TYPE::X), CoreAuxv::TYPE::X)
  LIEF::enum_<CoreAuxv::TYPE>(cls, "TYPE")
    PY_ENUM(END)
    PY_ENUM(IGNORE)
    PY_ENUM(EXECFD)
    PY_ENUM(PHDR)
    PY_ENUM(PHENT)
    PY_ENUM(PHNUM)
    PY_ENUM(PAGESZ)
    PY_ENUM(BASE)
    PY_ENUM(FLAGS)
    PY_ENUM(ENTRY)
    PY_ENUM(NOTELF)
    PY_ENUM(UID)
    PY_ENUM(EUID)
    PY_ENUM(GID)
    PY_ENUM(EGID)
    PY_ENUM(TGT_PLATFORM)
    PY_ENUM(HWCAP)
    PY_ENUM(CLKTCK)
    PY_ENUM(FPUCW)
    PY_ENUM(DCACHEBSIZE)
    PY_ENUM(ICACHEBSIZE)
    PY_ENUM(UCACHEBSIZE)
    PY_ENUM(IGNOREPPC)
    PY_ENUM(SECURE)
    PY_ENUM(BASE_PLATFORM)
    PY_ENUM(RANDOM)
    PY_ENUM(HWCAP2)
    PY_ENUM(EXECFN)
    PY_ENUM(SYSINFO)
    PY_ENUM(SYSINFO_EHDR)
  ;
  #undef PY_ENUM

  cls
    .def_prop_ro("values", &CoreAuxv::values,
      R"doc(
      Return the auxiliary vector as a dictionary of :class:`.TYPE` / `int`
      )doc"
    )

    .def("get",
        [] (const CoreAuxv& self, CoreAuxv::TYPE type) {
          return LIEF::py::value_or_none(&CoreAuxv::get, self, type);
        }, "type"_a,
        R"doc(
        Get the auxv value from the provided type. Return `None` if
        it is not present.
        )doc"_doc
    )

    .def("__getitem__",
        [] (const CoreAuxv& self, CoreAuxv::TYPE type) {
          return LIEF::py::value_or_none(&CoreAuxv::get, self, type);
        }
    )

    .def("set", nb::overload_cast<CoreAuxv::TYPE, uint64_t>(&CoreAuxv::set),
         "type"_a, "value"_a,
         R"doc(
         Change the value for the given type.
         )doc")
    .def("set", nb::overload_cast<const std::map<CoreAuxv::TYPE, uint64_t>&>(&CoreAuxv::set),
         R"doc(
         Replace **all** the values by the given dictionary.
         )doc")

    .def("__setitem__", nb::overload_cast<CoreAuxv::TYPE, uint64_t>(&CoreAuxv::set))
    .def("__setitem__", nb::overload_cast<const std::map<CoreAuxv::TYPE, uint64_t>&>(&CoreAuxv::set))

    LIEF_DEFAULT_STR(CoreAuxv);
}
}
