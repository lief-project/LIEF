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
#include <nanobind/stl/array.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/NoteAbi.hpp"
#include "enums_wrapper.hpp"
#include "pyErr.hpp"

namespace LIEF::ELF::py {

template<>
void create<NoteAbi>(nb::module_& m) {
  nb::class_<NoteAbi, Note> nabi(m, "NoteAbi",
    R"doc(
    Class that wraps the `NT_GNU_ABI_TAG` note
    )doc"_doc
  );

  #define ENTRY(X) .value(to_string(NoteAbi::ABI::X), NoteAbi::ABI::X)
  enum_<NoteAbi::ABI>(nabi, "ABI", "ABI recognized by this note"_doc)
    ENTRY(LINUX)
    ENTRY(GNU)
    ENTRY(SOLARIS2)
    ENTRY(FREEBSD)
    ENTRY(NETBSD)
    ENTRY(SYLLABLE)
    ENTRY(NACL)
  ;
  #undef ENTRY

  nabi
    .def_prop_ro("abi",
        [] (const NoteAbi& self) {
          return LIEF::py::value_or_none(nb::overload_cast<>(&NoteAbi::abi, nb::const_), self);
        },
        R"doc(Return the target :class:`~.ABI`)doc"_doc)

    .def_prop_ro("version",
        [] (const NoteAbi& self) {
          return LIEF::py::value_or_none(nb::overload_cast<>(&NoteAbi::version, nb::const_), self);
        },
        "Return the target version as ``(Major, Minor, Patch)``"_doc)

    LIEF_DEFAULT_STR(NoteAbi);
}
}
