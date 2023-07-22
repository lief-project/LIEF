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
#include <nanobind/stl/vector.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF::ELF::py {

template<>
void create<Note>(nb::module_& m) {
  nb::class_<Note, LIEF::Object>(m, "Note",
      R"delim(
      Class which represents an ELF note.
      )delim"_doc)

    .def(nb::init<>(),
        "Default constructor")

    .def(nb::init<const std::string&, NOTE_TYPES, const std::vector<uint8_t>&>(),
        "Constructor from a ``name``, ``type`` and ``description``"_doc,
        "name"_a, "type"_a, "description"_a)

    .def_prop_ro("details",
        nb::overload_cast<>(&Note::details),
        "Parse the given note description and return a " RST_CLASS_REF(lief.ELF.NoteDetails) " object"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("name",
        nb::overload_cast<>(&Note::name, nb::const_),
        nb::overload_cast<const std::string&>(&Note::name),
        "Return the *name* of the note (Usually the owner)."_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&Note::type, nb::const_),
        nb::overload_cast<NOTE_TYPES>(&Note::type),
        "Return the type of the note. It can be one of the " RST_CLASS_REF(lief.ELF.NOTE_TYPES) " values"_doc)

    .def_prop_rw("type_core",
        nb::overload_cast<>(&Note::type_core, nb::const_),
        nb::overload_cast<NOTE_TYPES_CORE>(&Note::type_core),
        "Return the type of the note for ELF Core (ET_CORE). It Can be one of the " RST_CLASS_REF(lief.ELF.NOTE_TYPES_CORE) " values"_doc)

    .def_prop_rw("description",
        nb::overload_cast<>(&Note::description, nb::const_),
        nb::overload_cast<const Note::description_t&>(&Note::description),
        "Return the description associated with the note"_doc)

    .def_prop_ro("is_core",
        &Note::is_core,
        "True if the note is associated with a coredump"_doc)

    .def_prop_ro("is_android",
        &Note::is_android,
        R"delim(
        True if the current note is specific to Android.

        If true, :attr:`lief.Note.details` returns a reference to the :class:`~lief.ELF.AndroidNote` object
        )delim"_doc)

    .def_prop_ro("size", &Note::size,
        "Size of the **raw** note"_doc)

    LIEF_DEFAULT_STR(Note);
}

}

