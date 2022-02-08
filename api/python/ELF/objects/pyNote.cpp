/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Note.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (Note::*)(void) const;

template<class T>
using setter_t = void (Note::*)(T);


template<>
void create<Note>(py::module& m) {

  py::class_<Note, LIEF::Object>(m, "Note",
      R"delim(
      Class which represents an ELF note.
      )delim")

    .def(py::init<>(),
        "Default constructor")

    .def(py::init<const std::string&, NOTE_TYPES, const std::vector<uint8_t>&>(),
        "Constructor from a ``name``, ``type`` and ``description``",
        "name"_a, "type"_a, "description"_a)

    .def_property_readonly("details",
        static_cast<NoteDetails& (Note::*)(void)>(&Note::details),
        "Parse the given note description and return a " RST_CLASS_REF(lief.ELF.NoteDetails) " object",
        py::return_value_policy::reference_internal)

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&Note::name),
        static_cast<setter_t<const std::string&>>(&Note::name),
        "Return the *name* of the note (Usually the owner)."
        )

    .def_property("type",
        static_cast<getter_t<NOTE_TYPES>>(&Note::type),
        static_cast<setter_t<NOTE_TYPES>>(&Note::type),
        "Return the type of the note. It can be one of the " RST_CLASS_REF(lief.ELF.NOTE_TYPES) " values"
        )

    .def_property("type_core",
        static_cast<getter_t<NOTE_TYPES_CORE>>(&Note::type_core),
        static_cast<setter_t<NOTE_TYPES_CORE>>(&Note::type_core),
        "Return the type of the note for ELF Core (ET_CORE). It Can be one of the " RST_CLASS_REF(lief.ELF.NOTE_TYPES_CORE) " values"
        )

    .def_property("description",
        static_cast<getter_t<const Note::description_t&>>(&Note::description),
        static_cast<setter_t<const Note::description_t&>>(&Note::description),
        "Return the description associated with the note"
        )

    .def_property_readonly("is_core",
        &Note::is_core,
        "True if the note is associated with a coredump")

    .def_property_readonly("is_android",
        &Note::is_android,
        R"delim(
        True if the current note is specific to Android.

        If true, :attr:`lief.Note.details` returns a reference to the :class:`~lief.ELF.AndroidNote` object
        )delim")

    .def_property_readonly("size",
        &Note::size,
        "Size of the **raw** note")

    .def("__eq__", &Note::operator==)
    .def("__ne__", &Note::operator!=)
    .def("__hash__",
        [] (const Note& note) {
          return Hash::hash(note);
        })

    .def("__str__",
        [] (const Note& note)
        {
          std::ostringstream stream;
          stream << note;
          std::string str = stream.str();
          return str;
        });
}

}
}
