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
#include <nanobind/stl/unique_ptr.h>

#include "ELF/pyELF.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/ELF/NoteDetails/NoteGnuProperty.hpp"
#include "LIEF/ELF/NoteDetails/properties/AArch64Feature.hpp"
#include "LIEF/ELF/NoteDetails/properties/X86Feature.hpp"
#include "LIEF/ELF/NoteDetails/properties/X86ISA.hpp"
#include "LIEF/ELF/NoteDetails/properties/StackSize.hpp"
#include "LIEF/ELF/NoteDetails/properties/NoteNoCopyOnProtected.hpp"
#include "LIEF/ELF/NoteDetails/properties/Generic.hpp"

namespace LIEF::ELF::py {

template<>
void create<NoteGnuProperty>(nb::module_& m) {
  nb::class_<NoteGnuProperty, Note> Class(m, "NoteGnuProperty",
    R"doc(
    This object represents the `NT_GNU_PROPERTY_TYPE_0` note.
    )doc"_doc);

  nb::class_<NoteGnuProperty::Property> Property(Class, "Property",
    R"doc(
    This class wraps the different properties that can be used in a
    `NT_GNU_PROPERTY_TYPE_0` note
    )doc"_doc);
  Property
    .def_prop_ro("type", &NoteGnuProperty::Property::type)
    LIEF_DEFAULT_STR(NoteGnuProperty::Property);

# define ENTRY(X) .value(to_string(NoteGnuProperty::Property::TYPE::X), NoteGnuProperty::Property::TYPE::X)
  enum_<NoteGnuProperty::Property::TYPE>(Property, "TYPE",
    R"doc(
    LIEF's mirror types of the original `GNU_PROPERTY_` values
    )doc"_doc)
    ENTRY(UNKNOWN)
    ENTRY(GENERIC)
    ENTRY(AARCH64_FEATURES)
    ENTRY(STACK_SIZE)
    ENTRY(NO_COPY_ON_PROTECTED)
    ENTRY(X86_ISA)
    ENTRY(X86_FEATURE)
    ENTRY(NEEDED)
  ;
# undef ENTRY

  create<AArch64Feature>(m);
  create<X86Features>(m);
  create<X86ISA>(m);
  create<StackSize>(m);
  create<NoteNoCopyOnProtected>(m);
  create<Generic>(m);

  Class
    .def_prop_ro("properties", &NoteGnuProperty::properties,
        R"doc(
        Return the properties as a list of Property
        )doc")
    .def("find", &NoteGnuProperty::find,
        R"doc(
        Find the property with the given type or return None
        )doc")
    LIEF_DEFAULT_STR(NoteGnuProperty);
}

}
