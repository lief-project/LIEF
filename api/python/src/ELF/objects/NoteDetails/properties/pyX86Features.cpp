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

#include <nanobind/stl/vector.h>
#include <nanobind/stl/pair.h>

#include "enums_wrapper.hpp"
#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/properties/X86Feature.hpp"

namespace LIEF::ELF::py {

template<>
void create<X86Features>(nb::module_& m) {
  nb::class_<X86Features, NoteGnuProperty::Property> Class(m, "X86Features",
    R"doc(
    This class interfaces the different ``GNU_PROPERTY_X86_FEATURE_*``
    properties which includes:

    - ``GNU_PROPERTY_X86_FEATURE_1_AND``
    - ``GNU_PROPERTY_X86_FEATURE_2_USED``
    - ``GNU_PROPERTY_X86_FEATURE_2_NEEDED``
    )doc"_doc
  );
  Class
    .def_prop_ro("features", &X86Features::features,
      R"doc(
      List of the features as a pair of (:class:`~.FLAG`, :class:`~.FEATURE`).
      )doc"_doc
    );

# define ENTRY(X,D) .value(to_string(X86Features::FLAG::X), X86Features::FLAG::X, D)
  enum_<X86Features::FLAG>(Class, "FLAG",
    R"doc(
    Flag according to the ``_AND``, ``_USED`` or ``_NEEDED`` suffixes
    )doc"_doc
  )
    ENTRY(NONE, "For the original ``GNU_PROPERTY_X86_FEATURE_1_AND`` property")
    ENTRY(NEEDED, "For the original ``GNU_PROPERTY_X86_FEATURE_2_USED`` property")
    ENTRY(USED, "For the original ``GNU_PROPERTY_X86_FEATURE_2_NEEDED`` property")
  ;
# undef ENTRY

# define ENTRY(X) .value(to_string(X86Features::FEATURE::X), X86Features::FEATURE::X)
  enum_<X86Features::FEATURE>(Class, "FEATURE",
    R"doc(
    Features provided by these different properties
    )doc"
  )
    ENTRY(UNKNOWN)
    ENTRY(IBT)
    ENTRY(SHSTK)
    ENTRY(LAM_U48)
    ENTRY(LAM_U57)
    ENTRY(X86)
    ENTRY(X87)
    ENTRY(MMX)
    ENTRY(XMM)
    ENTRY(YMM)
    ENTRY(ZMM)
    ENTRY(FXSR)
    ENTRY(XSAVE)
    ENTRY(XSAVEOPT)
    ENTRY(XSAVEC)
    ENTRY(TMM)
    ENTRY(MASK)
  ;
# undef ENTRY
}

}
