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

#include "ELF/pyELF.hpp"
#include "enums_wrapper.hpp"

#include <nanobind/stl/vector.h>
#include <nanobind/stl/pair.h>

#include "LIEF/ELF/NoteDetails/properties/X86ISA.hpp"

namespace LIEF::ELF::py {

template<>
void create<X86ISA>(nb::module_& m) {
  nb::class_<X86ISA, NoteGnuProperty::Property> Class(m, "X86ISA",
    R"doc(
    This class interfaces the different ``GNU_PROPERTY_X86_ISA_*``
    properties which includes:

    - ``GNU_PROPERTY_X86_ISA_1_USED``
    - ``GNU_PROPERTY_X86_ISA_1_NEEDED``
    - ``GNU_PROPERTY_X86_COMPAT_ISA_1_USED``
    - ``GNU_PROPERTY_X86_COMPAT_ISA_1_NEEDED``
    - ``GNU_PROPERTY_X86_COMPAT_2_ISA_1_USED``
    - ``GNU_PROPERTY_X86_COMPAT_2_ISA_1_NEEDED``
    )doc"_doc
  );
  Class
    .def_prop_ro("values", &X86ISA::values,
      R"doc(
      List of the ISA values in this property
      )doc"
    );

# define ENTRY(X) .value(to_string(X86ISA::FLAG::X), X86ISA::FLAG::X)
  enum_<X86ISA::FLAG>(Class, "FLAG")
    ENTRY(NONE)
    ENTRY(NEEDED)
    ENTRY(USED)
  ;
# undef ENTRY

# define ENTRY(X) .value(to_string(X86ISA::ISA::X), X86ISA::ISA::X)
  enum_<X86ISA::ISA>(Class, "ISA")
    ENTRY(UNKNOWN)
    ENTRY(BASELINE)
    ENTRY(V2)
    ENTRY(V3)
    ENTRY(V4)
    ENTRY(CMOV)
    ENTRY(FMA)
    ENTRY(I486)
    ENTRY(I586)
    ENTRY(I686)
    ENTRY(SSE)
    ENTRY(SSE2)
    ENTRY(SSE3)
    ENTRY(SSSE3)
    ENTRY(SSE4_1)
    ENTRY(SSE4_2)
    ENTRY(AVX)
    ENTRY(AVX2)
    ENTRY(AVX512F)
    ENTRY(AVX512CD)
    ENTRY(AVX512ER)
    ENTRY(AVX512PF)
    ENTRY(AVX512VL)
    ENTRY(AVX512DQ)
    ENTRY(AVX512BW)
    ENTRY(AVX512_4FMAPS)
    ENTRY(AVX512_4VNNIW)
    ENTRY(AVX512_BITALG)
    ENTRY(AVX512_IFMA)
    ENTRY(AVX512_VBMI)
    ENTRY(AVX512_VBMI2)
    ENTRY(AVX512_VNNI)
    ENTRY(AVX512_BF16)
  ;
# undef ENTRY

}

}
