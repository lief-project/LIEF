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
#include "PE/pyPE.hpp"
#include "pyIterator.hpp"

#include "LIEF/PE/signature/attributes/MsCounterSign.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<MsCounterSign>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<MsCounterSign, Attribute> CounterSig(m, "MsCounterSign",
    R"delim(
    This class exposes the ms-counter-signature.
    )delim"_doc);

  init_ref_iterator<MsCounterSign::it_certificates>(CounterSig, "it_const_crt");
  init_ref_iterator<MsCounterSign::it_signers>(CounterSig, "it_const_signers_t");

  CounterSig
    .def_prop_ro("version", &MsCounterSign::version)
    .def_prop_ro("digest_algorithm", &MsCounterSign::digest_algorithm)
    .def_prop_ro("content_info", &MsCounterSign::content_info)
    .def_prop_ro("certificates",
        nb::overload_cast<>(&MsCounterSign::certificates),
        "Return an iterator over " RST_CLASS_REF(lief.PE.x509) " certificates"_doc,
        nb::keep_alive<0, 1>())
    .def_prop_ro("signers",
        nb::overload_cast<>(&MsCounterSign::signers),
        "Return an iterator over the signers (" RST_CLASS_REF(lief.PE.SignerInfo) ")"_doc,
        nb::keep_alive<0, 1>());
}

}
