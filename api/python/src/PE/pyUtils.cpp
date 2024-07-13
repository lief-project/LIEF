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
#include "PE/pyPE.hpp"
#include "pyErr.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/Binary.hpp"

#include "LIEF/PE/signature/OIDToString.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

void init_utils(nb::module_& m) {
  using namespace LIEF::py;

  nb::enum_<IMPHASH_MODE>(m, "IMPHASH_MODE",
      "Enum to define the behavior of :func:`~lief.PE.get_imphash`"_doc)
    .value("DEFAULT", IMPHASH_MODE::DEFAULT, "Default implementation")
    .value("LIEF",    IMPHASH_MODE::LIEF,    "Same as DEFAULT")
    .value("PEFILE",  IMPHASH_MODE::PEFILE,  "Use pefile algorithm")
    .value("VT",      IMPHASH_MODE::VT,      "Same as PEFILE since Virus Total is using pefile");

  m.def("oid_to_string", &oid_to_string,
        "Convert an OID to a human-readable string"_doc);

  lief_mod->def("is_pe",
      nb::overload_cast<const std::string&>(&is_pe),
      "Check if the given file is a ``PE``"_doc,
      "file"_a);

  lief_mod->def("is_pe",
      nb::overload_cast<const std::vector<uint8_t>&>(&is_pe),
      "Check if the given raw data is a ``PE``"_doc,
      "raw"_a);

  m.def("get_type",
      [] (const std::string& file) {
        return error_or(static_cast<result<PE_TYPE> (*)(const std::string&)>(&get_type), file);
      },
      R"delim(
      If the input file is a a valid ``PE``, return the :class:`~.lief.PE.PE_TYPE`.
      Otherwise, return a :class:`lief.lief_errors`.
      )delim"_doc,
      "file"_a);


  m.def("get_type",
      [] (const std::vector<uint8_t>& raw) {
        return error_or(static_cast<result<PE_TYPE> (*)(const std::vector<uint8_t>&)>(&get_type), raw);
      },
      "raw"_a);

  m.def("get_imphash",
      &get_imphash,
      R"delim(
      Compute the hash of imported functions

      Properties of the hash generated:

        * Order agnostic
        * Casse agnostic
        * Ordinal (**in some extent**) agnostic

      If one needs the same output as Virus Total (i.e. pefile), you can use :attr:`~lief.PE.IMPHASH_MODE.PEFILE`
      as second parameter.

      .. warning::
          The algorithm used to compute the *imphash* value has some variations compared to Yara, pefile,
          VT implementation

      .. seealso::
          https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
      )delim"_doc,
      "binary"_a, "mode"_a = IMPHASH_MODE::DEFAULT);

  m.def("resolve_ordinals",
      [] (const Import& import, bool strict = false, bool use_std = false) {
        return error_or(resolve_ordinals, import, strict, use_std);
      },
      R"delim(
      Take a :class:`~lief.PE.Import` as input and try to resolve its ordinal imports.

      If the ``strict`` boolean parameter is set, a :attr:`lief.lief_errors.not_found` error is
      returned upon the first non-resolvable ordinal.
      )delim",
      "imp"_a, "strict"_a = false, "use_std"_a = false,
      nb::rv_policy::copy);
}
}
