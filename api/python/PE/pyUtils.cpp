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
#include "pyPE.hpp"
#include "pyErr.hpp"

#include "LIEF/PE/utils.hpp"

namespace LIEF {
namespace PE {

void init_utils(py::module& m) {
  py::enum_<IMPHASH_MODE>(m, "IMPHASH_MODE",
      "Enum to define the behavior of :func:`~lief.PE.get_imphash`")
    .value("DEFAULT", IMPHASH_MODE::DEFAULT, "Default implementation")
    .value("LIEF",    IMPHASH_MODE::LIEF,    "Same as DEFAULT")
    .value("PEFILE",  IMPHASH_MODE::PEFILE,  "Use pefile algorithm")
    .value("VT",      IMPHASH_MODE::VT,      "Same as PEFILE since Virus Total is using pefile");

  m.def("is_pe",
      static_cast<bool (*)(const std::string&)>(&is_pe),
      "Check if the given file is a ``PE``",
      "file"_a);

  m.def("is_pe",
      static_cast<bool (*)(const std::vector<uint8_t>&)>(&is_pe),
      "Check if the given raw data is a ``PE``",
      "raw"_a);

  m.def("get_type",
      [] (const std::string& file) {
        return error_or(static_cast<result<PE_TYPE> (*)(const std::string&)>(&get_type), file);
      },
      "If the input file is a ``PE`` one, return the " RST_CLASS_REF(lief.PE.PE_TYPE) " \n"
      "If the function fails to determine the type, it returns a " RST_CLASS_REF(lief.lief_errors) "",
      "file"_a);


  m.def("get_type",
      [] (const std::vector<uint8_t>& raw) {
        return error_or(static_cast<result<PE_TYPE> (*)(const std::vector<uint8_t>&)>(&get_type), raw);
      },
      "If the input *raw* data represent a ``PE`` file, return the " RST_CLASS_REF(lief.PE.PE_TYPE) " \n"
      "If the function fails to determine the type, it returns a " RST_CLASS_REF(lief.lief_errors) "",
      "raw"_a);

  m.def("get_imphash",
      &get_imphash,
      R"delim(
      Compute the hash of imported functions

      Properties of the hash generated:

        * Order agnostic
        * Casse agnostic
        * Ordinal (**in some extent**) agnostic
        *

      If one needs the same output as Virus Total (i.e. pefile), you can use :attr:`~lief.PE.IMPHASH_MODE.PEFILE`
      as second parameter.

      .. warning::
          The algorithm used to compute the *imphash* value has some variations compared to Yara, pefile,
          VT implementation

      .. seealso::
          https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
      )delim",
      "binary"_a, "mode"_a = IMPHASH_MODE::DEFAULT);

  m.def("resolve_ordinals",
      [] (const Import& import, bool strict = false, bool use_std = false) {
        return error_or(resolve_ordinals, import, strict, use_std);
      },
      "Take an " RST_CLASS_REF(lief.PE.Import) " as entry and try to resolve its ordinal imports\n\n"

      "The ``strict`` boolean parameter enables to throw a " RST_CLASS_REF(lief.not_found) " exception "
      "if the ordinal can't be resolved. Otherwise it skips the entry.",
      "import"_a, "strict"_a = false, "use_std"_a = false,
      py::return_value_policy::copy);
}

}
}
