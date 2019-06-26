/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/PE/utils.hpp"


namespace LIEF {
namespace PE {

void init_utils(py::module& m) {


  m.def("is_pe",
      static_cast<bool (*)(const std::string&)>(&is_pe),
      "Check if the given file is a ``PE``",
      "file"_a);

  m.def("is_pe",
      static_cast<bool (*)(const std::vector<uint8_t>&)>(&is_pe),
      "Check if the given raw data is a ``PE``",
      "raw"_a);

  m.def("get_type",
      static_cast<PE_TYPE (*)(const std::string&)>(&get_type),
      "If the input file is a ``PE`` one, return the " RST_CLASS_REF(lief.PE.PE_TYPE) "",
      "file"_a);


  m.def("get_type",
      static_cast<PE_TYPE (*)(const std::vector<uint8_t>&)>(&get_type),
      "If the input *raw* data represent a ``PE`` file, return the " RST_CLASS_REF(lief.PE.PE_TYPE) "",
      "raw"_a);

  m.def("get_imphash",
      &get_imphash,
      "Compute the hash of imported functions\n\n"

      "Properties of the hash generated:\n"
      "\t* Order agnostic\n"
      "\t* Casse agnostic\n"
      "\t* Ordinal (**in some extent**) agnostic\n\n"

      ".. warning::\n\n"
      "\tThe algorithm used to compute the *imphash* value has some variations compared to Yara, pefile, VT implementation\n"

      ".. seealso::\n\n"
      "\thttps://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html\n",
      "binary"_a);

  m.def("resolve_ordinals",
      &resolve_ordinals,
      "Take an " RST_CLASS_REF(lief.PE.Import) " as entry and try to resolve its ordinal imports\n\n"

      "The ``strict`` boolean parameter enables to throw a " RST_CLASS_REF(lief.not_found) " exception "
      "if the ordinal can't be resolved. Otherwise it skips the entry.",
      "import"_a, "strict"_a = false,
      py::return_value_policy::copy);
}

}
}
