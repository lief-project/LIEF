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
#include <algorithm>
#include <iomanip>

#include "LIEF/Visitor.hpp"

#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/PE/Import.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

Import::Import(const details::pe_import& import) :
  import_lookup_table_RVA_(import.ImportLookupTableRVA),
  timedatestamp_(import.TimeDateStamp),
  forwarder_chain_(import.ForwarderChain),
  name_RVA_(import.NameRVA),
  import_address_table_RVA_(import.ImportAddressTableRVA)
{}


const ImportEntry* Import::get_entry(const std::string& name) const {
  const auto it_entry = std::find_if(std::begin(entries_), std::end(entries_),
      [&name] (const ImportEntry& entry) {
        return entry.name() == name;
      });
  if (it_entry == std::end(entries_)) {
    return nullptr;
  }
  return &*it_entry;
}

result<uint32_t> Import::get_function_rva_from_iat(const std::string& function) const {
  const auto it_function = std::find_if(std::begin(entries_), std::end(entries_),
      [&function] (const ImportEntry& entry) {
        return entry.name() == function;
      });

  if (it_function == std::end(entries_)) {
    return make_error_code(lief_errors::not_found);
  }

  // Index of the function in the imported functions
  uint32_t idx = std::distance(std::begin(entries_), it_function);

  if (type_ == PE_TYPE::PE32) {
    return idx * sizeof(uint32_t);
  }
  return idx * sizeof(uint64_t);
}

void Import::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Import& entry) {
  os << std::hex;
  os << std::left
     << std::setw(20) << entry.name()
     << std::setw(10) << entry.import_lookup_table_rva()
     << std::setw(10) << entry.import_address_table_rva()
     << std::setw(10) << entry.forwarder_chain()
     << std::setw(10) << entry.timedatestamp()
     << '\n';

  for (const ImportEntry& functions: entry.entries()) {
    os << "\t - " << functions << '\n';
  }

  return os;
}
}
}
