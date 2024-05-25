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
#ifndef LIEF_PE_IMPORT_H
#define LIEF_PE_IMPORT_H

#include <string>
#include <ostream>

#include "LIEF/errors.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"
#include "LIEF/PE/ImportEntry.hpp"

namespace LIEF {
namespace PE {
class Parser;
class Builder;
class DataDirectory;

namespace details {
struct pe_import;
}

//! Class that represents a PE import.
class LIEF_API Import : public Object {

  friend class Parser;
  friend class Builder;

  public:
  using entries_t        = std::vector<ImportEntry>;
  using it_entries       = ref_iterator<entries_t&>;
  using it_const_entries = const_ref_iterator<const entries_t&>;

  Import(const details::pe_import& import);
  Import(std::string name) :
    name_(std::move(name))
  {}
  Import() = default;
  ~Import() override = default;

  Import(const Import& other) = default;
  Import(Import&& other) noexcept = default;
  Import& operator=(Import&& other) noexcept = default;
  Import& operator=(const Import& other) = default;

  //! The index of the first forwarder reference
  uint32_t forwarder_chain() const {
    return forwarder_chain_;
  }

  //! The stamp that is set to zero until the image is bound.
  //! After the image is bound, this field is set to the time/data stamp of the DLL
  uint32_t timedatestamp() const {
    return timedatestamp_;
  }

  //! Iterator over the PE::ImportEntry
  it_const_entries entries() const {
    return entries_;
  }

  it_entries entries() {
    return entries_;
  }

  //! The RVA of the import address table (``IAT``). The content of this table is
  //! **identical** to the content of the Import Lookup Table (``ILT``) until the
  //! image is bound.
  //!
  //! @warning
  //! This address could change when re-building the binary
  uint32_t import_address_table_rva() const {
    return import_address_table_RVA_;
  }

  //! Return the relative virtual address of the import lookup table.
  //!
  //! @warning
  //! This address could change when re-building the binary
  uint32_t import_lookup_table_rva() const {
    return import_lookup_table_RVA_;
  }

  //! Return the Function's RVA from the import address table (`IAT`)
  //!
  //! @warning
  //! This address could change when re-building the binary
  result<uint32_t> get_function_rva_from_iat(const std::string& function) const;

  //! Return the imported function with the given name
  ImportEntry* get_entry(const std::string& name) {
    return const_cast<ImportEntry*>(static_cast<const Import*>(this)->get_entry(name));
  }
  const ImportEntry* get_entry(const std::string& name) const;

  //! Return the library's name (e.g. `kernel32.dll`)
  const std::string& name() const {
    return name_;
  }

  //! Change the current import name
  void name(std::string name) {
    name_ = std::move(name);
  }

  //! Return the PE::DataDirectory associated with this import.
  //! It should be the one at index PE::DataDirectory::TYPES::IMPORT_TABLE
  //!
  //! If the data directory can't be found, return a nullptr
  DataDirectory* directory() {
    return directory_;
  }
  const DataDirectory* directory() const {
    return directory_;
  }

  //! Return the PE::DataDirectory associated associated with the IAT.
  //! It should be the one at index PE::DataDirectory::TYPES::IAT
  //!
  //! If the data directory can't be found, return a nullptr
  DataDirectory* iat_directory() {
    return iat_directory_;
  }
  const DataDirectory* iat_directory() const {
    return iat_directory_;
  }

  //! Add a new import entry (i.e. an imported function)
  ImportEntry& add_entry(ImportEntry entry) {
    entries_.push_back(std::move(entry));
    return entries_.back();
  }

  //! Add a new import entry with the given name (i.e. an imported function)
  ImportEntry& add_entry(const std::string& name) {
    entries_.emplace_back(name);
    return entries_.back();
  }

  void import_lookup_table_rva(uint32_t rva) {
    import_lookup_table_RVA_ = rva;
  }
  void import_address_table_rva(uint32_t rva) {
    import_address_table_RVA_ = rva;
  }

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Import& entry);

  private:
  entries_t        entries_;
  DataDirectory*   directory_ = nullptr;
  DataDirectory*   iat_directory_ = nullptr;
  uint32_t         import_lookup_table_RVA_ = 0;
  uint32_t         timedatestamp_ = 0;
  uint32_t         forwarder_chain_ = 0;
  uint32_t         name_RVA_ = 0;
  uint32_t         import_address_table_RVA_ = 0;
  std::string      name_;
  PE_TYPE          type_ = PE_TYPE::PE32;
};

}
}

#endif
