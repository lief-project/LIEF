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
#ifndef LIEF_PE_EXPORT_H
#define LIEF_PE_EXPORT_H

#include <ostream>
#include <string>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"
#include "LIEF/PE/ExportEntry.hpp"

namespace LIEF {
namespace PE {

class Builder;
class Parser;

namespace details {
struct pe_export_directory_table;
}

//! Class which represents a PE Export
class LIEF_API Export : public Object {
  friend class Builder;
  friend class Parser;

  public:
  using entries_t        = std::vector<ExportEntry>;
  using it_entries       = ref_iterator<entries_t&>;
  using it_const_entries = const_ref_iterator<const entries_t&>;

  Export() = default;
  Export(const details::pe_export_directory_table& header);
  Export(const Export&) = default;
  Export& operator=(const Export&) = default;
  ~Export() override = default;

  //! According to the PE specifications this value is reserved
  //! and should be set to 0
  uint32_t export_flags() const {
    return export_flags_;
  }

  //! The time and date that the export data was created
  uint32_t timestamp() const {
    return timestamp_;
  }

  //! The major version number (can be user-defined)
  uint16_t major_version() const {
    return major_version_;
  }

  //! The minor version number (can be user-defined)
  uint16_t minor_version() const {
    return minor_version_;
  }

  //! The starting number for the exports. Usually this value is set to 1
  uint32_t ordinal_base() const {
    return ordinal_base_;
  }

  //! The name of the library exported (e.g. `KERNEL32.dll`)
  const std::string& name() const {
    return name_;
  }

  //! Iterator over the ExportEntry
  it_entries entries() {
    return entries_;
  }

  it_const_entries entries() const {
    return entries_;
  }

  void export_flags(uint32_t flags) {
    export_flags_ = flags;
  }
  void timestamp(uint32_t timestamp) {
    timestamp_ = timestamp;
  }

  void major_version(uint16_t major_version) {
    major_version_ = major_version;
  }

  void minor_version(uint16_t minor_version) {
    minor_version_ = minor_version;
  }
  void ordinal_base(uint32_t ordinal_base) {
    ordinal_base_ = ordinal_base;
  }

  void name(std::string name) {
    name_ = std::move(name);
  }

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Export& exp);

  private:
  uint32_t export_flags_ = 0;
  uint32_t timestamp_ = 0;
  uint16_t major_version_ = 0;
  uint16_t minor_version_ = 0;
  uint32_t ordinal_base_ = 0;
  entries_t entries_;
  std::string name_;

};

}
}

#endif /* PE_EXPORT_H */
