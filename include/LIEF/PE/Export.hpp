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
#ifndef LIEF_PE_EXPORT_H_
#define LIEF_PE_EXPORT_H_

#include <iostream>
#include <string>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"

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

  Export();
  Export(const details::pe_export_directory_table& header);
  Export(const Export&);
  Export& operator=(const Export&);
  virtual ~Export();

  //! According to the PE specifications this value is reserved
  //! and should be set to 0
  uint32_t export_flags() const;

  //! The time and date that the export data was created
  uint32_t timestamp() const;

  //! The major version number (can be user-defined)
  uint16_t major_version() const;

  //! The minor version number (can be user-defined)
  uint16_t minor_version() const;

  //! The starting number for the exports. Usually this value is set
  //! to 1
  uint32_t ordinal_base() const;

  //! The name of the library exported (e.g. ``KERNEL32.dll``)
  const std::string& name() const;

  //! Iterator over the ExportEntry
  it_entries entries();
  it_const_entries entries() const;

  void export_flags(uint32_t flags);
  void timestamp(uint32_t timestamp);
  void major_version(uint16_t major_version);
  void minor_version(uint16_t minor_version);
  void ordinal_base(uint32_t ordinal_base);
  void name(const std::string& name);

  void accept(Visitor& visitor) const override;

  bool operator==(const Export& rhs) const;
  bool operator!=(const Export& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Export& exp);

  private:
  uint32_t    exportFlags_;
  uint32_t    timestamp_;
  uint16_t    majorVersion_;
  uint16_t    minorVersion_;
  uint32_t    ordinalBase_;
  std::string name_;
  entries_t   entries_;

};

}
}

#endif /* PE_EXPORT_H_ */
