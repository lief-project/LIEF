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
#ifndef LIEF_MACHO_DATA_IN_CODE_COMMAND_H_
#define LIEF_MACHO_DATA_IN_CODE_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/iterators.hpp"
#include "LIEF/span.hpp"

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/DataCodeEntry.hpp"

namespace LIEF {
namespace MachO {
class BinaryParser;
class LinkEdit;

namespace details {
struct linkedit_data_command;
}

//! Interface of the LC_DATA_IN_CODE command
//! This command is used to list slices of code sections that contain data. The *slices*
//! information are stored as an array of DataCodeEntry
//!
//! @see DataCodeEntry
class LIEF_API DataInCode : public LoadCommand {
  friend class BinaryParser;
  friend class LinkEdit;
  public:
  using entries_t        = std::vector<DataCodeEntry>;
  using it_const_entries = const_ref_iterator<const entries_t&>;
  using it_entries       = ref_iterator<entries_t&>;

  public:
  DataInCode();
  DataInCode(const details::linkedit_data_command& cmd);

  DataInCode& operator=(const DataInCode&);
  DataInCode(const DataInCode&);

  DataInCode* clone() const override;

  //! Start of the array of the DataCodeEntry entries
  uint32_t data_offset() const;

  //! Whole size of the array (``size = sizeof(DataCodeEntry) * nb_elements``)
  uint32_t data_size() const;

  void data_offset(uint32_t offset);
  void data_size(uint32_t size);

  //! Add a new entry
  DataInCode& add(const DataCodeEntry& entry);

  //! Iterator over the DataCodeEntry
  it_const_entries entries() const;
  it_entries entries();

  inline span<uint8_t> content() {
    return content_;
  }

  inline span<const uint8_t> content() const {
    return content_;
  }

  virtual ~DataInCode();

  bool operator==(const DataInCode& rhs) const;
  bool operator!=(const DataInCode& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  uint32_t  data_offset_ = 0;
  uint32_t  data_size_   = 0;
  entries_t entries_;
  span<uint8_t> content_;

};

}
}
#endif
