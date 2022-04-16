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
#ifndef LIEF_MACHO_TWO_LEVEL_HINTS_H
#define LIEF_MACHO_TWO_LEVEL_HINTS_H
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/span.hpp"
#include "LIEF/iterators.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class Builder;
class LinkEdit;

namespace details {
struct twolevel_hints_command;
}

//! Class which represents the `LC_TWOLEVEL_HINTS` command
class LIEF_API TwoLevelHints : public LoadCommand {
  friend class BinaryParser;
  friend class LinkEdit;
  friend class Builder;

  public:
  using hints_list_t     = std::vector<uint32_t>;
  using it_hints_t       = ref_iterator<hints_list_t&>;
  using it_const_hints_t = const_ref_iterator<const hints_list_t&>;

  TwoLevelHints();
  TwoLevelHints(const details::twolevel_hints_command& cmd);

  TwoLevelHints& operator=(const TwoLevelHints& copy);
  TwoLevelHints(const TwoLevelHints& copy);

  TwoLevelHints* clone() const override;

  //! Original payload of the command
  inline span<const uint8_t> content() const { return content_; }
  inline span<uint8_t> content() { return content_; }

  //! Iterator over the hints (`uint32_t` integers)
  it_hints_t hints() { return hints_; }
  it_const_hints_t hints() const { return hints_; }

  //! Original offset of the command. It should point in the
  //! `__LINKEDIT` segment
  inline uint32_t offset() const { return offset_; }
  inline void offset(uint32_t offset)  { offset_ = offset; }

  inline uint32_t original_nb_hints() const {
    return original_nb_hints_;
  }

  ~TwoLevelHints() override;

  bool operator==(const TwoLevelHints& rhs) const;
  bool operator!=(const TwoLevelHints& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  uint32_t offset_ = 0;
  hints_list_t hints_;
  span<uint8_t> content_;
  uint32_t original_nb_hints_ = 0;
};

}
}
#endif
