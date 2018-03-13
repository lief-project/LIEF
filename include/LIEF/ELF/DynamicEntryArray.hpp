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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_ARRAY_H_
#define LIEF_ELF_DYNAMIC_ENTRY_ARRAY_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {
class LIEF_API DynamicEntryArray : public DynamicEntry {

  public:
  using array_t = std::vector<uint64_t>;

  public:
  using DynamicEntry::DynamicEntry;

  DynamicEntryArray(void);
  DynamicEntryArray(DYNAMIC_TAGS tag, const array_t& array);

  DynamicEntryArray& operator=(const DynamicEntryArray&);
  DynamicEntryArray(const DynamicEntryArray&);

  array_t& array(void);
  const array_t& array(void) const;
  void array(const array_t& array);

  //! @brief Insert the given callback at ``pos``
  DynamicEntryArray& insert(size_t pos, uint64_t callback);

  //! @brief Append the given callback
  DynamicEntryArray& append(uint64_t callback);

  //! @brief Remove the given callback
  DynamicEntryArray& remove(uint64_t callback);

  //! @brief Number of callback registred
  size_t size(void) const;

  DynamicEntryArray& operator+=(uint64_t value);
  DynamicEntryArray& operator-=(uint64_t value);

  const uint64_t& operator[](size_t idx) const;
  uint64_t&       operator[](size_t idx);

  //! @brief Method so that the ``visitor`` can visit us
  virtual void accept(Visitor& visitor) const override;

  virtual std::ostream& print(std::ostream& os) const override;

  virtual ~DynamicEntryArray(void);

  private:
  array_t array_;

};
}
}

#endif
