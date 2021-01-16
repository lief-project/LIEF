/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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
#ifndef LIEF_PE_RESOURCE_STRING_TABLE_H_
#define LIEF_PE_RESOURCE_STRING_TABLE_H_
#include <string>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/type_traits.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;

class LIEF_API ResourceStringTable : public Object {

  friend class ResourcesManager;
  public:
  ResourceStringTable(void);

  ResourceStringTable(int16_t length, const std::u16string& name);
  ResourceStringTable(const ResourceStringTable&);

  ResourceStringTable& operator=(const ResourceStringTable&);

  virtual ~ResourceStringTable(void);

  virtual void accept(Visitor& visitor) const override;

  int16_t length(void) const;
  const std::u16string& name(void) const;

  bool operator==(const ResourceStringTable& rhs) const;
  bool operator!=(const ResourceStringTable& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceStringTable& string_table);

  private:
  std::u16string name_;
  int16_t length_;
};

}
}

#endif