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
#ifndef LIEF_PE_RESOURCE_ACCELERATOR_H_
#define LIEF_PE_RESOURCE_ACCELERATOR_H_

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/type_traits.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;

class LIEF_API ResourceAccelerator : public Object {

  friend class ResourcesManager;

  public:
  ResourceAccelerator(void);
  explicit ResourceAccelerator(const pe_resource_acceltableentry*);

  ResourceAccelerator(const ResourceAccelerator&);
  ResourceAccelerator& operator=(const ResourceAccelerator&);

  virtual ~ResourceAccelerator(void);

  std::set<ACCELERATOR_FLAGS> flags_list() const;
  std::string ansi_str() const;

  int16_t flags(void) const;
  int16_t ansi(void) const;
  uint16_t id(void) const;
  int16_t padding(void) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceAccelerator& rhs) const;
  bool operator!=(const ResourceAccelerator& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceAccelerator& acc);

  private:
  int16_t flags_;
  int16_t ansi_;
  uint16_t id_;
  int16_t padding_;

};

}
}

#endif