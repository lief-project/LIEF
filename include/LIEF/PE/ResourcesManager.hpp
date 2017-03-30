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
#ifndef LIEF_PE_RESOURCES_MANAGER_H_
#define LIEF_PE_RESOURCES_MANAGER_H_
#include <iostream>
#include <sstream>

#include "LIEF/visibility.h"

#include "LIEF/PE/ResourceDirectory.hpp"

namespace LIEF {
namespace PE {
class DLL_PUBLIC ResourcesManager {
  public:
  ResourcesManager(void) = delete;
  ResourcesManager(ResourceNode *rsrc);

  ResourcesManager(const ResourcesManager&);
  ResourcesManager& operator=(const ResourcesManager&);
  ~ResourcesManager(void);


  ResourceDirectory* cursor(void);
  // bitmap(void);
  //
  std::string print(uint32_t depth = 0) const;

  DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const ResourcesManager& m);

  private:
  void print_tree(
      const ResourceNode& node,
      std::ostringstream& stream,
      uint32_t current_depth,
      uint32_t max_depth) const;
  ResourceNode *resources_;
};

} // namespace PE
} // namespace LIEF

#endif
