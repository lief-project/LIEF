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
#ifndef LIEF_PE_RESOURCE_NODE_H_
#define LIEF_PE_RESOURCE_NODE_H_

#include <string>
#include <vector>
#include <memory>

#include "LIEF/Visitable.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {

enum class RESOURCE_NODE_TYPES : uint8_t {
  DIRECTORY = 0,
  DATA
};

class Parser;
class Builder;

class DLL_PUBLIC ResourceNode : public Visitable {

  friend class Parser;
  friend class Builder;

  public:
  ResourceNode(void);
  ResourceNode(const ResourceNode& other);
  ResourceNode& operator=(const ResourceNode& other);
  virtual ~ResourceNode(void);

  RESOURCE_NODE_TYPES               type(void) const;
  uint32_t                          id(void) const;
  const std::u16string&             name(void) const;
  std::vector<ResourceNode*>&       childs(void);
  const std::vector<ResourceNode*>& childs(void) const;
  bool                              has_name(void) const;

  void add_child(ResourceNode* child);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceNode& rhs) const;
  bool operator!=(const ResourceNode& rhs) const;

  protected:
  RESOURCE_NODE_TYPES        type_;
  uint32_t                   id_;
  std::u16string             name_;
  std::vector<ResourceNode*> childs_;
};
}
}
#endif /* RESOURCENODE_H_ */
