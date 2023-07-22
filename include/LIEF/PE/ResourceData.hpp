/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#ifndef LIEF_PE_RESOURCE_DATA_H
#define LIEF_PE_RESOURCE_DATA_H

#include <vector>

#include "LIEF/visibility.h"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/span.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

//! Class which represents a Data Node in the PE resources tree
class LIEF_API ResourceData : public ResourceNode {

  friend class Parser;
  friend class Builder;

  public:
  ResourceData();
  ResourceData(std::vector<uint8_t> content, uint32_t code_page);

  ResourceData(const ResourceData& other);
  ResourceData& operator=(ResourceData other);
  void swap(ResourceData& other);

  ~ResourceData() override;

  std::unique_ptr<ResourceNode> clone() const override {
    return std::unique_ptr<ResourceNode>{new ResourceData{*this}};
  }

  //! Return the code page that is used to decode code point
  //! values within the resource data. Typically, the code page is the Unicode code page.
  uint32_t code_page() const;

  //! Resource content
  span<const uint8_t> content() const;
  span<uint8_t> content();

  //! Reserved value. Should be ``0``
  uint32_t reserved() const;

  //! Offset of the content within the resource
  //!
  //! @warning This value may change when rebuilding resource table
  uint32_t offset() const;

  void code_page(uint32_t code_page);
  void content(const std::vector<uint8_t>& content);
  void reserved(uint32_t value);

  static bool classof(const ResourceNode* node) {
    return node->is_data();
  }

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceData& data);

  private:
  std::vector<uint8_t> content_;
  uint32_t code_page_ = 0;
  uint32_t reserved_ = 0;
  uint32_t offset_ = 0;

};

} // namespace PE
} // namepsace LIEF
#endif /* RESOURCEDATA_H */
