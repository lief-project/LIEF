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
#ifndef LIEF_PE_RESOURCE_DATA_H_
#define LIEF_PE_RESOURCE_DATA_H_

#include <vector>

#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/ResourceNode.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

class LIEF_API ResourceData : public ResourceNode {

  friend class Parser;
  friend class Builder;

  public:
  ResourceData(void);
  ResourceData(const std::vector<uint8_t>& content, uint32_t code_page);

  ResourceData(const ResourceData& other);
  ResourceData& operator=(ResourceData other);
  void swap(ResourceData& other);

  virtual ~ResourceData(void);

  virtual ResourceData* clone(void) const override;

  //! @brief The code page that is used to decode code point
  //! values within the resource data. Typically, the code
  //! page would be the Unicode code page.
  uint32_t code_page(void) const;

  //! @brief Resource content
  const std::vector<uint8_t>& content(void) const;

  //! @brief Reserved value. Should be ``0``
  uint32_t reserved(void) const;

  //! @brief Offset of the content within the resource
  //!
  //! @warning This value may change when rebuilding
  //! resource table
  uint32_t offset(void) const;

  void code_page(uint32_t code_page);
  void content(const std::vector<uint8_t>& content);
  void reserved(uint32_t value);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceData& rhs) const;
  bool operator!=(const ResourceData& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceData& data);

  private:
  std::vector<uint8_t> content_;
  uint32_t             code_page_;
  uint32_t             reserved_;
  uint32_t             offset_;

};

} // namespace PE
} // namepsace LIEF
#endif /* RESOURCEDATA_H_ */
