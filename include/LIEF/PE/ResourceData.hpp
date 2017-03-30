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

class DLL_PUBLIC ResourceData : public ResourceNode {

  friend class Parser;
  friend class Builder;

  public:
    ResourceData(void);
    ResourceData(const std::vector<uint8_t>& content, uint32_t codePage);
    ResourceData(const ResourceData&);
    ResourceData& operator=(const ResourceData&);
    virtual ~ResourceData(void);

    uint32_t                    code_page(void) const;
    const std::vector<uint8_t>& content(void) const;

    void code_page(uint32_t codePage);
    void content(const std::vector<uint8_t>& content);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const ResourceData& rhs) const;
    bool operator!=(const ResourceData& rhs) const;

  private:
    std::vector<uint8_t> content_;
    uint32_t             codePage_;

};

} // namespace PE
} // namepsace LIEF
#endif /* RESOURCEDATA_H_ */
