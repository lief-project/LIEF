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
#ifndef ELF_DATA_HANDLER_HANDLER_H_
#define ELF_DATA_HANDLER_HANDLER_H_

#include "LIEF/ELF/DataHandler/Node.hpp"
#include "LIEF/visibility.h"
#include "LIEF/utils.hpp"
#include <vector>

namespace LIEF {
namespace ELF {
namespace DataHandler {
class LIEF_API Handler {
  public:
    static constexpr size_t MAX_SIZE = 1_GB;
    Handler(const std::vector<uint8_t>& content);
    Handler(std::vector<uint8_t>&& content);
    ~Handler(void);

    Handler& operator=(const Handler&);
    Handler(const Handler&);

    const std::vector<uint8_t>& content(void) const;
    std::vector<uint8_t>& content(void);

    Node& add(const Node& node);

    bool has(uint64_t offset, uint64_t size, Node::Type type);

    Node& get(uint64_t offset, uint64_t size, Node::Type type);

    Node& create(uint64_t offset, uint64_t size, Node::Type type);

    void remove(uint64_t offset, uint64_t size, Node::Type type);

    void make_hole(uint64_t offset, uint64_t size);

    void reserve(uint64_t offset, uint64_t size);

  private:
    Handler(void);
    std::vector<uint8_t> data_;
    std::vector<Node*>   nodes_;
};
} // namespace DataHandler
} // namespace ELF
} // namespace LIEF

#endif
