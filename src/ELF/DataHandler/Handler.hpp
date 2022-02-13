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
#ifndef ELF_DATA_HANDLER_HANDLER_H_
#define ELF_DATA_HANDLER_HANDLER_H_
#include <vector>

#include "LIEF/visibility.h"
#include "LIEF/utils.hpp"
#include "LIEF/errors.hpp"

#include "ELF/DataHandler/Node.hpp"

namespace LIEF {
class BinaryStream;
namespace ELF {
namespace DataHandler {

class LIEF_API Handler {
  public:
  static constexpr size_t MAX_SIZE = 4_GB;
  Handler(std::vector<uint8_t> content);
  Handler(std::vector<uint8_t>&& content);
  ~Handler();

  // This class should not be implicitly copied as it might
  // have a huge impact on the performances
  Handler& operator=(const Handler&) = delete;
  Handler(const Handler&) = delete;

  Handler& operator=(Handler&&);
  Handler(Handler&&);

  const std::vector<uint8_t>& content() const;
  std::vector<uint8_t>& content();

  Node& add(const Node& node);

  bool has(uint64_t offset, uint64_t size, Node::Type type);

  result<Node&> get(uint64_t offset, uint64_t size, Node::Type type);

  Node& create(uint64_t offset, uint64_t size, Node::Type type);

  void remove(uint64_t offset, uint64_t size, Node::Type type);

  ok_error_t make_hole(uint64_t offset, uint64_t size);

  ok_error_t reserve(uint64_t offset, uint64_t size);

  static result<std::unique_ptr<Handler>> from_stream(std::unique_ptr<BinaryStream>& stream);

  private:
  Handler();
  Handler(BinaryStream& stream);
  std::vector<uint8_t> data_;
  std::vector<std::unique_ptr<Node>> nodes_;
};
} // namespace DataHandler
} // namespace ELF
} // namespace LIEF

#endif
