/* Copyright 2024 - 2025 R. Thomas
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
#pragma once
#include <cstdint>

#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/rust/PE/ResourceNode.hpp"
#include "LIEF/rust/Span.hpp"

class PE_ResourceData : public PE_ResourceNode {
  public:
  using lief_t = LIEF::PE::ResourceData;
  PE_ResourceData(const lief_t& obj) : PE_ResourceNode(obj) {}
  PE_ResourceData(std::unique_ptr<lief_t> obj) : PE_ResourceNode(std::move(obj)) {}

  static auto create_from_data(const uint8_t* buffer, size_t size) {
    return std::make_unique<PE_ResourceData>(
      std::make_unique<lief_t>(std::vector<uint8_t>{buffer, buffer + size}));
  }

  static auto create() {
    return std::make_unique<PE_ResourceData>(std::make_unique<lief_t>());
  }


  auto code_page() const { return impl().code_page(); }
  auto reserved() const { return impl().reserved(); }
  auto offset() const { return impl().offset(); }

  auto content() const {
    return make_span(impl().content());
  }

  void set_code_page(uint32_t value) {
    impl().code_page(value);
  }

  void set_reserved(uint32_t value) {
    impl().reserved(value);
  }

  void set_content(const uint8_t* ptr, size_t size) {
    impl().content(ptr, size);
  }

  static bool classof(const PE_ResourceNode& node) {
    return lief_t::classof(&node.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
  lief_t& impl() { return as<lief_t>(this); }
};
