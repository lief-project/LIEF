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

#include "LIEF/rust/Abstract/Symbol.hpp"
#include "LIEF/PE/ExportEntry.hpp"

class PE_ExportEntry : public AbstractSymbol {
  public:
  using lief_t = LIEF::PE::ExportEntry;
  PE_ExportEntry(const lief_t& info) : AbstractSymbol(info) {}
  PE_ExportEntry(std::unique_ptr<lief_t> impl) : AbstractSymbol(std::move(impl)) {}

  static auto create() {
    return std::make_unique<PE_ExportEntry>(std::make_unique<lief_t>());
  }

  static auto create_with_name(std::string name, uint32_t addr) {
    return std::make_unique<PE_ExportEntry>(
      std::make_unique<lief_t>(std::move(name), addr));
  }

  auto ordinal() const { return impl().ordinal(); }
  auto address() const { return impl().address(); }
  auto is_extern() const { return impl().is_extern(); }
  auto is_forwarded() const { return impl().is_forwarded(); }
  auto function_rva() const { return impl().function_rva();}

  auto fwd_library() const { return impl().forward_information().library; }
  auto fwd_function() const { return impl().forward_information().function; }

  void set_ordinal(uint16_t ordinal) { impl().ordinal(ordinal); }
  void set_address(uint32_t addr) { impl().address(addr); }

  auto demangled_name() const { return impl().demangled_name(); }
  private:
  const lief_t& impl() const { return as<lief_t>(this); }
  lief_t& impl() { return as<lief_t>(this); }
};
