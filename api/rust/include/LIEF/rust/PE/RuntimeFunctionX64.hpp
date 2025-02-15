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

#include "LIEF/PE/exceptions_info/RuntimeFunctionX64.hpp"
#include "LIEF/rust/PE/ExceptionInfo.hpp"
#include "LIEF/rust/PE/UnwindCodeX64.hpp"
#include "LIEF/rust/Span.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/optional.hpp"

class PE_RuntimeFunctionX64_unwind_info_t;

class PE_RuntimeFunctionX64 : public PE_ExceptionInfo {
  public:
  using lief_t = LIEF::PE::RuntimeFunctionX64;
  PE_RuntimeFunctionX64(const lief_t& obj) : PE_ExceptionInfo(obj) {}

  auto rva_end() const {
    return impl().rva_end();
  }

  auto unwind_rva() const {
    return impl().unwind_rva();
  }

  auto size() const {
    return impl().size();
  }

  auto unwind_info() const {
    return details::try_unique<PE_RuntimeFunctionX64_unwind_info_t>(impl().unwind_info());
  }

  static bool classof(const PE_ExceptionInfo& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_RuntimeFunctionX64_unwind_info_t :
  public Mirror<LIEF::PE::RuntimeFunctionX64::unwind_info_t>
{
  public:
  using lief_t = LIEF::PE::RuntimeFunctionX64::unwind_info_t;
  using Mirror::Mirror;

  class it_opcodes :
      public ContainerIterator<
        PE_unwind_x64_Code, std::vector<std::unique_ptr<LIEF::PE::unwind_x64::Code>>>
  {
    public:
    using container_t = std::vector<std::unique_ptr<LIEF::PE::unwind_x64::Code>>;
    it_opcodes(container_t content)
      : ContainerIterator(std::move(content)) { }
    auto next() { return ContainerIterator::next(); }
  };

  auto version() const { return get().version; }

  auto flags() const { return get().flags; }

  auto sizeof_prologue() const { return get().sizeof_prologue; }

  auto count_opcodes() const { return get().count_opcodes; }

  auto frame_reg() const { return get().frame_reg; }

  auto frame_reg_offset() const { return get().frame_reg_offset; }
  auto raw_opcodes() const { return make_span(get().raw_opcodes); }

  uint32_t handler(uint32_t& is_set) const {
    return details::make_optional(get().handler, is_set);
  }

  auto opcodes() const {
    it_opcodes::container_t ops = get().opcodes();
    return std::make_unique<it_opcodes>(std::move(ops));
  }

  auto chained() const {
    return details::try_unique<PE_RuntimeFunctionX64>(get().chained);
  }

  std::string to_string() const {
    return get().to_string();
  }



};
