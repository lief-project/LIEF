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

#include "LIEF/rust/PE/ExceptionInfo.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"
#include "LIEF/rust/Iterator.hpp"

#include "LIEF/PE/exceptions_info/RuntimeFunctionAArch64.hpp"
#include "LIEF/PE/exceptions_info/AArch64/PackedFunction.hpp"
#include "LIEF/PE/exceptions_info/AArch64/UnpackedFunction.hpp"

class PE_RuntimeFunctionAArch64 : public PE_ExceptionInfo {
  public:
  using lief_t = LIEF::PE::RuntimeFunctionAArch64;
  PE_RuntimeFunctionAArch64(const lief_t& obj) : PE_ExceptionInfo(obj) {}

  auto length() const { return impl().length(); }
  auto flag() const { return to_int(impl().flag()); }
  auto rva_end() const { return impl().rva_end(); }

  static bool classof(const PE_ExceptionInfo& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }

};

class PE_unwind_aarch64_PackedFunction : public PE_RuntimeFunctionAArch64 {
  public:
  using lief_t = LIEF::PE::unwind_aarch64::PackedFunction;

  auto frame_size() const { return impl().frame_size(); }
  auto reg_I() const { return impl().reg_I(); }
  auto reg_F() const { return impl().reg_F(); }
  auto H() const { return impl().H(); }
  auto CR() const { return impl().CR(); }

  static bool classof(const PE_RuntimeFunctionAArch64& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};


class PE_unwind_aarch64_UnpackedFunction_epilog_scope_t :
  public Mirror<LIEF::PE::unwind_aarch64::UnpackedFunction::epilog_scope_t>
{
  public:
  using lief_t = LIEF::PE::unwind_aarch64::UnpackedFunction::epilog_scope_t;
  using Mirror::Mirror;

  auto start_offset() const { return get().start_offset; }
  auto start_index() const { return get().start_index; }
  auto reserved() const { return get().reserved; }
};

class PE_unwind_aarch64_UnpackedFunction : public PE_RuntimeFunctionAArch64 {
  public:
  using lief_t = LIEF::PE::unwind_aarch64::UnpackedFunction;

  class it_const_epilog_scopes :
      public Iterator<PE_unwind_aarch64_UnpackedFunction_epilog_scope_t,
                      LIEF::PE::unwind_aarch64::UnpackedFunction::it_const_epilog_scopes>
  {
    public:
    it_const_epilog_scopes(const PE_unwind_aarch64_UnpackedFunction::lief_t& src)
      : Iterator(std::move(src.epilog_scopes())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };


  auto xdata_rva() const { return impl().xdata_rva(); }
  auto version() const { return impl().version(); }
  auto X() const { return impl().X(); }
  auto E() const { return impl().E(); }
  auto epilog_count() const { return impl().epilog_count(); }
  auto epilog_offset() const { return impl().epilog_offset(); }
  auto code_words() const { return impl().code_words(); }
  auto exception_handler() const { return impl().exception_handler(); }
  auto unwind_code() const { return make_span(impl().unwind_code()); }

  auto epilog_scopes() const {
    return std::make_unique<it_const_epilog_scopes>(impl());
  }

  static bool classof(const PE_RuntimeFunctionAArch64& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
