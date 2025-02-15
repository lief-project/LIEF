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

#include "LIEF/PE/exceptions_info/UnwindCodeX64.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_unwind_x64_Code : public Mirror<LIEF::PE::unwind_x64::Code> {
  public:
  using lief_t = LIEF::PE::ExceptionInfo;
  using Mirror::Mirror;

  auto position() const {
    return get().position();
  }

  uint32_t opcode() const {
    return to_int(get().opcode());
  }

  std::string to_string() const {
    return get().to_string();
  }

};

class PE_unwind_x64_Alloc : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::Alloc;
  PE_unwind_x64_Alloc(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  auto size() const { return impl().size(); }

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_unwind_x64_PushNonVol : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::PushNonVol;
  PE_unwind_x64_PushNonVol(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  auto reg() const { return to_int(impl().reg()); }

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_unwind_x64_PushMachFrame : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::PushMachFrame;
  PE_unwind_x64_PushMachFrame(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  auto value() const { return impl().value(); }

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_unwind_x64_SetFPReg : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::SetFPReg;
  PE_unwind_x64_SetFPReg(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  auto reg() const { return to_int(impl().reg()); }

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_unwind_x64_SaveNonVolatile : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::SaveNonVolatile;
  PE_unwind_x64_SaveNonVolatile(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  auto reg() const { return to_int(impl().reg()); }
  auto offset() const { return impl().offset(); }

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_unwind_x64_SaveXMM128 : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::SaveXMM128;
  PE_unwind_x64_SaveXMM128(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  auto num() const { return impl().num(); }

  auto offset() const { return impl().offset(); }

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_unwind_x64_Epilog : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::Epilog;
  PE_unwind_x64_Epilog(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  auto flags() const { return impl().flags(); }

  auto size() const { return impl().size(); }

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_unwind_x64_Spare : public PE_unwind_x64_Code {
  public:
  using lief_t = LIEF::PE::unwind_x64::Spare;
  PE_unwind_x64_Spare(const lief_t& obj) : PE_unwind_x64_Code(obj) {}

  static bool classof(const PE_unwind_x64_Code& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
