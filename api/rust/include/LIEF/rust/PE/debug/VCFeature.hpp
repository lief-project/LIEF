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
#include "LIEF/rust/PE/debug/Debug.hpp"
#include "LIEF/PE/debug/VCFeature.hpp"

class PE_VCFeature : public PE_Debug {
  public:
  using lief_t = LIEF::PE::VCFeature;
  PE_VCFeature(const lief_t& obj) : PE_Debug(obj) {}

  auto pre_vcpp() const { return impl().pre_vcpp(); }
  auto c_cpp() const { return impl().c_cpp(); }
  auto gs() const { return impl().gs(); }
  auto sdl() const { return impl().sdl(); }
  auto guards() const { return impl().guards(); }

  static bool classof(const PE_Debug& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
