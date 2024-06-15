/* Copyright 2024 R. Thomas
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
#include <memory>

#include "LIEF/rust/PE/debug/Debug.hpp"
#include "LIEF/rust/PE/debug/PogoEntry.hpp"
#include "LIEF/rust/Iterator.hpp"

#include "LIEF/PE/debug/Pogo.hpp"

class PE_Pogo : public PE_Debug {
  public:
  using lief_t = LIEF::PE::Pogo;
  class it_entries :
      public Iterator<PE_PogoEntry, LIEF::PE::Pogo::it_const_entries>
  {
    public:
    it_entries(const PE_Pogo::lief_t& src)
      : Iterator(std::move(src.entries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto entries() const {
    return std::make_unique<it_entries>(impl());
  }

  static bool classof(const PE_Debug& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
