/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/ObjC/Class.hpp"

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/ObjC/Method.hpp"
#include "LIEF/rust/ObjC/Protocol.hpp"
#include "LIEF/rust/ObjC/Property.hpp"
#include "LIEF/rust/ObjC/IVar.hpp"

#include "LIEF/rust/Iterator.hpp"

class ObjC_Class : private Mirror<LIEF::objc::Class> {
  public:
  using lief_t = LIEF::objc::Class;
  using Mirror::Mirror;

  class it_methods :
      public ForwardIterator<ObjC_Method, LIEF::objc::Method::Iterator>
  {
    public:
    it_methods(const ObjC_Class::lief_t& src)
      : ForwardIterator(src.methods()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_protocols :
      public ForwardIterator<ObjC_Protocol, LIEF::objc::Protocol::Iterator>
  {
    public:
    it_protocols(const ObjC_Class::lief_t& src)
      : ForwardIterator(src.protocols()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_properties :
      public ForwardIterator<ObjC_Property, LIEF::objc::Property::Iterator>
  {
    public:
    it_properties(const ObjC_Class::lief_t& src)
      : ForwardIterator(src.properties()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_ivars :
      public ForwardIterator<ObjC_IVar, LIEF::objc::IVar::Iterator>
  {
    public:
    it_ivars(const ObjC_Class::lief_t& src)
      : ForwardIterator(src.ivars()) { }
    auto next() { return ForwardIterator::next(); }
  };

  auto name() const { return get().name(); }
  auto demangled_name() const { return get().demangled_name(); }
  auto is_meta() const { return get().is_meta(); }

  auto super_class() const {
    return details::try_unique<ObjC_Class>(get().super_class());
  }

  auto methods() const { return std::make_unique<it_methods>(get()); }
  auto protocols() const { return std::make_unique<it_protocols>(get()); }
  auto properties() const { return std::make_unique<it_properties>(get()); }
  auto ivars() const { return std::make_unique<it_ivars>(get()); }

};
