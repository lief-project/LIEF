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
#include "LIEF/ObjC/Protocol.hpp"

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"

#include "LIEF/rust/ObjC/Method.hpp"
#include "LIEF/rust/ObjC/Property.hpp"

class ObjC_Protocol : private Mirror<LIEF::objc::Protocol> {
  public:
  using lief_t = LIEF::objc::Protocol;
  using Mirror::Mirror;

  class it_opt_methods :
      public ForwardIterator<ObjC_Method, LIEF::objc::Method::Iterator>
  {
    public:
    it_opt_methods(const ObjC_Protocol::lief_t& src)
      : ForwardIterator(src.optional_methods()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_req_methods :
      public ForwardIterator<ObjC_Method, LIEF::objc::Method::Iterator>
  {
    public:
    it_req_methods(const ObjC_Protocol::lief_t& src)
      : ForwardIterator(src.required_methods()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_properties :
      public ForwardIterator<ObjC_Property, LIEF::objc::Property::Iterator>
  {
    public:
    it_properties(const ObjC_Protocol::lief_t& src)
      : ForwardIterator(src.properties()) { }
    auto next() { return ForwardIterator::next(); }
  };

  auto mangled_name() const { return get().mangled_name(); }

  auto optional_methods() const {
    return std::make_unique<it_opt_methods>(get());
  }

  auto required_methods() const {
    return std::make_unique<it_req_methods>(get());
  }

  auto properties() const {
    return std::make_unique<it_properties>(get());
  }
};
