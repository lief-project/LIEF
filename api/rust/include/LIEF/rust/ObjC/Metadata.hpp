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
#include "LIEF/ObjC/Metadata.hpp"
#include "LIEF/rust/Mirror.hpp"

#include "LIEF/rust/ObjC/Class.hpp"
#include "LIEF/rust/ObjC/Protocol.hpp"

#include "LIEF/rust/Iterator.hpp"

class ObjC_Metadata : private Mirror<LIEF::objc::Metadata> {
  public:
  using lief_t = LIEF::objc::Metadata;
  using Mirror::Mirror;

  class it_classes :
      public ForwardIterator<ObjC_Class, LIEF::objc::Class::Iterator>
  {
    public:
    it_classes(const ObjC_Metadata::lief_t& src)
      : ForwardIterator(src.classes()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_protocols :
      public ForwardIterator<ObjC_Protocol, LIEF::objc::Protocol::Iterator>
  {
    public:
    it_protocols(const ObjC_Metadata::lief_t& src)
      : ForwardIterator(src.protocols()) { }
    auto next() { return ForwardIterator::next(); }
  };

  auto get_class(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ObjC_Class>(get().get_class(name));
  }

  auto get_protocol(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ObjC_Protocol>(get().get_protocol(name));
  }

  auto classes() const {
    return std::make_unique<it_classes>(get());
  }

  auto protocols() const {
    return std::make_unique<it_protocols>(get());
  }

  auto to_decl() const {
    return get().to_decl();
  }
};
