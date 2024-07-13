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
#include "LIEF/PDB/types/ClassLike.hpp"

#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/PDB/Type.hpp"
#include "LIEF/rust/PDB/types/Attribute.hpp"
#include "LIEF/rust/PDB/types/Method.hpp"

class PDB_types_ClassLike : public PDB_Type {
  public:
  using lief_t = LIEF::pdb::types::ClassLike;

  class it_attributes :
      public ForwardIterator<PDB_types_Attribute, LIEF::pdb::types::Attribute::Iterator>
  {
    public:
    it_attributes(const PDB_types_ClassLike::lief_t& src)
      : ForwardIterator(src.attributes()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_methods :
      public ForwardIterator<PDB_types_Method, LIEF::pdb::types::Method::Iterator>
  {
    public:
    it_methods(const PDB_types_ClassLike::lief_t& src)
      : ForwardIterator(src.methods()) { }
    auto next() { return ForwardIterator::next(); }
  };

  auto name() const { return impl().name(); }
  auto unique_name() const { return impl().unique_name(); }
  auto size() const { return impl().size(); }

  auto attributes() const {
    return std::make_unique<it_attributes>(impl());
  }

  auto methods() const {
    return std::make_unique<it_methods>(impl());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};


class PDB_types_Class : public PDB_types_ClassLike {
  public:
  using lief_t = LIEF::pdb::types::Class;

  static bool classof(const PDB_Type& type) {
    return lief_t::classof(&type.get());
  }
};

class PDB_types_Structure : public PDB_types_ClassLike {
  public:
  using lief_t = LIEF::pdb::types::Structure;

  static bool classof(const PDB_Type& type) {
    return lief_t::classof(&type.get());
  }
};

class PDB_types_Interface : public PDB_types_ClassLike {
  public:
  using lief_t = LIEF::pdb::types::Interface;

  static bool classof(const PDB_Type& type) {
    return lief_t::classof(&type.get());
  }
};
