/* Copyright 2024 - 2026 R. Thomas
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
#include "LIEF/rust/ELF/Note.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/ELF/NoteDetails/NoteGnuProperty.hpp"

#include "LIEF/ELF/NoteDetails/properties/AArch64Feature.hpp"
#include "LIEF/ELF/NoteDetails/properties/AArch64PAuth.hpp"
#include "LIEF/ELF/NoteDetails/properties/Needed.hpp"
#include "LIEF/ELF/NoteDetails/properties/NoteNoCopyOnProtected.hpp"
#include "LIEF/ELF/NoteDetails/properties/X86ISA.hpp"
#include "LIEF/ELF/NoteDetails/properties/StackSize.hpp"
#include "LIEF/ELF/NoteDetails/properties/X86Feature.hpp"
#include "LIEF/ELF/NoteDetails/properties/Generic.hpp"

class ELF_NoteGnuProperty_Property
  : public Mirror<LIEF::ELF::NoteGnuProperty::Property> {
  public:
  using lief_t = LIEF::ELF::NoteGnuProperty::Property;
  using Mirror::Mirror;

  auto get_type() const {
    return to_int(get().type());
  }
};

class ELF_NoteGnuProperty_AArch64Feature : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::AArch64Feature;
  ELF_NoteGnuProperty_AArch64Feature(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const ELF_NoteGnuProperty_Property::lief_t&>(impl)
    ) {}

  auto features() const {
    return to_vector(as<lief_t>(this).features());
  }

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty_AArch64PAuth : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::AArch64PAuth;
  ELF_NoteGnuProperty_AArch64PAuth(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const ELF_NoteGnuProperty_Property::lief_t&>(impl)
    ) {}

  auto platform() const {
    return as<lief_t>(this).platform();
  }

  auto version() const {
    return as<lief_t>(this).version();
  }

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty_Generic : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::Generic;
  ELF_NoteGnuProperty_Generic(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const ELF_NoteGnuProperty_Property::lief_t&>(impl)
    ) {}

  auto raw_type() const {
    return as<lief_t>(this).type();
  }

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty_Needed : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::Needed;
  ELF_NoteGnuProperty_Needed(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const ELF_NoteGnuProperty_Property::lief_t&>(impl)
    ) {}

  auto needs() const {
    return to_vector(as<lief_t>(this).needs());
  }

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty_NoteNoCopyOnProtected
  : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::NoteNoCopyOnProtected;
  ELF_NoteGnuProperty_NoteNoCopyOnProtected(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const ELF_NoteGnuProperty_Property::lief_t&>(impl)
    ) {}

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty_StackSize : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::StackSize;
  ELF_NoteGnuProperty_StackSize(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const ELF_NoteGnuProperty_Property::lief_t&>(impl)
    ) {}

  auto stack_size() const {
    return as<lief_t>(this).stack_size();
  }

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty_X86Features : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::X86Features;
  ELF_NoteGnuProperty_X86Features(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const ELF_NoteGnuProperty_Property::lief_t&>(impl)
    ) {}

  // Returns pairs of (flag, feature) as a flat vector: [flag0, feat0, flag1,
  // feat1, ...]
  auto features() const {
    std::vector<uint64_t> result;
    for (const auto& [f, feat] : as<lief_t>(this).features()) {
      result.push_back((uint64_t)f);
      result.push_back((uint64_t)feat);
    }
    return result;
  }

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty_X86ISA : public ELF_NoteGnuProperty_Property {
  public:
  using lief_t = LIEF::ELF::X86ISA;
  ELF_NoteGnuProperty_X86ISA(const lief_t& impl) :
    ELF_NoteGnuProperty_Property(
        static_cast<const LIEF::ELF::NoteGnuProperty::Property&>(impl)
    ) {}

  // Returns pairs of (flag, isa) as a flat vector: [flag0, isa0, flag1, isa1, ...]
  auto values() const {
    std::vector<uint64_t> result;
    for (const auto& [f, isa] : as<lief_t>(this).values()) {
      result.push_back((uint64_t)f);
      result.push_back((uint64_t)isa);
    }
    return result;
  }

  static bool classof(const ELF_NoteGnuProperty_Property& prop) {
    return lief_t::classof(&prop.get());
  }
};

class ELF_NoteGnuProperty : public ELF_Note {
  public:
  using lief_t = LIEF::ELF::NoteGnuProperty;

  class it_properties : public ContainerIterator<ELF_NoteGnuProperty_Property,
                                                 lief_t::properties_t> {
    public:
    it_properties(const lief_t& src) :
      ContainerIterator(src.properties()) {}
    auto next() {
      return ContainerIterator::next();
    }
    auto size() const {
      return ContainerIterator::size();
    }
  };

  ELF_NoteGnuProperty(const lief_t& impl) :
    ELF_Note(static_cast<const ELF_Note::lief_t&>(impl)) {}

  auto properties() const {
    return std::make_unique<it_properties>(impl());
  }

  auto find(uint32_t type) const {
    return details::try_unique<ELF_NoteGnuProperty_Property>(
        impl().find((lief_t::Property::TYPE)type)
    );
  }

  static bool classof(const ELF_Note& note) {
    return lief_t::classof(&note.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
