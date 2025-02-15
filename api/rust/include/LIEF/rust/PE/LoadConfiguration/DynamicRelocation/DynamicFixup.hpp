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

#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixup.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupARM64Kernel.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupARM64X.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupControlTransfer.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupGeneric.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicFixupUnknown.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/FunctionOverride.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/FunctionOverrideInfo.hpp"

#include "LIEF/rust/PE/Relocation.hpp"

#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class PE_DynamicFixup : public Mirror<LIEF::PE::DynamicFixup> {
  public:
  using lief_t = LIEF::PE::DynamicFixup;
  using Mirror::Mirror;

  std::string to_string() const {
    return get().to_string();
  }
};

class PE_DynamicFixupARM64Kernel_entry :
  private Mirror<LIEF::PE::DynamicFixupARM64Kernel::reloc_entry_t>
{
  public:
  using lief_t = LIEF::PE::DynamicFixupARM64Kernel::reloc_entry_t;
  using Mirror::Mirror;

  auto rva() const { return get().rva; }
  auto indirect_call() const { return get().indirect_call; }
  auto register_index() const { return get().register_index; }
  uint8_t import_type() const { return to_int(get().import_type); }
  auto iat_index() const { return get().iat_index; }
  std::string to_string() const { return get().to_string(); }
};

class PE_DynamicFixupARM64Kernel : public PE_DynamicFixup {
  public:
  using lief_t = LIEF::PE::DynamicFixupARM64Kernel;

  class it_relocations :
      public Iterator<PE_DynamicFixupARM64Kernel_entry, LIEF::PE::DynamicFixupARM64Kernel::it_const_relocations>
  {
    public:
    it_relocations(const PE_DynamicFixupARM64Kernel::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto relocations() const {
    return std::make_unique<it_relocations>(impl());
  }

  static bool classof(const PE_DynamicFixup* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_DynamicFixupARM64X_entry :
  private Mirror<LIEF::PE::DynamicFixupARM64X::reloc_entry_t>
{
  public:
  using lief_t = LIEF::PE::DynamicFixupARM64X::reloc_entry_t;
  using Mirror::Mirror;

  auto rva() const { return get().rva; }
  auto value() const { return get().value; }
  uint32_t size() const { return get().size; }
  auto get_type() const { return to_int(get().type); }
  auto get_bytes() const { return make_span(get().bytes); }
  std::string to_string() const { return get().to_string(); }
};

class PE_DynamicFixupARM64X : public PE_DynamicFixup {
  public:
  using lief_t = LIEF::PE::DynamicFixupARM64X;

  class it_relocations :
      public Iterator<PE_DynamicFixupARM64X_entry, LIEF::PE::DynamicFixupARM64X::it_const_relocations>
  {
    public:
    it_relocations(const PE_DynamicFixupARM64X::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto relocations() const {
    return std::make_unique<it_relocations>(impl());
  }

  static bool classof(const PE_DynamicFixup* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};


class PE_DynamicFixupControlTransfer_entry :
  private Mirror<LIEF::PE::DynamicFixupControlTransfer::reloc_entry_t>
{
  public:
  using lief_t = LIEF::PE::DynamicFixupControlTransfer::reloc_entry_t;
  using Mirror::Mirror;

  auto rva() const { return get().rva; }
  auto is_call() const { return get().is_call; }
  auto iat_index() const { return get().iat_index; }
  std::string to_string() const { return get().to_string(); }
};

class PE_DynamicFixupControlTransfer : public PE_DynamicFixup {
  public:
  using lief_t = LIEF::PE::DynamicFixupControlTransfer;

  class it_relocations :
      public Iterator<PE_DynamicFixupControlTransfer_entry, LIEF::PE::DynamicFixupControlTransfer::it_const_relocations>
  {
    public:
    it_relocations(const PE_DynamicFixupControlTransfer::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto relocations() const {
    return std::make_unique<it_relocations>(impl());
  }

  static bool classof(const PE_DynamicFixup* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_DynamicFixupGeneric : public PE_DynamicFixup {
  public:
  using lief_t = LIEF::PE::DynamicFixupGeneric;

  class it_relocations :
      public Iterator<PE_Relocation, LIEF::PE::DynamicFixupGeneric::it_const_relocations>
  {
    public:
    it_relocations(const PE_DynamicFixupGeneric::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto relocations() const {
    return std::make_unique<it_relocations>(impl());
  }

  static bool classof(const PE_DynamicFixup* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_DynamicFixupUnknown : public PE_DynamicFixup {
  public:
  using lief_t = LIEF::PE::DynamicFixupUnknown;

  auto payload() const { return make_span(impl().payload()); }

  static bool classof(const PE_DynamicFixup* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_FunctionOverride_image_bdd_dynamic_relocation_t :
  private Mirror<LIEF::PE::FunctionOverride::image_bdd_dynamic_relocation_t>
{
  public:
  using lief_t = LIEF::PE::FunctionOverride::image_bdd_dynamic_relocation_t;
  using Mirror::Mirror;

  auto left() const { return get().left; }
  auto right() const { return get().right; }
  auto value() const { return get().value; }
};

class PE_FunctionOverride_image_bdd_info_t :
  private Mirror<LIEF::PE::FunctionOverride::image_bdd_info_t>
{
  public:
  using lief_t = LIEF::PE::FunctionOverride::image_bdd_info_t;
  using Mirror::Mirror;

  class it_relocations :
      public ContainerIterator<
        PE_FunctionOverride_image_bdd_dynamic_relocation_t,
          std::vector<LIEF::PE::FunctionOverride::image_bdd_dynamic_relocation_t>>
  {
    public:
    using container_t = std::vector<LIEF::PE::FunctionOverride::image_bdd_dynamic_relocation_t>;
    it_relocations(container_t content)
      : ContainerIterator(std::move(content)) { }
    auto next() { return ContainerIterator::next(); }
  };

  auto version() const { return get().version; }
  auto original_size() const { return get().original_size; }
  auto original_offset() const { return get().original_offset; }
  auto payload() const { return make_span(get().payload); }

  auto relocations() const {
    return std::make_unique<it_relocations>(get().relocations);
  }
};

class PE_FunctionOverrideInfo : public Mirror<LIEF::PE::FunctionOverrideInfo> {
  public:
  using lief_t = LIEF::PE::FunctionOverrideInfo;
  using Mirror::Mirror;

  class it_relocations :
      public Iterator<PE_Relocation, LIEF::PE::FunctionOverrideInfo::it_const_relocations>
  {
    public:
    it_relocations(const PE_FunctionOverrideInfo::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto original_rva() const { return get().original_rva(); }
  auto bdd_offset() const { return get().bdd_offset(); }
  auto rva_size() const { return get().rva_size(); }
  auto base_reloc_size() const { return get().base_reloc_size(); }
  std::vector<uint32_t> functions_rva() const { return get().functions_rva(); }

  auto relocations() const {
    return std::make_unique<it_relocations>(get());
  }

  auto to_string() const {
    return get().to_string();
  }
};

class PE_FunctionOverride : public PE_DynamicFixup {
  public:
  using lief_t = LIEF::PE::FunctionOverride;

  class it_func_overriding_info :
      public Iterator<PE_FunctionOverrideInfo, LIEF::PE::FunctionOverride::it_const_func_overriding_info>
  {
    public:
    it_func_overriding_info(const PE_FunctionOverride::lief_t& src)
      : Iterator(std::move(src.func_overriding_info())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_bdd_info :
      public Iterator<PE_FunctionOverride_image_bdd_info_t, LIEF::PE::FunctionOverride::it_const_bdd_info>
  {
    public:
    it_bdd_info(const PE_FunctionOverride::lief_t& src)
      : Iterator(std::move(src.bdd_info())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto func_overriding_info() const {
    return std::make_unique<it_func_overriding_info>(impl());
  }

  auto bdd_info() const {
    return std::make_unique<it_bdd_info>(impl());
  }

  auto bdd_info_at(uint32_t offset) const {
    return details::try_unique<PE_FunctionOverride_image_bdd_info_t>(impl().find_bdd_info(offset));
  }

  auto bdd_info_for(const PE_FunctionOverrideInfo& info) const {
    return details::try_unique<PE_FunctionOverride_image_bdd_info_t>(impl().find_bdd_info(info.get()));
  }

  static bool classof(const PE_DynamicFixup* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

