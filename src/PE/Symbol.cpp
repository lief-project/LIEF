/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include <ostream>
#include "LIEF/Visitor.hpp"

#include "LIEF/BinaryStream/BinaryStream.hpp"

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/AuxiliarySymbol.hpp"

#include "frozen.hpp"
#include "logging.hpp"
#include "internal_utils.hpp"

namespace LIEF {
namespace PE {

namespace details {

#pragma pack(push,1)
struct coff_symbol_t {
  union {
    std::array<char, 8> short_name;
    struct {
      uint32_t zeroes = 0;
      uint32_t offset = 0;
    } offset;
  } name;

  uint32_t value;
  uint16_t sec_idx;
  uint16_t type;
  uint8_t storage_class;
  uint8_t nb_aux;
};
#pragma pack(pop)

static_assert(sizeof(coff_symbol_t) == 18);

static constexpr auto SYM16_SZ = 18;
}


Symbol::Symbol() = default;
Symbol::Symbol(Symbol&&) = default;
Symbol& Symbol::operator=(Symbol&&) = default;

Symbol::~Symbol() = default;
Symbol::Symbol(const Symbol& other) :
  LIEF::Symbol(other),
  type_(other.type_),
  storage_class_(other.storage_class_),
  section_idx_(other.section_idx_)
{
  if (!other.auxiliary_symbols_.empty()) {
    auxiliary_symbols_.reserve(other.auxiliary_symbols_.size());
    for (const std::unique_ptr<AuxiliarySymbol>& aux : other.auxiliary_symbols_) {
      auxiliary_symbols_.push_back(aux->clone());
    }
  }
}

Symbol& Symbol::operator=(const Symbol& other) {
  if (this == &other) {
    return *this;
  }
  LIEF::Symbol::operator=(other);
  type_ = other.type_;
  storage_class_ = other.storage_class_;
  section_idx_ = other.section_idx_;

  if (!other.auxiliary_symbols_.empty()) {
    auxiliary_symbols_.reserve(other.auxiliary_symbols_.size());
    for (const std::unique_ptr<AuxiliarySymbol>& aux : other.auxiliary_symbols_) {
      auxiliary_symbols_.push_back(aux->clone());
    }
  }

  return *this;
};

std::unique_ptr<Symbol> Symbol::parse(Parser& ctx, BinaryStream& stream, size_t* idx) {
  auto raw = stream.read<details::coff_symbol_t>();
  if (!raw) {
    return nullptr;
  }
  auto sym = std::make_unique<Symbol>();
  sym->value(raw->value);
  sym->type(raw->type);
  sym->storage_class(raw->storage_class);
  sym->section_idx_ = raw->sec_idx;

  if (raw->name.offset.zeroes == 0) {
    sym->coff_name_ = ctx.find_coff_string(raw->name.offset.offset);
  } else {
    sym->name_ = std::string(raw->name.short_name.data(),
                             raw->name.short_name.size());
    sym->name_ = sym->name_.c_str();
  }

  *idx += raw->nb_aux + 1;

  for (size_t i = 0; i < raw->nb_aux; ++i) {
    std::vector<uint8_t> raw_aux;
    if (!stream.read_data(raw_aux, details::SYM16_SZ)) {
      return sym;
    }

    auto aux = AuxiliarySymbol::parse(*sym, std::move(raw_aux));
    if (aux == nullptr) {
      LIEF_WARN("Failed to parse auxiliary symbols #{}", i);
      continue;
    }

    sym->add_aux(std::move(aux));
  }

  return sym;
}

void Symbol::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

const std::string& Symbol::name() const {
  if (coff_name_ != nullptr) {
    return coff_name_->str();
  }
  return name_;
}

std::string& Symbol::name() {
  if (coff_name_ != nullptr) {
    return const_cast<std::string&>(coff_name_->str());
  }
  return name_;
}

std::ostream& operator<<(std::ostream& os, const Symbol& entry) {
  os << "Symbol {\n";
  os << "  Name: " << entry.name() << '\n'
     << "  Value: " << entry.value() << '\n'
     << "  Section index: " << entry.section_idx() << '\n'
     << fmt::format("  Base type: {} ({})\n", to_string(entry.base_type()), (int)entry.base_type())
     << fmt::format("  Complex type: {} ({})\n", to_string(entry.complex_type()), (int)entry.complex_type())
     << fmt::format("  Storage class: {} ({})\n", to_string(entry.storage_class()), (int)entry.storage_class())
     << "  Nb auxiliary symbols: " << entry.auxiliary_symbols().size() << '\n';
  for (const AuxiliarySymbol& aux : entry.auxiliary_symbols()) {
    os << indent(aux.to_string(), 2) << '\n';
  }
  os << "}\n";

  return os;
}

const char* to_string(Symbol::STORAGE_CLASS e) {
  #define ENTRY(X) std::pair(Symbol::STORAGE_CLASS::X, #X)
  STRING_MAP enums2str {
    ENTRY(INVALID),
    ENTRY(END_OF_FUNCTION),
    ENTRY(NONE),
    ENTRY(AUTOMATIC),
    ENTRY(EXTERNAL),
    ENTRY(STATIC),
    ENTRY(REGISTER),
    ENTRY(EXTERNAL_DEF),
    ENTRY(LABEL),
    ENTRY(UNDEFINED_LABEL),
    ENTRY(MEMBER_OF_STRUCT),
    ENTRY(ARGUMENT),
    ENTRY(STRUCT_TAG),
    ENTRY(MEMBER_OF_UNION),
    ENTRY(UNION_TAG),
    ENTRY(TYPE_DEFINITION),
    ENTRY(UNDEFINED_STATIC),
    ENTRY(ENUM_TAG),
    ENTRY(MEMBER_OF_ENUM),
    ENTRY(REGISTER_PARAM),
    ENTRY(BIT_FIELD),
    ENTRY(BLOCK),
    ENTRY(FUNCTION),
    ENTRY(END_OF_STRUCT),
    ENTRY(FILE),
    ENTRY(SECTION),
    ENTRY(WEAK_EXTERNAL),
    ENTRY(CLR_TOKEN),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "NONE";
}

const char* to_string(Symbol::BASE_TYPE e) {
  #define ENTRY(X) std::pair(Symbol::BASE_TYPE::TY_##X, #X)
  STRING_MAP enums2str {
    ENTRY(NULL),
    ENTRY(VOID),
    ENTRY(CHAR),
    ENTRY(SHORT),
    ENTRY(INT),
    ENTRY(LONG),
    ENTRY(FLOAT),
    ENTRY(DOUBLE),
    ENTRY(STRUCT),
    ENTRY(UNION),
    ENTRY(ENUM),
    ENTRY(MOE),
    ENTRY(BYTE),
    ENTRY(WORD),
    ENTRY(UINT),
    ENTRY(DWORD),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "NONE";
}
const char* to_string(Symbol::COMPLEX_TYPE e) {

  #define ENTRY(X) std::pair(Symbol::COMPLEX_TYPE::TY_##X, #X)
  STRING_MAP enums2str {
    ENTRY(NULL),
    ENTRY(POINTER),
    ENTRY(FUNCTION),
    ENTRY(ARRAY),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "NONE";
}

AuxiliarySymbol& Symbol::add_aux(std::unique_ptr<AuxiliarySymbol> sym) {
  auxiliary_symbols_.push_back(std::move(sym));
  return *auxiliary_symbols_.back();
}

}
}
