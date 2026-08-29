/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_ELF_RELOCATION_H
#define LIEF_ELF_RELOCATION_H

#include <memory>
#include <ostream>

#include "LIEF/Object.hpp"
#include "LIEF/errors.hpp"
#include "LIEF/logging.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Header.hpp"
#include "LIEF/ELF/enums.hpp"


namespace LIEF::ELF {

class Parser;
class Binary;
class Builder;
class Symbol;
class Section;

/// Class that represents an ELF relocation.
class LIEF_API Relocation : public LIEF::Relocation {

  friend class Parser;
  friend class Binary;
  friend class Builder;

  public:
  /// The *purpose* of a relocation defines how this relocation is used by the
  /// loader.
  enum class PURPOSE {
    NONE = 0,
    /// The relocation is associated with the PLT/GOT resolution
    PLTGOT,

    /// The relocation is used for regular data/code relocation
    DYNAMIC,

    /// The relocation is used in an object file
    OBJECT,
  };

  enum class ENCODING {
    UNKNOWN = 0,

    /// The relocation is using the regular Elf_Rel structure
    REL,

    /// The relocation is using the regular Elf_Rela structure
    RELA,

    /// The relocation is using the relative relocation format
    RELR,

    /// The relocation is using the packed Android-SLEB128 format
    ANDROID_SLEB,
  };

  static constexpr uint64_t R_BIT = 27;
  static constexpr uint64_t R_MASK = (uint64_t(1) << R_BIT) - 1;

  // clang-format off
  static constexpr uint64_t R_X64     = uint64_t(1)  << R_BIT;
  static constexpr uint64_t R_AARCH64 = uint64_t(2)  << R_BIT;
  static constexpr uint64_t R_ARM     = uint64_t(3)  << R_BIT;
  static constexpr uint64_t R_HEXAGON = uint64_t(4)  << R_BIT;
  static constexpr uint64_t R_X86     = uint64_t(5)  << R_BIT;
  static constexpr uint64_t R_LARCH   = uint64_t(6)  << R_BIT;
  static constexpr uint64_t R_MIPS    = uint64_t(7)  << R_BIT;
  static constexpr uint64_t R_PPC     = uint64_t(8)  << R_BIT;
  static constexpr uint64_t R_PPC64   = uint64_t(9)  << R_BIT;
  static constexpr uint64_t R_SPARC   = uint64_t(10) << R_BIT;
  static constexpr uint64_t R_SYSZ    = uint64_t(11) << R_BIT;
  static constexpr uint64_t R_RISCV   = uint64_t(12) << R_BIT;
  static constexpr uint64_t R_BPF     = uint64_t(13) << R_BIT;
  static constexpr uint64_t R_SH4     = uint64_t(14) << R_BIT;
  // clang-format on

  /// The different types of the relocation
  enum class TYPE : uint32_t {
    UNKNOWN = uint32_t(-1),

#define ELF_RELOC(name, value) name = (value | R_X64),
#include "LIEF/ELF/Relocations/x86_64.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_AARCH64),
#include "LIEF/ELF/Relocations/AArch64.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_ARM),
#include "LIEF/ELF/Relocations/ARM.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_HEXAGON),
#include "LIEF/ELF/Relocations/Hexagon.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_X86),
#include "LIEF/ELF/Relocations/i386.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_LARCH),
#include "LIEF/ELF/Relocations/LoongArch.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_MIPS),
#include "LIEF/ELF/Relocations/Mips.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_PPC),
#include "LIEF/ELF/Relocations/PowerPC.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_PPC64),
#include "LIEF/ELF/Relocations/PowerPC64.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_SPARC),
#include "LIEF/ELF/Relocations/Sparc.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_SYSZ),
#include "LIEF/ELF/Relocations/SystemZ.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_RISCV),
#include "LIEF/ELF/Relocations/RISCV.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_BPF),
#include "LIEF/ELF/Relocations/BPF.def"
#undef ELF_RELOC

#define ELF_RELOC(name, value) name = (value | R_SH4),
#include "LIEF/ELF/Relocations/SH4.def"
#undef ELF_RELOC
  };

  /// Fields decoded from the MIPS-specific n64 `r_info` layout.
  struct DecodedMipsN64 {
    /// Primary relocation type.
    uint32_t type_value = 0;

    /// Index of the symbol associated with the relocation.
    uint32_t sym_idx = 0;

    /// Special symbol used by the second relocation operation.
    uint8_t special_symbol = 0;

    /// Second relocation type.
    uint8_t type2 = 0;

    /// Third relocation type.
    uint8_t type3 = 0;
  };

  /// Decode `r_info` for MIPS n64.
  static DecodedMipsN64 decode_mips_n64(uint64_t r_info, Header::ELF_DATA data) {
    if (data == Header::ELF_DATA::LSB) {
      return {
          uint32_t(r_info >> 56), uint32_t(r_info & 0xffffffff),
          uint8_t(r_info >> 32),  uint8_t(r_info >> 48),
          uint8_t(r_info >> 40),
      };
    }
    return {
        uint32_t(r_info & 0xff), uint32_t(r_info >> 32), uint8_t(r_info >> 24),
        uint8_t(r_info >> 8),    uint8_t(r_info >> 16),
    };
  }

  /// Encode all the fields of a MIPS n64 relocation into a `r_info` value
  static uint64_t encode_mips_n64(DecodedMipsN64 decoded, Header::ELF_DATA data) {
    // clang-format off
    if (data == Header::ELF_DATA::LSB) {
      return (uint64_t(decoded.sym_idx)           <<  0) |
             (uint64_t(decoded.special_symbol)    << 32) |
             (uint64_t(decoded.type3)             << 40) |
             (uint64_t(decoded.type2)             << 48) |
             (uint64_t(decoded.type_value & 0xff) << 56);
    }
    return (uint64_t(decoded.sym_idx)           << 32) |
           (uint64_t(decoded.special_symbol)    << 24) |
           (uint64_t(decoded.type3)             << 16) |
           (uint64_t(decoded.type2)             << 8)  |
           (uint64_t(decoded.type_value & 0xff) << 0);
    // clang-format on
  }

  static uint64_t encode_mips_n64(uint32_t type_value, uint32_t sym_idx,
                                  Header::ELF_DATA data) {
    return encode_mips_n64({type_value, sym_idx}, data);
  }

  static TYPE type_from(uint32_t value, ARCH arch);

  static uint32_t to_value(TYPE type) {
    return static_cast<uint32_t>(type) & R_MASK;
  }

  Relocation(uint64_t address, TYPE type, ENCODING enc);

  Relocation() = default;
  Relocation(ARCH arch) :
    architecture_(arch) {}

  ~Relocation() override = default;

  /// Copy constructor.
  ///
  /// @warning When this constructor is invoked, referenced sections or symbols
  /// are discarded. This means that on the copied Relocation, Relocation::section,
  /// Relocation::symbol and Relocation::symbol_table are set to a nullptr.
  Relocation(const Relocation& other) :
    LIEF::Relocation{other},
    type_{other.type_},
    addend_{other.addend_},
    encoding_{other.encoding_},
    architecture_{other.architecture_},
    metadata_{other.metadata_},
    info_{other.info_} {}

  /// Copy assignment operator.
  ///
  /// Please read the notice of the copy constructor
  Relocation& operator=(Relocation other) {
    swap(other);
    return *this;
  }

  void swap(Relocation& other) {
    std::swap(address_, other.address_);
    std::swap(type_, other.type_);
    std::swap(addend_, other.addend_);
    std::swap(encoding_, other.encoding_);
    std::swap(symbol_, other.symbol_);
    std::swap(architecture_, other.architecture_);
    std::swap(metadata_, other.metadata_);
    std::swap(section_, other.section_);
    std::swap(symbol_table_, other.symbol_table_);
    std::swap(info_, other.info_);
    std::swap(binary_, other.binary_);
  }

  /// Additional value that can be involved in the relocation processing
  int64_t addend() const {
    return addend_;
  }

  /// Type of the relocation
  TYPE type() const {
    return type_;
  }

  /// Check if the relocation uses the explicit addend() field
  /// (this is usually the case for 64 bits binaries)
  bool is_rela() const {
    return encoding_ == ENCODING::RELA;
  }

  /// Check if the relocation uses the implicit addend
  /// (i.e. not present in the ELF structure)
  bool is_rel() const {
    return encoding_ == ENCODING::REL;
  }

  /// True if the relocation is using the relative encoding
  bool is_relatively_encoded() const {
    return encoding_ == ENCODING::RELR;
  }

  /// True if the relocation is using the Android packed relocation format
  bool is_android_packed() const {
    return encoding_ == ENCODING::ANDROID_SLEB;
  }

  /// Relocation info which contains, for instance, the symbol index
  uint32_t info() const {
    return info_;
  }

  /// (re)Compute the *raw* `r_info` attribute based on the given ELF class and
  /// endianness.
  uint64_t r_info(Header::CLASS clazz, Header::ELF_DATA data) const {
    // Mips n64
    if (architecture_ == ARCH::MIPS && clazz == Header::CLASS::ELF64 &&
        !is_android_packed())
    {
      return encode_mips_n64(mips_n64_info(), data);
    }

    if (clazz == Header::CLASS::NONE) {
      return 0;
    }
    return clazz == Header::CLASS::ELF32 ?
               uint32_t(info()) << 8 | to_value(type()) :
               uint64_t(info()) << 32 | (to_value(type()) & 0xffffffffL);
  }

  /// (re)Compute the raw `r_info` attribute from the given ELF header.
  uint64_t r_info(const Header& hdr) const {
    if (hdr.machine_type() != architecture_) {
      logging::err("Failed to compute r_info: architectures mismatch: {} vs {}",
                   to_string(hdr.machine_type()), to_string(architecture_));
      return 0;
    }
    return r_info(hdr.identity_class(), hdr.identity_data());
  }

  /// Target architecture for this relocation
  ARCH architecture() const {
    return architecture_;
  }

  PURPOSE purpose() const {
    return PURPOSE(metadata_.purpose);
  }

  /// The encoding of the relocation
  ENCODING encoding() const {
    return encoding_;
  }

  /// True if the semantic of the relocation is `<ARCH>_RELATIVE`
  bool is_relative() const {
    return type_ == TYPE::AARCH64_RELATIVE || type_ == TYPE::X86_64_RELATIVE ||
           type_ == TYPE::X86_RELATIVE || type_ == TYPE::ARM_RELATIVE ||
           type_ == TYPE::HEX_RELATIVE || type_ == TYPE::PPC64_RELATIVE ||
           type_ == TYPE::PPC_RELATIVE;
  }

  /// Return the size (in **bits**) of the value associated with this relocation
  /// Return -1 if the size can't be determined
  size_t size() const override;

  /// True if the current relocation is associated with a symbol
  bool has_symbol() const {
    return symbol_ != nullptr;
  }

  /// Symbol associated with the relocation (or a nullptr)
  Symbol* symbol() LIEF_LIFETIMEBOUND {
    return symbol_;
  }

  const Symbol* symbol() const LIEF_LIFETIMEBOUND {
    return symbol_;
  }

  /// True if the relocation has an associated section
  bool has_section() const {
    return section() != nullptr;
  }

  /// The section in which the relocation is applied (or a nullptr)
  Section* section() LIEF_LIFETIMEBOUND {
    return section_;
  }

  const Section* section() const LIEF_LIFETIMEBOUND {
    return section_;
  }

  /// The associated symbol table (or a nullptr)
  Section* symbol_table() LIEF_LIFETIMEBOUND {
    return symbol_table_;
  }

  const Section* symbol_table() const LIEF_LIFETIMEBOUND {
    return symbol_table_;
  }

  void addend(int64_t addend) {
    addend_ = addend;
  }

  void type(TYPE type) {
    type_ = type;
  }

  void purpose(PURPOSE purpose) {
    metadata_.purpose = uint32_t(purpose);
  }

  void info(uint32_t v) {
    info_ = v;
  }

  void symbol(Symbol* symbol) {
    symbol_ = symbol;
  }

  void section(Section* section) {
    section_ = section;
  }

  void symbol_table(Section* section) {
    symbol_table_ = section;
  }

  /// Try to resolve the value of the relocation such as
  /// `*address() = resolve()`
  result<uint64_t> resolve(uint64_t base_address = 0) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const Relocation& entry);
  template<class T>
  LIEF_LOCAL static std::unique_ptr<Relocation>
      create(const T& header, PURPOSE purpose, ENCODING enc,
             const Header& elf_hdr);

  private:
  // clang-format off
  struct Metadata {
    uint32_t purpose        : 8,
             special_symbol : 8,
             type2          : 8,
             type3          : 8;
  };
  // clang-format on

  static_assert(sizeof(Metadata) == sizeof(uint32_t));

  DecodedMipsN64 mips_n64_info() const {
    return {
        to_value(type()),
        info(),
        uint8_t(metadata_.special_symbol),
        uint8_t(metadata_.type2),
        uint8_t(metadata_.type3),
    };
  }

  uint8_t mips_n64_type2() const {
    return uint8_t(metadata_.type2);
  }

  LIEF_LOCAL Relocation(uint64_t addr, uint32_t info, TYPE type, int64_t addend,
                        PURPOSE purpose, ENCODING enc, ARCH arch,
                        DecodedMipsN64 mips_n64) :
    LIEF::Relocation{addr, 0},
    type_{type},
    addend_{addend},
    encoding_{enc},
    architecture_{arch},
    metadata_{uint32_t(purpose), mips_n64.special_symbol, mips_n64.type2,
              mips_n64.type3},
    info_{info} {}

  TYPE type_ = TYPE::UNKNOWN;
  int64_t addend_ = 0;
  ENCODING encoding_ = ENCODING::UNKNOWN;
  Symbol* symbol_ = nullptr;
  ARCH architecture_ = ARCH::NONE;
  Metadata metadata_ = {};
  Section* section_ = nullptr;
  Section* symbol_table_ = nullptr;
  uint32_t info_ = 0;

  Binary* binary_ = nullptr;
};

LIEF_API const char* to_string(Relocation::TYPE type);

}

#endif
