/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include <numeric>
#include <iomanip>
#include <sstream>

#include "LIEF/logging++.hpp"

#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/EnumToString.hpp"

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/ExportInfo.hpp"

namespace LIEF {
namespace MachO {

DyldInfo::DyldInfo(void) :
  LoadCommand{},
  rebase_{},
  rebase_opcodes_{},
  bind_{},
  bind_opcodes_{},
  weak_bind_{},
  weak_bind_opcodes_{},
  lazy_bind_{},
  lazy_bind_opcodes_{},
  export_{},
  export_trie_{},
  export_info_{},
  binding_info_{},
  binary_{nullptr}
{}

DyldInfo& DyldInfo::operator=(DyldInfo other) {
  this->swap(other);
  return *this;
}

DyldInfo::DyldInfo(const DyldInfo& copy) :
  LoadCommand::LoadCommand{copy},
  rebase_{copy.rebase_},
  rebase_opcodes_{copy.rebase_opcodes_},
  bind_{copy.bind_},
  bind_opcodes_{copy.bind_opcodes_},
  weak_bind_{copy.weak_bind_},
  weak_bind_opcodes_{copy.weak_bind_opcodes_},
  lazy_bind_{copy.lazy_bind_},
  lazy_bind_opcodes_{copy.lazy_bind_opcodes_},
  export_{copy.export_},
  export_trie_{copy.export_trie_},
  export_info_{},
  binding_info_{},
  binary_{nullptr}
{}

DyldInfo::~DyldInfo(void) {
  for (BindingInfo* binfo : this->binding_info_) {
    delete binfo;
  }

  for (ExportInfo* einfo : this->export_info_) {
    delete einfo;
  }
}

DyldInfo::DyldInfo(const dyld_info_command *dyld_info_cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(dyld_info_cmd->cmd), dyld_info_cmd->cmdsize},
  rebase_{dyld_info_cmd->rebase_off, dyld_info_cmd->rebase_size},
  rebase_opcodes_{},
  bind_{dyld_info_cmd->bind_off, dyld_info_cmd->bind_size},
  bind_opcodes_{},
  weak_bind_{dyld_info_cmd->weak_bind_off, dyld_info_cmd->weak_bind_size},
  weak_bind_opcodes_{},
  lazy_bind_{dyld_info_cmd->lazy_bind_off, dyld_info_cmd->lazy_bind_size},
  lazy_bind_opcodes_{},
  export_{dyld_info_cmd->export_off, dyld_info_cmd->export_size},
  export_trie_{},
  export_info_{},
  binding_info_{},
  binary_{nullptr}
{}


void DyldInfo::swap(DyldInfo& other) {
  LoadCommand::swap(other);

  std::swap(this->rebase_,             other.rebase_);
  std::swap(this->rebase_opcodes_,     other.rebase_opcodes_);

  std::swap(this->bind_,               other.bind_);
  std::swap(this->bind_opcodes_,       other.bind_opcodes_);

  std::swap(this->weak_bind_,          other.weak_bind_);
  std::swap(this->weak_bind_opcodes_,  other.weak_bind_opcodes_);

  std::swap(this->lazy_bind_,          other.lazy_bind_);
  std::swap(this->lazy_bind_opcodes_,  other.lazy_bind_opcodes_);

  std::swap(this->export_,             other.export_);
  std::swap(this->export_trie_,        other.export_trie_);

  std::swap(this->export_info_,        other.export_info_);
  std::swap(this->binding_info_,       other.binding_info_);

  std::swap(this->binary_,             other.binary_);
}


// Rebase
// ======
const DyldInfo::info_t& DyldInfo::rebase(void) const {
  return this->rebase_;
}

const buffer_t& DyldInfo::rebase_opcodes(void) const {
  return this->rebase_opcodes_;
}

buffer_t& DyldInfo::rebase_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->rebase_opcodes());
}

void DyldInfo::rebase_opcodes(const buffer_t& raw) {
  this->rebase_opcodes_ = raw;
}


std::string DyldInfo::show_rebases_opcodes(void) const {
  if (not this->binary_) {
    LOG(WARNING) << "Can't print rebase opcode";
    return "";
  }

  size_t pint_v = static_cast<LIEF::Binary*>(this->binary_)->header().is_64() ? sizeof(uint64_t) : sizeof(uint32_t);
  std::ostringstream output;
  const buffer_t& rebase_opcodes = this->rebase_opcodes();

  bool     done = false;
  uint8_t  type = 0;
  uint32_t segment_index = 0;
  uint64_t segment_offset = 0;
  uint32_t count = 0;
  uint32_t skip = 0;
  VectorStream rebase_stream{rebase_opcodes};
  const std::string tab = "    ";

  it_segments segments = this->binary_->segments();

  while (not done and rebase_stream.pos() < rebase_opcodes.size()) {
    uint8_t imm    = rebase_stream.peek<uint8_t>() & REBASE_IMMEDIATE_MASK;
    uint8_t opcode = rebase_stream.read<uint8_t>() & REBASE_OPCODE_MASK;

    switch(static_cast<REBASE_OPCODES>(opcode)) {
      case REBASE_OPCODES::REBASE_OPCODE_DONE:
        {
          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "]" << std::endl;
          done = true;
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_SET_TYPE_IMM:
        {
          type = imm;
          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "] ";
          output << "Type: " << to_string(static_cast<REBASE_TYPES>(type));
          output << std::endl;
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {

          segment_index   = imm;
          segment_offset  = rebase_stream.read_uleb128();


          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "] ";
          output << "Segment Index := " << std::dec << segment_index << " (" << segments[segment_index].name() << ") ";
          output << "Segment Offset := " << std::hex << std::showbase << segment_offset;
          output << std::endl;

          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_ULEB:
        {

          uint64_t val = rebase_stream.read_uleb128();
          segment_offset += val;

          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "] ";
          output << "Segment Offset += " << std::hex << std::showbase << val << " (" << segment_offset << ")";
          output << std::endl;
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        {
          segment_offset += (imm * pint_v);

          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "]" ;
          output << "Segment Offset += " << std::hex << std::showbase << (imm * pint_v) << " (" << segment_offset << ")";
          output << std::endl;
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        {
          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "]" << std::endl;
          output << tab << "for i in range(" << std::dec << static_cast<uint32_t>(imm) << "):" << std::endl;
          for (size_t i = 0; i < imm; ++i) {
            output << tab << tab;
            output << "rebase(";
            output << to_string(static_cast<REBASE_TYPES>(type));
            output << ", ";
            output << segments[segment_index].name();
            output << ", ";
            output << std::hex << std::showbase << segment_offset;
            output << ")" << std::endl;

            segment_offset += pint_v;

            output << tab << tab;
            output << "Segment Offset += " << std::hex << std::showbase << pint_v << " (" << segment_offset << ")";
            output << std::endl << std::endl;
          }
          output << std::endl;
          break;
        }
      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        {

          count = rebase_stream.read_uleb128();

          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "]" << std::endl;

          output << tab << "for i in range(" << std::dec << static_cast<uint32_t>(count) << "):" << std::endl;
          for (size_t i = 0; i < count; ++i) {
            output << tab << tab;
            output << "rebase(";
            output << to_string(static_cast<REBASE_TYPES>(type));
            output << ", ";
            output << segments[segment_index].name();
            output << ", ";
            output << std::hex << std::showbase << segment_offset;
            output << ")" << std::endl;

            segment_offset += pint_v;

            output << tab << tab;
            output << "Segment Offset += " << std::hex << std::showbase << pint_v << " (" << segment_offset << ")";
            output << std::endl << std::endl;
          }

          output << std::endl;
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        {

          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "]" << std::endl;

          output << tab;
          output << "rebase(";
          output << to_string(static_cast<REBASE_TYPES>(type));
          output << ", ";
          output << segments[segment_index].name();
          output << ", ";
          output << std::hex << std::showbase << segment_offset;
          output << ")" << std::endl;

          uint64_t val = rebase_stream.read_uleb128();
          segment_offset += val + pint_v;


          output << tab;
          output << "Segment Offset += " << std::hex << std::showbase << (val + pint_v) << " (" << segment_offset << ")";
          output << std::endl;

          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        {

          output << "[" << to_string(static_cast<REBASE_OPCODES>(opcode)) << "]" << std::endl;

          // Count
          count = rebase_stream.read_uleb128();

          // Skip
          skip = rebase_stream.read_uleb128();

          output << tab << "for i in range(" << std::dec << static_cast<uint32_t>(count) << "):" << std::endl;
          for (size_t i = 0; i < count; ++i) {
            output << tab << tab;
            output << "rebase(";
            output << to_string(static_cast<REBASE_TYPES>(type));
            output << ", ";
            output << segments[segment_index].name();
            output << ", ";
            output << std::hex << std::showbase << segment_offset;
            output << ")" << std::endl;

            segment_offset += skip + pint_v;

            output << tab << tab;
            output << "Segment Offset += " << std::hex << std::showbase << skip << " + " << pint_v << " (" << segment_offset << ")";
            output << std::endl << std::endl;
          }

          break;
        }

      default:
        {
          output << "[UNSUPPORTED OPCODE - " << std::showbase << std::hex << static_cast<uint32_t>(opcode) << "]" << std::endl;
          break;
        }
    }
  }

  return output.str();
}

// Binding
// =======

it_binding_info DyldInfo::bindings(void) {
  return this->binding_info_;
}

it_const_binding_info DyldInfo::bindings(void) const {
  return this->binding_info_;
}

const DyldInfo::info_t& DyldInfo::bind(void) const {
  return this->bind_;
}

const buffer_t& DyldInfo::bind_opcodes(void) const {
  return this->bind_opcodes_;
}

buffer_t& DyldInfo::bind_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->bind_opcodes());
}

void DyldInfo::bind_opcodes(const buffer_t& raw) {
  this->bind_opcodes_ = raw;
}


std::string DyldInfo::show_bind_opcodes(void) const {
  std::ostringstream output;
  this->show_bindings(output, this->bind_opcodes(), /* is_lazy = */ false);
  return output.str();
}

void DyldInfo::show_bindings(std::ostream& output, const buffer_t& bind_opcodes, bool is_lazy) const {
  if (not this->binary_) {
    LOG(WARNING) << "Can't print bind opcodes";
    return;
  }

  size_t pint_v = static_cast<LIEF::Binary*>(this->binary_)->header().is_64() ? sizeof(uint64_t) : sizeof(uint32_t);

  uint8_t     type = is_lazy ? static_cast<uint8_t>(BIND_TYPES::BIND_TYPE_POINTER) : 0;
  uint8_t     segment_idx = 0;
  uint64_t    segment_offset = 0;
  std::string symbol_name = "";
  int         library_ordinal = 0;

  int64_t     addend = 0;
  uint32_t    count = 0;
  uint32_t    skip = 0;

  bool        is_weak_import = false;
  bool        done = false;

  it_segments segments = this->binary_->segments();
  it_libraries libraries = this->binary_->libraries();

  const std::string tab = "    ";

  VectorStream bind_stream{bind_opcodes};

  while (not done and bind_stream.pos() < bind_opcodes.size()) {
    uint8_t imm  = bind_stream.peek<uint8_t>() & BIND_IMMEDIATE_MASK;
    BIND_OPCODES opcode = static_cast<BIND_OPCODES>(bind_stream.read<uint8_t>() & BIND_OPCODE_MASK);

    switch (opcode) {
      case BIND_OPCODES::BIND_OPCODE_DONE:
        {
          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;
          if (not is_lazy) {
            done = true;
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        {
          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;

          library_ordinal = imm;

          output << tab << "Library Ordinal := " << std::dec << static_cast<uint32_t>(imm) << std::endl;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;

          library_ordinal = bind_stream.read_uleb128();

          output << tab << "Library Ordinal := " << std::dec << library_ordinal << std::endl;

          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;
          // the special ordinals are negative numbers
          if (imm == 0) {
            library_ordinal = 0;
          } else {
            int8_t sign_extended = static_cast<int8_t>(BIND_OPCODE_MASK) | imm;
            library_ordinal = sign_extended;
          }

          output << tab << "Library Ordinal := " << std::dec << library_ordinal << std::endl;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;
          symbol_name = bind_stream.read_string();

          if ((imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0) {
            is_weak_import = true;
          } else {
            is_weak_import = false;
          }

          output << tab << "Symbol name := " << symbol_name << std::endl;
          output << tab << "Is Weak ? " << std::boolalpha << is_weak_import << std::endl;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_TYPE_IMM:
        {
          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;

          type = imm;

          output << tab << "Type := " << to_string(static_cast<BIND_TYPES>(type)) << std::endl;

          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_ADDEND_SLEB:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;
          addend          = bind_stream.read_sleb128();

          output << tab << "Addend := " << std::dec << addend << std::endl;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;
          segment_idx  = imm;

          segment_offset  = bind_stream.read_uleb128();

          output << tab << "Segment := " << segments[segment_idx].name() << std::endl;
          output << tab << "Segment Offset := " << std::hex << std::showbase << segment_offset << std::endl;

          break;
        }

      case BIND_OPCODES::BIND_OPCODE_ADD_ADDR_ULEB:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;

          uint64_t val = bind_stream.read_uleb128();
          segment_offset += val;

          output << tab << "Segment Offset += " << std::hex << std::showbase << val << " (" << segment_offset << ")" << std::endl;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;



          output << tab;
          output << "bind(";
          output << to_string(static_cast<BIND_TYPES>(type));
          output << ", ";
          output << segments[segment_idx].name();
          output << ", ";
          output << std::hex << std::showbase << segment_offset;
          output << ", ";
          output << symbol_name;
          output << ", library_ordinal=";
          output << (library_ordinal > 0 ? libraries[library_ordinal - 1].name() : std::to_string(library_ordinal));
          output << ", addend=";
          output << std::dec << addend;
          output << ", is_weak_import=";
          output << std::boolalpha << is_weak_import;
          output << ")" << std::endl;

          segment_offset += pint_v;

          output << tab << "Segment Offset += " << std::hex << std::showbase << pint_v << " (" << segment_offset << ")" << std::endl;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;

          output << tab;
          output << "bind(";
          output << to_string(static_cast<BIND_TYPES>(type));
          output << ", ";
          output << segments[segment_idx].name();
          output << ", ";
          output << std::hex << std::showbase << segment_offset;
          output << ", ";
          output << symbol_name;
          output << ", library_ordinal=";
          output << (library_ordinal > 0 ? libraries[library_ordinal - 1].name() : std::to_string(library_ordinal));
          output << ", addend=";
          output << std::dec << addend;
          output << ", is_weak_import=";
          output << std::boolalpha << is_weak_import;
          output << ")" << std::endl;

          uint64_t v = bind_stream.read_uleb128();
          segment_offset += v + pint_v;

          output << tab << "Segment Offset += " << std::hex << std::showbase << v + pint_v << " (" << segment_offset << ")" << std::endl;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;

          output << tab;
          output << "bind(";
          output << to_string(static_cast<BIND_TYPES>(type));
          output << ", ";
          output << segments[segment_idx].name();
          output << ", ";
          output << std::hex << std::showbase << segment_offset;
          output << ", ";
          output << symbol_name;
          output << ", library_ordinal=";
          output << (library_ordinal > 0 ? libraries[library_ordinal - 1].name() : std::to_string(library_ordinal));
          output << ", addend=";
          output << std::dec << addend;
          output << ", is_weak_import=";
          output << std::boolalpha << is_weak_import;
          output << ")" << std::endl;

          segment_offset += imm * pint_v + pint_v;

          output << tab << "Segment Offset += " << std::hex << std::showbase << (imm * pint_v + pint_v) << " (" << segment_offset << ")" << std::endl;

          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {

          output << "[" << to_string(static_cast<BIND_OPCODES>(opcode)) << "]" << std::endl;
          // Count
          count           = bind_stream.read_uleb128();

          // Skip
          skip            = bind_stream.read_uleb128();;

          output << tab << "for i in range(" << std::dec << static_cast<uint32_t>(count) << "):" << std::endl;
          for (size_t i = 0; i < count; ++i) {
            output << tab << tab;
            output << "bind(";
            output << to_string(static_cast<BIND_TYPES>(type));
            output << ", ";
            output << segments[segment_idx].name();
            output << ", ";
            output << std::hex << std::showbase << segment_offset;
            output << ", ";
            output << symbol_name;
            output << ", library_ordinal=";
            output << (library_ordinal > 0 ? libraries[library_ordinal - 1].name() : std::to_string(library_ordinal));
            output << ", addend=";
            output << std::dec << addend;
            output << ", is_weak_import=";
            output << std::boolalpha << is_weak_import;
            output << ")" << std::endl;


            segment_offset += skip + pint_v;

            output << "Segment Offset += " << std::hex << std::showbase << skip << " + " << pint_v << " (" << segment_offset << ")";

            output << std::endl << std::endl;
          }
          break;
        }

      default:
        {
          LOG(ERROR) << "Unsupported opcode: 0x" << std::hex << static_cast<uint32_t>(opcode);
          break;
        }
      }
  }
}

// Weak Binding
// ============
const DyldInfo::info_t& DyldInfo::weak_bind(void) const {
  return this->weak_bind_;
}

const buffer_t& DyldInfo::weak_bind_opcodes(void) const {
  return this->weak_bind_opcodes_;
}

buffer_t& DyldInfo::weak_bind_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->weak_bind_opcodes());
}

void DyldInfo::weak_bind_opcodes(const buffer_t& raw) {
  this->weak_bind_opcodes_ = raw;
}


std::string DyldInfo::show_weak_bind_opcodes(void) const {
  std::ostringstream output;
  this->show_bindings(output, this->weak_bind_opcodes(), /* is_lazy = */ false);
  return output.str();
}

// Lazy Binding
// ============
const DyldInfo::info_t& DyldInfo::lazy_bind(void) const {
  return this->lazy_bind_;
}

const buffer_t& DyldInfo::lazy_bind_opcodes(void) const {
  return this->lazy_bind_opcodes_;
}

buffer_t& DyldInfo::lazy_bind_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->lazy_bind_opcodes());
}

void DyldInfo::lazy_bind_opcodes(const buffer_t& raw) {
  this->lazy_bind_opcodes_ = raw;
}

std::string DyldInfo::show_lazy_bind_opcodes(void) const {
  std::ostringstream output;
  this->show_bindings(output, this->lazy_bind_opcodes(), true);
  return output.str();
}

// Export Info
// ===========
it_export_info DyldInfo::exports(void) {
  return this->export_info_;
}

it_const_export_info DyldInfo::exports(void) const {
  return this->export_info_;
}

const DyldInfo::info_t& DyldInfo::export_info(void) const {
  return this->export_;
}

const buffer_t& DyldInfo::export_trie(void) const {
  return this->export_trie_;
}

buffer_t& DyldInfo::export_trie(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->export_trie());
}


std::string DyldInfo::show_export_trie(void) const {
  if (not this->binary_) {
    LOG(WARNING) << "Can't print bind opcodes";
    return "";
  }

  std::ostringstream output;
  const buffer_t& buffer = this->export_trie();

  VectorStream stream{buffer};
  this->show_trie(output, "", stream, 0, buffer.size(), "");

  return output.str();


}

void DyldInfo::show_trie(std::ostream& output, std::string output_prefix, VectorStream& stream, uint64_t start, uint64_t end, const std::string& prefix) const {

  if (stream.pos() >= end) {
    return;
  }

  if (start > stream.pos()) {
    return;
  }

  const uint8_t terminal_size = stream.read<uint8_t>();

  uint64_t children_offset = stream.pos() + terminal_size;

  if (terminal_size != 0) {

    uint64_t flags   = stream.read_uleb128();
    uint64_t address = stream.read_uleb128();

    const std::string& symbol_name = prefix;
    output << output_prefix;
    output << symbol_name;
    output << "{";
    output << "addr: " << std::showbase << std::hex << address << ", ";
    output << "flags: " << std::showbase << std::hex << flags;
    output << "}";
    output << std::endl;

    if (not this->binary_->has_symbol(symbol_name)) {
      output << " [NOT REGISTRED]";
    }
    output << std::endl;

  }
  stream.setpos(children_offset);
  const uint8_t nb_children = stream.read<uint8_t>();

  output_prefix += "    ";
  for (size_t i = 0; i < nb_children; ++i) {
    std::string suffix = stream.read_string();
    std::string name   = prefix + suffix;

    uint32_t child_node_offet  = static_cast<uint32_t>(stream.read_uleb128());

    if (child_node_offet == 0) {
      break;
    }

    output << output_prefix << name << "@off." << std::hex << std::showbase << stream.pos() << std::endl;

    size_t current_pos = stream.pos();
    stream.setpos(start + child_node_offet);
    this->show_trie(output, output_prefix, stream, start, end, name);
    stream.setpos(current_pos);
  }
}

void DyldInfo::export_trie(const buffer_t& raw) {
  this->export_trie_ = raw;
}


void DyldInfo::rebase(const DyldInfo::info_t& info) {
  this->rebase_ = info;
}

void DyldInfo::bind(const DyldInfo::info_t& info) {
  this->bind_ = info;
}

void DyldInfo::weak_bind(const DyldInfo::info_t& info) {
  this->weak_bind_ = info;
}

void DyldInfo::lazy_bind(const DyldInfo::info_t& info) {
  this->lazy_bind_ = info;
}

void DyldInfo::export_info(const DyldInfo::info_t& info) {
  this->export_ = info;
}



void DyldInfo::set_rebase_offset(uint32_t offset) {
  this->rebase_ = {offset, std::get<1>(this->rebase())};
}
void DyldInfo::set_rebase_size(uint32_t size) {
  this->rebase_ = {std::get<0>(this->rebase()), size};
}


void DyldInfo::set_bind_offset(uint32_t offset) {
  this->bind_ = {offset, std::get<1>(this->bind())};
}
void DyldInfo::set_bind_size(uint32_t size) {
  this->bind_ = {std::get<0>(this->bind()), size};
}


void DyldInfo::set_weak_bind_offset(uint32_t offset) {
  this->weak_bind_ = {offset, std::get<1>(this->weak_bind())};
}
void DyldInfo::set_weak_bind_size(uint32_t size) {
  this->weak_bind_ = {std::get<0>(this->weak_bind()), size};
}


void DyldInfo::set_lazy_bind_offset(uint32_t offset) {
  this->lazy_bind_ = {offset, std::get<1>(this->lazy_bind())};
}
void DyldInfo::set_lazy_bind_size(uint32_t size) {
  this->lazy_bind_ = {std::get<0>(this->lazy_bind()), size};
}


void DyldInfo::set_export_offset(uint32_t offset) {
  this->export_ = {offset, std::get<1>(this->export_info())};
}
void DyldInfo::set_export_size(uint32_t size) {
  this->export_ = {std::get<0>(this->export_info()), size};
}

void DyldInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DyldInfo::operator==(const DyldInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DyldInfo::operator!=(const DyldInfo& rhs) const {
  return not (*this == rhs);
}


std::ostream& DyldInfo::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex << std::left;
  os << std::setw(11) << "Type "       << std::setw(10) << "Offset" << "Size" << std::endl;
  os << std::setw(11) << "Rebase: "    << std::setw(10) << std::get<0>(this->rebase())      << std::get<1>(this->rebase())      << std::endl;
  os << std::setw(11) << "Bind: "      << std::setw(10) << std::get<0>(this->bind())        << std::get<1>(this->bind())        << std::endl;
  os << std::setw(11) << "Weak bind: " << std::setw(10) << std::get<0>(this->weak_bind())   << std::get<1>(this->weak_bind())   << std::endl;
  os << std::setw(11) << "Lazy bind: " << std::setw(10) << std::get<0>(this->lazy_bind())   << std::get<1>(this->lazy_bind())   << std::endl;
  os << std::setw(11) << "Export: "    << std::setw(10) << std::get<0>(this->export_info()) << std::get<1>(this->export_info()) << std::endl;

  it_const_binding_info bindings = this->bindings();
  for (size_t i = 0; i < bindings.size(); ++i) {
    os << "Binding Info #" << std::dec << i << std::endl;
    os << "================" << std::endl;
    os << bindings[i] << std::endl;
  }


  it_const_export_info exports = this->exports();
  for (size_t i = 0; i < exports.size(); ++i) {
    os << "Export Info #" << std::dec << i << std::endl;
    os << "==============" << std::endl;
    os << exports[i] << std::endl;
  }
  return os;
}


}
}
