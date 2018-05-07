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
#include <fstream>
#include "LIEF/DEX/File.hpp"
#include "LIEF/logging++.hpp"
#include "LIEF/DEX/instructions.hpp"
#include "LIEF/DEX/hash.hpp"

#include "LIEF/json.hpp"

namespace LIEF {
namespace DEX {

File::File(void) :
  name_{"classes.dex"},
  location_{""},
  header_{},
  classes_{},
  methods_{},
  strings_{},
  original_data_{}
{}


dex_version_t File::version(void) const {
  magic_t m = this->header().magic();
  const char* version = reinterpret_cast<const char*>(m.data() + sizeof(DEX::magic));
  return static_cast<dex_version_t>(std::stoul(version));
}

std::string File::save(const std::string path, bool deoptimize) const {
  if (path.empty()) {
    if (not this->name().empty()) {
      return this->save(this->name());
    } else {
      return this->save("classes.dex");
    }
  }

  if (std::ofstream ifs{path, std::ios::binary | std::ios::trunc}) {
    if (deoptimize) {
      const std::vector<uint8_t> raw = this->raw(deoptimize);
      ifs.write(reinterpret_cast<const char*>(raw.data()), raw.size());
    } else {
      ifs.write(reinterpret_cast<const char*>(this->original_data_.data()), this->original_data_.size());
    }
    return path;
  }

  return "";
}


std::vector<uint8_t> File::raw(bool deoptimize) const {
  if (not deoptimize) {
    return this->original_data_;
  }
  dex2dex_info_t dex2dex_info = this->dex2dex_info();

  if (dex2dex_info.size() == 0) {
    return this->original_data_;
  }

  std::vector<uint8_t> raw = this->original_data_;

  for (Method* method : this->methods_) {
    if (method->bytecode().size() == 0) {
      continue;
    }
    const uint32_t code_item_offset = method->code_offset();
    const uint8_t* inst_start = raw.data() + code_item_offset;
    uint8_t* inst_ptr = raw.data() + code_item_offset;
    uint8_t* inst_end = inst_ptr + method->bytecode().size();
    dex2dex_method_info_t meth_info = method->dex2dex_info();

    while (inst_ptr < inst_end) {
      uint16_t dex_pc = (inst_ptr - inst_start) / sizeof(uint16_t);
      OPCODES opcode = static_cast<OPCODES>(*inst_ptr);
      uint32_t value = -1u;

      if (meth_info.find(dex_pc) != std::end(meth_info)) {
        value = meth_info[dex_pc];
      }

      // Skip packed-switch, sparse-switch, fill-array instructions
      if (is_switch_array(inst_ptr, inst_end)) {
        inst_ptr += switch_array_size(inst_ptr, inst_end);
        continue;
      }

      switch(opcode) {
        case OPCODES::OP_NOP:
          {
            //deoptimize_nop(inst_ptr, 0);
            break;
          }

        case OPCODES::OP_RETURN_VOID_NO_BARRIER:
          {

            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] return-void-no-barrier -> return-void";
            deoptimize_return(inst_ptr, 0);
            break;
          }

        case OPCODES::OP_IGET_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iget-quick -> iget @" << std::dec << value;
            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iget-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IGET);
            break;
          }

        case OPCODES::OP_IGET_WIDE_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iget-wide-quick -> iget-wide @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iget-wide-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IGET_WIDE);
            break;
          }

        case OPCODES::OP_IGET_OBJECT_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iget-object-quick -> iget-object @" << std::dec << value;
            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iget-object-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IGET_OBJECT);
            break;
          }

        case OPCODES::OP_IPUT_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iput-quick -> iput @" << std::dec << value;
            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iput-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IPUT);
            break;
          }

        case OPCODES::OP_IPUT_WIDE_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iput-wide-quick -> iput-wide @" << std::dec << value;
            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iput-wide-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IPUT_WIDE);
            break;
          }

        case OPCODES::OP_IPUT_OBJECT_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iput-object-quick -> iput-object @" << std::dec << value;
            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iput-object-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IPUT_OBJECT);
            break;
          }

        case OPCODES::OP_INVOKE_VIRTUAL_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] invoke-virtual-quick -> invoke-virtual @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (invoke-virtual-quick)";
              break;
            }
            deoptimize_invoke_virtual(inst_ptr, value, OPCODES::OP_INVOKE_VIRTUAL);
            break;
          }

        case OPCODES::OP_INVOKE_VIRTUAL_RANGE_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] invoke-virtual-quick/range -> invoke-virtual/range @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (invoke-virtual-quick/range)";
              break;
            }
            deoptimize_invoke_virtual(inst_ptr, value, OPCODES::OP_INVOKE_VIRTUAL_RANGE);
            break;
          }

        case OPCODES::OP_IPUT_BOOLEAN_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iput-boolean-quick -> iput-boolean @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iput-boolean-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IPUT_BOOLEAN);
            break;
          }

        case OPCODES::OP_IPUT_BYTE_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iput-byte-quick -> iput-byte @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iput-byte-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IPUT_BYTE);
            break;
          }

        case OPCODES::OP_IPUT_CHAR_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iput-char-quick -> iput-char @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iput-char-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IPUT_CHAR);
            break;
          }

        case OPCODES::OP_IPUT_SHORT_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iput-short-quick -> iput-short @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iput-short-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IPUT_SHORT);
            break;
          }

        case OPCODES::OP_IGET_BOOLEAN_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iget-boolean-quick -> iget-boolean @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iget-boolean-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IGET_BOOLEAN);
            break;
          }

        case OPCODES::OP_IGET_BYTE_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iget-byte-quick -> iget-byte @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iget-byte-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IGET_BYTE);
            break;
          }

        case OPCODES::OP_IGET_CHAR_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iget-char-quick -> iget-char @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iget-char-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IGET_CHAR);
            break;
          }

        case OPCODES::OP_IGET_SHORT_QUICK:
          {
            VLOG_IF(false, VDEBUG) << method->cls().fullname() << "." << method->name();
            VLOG_IF(false, VDEBUG) << "[" << std::hex << dex_pc << "] iget-short-quick -> iget-short @" << std::dec << value;

            if (static_cast<int32_t>(value) == -1) {
              LOG(WARNING) << "Unable to resolve instruction: " << method->cls().fullname() << "." << method->name() << " at " << std::hex << dex_pc << " (iget-short-quick)";
              break;
            }
            deoptimize_instance_field_access(inst_ptr, value, OPCODES::OP_IGET_SHORT);
            break;
          }
        default:
          {
          }
      }
      inst_ptr += inst_size_from_opcode(opcode);
    }
  }

  return raw;
}

void File::deoptimize_nop(uint8_t* inst_ptr, uint32_t value) {
  *inst_ptr = OPCODES::OP_CHECK_CAST;
}

void File::deoptimize_return(uint8_t* inst_ptr, uint32_t value) {
  *inst_ptr = OPCODES::OP_RETURN_VOID;
}

void File::deoptimize_invoke_virtual(uint8_t* inst_ptr, uint32_t value, OPCODES new_inst) {
  *inst_ptr = new_inst;
  reinterpret_cast<uint16_t*>(inst_ptr)[1] = value;
}

void File::deoptimize_instance_field_access(uint8_t* inst_ptr, uint32_t value, OPCODES new_inst) {
  *inst_ptr = new_inst;
  reinterpret_cast<uint16_t*>(inst_ptr)[1] = value;
}

const std::string& File::name(void) const {
  return this->name_;
}


const std::string& File::location(void) const {
  return this->location_;
}


const Header& File::header(void) const {
  return this->header_;
}

Header& File::header(void) {
  return const_cast<Header&>(static_cast<const File*>(this)->header());
}

it_const_classes File::classes(void) const {
  classes_list_t classes;
  classes.reserve(this->classes_.size());

  std::transform(
      std::begin(this->classes_), std::end(this->classes_),
      std::back_inserter(classes),
      [] (std::pair<std::string, Class*> it) {
        return it.second;
      });
  return classes;
}

it_classes File::classes(void) {
  classes_list_t classes;
  classes.reserve(this->classes_.size());

  std::transform(
      std::begin(this->classes_), std::end(this->classes_),
      std::back_inserter(classes),
      [] (std::pair<std::string, Class*> it) {
        return it.second;
      });
  return classes;
}

bool File::has_class(const std::string& class_name) const {
  return this->classes_.find(Class::fullname_normalized(class_name)) != std::end(this->classes_);
}

const Class& File::get_class(const std::string& class_name) const {
  if (not this->has_class(class_name)) {
    throw not_found(class_name);
  }
  return *(this->classes_.find(Class::fullname_normalized(class_name))->second);
}

Class& File::get_class(const std::string& class_name) {
  return const_cast<Class&>(static_cast<const File*>(this)->get_class(class_name));
}


const Class& File::get_class(size_t index) const {
  if (index >= this->classes_.size()) {
    throw not_found("Can't find class at index " + std::to_string(index));
  }
  return *this->class_list_[index];

}

Class& File::get_class(size_t index) {
  return const_cast<Class&>(static_cast<const File*>(this)->get_class(index));
}


dex2dex_info_t File::dex2dex_info(void) const {
  dex2dex_info_t info;
  for (auto&& p : this->classes_) {
    dex2dex_class_info_t class_info = p.second->dex2dex_info();
    if (class_info.size() > 0) {
      info.emplace(p.second, std::move(class_info));
    }
  }
  return info;
}

std::string File::dex2dex_json_info(void) {

#if defined(LIEF_JSON_SUPPORT)
  json mapping = json::object();

  // Iter over the class quickened
  for (auto&& class_map : this->dex2dex_info()) {
    const Class* clazz = class_map.first;
    const std::string& class_name = clazz->fullname();
    mapping[class_name] = json::object();

    const dex2dex_class_info_t& class_info = class_map.second;
    // Iter over the method within the class
    for (auto&& method_map : class_info) {

      // Index of the method within the Dex File
      uint32_t index = method_map.first->index();

      mapping[class_name][std::to_string(index)] = json::object();

      for (auto&& pc_index : method_map.second) {
        mapping[class_name][std::to_string(index)][std::to_string(pc_index.first)] = pc_index.second;
      }
    }
  }
  return mapping.dump();
#else
  return "";
#endif
}

it_const_methods File::methods(void) const {
  return this->methods_;
}

it_methods File::methods(void) {
  return this->methods_;
}


it_const_strings File::strings(void) const {
  return this->strings_;
}

it_strings File::strings(void) {
  return this->strings_;
}

it_const_types File::types(void) const {
  return this->types_;
}

it_types File::types(void) {
  return this->types_;
}


it_const_protypes File::prototypes(void) const {
  return this->prototypes_;
}

it_protypes File::prototypes(void) {
  return this->prototypes_;
}

const MapList& File::map(void) const {
  return this->map_;
}

MapList& File::map(void) {
  return this->map_;
}


void File::name(const std::string& name) {
  this->name_ = name;
}

void File::location(const std::string& location) {
  this->location_ = location;
}

void File::add_class(Class* cls) {
  this->classes_.emplace(cls->fullname(), cls);
  this->class_list_.push_back(cls);
}

void File::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool File::operator==(const File& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool File::operator!=(const File& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const File& file) {
  os << "DEX File " << file.name() << " Version: " << std::dec << file.version();
  if (not file.location().empty()) {
    os << " - " << file.location();
  }
  os << std::endl;

  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << file.header();

  os << std::endl;

  os << "Map" << std::endl;
  os << "===" << std::endl;

  os << file.map();

  os << std::endl;
  return os;
}

File::~File(void) {
  for (const std::pair<std::string, Class*>& p : this->classes_) {
    delete p.second;
  }

  for (Method* mtd : this->methods_) {
    delete mtd;
  }

  for (std::string* str : this->strings_) {
    delete str;
  }


  for (Type* t : this->types_) {
    delete t;
  }

  for (Prototype* pt : this->prototypes_) {
    delete pt;
  }
}



}
}
