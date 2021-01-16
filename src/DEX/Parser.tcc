/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include "logging.hpp"

#include "LIEF/utils.hpp"

#include "LIEF/DEX/Structures.hpp"

#include "Header.tcc"

namespace LIEF {
namespace DEX {

template<typename DEX_T>
void Parser::parse_file(void) {
  this->file_->original_data_ = this->stream_->content();

  this->parse_header<DEX_T>();
  this->parse_map<DEX_T>();
  this->parse_strings<DEX_T>();
  this->parse_types<DEX_T>();
  this->parse_fields<DEX_T>();
  this->parse_prototypes<DEX_T>();
  this->parse_methods<DEX_T>();
  this->parse_classes<DEX_T>();


  this->resolve_types();
  this->resolve_inheritance();
  this->resolve_external_methods();

}


template<typename DEX_T>
void Parser::parse_header(void) {
  using header_t = typename DEX_T::dex_header;
  LIEF_DEBUG("Parsing Header");

  const header_t& hdr = this->stream_->peek<header_t>(0);
  this->file_->header_ = &hdr;
}



template<typename DEX_T>
void Parser::parse_map(void) {
  LIEF_DEBUG("Parsing map items");

  uint32_t offset = this->file_->header().map();
  this->stream_->setpos(offset);
  if (not this->stream_->can_read<uint32_t>()) {
    return;
  }

  const uint32_t nb_elements = this->stream_->read<uint32_t>();
  for (size_t i = 0; i < nb_elements; ++i) {
    if (not this->stream_->can_read<map_items>()) {
      break;
    }
    const map_items& item = this->stream_->read<map_items>();
    const MapItem::TYPES type = static_cast<MapItem::TYPES>(item.type);
    this->file_->map_.items_[type] = {type, item.offset, item.size, item.unused};
  }
}

template<typename DEX_T>
void Parser::parse_strings(void) {
  // (Offset, Size)
  Header::location_t strings_location = this->file_->header().strings();
  if (strings_location.second == 0) {
    LIEF_WARN("No strings found in DEX file {}", this->file_->location());
    return;
  }

  LIEF_DEBUG("Parsing #{:d} STRINGS at 0x{:x}", strings_location.second, strings_location.first);

  if (this->file_->map().has(MapItem::TYPES::STRING_ID)) {
    const MapItem& string_item = this->file_->map()[MapItem::TYPES::STRING_ID];
    if (string_item.offset() != strings_location.first) {
      LIEF_WARN("Different values for string offset between map and header");
    }

    if (string_item.size() != strings_location.second) {
      LIEF_WARN("Different values for string size between map and header");
    }
  }

  this->file_->strings_.reserve(strings_location.second);
  for (size_t i = 0; i < strings_location.second; ++i) {
    uint32_t string_offset = this->stream_->peek<uint32_t>(strings_location.first + i * sizeof(uint32_t));
    this->stream_->setpos(string_offset);
    size_t str_size = this->stream_->read_uleb128(); // Code point count
    std::string string_value = this->stream_->read_mutf8(str_size);
    this->file_->strings_.push_back(new std::string{std::move(string_value)});
  }
}

template<typename DEX_T>
void Parser::parse_types(void) {
  Header::location_t types_location = this->file_->header().types();

  LIEF_DEBUG("Parsing #{:d} TYPES at 0x{:x}", types_location.second, types_location.first);

  if (types_location.first == 0) {
    return;
  }

  this->stream_->setpos(types_location.first);
  for (size_t i = 0; i < types_location.second; ++i) {
    if (not this->stream_->can_read<uint32_t>()) {
      break;
    }
    uint32_t descriptor_idx = this->stream_->read<uint32_t>();

    if (descriptor_idx > this->file_->strings_.size()) {
      break;
    }
    std::string* descriptor_str = this->file_->strings_[descriptor_idx];
    std::unique_ptr<Type> type{new Type{*descriptor_str}};

    if (type->type() == Type::TYPES::CLASS) {
      this->class_type_map_.emplace(*descriptor_str, type.get());

    }

    else if (type->type() == Type::TYPES::ARRAY) {
      const Type& array_type = type->underlying_array_type();
      if (array_type.type() == Type::TYPES::CLASS) {
        std::string mangled_name = *descriptor_str;
        mangled_name = mangled_name.substr(mangled_name.find_last_of('[') + 1);
        this->class_type_map_.emplace(mangled_name, type.get());
      }
    }

    this->file_->types_.push_back(type.release());
  }
}

template<typename DEX_T>
void Parser::parse_fields(void) {

  Header::location_t fields_location = this->file_->header().fields();
  LIEF_DEBUG("Parsing #{:d} FIELDS at 0x{:x}", fields_location.second, fields_location.first);
  // TODO(romain): To implement
}

template<typename DEX_T>
void Parser::parse_prototypes(void) {
  Header::location_t prototypes_locations = this->file_->header().prototypes();
  if (prototypes_locations.first == 0) {
    return;
  }

  LIEF_DEBUG("Parsing #{:d} PROTYPES at 0x{:x}", prototypes_locations.second, prototypes_locations.first);

  this->stream_->setpos(prototypes_locations.first);
  for (size_t i = 0; i < prototypes_locations.second; ++i) {
    if (not this->stream_->can_read<proto_id_item>()) {
      LIEF_WARN("Prototype #{:d} corrupted", i);
      break;
    }
    const proto_id_item& item = this->stream_->read<proto_id_item>();

    if (item.shorty_idx >= this->file_->strings_.size()) {
      LIEF_WARN("prototype.shorty_idx corrupted ({:d})", item.shorty_idx);
      break;
    }
    //std::string* shorty_str = this->file_->strings_[item.shorty_idx];

    // Type object that is returned
    if (item.return_type_idx >= this->file_->types_.size()) {
      LIEF_WARN("prototype.return_type_idx corrupted ({:d})", item.return_type_idx);
      break;
    }
    std::unique_ptr<Prototype> prototype{new Prototype{}};
    prototype->return_type_ = this->file_->types_[item.return_type_idx];


    if (item.parameters_off > 0 and this->stream_->can_read<uint32_t>(item.parameters_off)) {
      const size_t saved_pos = this->stream_->pos();
      this->stream_->setpos(item.parameters_off);
      size_t nb_params = this->stream_->read<uint32_t>();

      for (size_t i = 0; i < nb_params; ++i) {
        if (not this->stream_->can_read<uint32_t>()) {
          break;
        }
        uint32_t type_idx = this->stream_->read<uint32_t>();

        if (type_idx > this->file_->types_.size()) {
          break;
        }

        Type* param_type = this->file_->types_[type_idx];
        prototype->params_.push_back(param_type);
      }
      this->stream_->setpos(saved_pos);
    }

    this->file_->prototypes_.push_back(prototype.release());
  }


}

template<typename DEX_T>
void Parser::parse_methods(void) {
  Header::location_t methods_location = this->file_->header().methods();
  Header::location_t types_location = this->file_->header().types();

  const uint64_t methods_offset = methods_location.first;

  LIEF_DEBUG("Parsing #{:d} METHODS at 0x{:x}", methods_location.second, methods_location.first);

  for (size_t i = 0; i < methods_location.second; ++i) {
    const method_id_item& item = this->stream_->peek<method_id_item>(methods_offset + i * sizeof(method_id_item));


    // Class name in which the method is defined
    if (item.class_idx > types_location.second) {
      LIEF_WARN("Type index for class name is corrupted");
      continue;
    }
    uint32_t class_name_idx = this->stream_->peek<uint32_t>(types_location.first + item.class_idx * sizeof(uint32_t));

    if (class_name_idx > this->file_->strings_.size()) {
      LIEF_WARN("String index for class name is corrupted");
      continue;
    }
    std::string clazz = *this->file_->strings_[class_name_idx];
    if (not clazz.empty() and clazz[0] == '[') {
      size_t pos = clazz.find_last_of('[');
      clazz = clazz.substr(pos + 1);
    }

    //CHECK_EQ(clazz[0], 'L') << "Not supported class: " << clazz;


    // Prototype
    // =======================
    if (item.proto_idx >= this->file_->prototypes_.size()) {
      LIEF_WARN("Prototype #{:d} out of bound ({:d})", item.proto_idx, this->file_->prototypes_.size());
      break;
    }
    Prototype* pt = this->file_->prototypes_[item.proto_idx];

    // Method Name
    if (item.name_idx > this->file_->strings_.size()) {
      LIEF_WARN("Name of method #{:d} is out of bound!", i);
      continue;
    }

    std::string name = *this->file_->strings_[item.name_idx];
    if (clazz.empty()) {
      LIEF_WARN("Empty class name");
    }

    Method* method = new Method{name};
    if (name == "<init>" or name == "<clinit>") {
      method->access_flags_ |= ACCESS_FLAGS::ACC_CONSTRUCTOR;
    }
    method->original_index_ = i;
    method->prototype_ = pt;
    this->file_->methods_.push_back(method);


    if (not clazz.empty() and clazz[0] != '[') {
      this->class_method_map_.emplace(clazz, method);
    }
  }
}

template<typename DEX_T>
void Parser::parse_classes(void) {
  Header::location_t classes_location = this->file_->header().classes();
  Header::location_t types_location = this->file_->header().types();

  const uint64_t classes_offset = classes_location.first;

  LIEF_DEBUG("Parsing #{:d} CLASSES at 0x{:x}", classes_location.second, classes_offset);

  for (size_t i = 0; i < classes_location.second; ++i) {
    const class_def_item& item = this->stream_->peek<class_def_item>(classes_offset + i * sizeof(class_def_item));

    // Get full class name
    uint32_t type_idx = item.class_idx;

    std::string name;
    if (type_idx > types_location.second) {
      LIEF_ERR("Type Corrupted");
    } else {
      uint32_t class_name_idx = this->stream_->peek<uint32_t>(types_location.first + type_idx * sizeof(uint32_t));
      if (class_name_idx >= this->file_->strings_.size()) {
        LIEF_WARN("String index for class name corrupted");
      } else {
        name = *this->file_->strings_[class_name_idx];
      }
    }

    // Get parent class name (if any)
    std::string parent_name;
    Class* parent_ptr = nullptr;
    if (item.superclass_idx != NO_INDEX) {
      if (item.superclass_idx > types_location.second) {
        LIEF_WARN("Type index for super class name corrupted");
        continue;
      }
      uint32_t super_class_name_idx = this->stream_->peek<uint32_t>(
          types_location.first + item.superclass_idx * sizeof(uint32_t));
      if (super_class_name_idx >= this->file_->strings_.size()) {
        LIEF_WARN("String index for super class name corrupted");
      } else {
        parent_name = *this->file_->strings_[super_class_name_idx];
      }

      // Check if already parsed the parent class
      auto&& it_parent = this->file_->classes_.find(parent_name);
      if (it_parent != std::end(this->file_->classes_)) {
        parent_ptr = it_parent->second;
      }
    }

    // Get Source filename (if any)
    std::string source_filename;
    if (item.source_file_idx != NO_INDEX) {
      if (item.source_file_idx >= this->file_->strings_.size()) {
        LIEF_WARN("String index for source filename corrupted");
      } else {
        source_filename = *this->file_->strings_[item.source_file_idx];
      }
    }

    Class* clazz = new Class{name, item.access_flags, parent_ptr, source_filename};
    clazz->original_index_ = i;
    if (parent_ptr == nullptr) {
      // Register in inheritance map to be resolved later
      this->inheritance_.emplace(parent_name, clazz);
    }

    this->file_->add_class(clazz);

    // Parse class annotations
    if (item.annotations_off > 0) {
    }

    // Parse Class content
    if (item.class_data_off > 0) {
      this->parse_class_data<DEX_T>(item.class_data_off, clazz);
    }

  }

}


template<typename DEX_T>
void Parser::parse_class_data(uint32_t offset, Class* cls) {
  this->stream_->setpos(offset);

  // The number of static fields defined in this item
  uint64_t static_fields_size = this->stream_->read_uleb128();

  // The number of instance fields defined in this item
  uint64_t instance_fields_size = this->stream_->read_uleb128();

  // The number of direct methods defined in this item
  uint64_t direct_methods_size = this->stream_->read_uleb128();

  // The number of virtual methods defined in this item
  uint64_t virtual_methods_size = this->stream_->read_uleb128();

  cls->methods_.reserve(direct_methods_size + virtual_methods_size);

  // Static Fields
  // =============
  for (size_t field_idx = 0, i = 0; i < static_fields_size; ++i) {
    field_idx += this->stream_->read_uleb128();
    /* uint64_t access_flags = */ this->stream_->read_uleb128();
  }

  // Instances
  // =========
  for (size_t field_idx = 0, i = 0; i < instance_fields_size; ++i) {
    field_idx += this->stream_->read_uleb128();
    /* uint64_t access_flags = */ this->stream_->read_uleb128();
  }

  // Direct Methods
  // ==============
  for (size_t method_idx = 0, i = 0; i < direct_methods_size; ++i) {
    method_idx += this->stream_->read_uleb128();
    if (method_idx > this->file_->methods_.size()) {
      LIEF_WARN("Corrupted method index #{:d} for class: {} ({:d} methods)",
          method_idx, cls->fullname(), this->file_->methods_.size());
      break;
    }

    this->parse_method<DEX_T>(method_idx, cls, false);
  }

  // Virtual Methods
  // ===============
  for (size_t method_idx = 0, i = 0; i < virtual_methods_size; ++i) {
    method_idx += this->stream_->read_uleb128();

    if (method_idx > this->file_->methods_.size()) {
      LIEF_WARN("Corrupted method index #{:d} for class: {} ({:d} methods)",
          method_idx, cls->fullname(), virtual_methods_size);
      break;
    }
    this->parse_method<DEX_T>(method_idx, cls, true);
  }

}


template<typename DEX_T>
void Parser::parse_method(size_t index, Class* cls, bool is_virtual) {
  // Access Flags
  uint64_t access_flags = this->stream_->read_uleb128();

  // Dalvik bytecode offset
  uint64_t code_offset = this->stream_->read_uleb128();

  Method* method = this->file_->methods_[index];
  method->set_virtual(is_virtual);

  if (method->index() != index) {
    LIEF_WARN("method->index() is not consistent");
    return;
  }

  method->access_flags_ = static_cast<uint32_t>(access_flags);
  method->parent_ = cls;
  cls->methods_.push_back(method);

  auto&& range = this->class_method_map_.equal_range(cls->fullname());
  for (auto&& it = range.first; it != range.second;) {
    if (it->second == method) {
      it = this->class_method_map_.erase(it);
    } else {
      ++it;
    }
  }

  if (code_offset > 0) {
    this->parse_code_info<DEX_T>(code_offset, method);
  }
}

template<typename DEX_T>
void Parser::parse_code_info(uint32_t offset, Method* method) {
  const code_item& codeitem = this->stream_->peek<code_item>(offset);
  method->code_info_ = &codeitem;

  const uint8_t* bytecode = this->stream_->peek_array<uint8_t>(offset + sizeof(code_item), codeitem.insns_size * sizeof(uint16_t), /* check */false);
  method->code_offset_ = offset + sizeof(code_item);
  if (bytecode != nullptr) {
    method->bytecode_ = {bytecode, bytecode + codeitem.insns_size * sizeof(uint16_t)};
  }
}



}
}
