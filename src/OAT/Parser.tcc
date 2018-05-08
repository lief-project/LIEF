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

#include <type_traits>

#include "LIEF/logging++.hpp"

#include "LIEF/utils.hpp"

#include "LIEF/DEX.hpp"

#include "Header.tcc"
#include "Object.tcc"

#include "oat_64.tcc"
#include "oat_79.tcc"
#include "oat_124.tcc"
#include "oat_131.tcc"

namespace LIEF {
namespace OAT {


template<>
void Parser::parse_dex_files<OAT88_t>(void) {
  return this->parse_dex_files<OAT79_t>();
}

template<>
void Parser::parse_oat_classes<OAT88_t>(void) {
  return this->parse_oat_classes<OAT79_t>();
}


// Parse Binary
// ============
template<>
void Parser::parse_binary<OAT64_t>(void) {

  std::vector<uint8_t> raw_oat;

  if (this->oat_binary_->has_symbol("oatdata")) {
    const LIEF::ELF::Symbol* oat_data = this->oat_binary_->get_symbol("oatdata").as<LIEF::ELF::Symbol>();

    raw_oat.reserve(oat_data->size());

    const std::vector<uint8_t>& raw_data = this->oat_binary_->get_content_from_virtual_address(oat_data->value(), oat_data->size());
    std::move(std::begin(raw_data), std::end(raw_data), std::back_inserter(raw_oat));

    this->data_address_ = oat_data->value();
    this->data_size_    = oat_data->size();
  }

  if (this->oat_binary_->has_symbol("oatexec")) {
    const LIEF::ELF::Symbol* oat_exec = this->oat_binary_->get_symbol("oatexec").as<LIEF::ELF::Symbol>();

    this->exec_start_ = oat_exec->value();
    this->exec_size_  = oat_exec->size();

    const std::vector<uint8_t>& raw_oatexec = this->oat_binary_->get_content_from_virtual_address(oat_exec->value(), oat_exec->size());

    uint32_t padding = this->exec_start_ - (this->data_address_ + this->data_size_);

    raw_oat.reserve(raw_oat.size() + oat_exec->size() + padding);
    raw_oat.insert(std::end(raw_oat), padding, 0);

    std::move(std::begin(raw_oatexec), std::end(raw_oatexec), std::back_inserter(raw_oat));
  }

  uint32_t padding = align(raw_oat.size(), sizeof(uint32_t) * 8) - raw_oat.size();
  raw_oat.insert(std::end(raw_oat), padding, 0);

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{std::move(raw_oat)});

  this->parse_header<OAT64_t>();
  this->parse_dex_files<OAT64_t>();
  this->parse_oat_classes<OAT64_t>();
}

template<>
void Parser::parse_binary<OAT79_t>(void) {

  std::vector<uint8_t> raw_oat;

  if (this->oat_binary_->has_symbol("oatdata")) {
    const LIEF::ELF::Symbol* oat_data = this->oat_binary_->get_symbol("oatdata").as<LIEF::ELF::Symbol>();

    raw_oat.reserve(oat_data->size());

    const std::vector<uint8_t>& raw_data = this->oat_binary_->get_content_from_virtual_address(oat_data->value(), oat_data->size());
    std::move(std::begin(raw_data), std::end(raw_data), std::back_inserter(raw_oat));

    this->data_address_ = oat_data->value();
    this->data_size_    = oat_data->size();
  }

  if (this->oat_binary_->has_symbol("oatexec")) {
    const LIEF::ELF::Symbol* oat_exec = this->oat_binary_->get_symbol("oatexec").as<LIEF::ELF::Symbol>();

    this->exec_start_ = oat_exec->value();
    this->exec_size_  = oat_exec->size();

    const std::vector<uint8_t>& raw_oatexec = this->oat_binary_->get_content_from_virtual_address(oat_exec->value(), oat_exec->size());

    uint32_t padding = this->exec_start_ - (this->data_address_ + this->data_size_);

    raw_oat.reserve(raw_oat.size() + oat_exec->size() + padding);
    raw_oat.insert(std::end(raw_oat), padding, 0);

    std::move(std::begin(raw_oatexec), std::end(raw_oatexec), std::back_inserter(raw_oat));
  }

  uint32_t padding = align(raw_oat.size(), sizeof(uint32_t) * 8) - raw_oat.size();
  raw_oat.insert(std::end(raw_oat), padding, 0);

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{std::move(raw_oat)});


  this->parse_header<OAT79_t>();
  this->parse_dex_files<OAT79_t>();

  this->parse_type_lookup_table<OAT79_t>();
  this->parse_oat_classes<OAT79_t>();
}

template<>
void Parser::parse_binary<OAT88_t>(void) {
  std::vector<uint8_t> raw_oat;

  if (this->oat_binary_->has_symbol("oatdata")) {
    const LIEF::ELF::Symbol* oat_data = this->oat_binary_->get_symbol("oatdata").as<LIEF::ELF::Symbol>();

    raw_oat.reserve(oat_data->size());

    const std::vector<uint8_t>& raw_data = this->oat_binary_->get_content_from_virtual_address(oat_data->value(), oat_data->size());
    std::move(std::begin(raw_data), std::end(raw_data), std::back_inserter(raw_oat));

    this->data_address_ = oat_data->value();
    this->data_size_    = oat_data->size();
  }

  if (this->oat_binary_->has_symbol("oatexec")) {
    const LIEF::ELF::Symbol* oat_exec = this->oat_binary_->get_symbol("oatexec").as<LIEF::ELF::Symbol>();

    this->exec_start_ = oat_exec->value();
    this->exec_size_  = oat_exec->size();

    const std::vector<uint8_t>& raw_oatexec = this->oat_binary_->get_content_from_virtual_address(oat_exec->value(), oat_exec->size());

    uint32_t padding = this->exec_start_ - (this->data_address_ + this->data_size_);

    raw_oat.reserve(raw_oat.size() + oat_exec->size() + padding);
    raw_oat.insert(std::end(raw_oat), padding, 0);

    std::move(std::begin(raw_oatexec), std::end(raw_oatexec), std::back_inserter(raw_oat));
  }

  uint32_t padding = align(raw_oat.size(), sizeof(uint32_t) * 8) - raw_oat.size();
  raw_oat.insert(std::end(raw_oat), padding, 0);

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{std::move(raw_oat)});


  this->parse_header<OAT88_t>();
  this->parse_dex_files<OAT88_t>();

  this->parse_type_lookup_table<OAT88_t>();
  this->parse_oat_classes<OAT88_t>();
}

template<>
void Parser::parse_binary<OAT124_t>(void) {
  std::vector<uint8_t> raw_oat;

  if (this->oat_binary_->has_symbol("oatdata")) {
    const LIEF::ELF::Symbol* oat_data = this->oat_binary_->get_symbol("oatdata").as<LIEF::ELF::Symbol>();

    raw_oat.reserve(oat_data->size());

    const std::vector<uint8_t>& raw_data = this->oat_binary_->get_content_from_virtual_address(oat_data->value(), oat_data->size());
    std::move(std::begin(raw_data), std::end(raw_data), std::back_inserter(raw_oat));

    this->data_address_ = oat_data->value();
    this->data_size_    = oat_data->size();
  }

  if (this->oat_binary_->has_symbol("oatexec")) {
    const LIEF::ELF::Symbol* oat_exec = this->oat_binary_->get_symbol("oatexec").as<LIEF::ELF::Symbol>();

    this->exec_start_ = oat_exec->value();
    this->exec_size_  = oat_exec->size();

    const std::vector<uint8_t>& raw_oatexec = this->oat_binary_->get_content_from_virtual_address(oat_exec->value(), oat_exec->size());

    uint32_t padding = this->exec_start_ - (this->data_address_ + this->data_size_);

    raw_oat.reserve(raw_oat.size() + oat_exec->size() + padding);
    raw_oat.insert(std::end(raw_oat), padding, 0);

    std::move(std::begin(raw_oatexec), std::end(raw_oatexec), std::back_inserter(raw_oat));
  }

  uint32_t padding = align(raw_oat.size(), sizeof(uint32_t) * 8) - raw_oat.size();
  raw_oat.insert(std::end(raw_oat), padding, 0);

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{std::move(raw_oat)});


  this->parse_header<OAT124_t>();
  this->parse_dex_files<OAT124_t>();
  if (this->has_vdex()) {
    this->parse_type_lookup_table<OAT124_t>();
    this->parse_oat_classes<OAT124_t>();
  }
}

template<>
void Parser::parse_binary<OAT131_t>(void) {
  std::vector<uint8_t> raw_oat;

  if (this->oat_binary_->has_symbol("oatdata")) {
    const LIEF::ELF::Symbol* oat_data = this->oat_binary_->get_symbol("oatdata").as<LIEF::ELF::Symbol>();

    raw_oat.reserve(oat_data->size());

    const std::vector<uint8_t>& raw_data = this->oat_binary_->get_content_from_virtual_address(oat_data->value(), oat_data->size());
    std::move(std::begin(raw_data), std::end(raw_data), std::back_inserter(raw_oat));

    this->data_address_ = oat_data->value();
    this->data_size_    = oat_data->size();
  }

  if (this->oat_binary_->has_symbol("oatexec")) {
    const LIEF::ELF::Symbol* oat_exec = this->oat_binary_->get_symbol("oatexec").as<LIEF::ELF::Symbol>();

    this->exec_start_ = oat_exec->value();
    this->exec_size_  = oat_exec->size();

    const std::vector<uint8_t>& raw_oatexec = this->oat_binary_->get_content_from_virtual_address(oat_exec->value(), oat_exec->size());

    uint32_t padding = this->exec_start_ - (this->data_address_ + this->data_size_);

    raw_oat.reserve(raw_oat.size() + oat_exec->size() + padding);
    raw_oat.insert(std::end(raw_oat), padding, 0);

    std::move(std::begin(raw_oatexec), std::end(raw_oatexec), std::back_inserter(raw_oat));
  }

  uint32_t padding = align(raw_oat.size(), sizeof(uint32_t) * 8) - raw_oat.size();
  raw_oat.insert(std::end(raw_oat), padding, 0);

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{std::move(raw_oat)});

  this->parse_header<OAT131_t>();
  this->parse_dex_files<OAT131_t>();

  if (this->has_vdex()) {
    this->parse_type_lookup_table<OAT131_t>();
    this->parse_oat_classes<OAT131_t>();
  }
}



template<typename OAT_T>
void Parser::parse_header(void) {
  VLOG(VDEBUG) << "Parsing OAT header";
  using oat_header = typename OAT_T::oat_header;

  const oat_header& oat_hdr = this->stream_->peek<oat_header>(0);
  this->oat_binary_->header_ = &oat_hdr;
  VLOG(VDEBUG) << "Nb dex files: " << std::dec << this->oat_binary_->header_.nb_dex_files();
  VLOG(VDEBUG) << "OAT version: " << std::dec << oat_hdr.oat_version;

  this->parse_header_keys<OAT_T>();
}


template<typename OAT_T>
void Parser::parse_header_keys(void) {
  using oat_header = typename OAT_T::oat_header;

  const uint64_t keys_offset = sizeof(oat_header);
  const size_t keys_size = this->oat_binary_->header_.key_value_size();

  std::string key_values;

  const char* keys_start = this->stream_->peek_array<char>(keys_offset, keys_size, /* check */false);
  if (keys_start != nullptr) {
    key_values = {keys_start, keys_size};
  }

  for (HEADER_KEYS key : header_keys_list) {
    std::string key_str = std::string{'\0'} + Header::key_to_string(key);

    size_t pos = key_values.find(key_str);

    if (pos != std::string::npos) {
      std::string value = std::string{key_values.data() + pos + key_str.size() + 1};
      this->oat_binary_->header_.dex2oat_context_.emplace(key, value);
    }
  }
}



template<typename OAT_T>
void Parser::parse_type_lookup_table(void) {
  //using oat_header           = typename OAT_T::oat_header;
  //using dex_file             = typename OAT_T::dex_file;
  //using lookup_table_entry_t = typename OAT_T::lookup_table_entry_t;


  //VLOG(VDEBUG) << "Parsing TypeLookupTable";
  //for (size_t i = 0; i < this->oat_binary_->dex_files_.size(); ++i) {

  //  const DexFile* oat_dex_file = this->oat_binary_->oat_dex_files_[i];
  //  uint64_t tlt_offset = oat_dex_file->lookup_table_offset();

  //  VLOG(VDEBUG) << "Getting TypeLookupTable for DexFile "
  //                << oat_dex_file->location()
  //                << " (#" << std::dec << oat_dex_file->dex_file().header().nb_classes() << ")";
  //  for (size_t j = 0; j < oat_dex_file->dex_file().header().nb_classes();) {
  //    const lookup_table_entry_t* entry = reinterpret_cast<const lookup_table_entry_t*>(this->stream_->read(tlt_offset, sizeof(lookup_table_entry_t)));

  //    if (entry->str_offset) {
  //      uint64_t string_offset = oat_dex_file->dex_offset() + entry->str_offset;
  //      std::pair<uint64_t, uint64_t> len_size = this->stream_->read_uleb128(string_offset);
  //      string_offset += len_size.second;
  //      std::string class_name = this->stream_->get_string(string_offset);
  //      //VLOG(VDEBUG) << "    " << "#" << std::dec << j << " " << class_name;
  //      ++j;
  //    }
  //    tlt_offset += sizeof(lookup_table_entry_t);
  //  }
  //}
}


template<typename OAT_T>
void Parser::parse_oat_classes(void) {
  VLOG(VDEBUG) << "Parsing OAT Classes";
  for (size_t dex_idx = 0; dex_idx < this->oat_binary_->oat_dex_files_.size(); ++dex_idx) {
    DexFile* oat_dex_file = this->oat_binary_->oat_dex_files_[dex_idx];
    const DEX::File& dex_file = oat_dex_file->dex_file();

    const std::vector<uint32_t>& classes_offsets = oat_dex_file->classes_offsets();
    uint32_t nb_classes = dex_file.header().nb_classes();

    VLOG(VDEBUG) << "Dealing with DexFile #" << std::dec << dex_idx
                 << " (" << nb_classes << ")";

    for (size_t class_idx = 0; class_idx < nb_classes; ++class_idx) {
      const DEX::Class& cls = dex_file.get_class(class_idx);

      CHECK_LE(cls.index(), classes_offsets.size());
      uint32_t oat_class_offset = classes_offsets[cls.index()];
      this->stream_->setpos(oat_class_offset);

      // OAT Status
      OAT_CLASS_STATUS status = static_cast<OAT_CLASS_STATUS>(this->stream_->read<int16_t>());

      // OAT Type
      OAT_CLASS_TYPES type = static_cast<OAT_CLASS_TYPES>(this->stream_->read<uint16_t>());

      // Bitmap (if type is "some compiled")
      uint32_t method_bitmap_size = 0;
      std::vector<uint32_t> bitmap;

      if (type == OAT_CLASS_TYPES::OAT_CLASS_SOME_COMPILED) {
        method_bitmap_size = this->stream_->read<uint32_t>();
        const uint32_t nb_entries = method_bitmap_size / sizeof(uint32_t);

        const uint32_t* raw = this->stream_->read_array<uint32_t>(nb_entries, /* check */false);
        if (raw != nullptr) {
          bitmap = {raw, raw + nb_entries};
        }
      }

      Class* oat_class = new Class{status, type, const_cast<DEX::Class*>(&cls), bitmap};
      this->oat_binary_->classes_.emplace(cls.fullname(), oat_class);


      // Methods Offsets
      const uint64_t method_offsets = this->stream_->pos();
      this->parse_oat_methods<OAT_T>(method_offsets, oat_class, cls);
    }
  }
}

template<typename OAT_T>
void Parser::parse_oat_methods(uint64_t methods_offsets, Class* clazz, const DEX::Class& dex_class) {
  using oat_quick_method_header = typename OAT_T::oat_quick_method_header;
  DEX::it_const_methods methods = dex_class.methods();

  for (size_t method_idx = 0; method_idx < methods.size(); ++method_idx) {

    const DEX::Method& method = methods[method_idx];
    if (not clazz->is_quickened(method)) {
      continue;
    }

    uint32_t computed_index = clazz->method_offsets_index(method);
    uint32_t code_off = this->stream_->peek<uint32_t>(methods_offsets + computed_index * sizeof(uint32_t));

    // Offset of the Quick method header relative to the beginning of oatexec
    uint32_t quick_method_header_off = code_off - sizeof(oat_quick_method_header);
    quick_method_header_off &= ~1u;

    if (not this->stream_->can_read<oat_quick_method_header>(quick_method_header_off)) {
      break;
    }

    const oat_quick_method_header& quick_header = this->stream_->peek<oat_quick_method_header>(quick_method_header_off);

    uint32_t vmap_table_offset = code_off - quick_header.vmap_table_offset;

    std::unique_ptr<Method> oat_method{new Method{const_cast<DEX::Method*>(&method), clazz}};

    if (quick_header.code_size > 0) {

      const uint8_t* code = this->stream_->peek_array<uint8_t>(code_off, quick_header.code_size, /* check */false);
      if (code != nullptr) {
        oat_method->quick_code_ = {code, code + quick_header.code_size};
      }
    }

    // Quickened with "Optimizing compiler"
    if (quick_header.code_size > 0 and vmap_table_offset > 0) {
    }

    // Quickened with "dex2dex"
    if (quick_header.code_size == 0 and vmap_table_offset > 0) {
      this->stream_->setpos(vmap_table_offset);

      for (size_t pc = 0, round = 0; pc < method.bytecode().size(); ++round) {
        if (this->stream_->pos() >= this->stream_->size()) {
          break;
        }

        uint32_t new_pc = static_cast<uint32_t>(this->stream_->read_uleb128());

        if (new_pc <= pc and round > 0) {
          break;
        }

        pc = new_pc;


        if (this->stream_->pos() >= this->stream_->size()) {
          break;
        }

        uint32_t index = static_cast<uint32_t>(this->stream_->read_uleb128());
        oat_method->dex_method().insert_dex2dex_info(pc, index);
      }

    }
    clazz->methods_.push_back(oat_method.get());
    this->oat_binary_->methods_.push_back(oat_method.release());
  }

}

}
}
