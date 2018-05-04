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
#include "LIEF/logging++.hpp"

#include "LIEF/utils.hpp"

#include "LIEF/ART/EnumToString.hpp"
#include "LIEF/PE/utils.hpp"

namespace LIEF {
namespace ART {

template<typename ART_T>
void Parser::parse_file(void) {
  VLOG(VDEBUG) << "Parsing ART version " << std::dec << ART_T::art_version;
  const size_t ptr_size = this->parse_header<ART_T>();
}

template<typename ART_T>
size_t Parser::parse_header(void) {
  using art_header_t = typename ART_T::art_header_t;

  const art_header_t& hdr = this->stream_->peek<art_header_t>(0);
  this->imagebase_ = hdr.image_begin;
  CHECK_EQ(hdr.patch_delta, 0);
  if (hdr.pointer_size != sizeof(uint32_t) and hdr.pointer_size != sizeof(uint64_t)) {
    throw corrupted("Wrong pointer size!");
  }
  this->file_->header_ = &hdr;
  return hdr.pointer_size;
}

#if 0
template<typename ART_T, typename PTR_T>
void Parser::parse_sections(void) {
  using IMAGE_SECTIONS = typename ART_T::IMAGE_SECTIONS;
  using art_header_t   = typename ART_T::art_header_t;
  using jarray_t       = typename ART_T::template jarray_t<>;
  using jclass_t       = typename ART_T::template jclass_t<>;
  using jobject_t       = typename ART_T::template jobject_t<>;

  VLOG(VDEBUG) << "Parsing Image Sections" << std::endl;
  size_t nb_sections = this->file_->header().nb_sections_;

  const art_header_t& hdr = this->stream_->peek<art_header_t>(0);

  VLOG(VDEBUG) << "Parsing " << std::dec << this->file_->header().nb_sections_ << " sections";

  size_t start_offset = align(sizeof(art_header_t), sizeof(uint64_t));
  // TODO: Check section size number
  for (size_t i = 0; i < nb_sections; ++i) {
    IMAGE_SECTIONS section_type = static_cast<IMAGE_SECTIONS>(i);
    ART::image_section_t section_header = hdr.sections[i];

    uint64_t jarray_offset = start_offset;
    if (i == 1) {
      jarray_offset = align(sizeof(art_header_t) + sizeof(jarray_t) + (3409 - 1) * sizeof(uint32_t), sizeof(uint64_t));
    }

    if (i == 2) {
      jarray_offset = align(sizeof(art_header_t) + sizeof(jarray_t) + (3409 - 1) * sizeof(uint32_t), sizeof(uint64_t));
      jarray_offset += sizeof(jarray_t) + 2 * (32062 - 1) * (sizeof(uint32_t));
      jarray_offset = align(jarray_offset, sizeof(uint64_t));
      //jarray_offset = 0x700e1db0 - this->imagebase_;
    }
    std::cout << "addr:" << std::hex << this->imagebase_ + jarray_offset << std::endl;

    const jarray_t* array = reinterpret_cast<const jarray_t*>(this->stream_->read(jarray_offset, sizeof(jarray_t)));
    uint64_t elements_offset = jarray_offset + offsetof(jarray_t, elements);



    VLOG(VDEBUG) << to_string(section_type) << "@" << std::hex << section_header.offset
                 << " --> " << (section_header.offset + section_header.size)
                 << " #" << std::dec << array->length;

    std::cout << std::hex << this->stream_->read_integer<uint32_t>(jarray_offset) << std::endl;
    std::cout << std::hex << this->stream_->read_integer<uint32_t>(jarray_offset + sizeof(uint32_t)) << std::endl;
    std::cout << std::hex << this->stream_->read_integer<uint32_t>(jarray_offset + 2 * sizeof(uint32_t)) << std::endl;
    std::cout << std::hex << this->stream_->read_integer<uint32_t>(jarray_offset + 3 * sizeof(uint32_t)) << std::endl;
    std::cout << std::hex << this->stream_->read_integer<uint32_t>(jarray_offset + 4 * sizeof(uint32_t)) << std::endl;


    uint32_t parent  = array->object.klass - this->imagebase_;
    const jclass_t* pp = reinterpret_cast<const jclass_t*>(this->stream_->read(parent, sizeof(jclass_t)));
    this->parse_jstring<ART_T, PTR_T>(pp->name - this->imagebase_);

    switch (section_type) {
      case IMAGE_SECTIONS::SECTION_OBJECTS:
        {

          // '0x70000090'
          this->parse_objects<ART_T, PTR_T>(elements_offset, array->length);
          break;
        }

      case IMAGE_SECTIONS::SECTION_ART_FIELDS:
        {
          // '0x700035e0'
          this->parse_art_fields<ART_T, PTR_T>(elements_offset, array->length);
          break;
        }

      case IMAGE_SECTIONS::SECTION_ART_METHODS:
        {
          // 0x6ff99db0: long[] length:65533
          this->parse_art_methods<ART_T, PTR_T>(elements_offset, array->length);
          break;
        }

      case IMAGE_SECTIONS::SECTION_INTERNED_STRINGS:
        {
          this->parse_interned_strings<ART_T, PTR_T>(elements_offset, array->length);
          break;
        }

      default:
        {
          LOG(WARNING) << to_string(section_type) << " is not handle yet!";
        }
    }

  }
}


template<typename ART_T, typename PTR_T>
void Parser::parse_roots(void) {
  using jarray_t = typename ART_T::template jarray_t<>;
  VLOG(VDEBUG) << "Parsing Image Roots" << std::endl;
  using IMAGE_ROOTS = typename ART_T::IMAGE_ROOTS;

  uint32_t image_root_offset = this->file_->header().image_roots_ - this->file_->header().image_begin_;

  VLOG(VDEBUG) << "Image root at: " << std::hex << std::showbase << this->file_->header().image_roots_;
  VLOG(VDEBUG) << "Image root offset: " << std::hex << std::showbase << image_root_offset;

  const jarray_t* array = reinterpret_cast<const jarray_t*>(this->stream_->read(image_root_offset, sizeof(jarray_t)));
  std::cout << "Nb elements: " << array->length << std::endl;

  const uint32_t* array_values = reinterpret_cast<const uint32_t*>(
      this->stream_->read(
        image_root_offset + offsetof(jarray_t, elements),
        array->length * sizeof(uint32_t)
      ));


  for (size_t i = 0; i < ART_T::nb_image_roots; ++i) {
    IMAGE_ROOTS type = static_cast<IMAGE_ROOTS>(i);
    uint64_t struct_offset = array_values[i] - this->imagebase_;
    std::cout << std::hex << struct_offset << std::endl;
    const jarray_t* array = reinterpret_cast<const jarray_t*>(this->stream_->read(struct_offset, sizeof(jarray_t)));
    std::cout << "Nb elements: " << std::dec << array->length << std::endl;
    switch (type) {
      case IMAGE_ROOTS::DEX_CACHES:
        {
          this->parse_dex_caches<ART_T, PTR_T>(struct_offset + offsetof(jarray_t, elements), array->length);
          break;
        }

      case IMAGE_ROOTS::CLASS_ROOTS:
        {
          this->parse_class_roots<ART_T, PTR_T>(struct_offset + offsetof(jarray_t, elements), array->length);
          break;
        }

      case ART_44::IMAGE_ROOTS::CLASS_LOADER:
        {
          //this->parse_dex_caches<ART_T, PTR_T>(struct_offset + offsetof(jarray_t, elements), array->length);
          break;
        }

      default:
        {
          LOG(WARNING) << to_string(type) << " is not handle yet!";
        }
    }

  }
}


template<typename ART_T, typename PTR_T>
void Parser::parse_class_roots(size_t offset, size_t size) {
  using jclass_t = typename ART_T::template jclass_t<>;
  using jstring_t    = typename ART_T::template jstring_t<>;
  VLOG(VDEBUG) << "Parsing Class Roots" << std::endl;

  for (size_t i = 0; i < size; ++i) {
    uint32_t object_offset = this->stream_->read_integer<uint32_t>(offset + i * sizeof(uint32_t)) - this->imagebase_;
    this->parse_class<ART_T, PTR_T>(object_offset);
  }
}

template<typename ART_T, typename PTR_T>
void Parser::parse_class(size_t offset) {
  using jclass_t     = typename ART_T::template jclass_t<>;
  using jstring_t    = typename ART_T::template jstring_t<>;

  const jclass_t* cls = reinterpret_cast<const jclass_t*>(this->stream_->read(offset, sizeof(jclass_t)));
  this->parse_jstring<ART_T, PTR_T>(cls->name - this->imagebase_);
}

template<typename ART_T, typename PTR_T>
void Parser::parse_jstring(size_t offset) {
  using jstring_t    = typename ART_T::template jstring_t<>;
  const jstring_t* jstring = reinterpret_cast<const jstring_t*>(this->stream_->read(offset, sizeof(jstring_t)));
  //std::cout << "Class leng: " << std::dec << jstring->count << std::endl;

  uint64_t value_offset = offset + offsetof(jstring_t, value);

  std::u16string str = {
    reinterpret_cast<const char16_t*>(this->stream_->read(value_offset, static_cast<uint16_t>(jstring->count) * sizeof(char16_t))),
    static_cast<uint16_t>(jstring->count)
  };
  std::cout << u16tou8(str)  << std::endl;
}

template<typename ART_T, typename PTR_T>
void Parser::parse_dex_caches(size_t offset, size_t size) {
  using jobject_t    = typename ART_T::template jobject_t<>;
  using jarray_t     = typename ART_T::template jarray_t<>;
  using jclass_t     = typename ART_T::template jclass_t<>;
  using jstring_t    = typename ART_T::template jstring_t<>;
  using jdex_cache_t = typename ART_T::template jdex_cache_t<>;

  VLOG(VDEBUG) << "Parsing Dex Cache" << std::endl;

  for (size_t i = 0; i < size; ++i) {
    uint32_t object_offset = this->stream_->read_integer<uint32_t>(offset + i * sizeof(uint32_t)) - this->imagebase_;
    this->parse_dex_cache<ART_T, PTR_T>(object_offset);
  }
}

template<typename ART_T, typename PTR_T>
void Parser::parse_dex_cache(size_t object_offset) {
  using jstring_t    = typename ART_T::template jstring_t<>;
  using jdex_cache_t = typename ART_T::template jdex_cache_t<>;
  const jdex_cache_t* cache = reinterpret_cast<const jdex_cache_t*>(this->stream_->read(object_offset, sizeof(jdex_cache_t)));
  const jstring_t* location = reinterpret_cast<const jstring_t*>(this->stream_->read(cache->location - this->imagebase_, sizeof(jstring_t)));

  uint64_t name_offset = cache->location - this->imagebase_ + offsetof(jstring_t, value);

  if (location->count & 1) {
    size_t len = location->count >> 1;

    std::string location_string = {
      reinterpret_cast<const char*>(this->stream_->read(name_offset, static_cast<uint16_t>(len) * sizeof(char))),
      len
    };
    std::cout << location_string  << std::endl;
  } else {

    std::u16string location_string = {
      reinterpret_cast<const char16_t*>(this->stream_->read(name_offset, static_cast<uint16_t>(location->count) * sizeof(char16_t))),
      static_cast<uint16_t>(location->count)
    };
    std::cout << u16tou8(location_string)  << std::endl;
  }
}

template<typename ART_T, typename PTR_T>
void Parser::parse_methods(void) {
  using art_header_t = typename ART_T::art_header_t;
  using IMAGE_METHODS = typename ART_T::IMAGE_METHODS;

  VLOG(VDEBUG) << "Parsing Image Methods" << std::endl;


  const art_header_t* hdr = reinterpret_cast<const art_header_t*>(this->stream_->read(0, sizeof(art_header_t)));

  uint32_t nb_methods = this->file_->header().nb_methods_;
  //TODO check with ART::nb_methods... (more secure)
  for (size_t i = 0; i < nb_methods; ++i) {
    IMAGE_METHODS type = static_cast<IMAGE_METHODS>(i);
    uint64_t address = hdr->image_methods[i];
    VLOG(VDEBUG) << to_string(type) << " at " << std::showbase << std::hex << address;
  }
}


template<typename ART_T, typename PTR_T>
void Parser::parse_objects(size_t offset, size_t size) {
  using jobject_t = typename ART_T::template jobject_t<>;
  using jarray_t  = typename ART_T::template jarray_t<>;
  using jclass_t  = typename ART_T::template jclass_t<>;
  using jstring_t = typename ART_T::template jstring_t<>;

  VLOG(VDEBUG) << "Paring objects at " << std::hex << offset << std::endl;
  //const jarray_t* array = reinterpret_cast<const jarray_t*>(this->stream_->read(offset, sizeof(jarray_t)));
  //std::cout << std::dec << "nb elements " << array->length << std::endl;;
}


template<typename ART_T, typename PTR_T>
void Parser::parse_art_fields(size_t offset, size_t size) {
  VLOG(VDEBUG) << "Paring ART Fields at " << std::hex << offset << std::endl;
}

template<typename ART_T, typename PTR_T>
void Parser::parse_art_methods(size_t offset, size_t size) {
  VLOG(VDEBUG) << "Paring ART Methods at " << std::hex << offset << std::endl;
  // 0x6ff99db0: long[] length:65533
  const PTR_T* methods = reinterpret_cast<const PTR_T*>(this->stream_->read(offset, size));
  // 26740: 0x70a7ea60
  PTR_T get_device_id = methods[26740];

  std::cout << std::hex << "Get device ID " << get_device_id << std::endl;
}

template<typename ART_T, typename PTR_T>
void Parser::parse_interned_strings(size_t offset, size_t size) {

}
#endif

}
}
