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

#include "LIEF/DEX/Type.hpp"
#include "LIEF/DEX/hash.hpp"
#include "LIEF/logging++.hpp"

namespace LIEF {
namespace DEX {

Type::Type(void) = default;

Type::Type(const std::string& mangled) {
  this->parse(mangled);
}


Type::Type(const Type& other) :
  Object{other},
  type_{other.type_}
{
  switch (this->type()) {
    case TYPES::ARRAY:
      {
        this->array_ = new array_t{};
        std::copy(
            std::begin(other.array()),
            std::end(other.array()),
            std::back_inserter(*this->array_));
        break;
      }

    case TYPES::CLASS:
      {
        this->cls_ = other.cls_;
        break;
      }

    case TYPES::PRIMITIVE:
      {
        this->basic_ = new PRIMITIVES{other.primitive()};
        break;
      }

    default:
      {}
  }
}

Type::TYPES Type::type(void) const {
  return this->type_;
}

const Class& Type::cls(void) const {
  return *this->cls_;
}

const Type::array_t& Type::array(void) const {
  return *this->array_;
}

const Type::PRIMITIVES& Type::primitive(void) const {
  return *this->basic_;
}


Class& Type::cls(void) {
  return const_cast<Class&>(static_cast<const Type*>(this)->cls());
}

Type::array_t& Type::array(void) {
  return const_cast<Type::array_t&>(static_cast<const Type*>(this)->array());
}

Type::PRIMITIVES& Type::primitive(void) {
  return const_cast<Type::PRIMITIVES&>(static_cast<const Type*>(this)->primitive());
}

const Type& Type::underlying_array_type(void) const {
  const Type* underlying_type = this;
  while (underlying_type->type() == TYPES::ARRAY) {
    underlying_type = &underlying_type->array().back();
  }
  return *underlying_type;
}


Type& Type::underlying_array_type(void) {
  return const_cast<Type&>((static_cast<const Type*>(this)->underlying_array_type()));
}


void Type::parse(const std::string& type) {
  const char t = type[0];
  switch(t) {
    case 'V':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::VOID_T};
        break;
      }

    case 'Z':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::BOOLEAN};
        break;
      }

    case 'B':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::BYTE};
        break;
      }

    case 'S':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::SHORT};
        break;
      }

    case 'C':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::CHAR};
        break;
      }

    case 'I':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::INT};
        break;
      }

    case 'J':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::LONG};
        break;
      }

    case 'F':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::FLOAT};
        break;
      }

    case 'D':
      {
        this->type_ = Type::TYPES::PRIMITIVE;
        this->basic_ = new Type::PRIMITIVES{Type::PRIMITIVES::DOUBLE};
        break;
      }

    case 'L': //CLASS
      {
        this->type_ = Type::TYPES::CLASS;
        break;
      }

    case '[': //ARRAY
      {
        if (this->array_ == nullptr) {
          this->array_ = new array_t{};
        }
        this->type_ = Type::TYPES::ARRAY;
        this->array_->emplace_back(type.substr(1));
        break;
      }

    default:
      {
        LOG(WARNING) << "Unknown type: '" << t << "'";
      }
  }
}

size_t Type::dim(void) const {
  if (this->type() != TYPES::ARRAY) {
    return 0;
  }

  const Type* t = this;
  size_t d = 0;
  while (t->type() == TYPES::ARRAY) {
    ++d;
    t = &(t->array().back());
  }
  return d;
}

void Type::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Type::operator==(const Type& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Type::operator!=(const Type& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Type& type) {
  switch (type.type()) {
    case Type::TYPES::ARRAY:
      {
        os << type.underlying_array_type();
        for (size_t i = 0; i < type.dim(); ++i) {
          os << "[]";
        }
        return os;
      }

    case Type::TYPES::CLASS:
      {
        os << type.cls().fullname();
        return os;
      }

    case Type::TYPES::PRIMITIVE:
      {
        os << Type::pretty_name(type.primitive());
        return os;
      }

    default:
      {
        return os;
      }
  }
  return os;
}


std::string Type::pretty_name(PRIMITIVES p) {
  switch (p) {
    case PRIMITIVES::BOOLEAN:
      {
        return "bool";
      }

    case PRIMITIVES::BYTE:
      {
        return "byte";
      }

    case PRIMITIVES::CHAR:
      {
        return "char";
      }

    case PRIMITIVES::DOUBLE:
      {
        return "double";
      }

    case PRIMITIVES::FLOAT:
      {
        return "float";
      }

    case PRIMITIVES::INT:
      {
        return "int";
      }

    case PRIMITIVES::LONG:
      {
        return "long";
      }

    case PRIMITIVES::SHORT:
      {
        return "short";
      }

    case PRIMITIVES::VOID_T:
      {
        return "void";
      }

    default:
      {
        return "";
      }
  }
}

Type::~Type(void) {
  switch (this->type()) {
    case Type::TYPES::ARRAY:
      {
        delete this->array_;
        break;
      }

    case Type::TYPES::PRIMITIVE:
      {
        delete this->basic_;
        break;
      }

    case Type::TYPES::CLASS:
    case Type::TYPES::UNKNOWN:
    default:
      {
      }
  }
}

}
}
