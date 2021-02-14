#include "LIEF/DEX/Field.hpp"
#include "LIEF/DEX/Class.hpp"
#include "logging.hpp"
#include "LIEF/DEX/hash.hpp"
#include "LIEF/DEX/enums.hpp"
#include "LIEF/DEX/EnumToString.hpp"

#include <numeric>


namespace LIEF {
namespace DEX {

Field::Field(const Field&) = default;
Field& Field::operator=(const Field&) = default;

Field::Field(void) = default;

Field::Field(const std::string& name, Class* parent) :
  name_{name},
  parent_{parent},
  access_flags_{ACCESS_FLAGS::ACC_UNKNOWN},
  original_index_{-1u}
{}

const std::string& Field::name(void) const {
  return this->name_;
}

bool Field::has_class(void) const {
  return this->parent_ != nullptr;
}

const Class& Field::cls(void) const {
  if (not this->has_class()) {
    throw not_found("Can't find class associated with " + this->name());
  }
  return *this->parent_;
}

Class& Field::cls(void) {
  return const_cast<Class&>(static_cast<const Field*>(this)->cls());
}

size_t Field::index(void) const {
  return this->original_index_;
}

bool Field::is_static(void) const {
    return this->is_static_;
}

void Field::set_static(bool v) {
    this->is_static_ = v;
}


bool Field::has(ACCESS_FLAGS f) const {
  return (this->access_flags_ & f);
}

Field::access_flags_list_t Field::access_flags(void) const {
  Field::access_flags_list_t flags;

  std::copy_if(
      std::begin(access_flags_list), std::end(access_flags_list),
      std::back_inserter(flags),
      std::bind(static_cast<bool (Field::*)(ACCESS_FLAGS) const>(&Field::has), this, std::placeholders::_1));

  return flags;

}

const Type& Field::type(void) const {
  CHECK(this->type_ != nullptr, "Type is null!");
  return *this->type_;
}

Type& Field::type(void) {
  return const_cast<Type&>(static_cast<const Field*>(this)->type());
}

void Field::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Field::operator==(const Field& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Field::operator!=(const Field& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Field& field) {
  std::string pretty_cls_name = field.cls().fullname();
  if (not pretty_cls_name.empty()) {
    pretty_cls_name = pretty_cls_name.substr(1, pretty_cls_name.size() - 2);
    std::replace(std::begin(pretty_cls_name), std::end(pretty_cls_name), '/', '.');
  }

  Method::access_flags_list_t aflags = field.access_flags();
  std::string flags_str = std::accumulate(
      std::begin(aflags),
      std::end(aflags),
      std::string{},
      [] (const std::string& l, ACCESS_FLAGS r) {
        std::string str = to_string(r);
        std::transform(std::begin(str), std::end(str), std::begin(str), ::tolower);
        return l.empty() ? str : l + " " + str;
      });

  if (not flags_str.empty()) {
    os << flags_str << " ";
  }
  os << field.type()
     << " "
     << pretty_cls_name << "->" << field.name();

  return os;
}

Field::~Field(void) = default;

}
}
