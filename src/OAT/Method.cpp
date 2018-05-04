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

#include "LIEF/OAT/Method.hpp"
#include "LIEF/OAT/hash.hpp"

namespace LIEF {
namespace OAT {

Method::Method(const Method&) = default;
Method& Method::operator=(const Method&) = default;

Method::Method(DEX::Method* method, Class* oat_class, const std::vector<uint8_t>& quick_code) :
  dex_method_{method},
  class_{oat_class},
  quick_code_{quick_code}
{}


Method::Method(void) :
  dex_method_{nullptr},
  class_{nullptr},
  quick_code_{}
{}


const Class& Method::oat_class(void) const {
  if (this->class_ == nullptr) {
    throw integrity_error("No class found for method");
  }
  return *this->class_;
}

Class& Method::oat_class(void) {
  return const_cast<Class&>(static_cast<const Method*>(this)->oat_class());
}


bool Method::has_dex_method(void) const {
  return this->dex_method_ != nullptr;
}

const DEX::Method& Method::dex_method(void) const {
  if (not this->has_dex_method()) {
    throw integrity_error("No DEX Method found for the current OAT method");
  }
  return *this->dex_method_;
}

DEX::Method& Method::dex_method(void) {
  return const_cast<DEX::Method&>(static_cast<const Method*>(this)->dex_method());
}

bool Method::is_dex2dex_optimized(void) const {
  return this->dex2dex_info().size() > 0;
}

bool Method::is_compiled(void) const {
  return this->quick_code_.size() > 0;
}


std::string Method::name(void) const {
  if (this->dex_method_ == nullptr) {
    return "";
  }

  return this->dex_method_->name();
}

const DEX::dex2dex_method_info_t& Method::dex2dex_info(void) const {
  return this->dex_method_->dex2dex_info();
}


const Method::quick_code_t& Method::quick_code(void) const {
  return this->quick_code_;
}

void Method::quick_code(const Method::quick_code_t& code) {
  this->quick_code_ = code;
}

void Method::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Method::operator==(const Method& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Method::operator!=(const Method& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Method& meth) {
  std::string pretty_name = meth.oat_class().fullname();
  pretty_name = pretty_name.substr(1, pretty_name.size() - 2);

  os << pretty_name << "." << meth.name();
  if (meth.is_compiled()) {
    os << " - Compiled";
  }

  if (meth.is_dex2dex_optimized()) {
    os << " - Optimized";
  }

  return os;
}

Method::~Method(void) = default;



}
}
