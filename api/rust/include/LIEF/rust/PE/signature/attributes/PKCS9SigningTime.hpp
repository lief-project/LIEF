#pragma once
#include "LIEF/rust/helpers.hpp"
#include "LIEF/PE/signature/attributes/PKCS9SigningTime.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_PKCS9SigningTime : public PE_Attribute {
  using lief_t = LIEF::PE::PKCS9SigningTime;

  public:
  PE_PKCS9SigningTime(const lief_t& base) :
    PE_Attribute(base) {}

  auto time() const {
    return make_unique_vector<uint64_t>(details::make_vector(impl().time()));
  }

  static auto classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
