#pragma once
#include "LIEF/PE/signature/attributes/PKCS9MessageDigest.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"
#include "LIEF/rust/Span.hpp"

class PE_PKCS9MessageDigest : public PE_Attribute {
  using lief_t = LIEF::PE::PKCS9MessageDigest;
  public:
  PE_PKCS9MessageDigest(const lief_t& base) : PE_Attribute(base) {}

  Span digest() const {
    return make_span(impl().digest());
  }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
