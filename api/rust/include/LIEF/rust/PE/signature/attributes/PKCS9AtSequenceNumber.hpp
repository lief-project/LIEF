#pragma once
#include "LIEF/PE/signature/attributes/PKCS9AtSequenceNumber.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_PKCS9AtSequenceNumber : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::PKCS9AtSequenceNumber;
  PE_PKCS9AtSequenceNumber(const lief_t& base) : PE_Attribute(base) {}

  uint32_t number() const { return impl().number(); }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
