#pragma once
#include "LIEF/PE/signature/attributes/PKCS9CounterSignature.hpp"
#include "LIEF/rust/PE/signature/SignerInfo.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_PKCS9CounterSignature : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::PKCS9CounterSignature;
  PE_PKCS9CounterSignature(lief_t& base) : PE_Attribute(base) {}

  auto signer() const {
    return std::make_unique<PE_SignerInfo>(impl().signer());
  }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
